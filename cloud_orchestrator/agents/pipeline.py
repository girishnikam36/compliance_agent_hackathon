"""
cloud_orchestrator/agents/pipeline.py
======================================
Three-phase LLM compliance pipeline — all running on Groq free tier.

PROVIDERS (all free, one API key):
  Phase 1 Auditor   → Groq → llama-3.3-70b-versatile
  Phase 2 Judge     → Groq → deepseek-r1-distill-llama-70b  (real R1 reasoning)
  Phase 3 Architect → Groq → llama-3.3-70b-versatile

Why all Groq:
  - Single API key, no juggling multiple providers
  - deepseek-r1-distill-llama-70b is the full DeepSeek R1 reasoning model
    distilled into Llama 70B — same reasoning quality, Groq speed
  - All confirmed working on the free tier (1,000 req/day, 30 RPM)
  - Sign up at https://console.groq.com — no credit card needed

Set ENABLE_MOCK_LLM=false in .env to use real models.
Set ENABLE_MOCK_LLM=true  for instant mock responses during UI dev.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
import uuid
from enum import Enum
from typing import Any

import httpx
from pydantic import BaseModel, Field

logger: logging.Logger = logging.getLogger("oxbuild.pipeline")


# ─────────────────────────────────────────────────────────────────────────────
# Config helpers — tries both cloud_orchestrator.core and core import paths
# because uvicorn is run from inside cloud_orchestrator/ so the package
# root shifts. Both paths are tried transparently.
# ─────────────────────────────────────────────────────────────────────────────

def _mock_enabled() -> bool:
    try:
        try:
            from cloud_orchestrator.core.config import settings
        except ImportError:
            from core.config import settings  # type: ignore[no-redef]
        return settings.enable_mock_llm
    except Exception:
        return os.environ.get("ENABLE_MOCK_LLM", "true").lower() == "true"


def _get_phase_config(phase: str) -> tuple[str, str, str]:
    """
    Return (api_key, base_url, model) for AUDITOR | JUDGE | ARCHITECT.
    Reads from config.py if available, falls back to direct env vars.
    """
    try:
        try:
            from cloud_orchestrator.core.config import settings
        except ImportError:
            from core.config import settings  # type: ignore[no-redef]
        return settings.get_phase_config(phase)
    except RuntimeError:
        raise
    except Exception:
        phase = phase.upper()
        api_key  = os.environ.get(f"{phase}_API_KEY", "")
        base_url = os.environ.get(f"{phase}_BASE_URL", "https://api.groq.com/openai/v1").rstrip("/")
        model    = os.environ.get(f"{phase}_MODEL", "llama-3.3-70b-versatile")
        if not api_key:
            raise RuntimeError(
                f"{phase}_API_KEY not set in .env.\n"
                "Get a free Groq key at https://console.groq.com (no credit card)"
            )
        return api_key, base_url, model


# ─────────────────────────────────────────────────────────────────────────────
# Model defaults — overridden by .env AUDITOR_MODEL / JUDGE_MODEL / ARCHITECT_MODEL
# ─────────────────────────────────────────────────────────────────────────────

AUDITOR_MODEL   = os.environ.get("AUDITOR_MODEL",   "llama-3.3-70b-versatile")
JUDGE_MODEL     = os.environ.get("JUDGE_MODEL",     "deepseek-r1-distill-llama-70b")
ARCHITECT_MODEL = os.environ.get("ARCHITECT_MODEL", "llama-3.3-70b-versatile")


# ─────────────────────────────────────────────────────────────────────────────
# Language helpers
# ─────────────────────────────────────────────────────────────────────────────

def _normalise_lang(language: str) -> str:
    lang = language.strip().lower()
    if lang in ("js", "javascript", "node", "nodejs", "node.js", "jsx", "mjs", "cjs"):
        return "javascript"
    if lang in ("ts", "typescript", "tsx"):
        return "typescript"
    if lang in ("py", "python", "python3"):
        return "python"
    if lang in ("java",):
        return "java"
    if lang in ("go", "golang"):
        return "go"
    if lang in ("rs", "rust"):
        return "rust"
    return lang

def _comment_char(lang: str) -> str:
    return "#" if lang in ("python", "ruby", "bash", "sh") else "//"

def _is_js_family(lang: str) -> bool:
    return lang in ("javascript", "typescript")


# ─────────────────────────────────────────────────────────────────────────────
# Pydantic output schemas
# ─────────────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

class Violation(BaseModel):
    id:          str        = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    regulation:  str        = Field(...)
    article:     str        = Field(...)
    severity:    Severity   = Field(...)
    title:       str        = Field(...)
    description: str        = Field(...)
    line_hint:   str | None = Field(None)
    remediation: str        = Field(...)

class AuditReport(BaseModel):
    model:          str             = Field(default="")
    regulations:    list[str]       = Field(default_factory=list)
    violations:     list[Violation] = Field(default_factory=list)
    total_count:    int             = 0
    critical_count: int             = 0
    high_count:     int             = 0
    summary:        str             = ""
    elapsed_ms:     float           = 0.0

class FinePrediction(BaseModel):
    regulation:  str
    min_eur:     float
    max_eur:     float
    basis:       str
    probability: float = 0.7

class RiskAssessment(BaseModel):
    model:                  str                  = Field(default="")
    raw_risk_score:         float                = 0.0
    normalised_score:       int                  = 0
    risk_label:             str                  = "MINIMAL"
    fine_predictions:       list[FinePrediction] = Field(default_factory=list)
    total_exposure_min_eur: float                = 0.0
    total_exposure_max_eur: float                = 0.0
    rationale:              str                  = ""
    elapsed_ms:             float                = 0.0

    @property
    def risk_score(self) -> int:
        return self.normalised_score

class DiffHunk(BaseModel):
    hunk_id:    int
    original:   str
    patched:    str
    comment:    str
    regulation: str = ""
    article:    str = ""

class PatchResult(BaseModel):
    model:           str            = Field(default="")
    patched_code:    str            = ""
    diff_hunks:      list[DiffHunk] = Field(default_factory=list)
    changes_summary: list[str]      = Field(default_factory=list)
    elapsed_ms:      float          = 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Core HTTP caller
# ─────────────────────────────────────────────────────────────────────────────

async def _call_llm(
    phase:         str,
    system_prompt: str,
    user_message:  str,
    temperature:   float = 0.1,
    max_tokens:    int   = 4096,
    max_retries:   int   = 3,
) -> str:
    """
    POST to the provider configured for `phase`.
    All providers use the OpenAI-compatible chat completions format.
    Returns the assistant message content string.
    Returns "" if ENABLE_MOCK_LLM=true (callers handle the mock path).
    """
    if _mock_enabled():
        logger.info("[MOCK] Skipping real LLM call | phase=%s", phase)
        return ""

    api_key, base_url, model = _get_phase_config(phase)
    endpoint = f"{base_url}/chat/completions"
    headers  = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type":  "application/json",
        "HTTP-Referer":  "https://oxbuild.ai",
        "X-Title":       "Oxbuild Compliance Agent",
    }
    payload = {
        "model":       model,
        "temperature": temperature,
        "max_tokens":  max_tokens,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_message},
        ],
    }

    last_error: Exception | None = None

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(connect=15.0, read=120.0, write=30.0, pool=5.0)
    ) as client:
        for attempt in range(max_retries):
            try:
                t0 = time.perf_counter()
                r  = await client.post(endpoint, headers=headers, json=payload)
                ms = (time.perf_counter() - t0) * 1000

                if r.status_code == 200:
                    data    = r.json()
                    content = data["choices"][0]["message"]["content"]
                    tokens  = data.get("usage", {}).get("total_tokens", "?")
                    logger.info("LLM OK | phase=%s model=%s %.0fms tokens=%s",
                                phase, model, ms, tokens)
                    return content

                if r.status_code == 429:
                    wait = float(r.headers.get("Retry-After", 10 * (attempt + 1)))
                    logger.warning("Rate limited (429) | phase=%s — waiting %.0fs", phase, wait)
                    await asyncio.sleep(wait)
                    last_error = RuntimeError("Rate limited")
                    continue

                if r.status_code in (401, 403):
                    raise RuntimeError(
                        f"Authentication failed ({r.status_code}) for phase={phase}.\n"
                        f"Check {phase}_API_KEY in your .env file.\n"
                        f"Get a free Groq key at https://console.groq.com"
                    )

                if r.status_code == 402:
                    raise RuntimeError(
                        f"Insufficient balance for phase={phase}.\n"
                        f"Current provider ({base_url}) requires payment.\n"
                        "Switch to Groq free tier: set {phase}_BASE_URL=https://api.groq.com/openai/v1\n"
                        "and {phase}_API_KEY=your_groq_key in .env"
                    )

                if r.status_code == 404:
                    raise RuntimeError(
                        f"Model not found (404) for phase={phase}.\n"
                        f"Model '{model}' does not exist at {base_url}.\n"
                        f"Check {phase}_MODEL in your .env file.\n"
                        f"Confirmed working Groq models:\n"
                        f"  llama-3.3-70b-versatile\n"
                        f"  deepseek-r1-distill-llama-70b"
                    )

                if r.status_code >= 500:
                    delay = 2 ** attempt
                    logger.warning("Server error %d | phase=%s — retrying in %ds",
                                   r.status_code, phase, delay)
                    await asyncio.sleep(delay)
                    last_error = RuntimeError(f"Server error {r.status_code}")
                    continue

                raise RuntimeError(
                    f"LLM error {r.status_code} | phase={phase}: {r.text[:300]}"
                )

            except httpx.TimeoutException as exc:
                delay = 2 ** attempt
                logger.warning("Timeout | phase=%s attempt %d — retrying in %ds",
                               phase, attempt + 1, delay)
                await asyncio.sleep(delay)
                last_error = RuntimeError(f"Timed out: {exc}")

            except httpx.NetworkError as exc:
                raise RuntimeError(f"Network error reaching {base_url}: {exc}") from exc

    raise RuntimeError(
        f"All {max_retries} attempts failed | phase={phase}. Last: {last_error}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# JSON extraction — handles all LLM response quirks
# ─────────────────────────────────────────────────────────────────────────────

def _extract_json(text: str) -> Any:
    """
    Parse JSON from LLM output that may contain:
    - <think>...</think> blocks (DeepSeek R1 on Groq)
    - ```json ... ``` markdown fences
    - Explanation text before/after the JSON
    - Trailing commas
    """
    if not text:
        return None

    # Strip DeepSeek R1 thinking blocks
    text = re.sub(r"<think>[\s\S]*?</think>", "", text, flags=re.DOTALL).strip()

    def _try(s: str) -> Any:
        s = s.strip()
        try:
            return json.loads(s)
        except json.JSONDecodeError:
            pass
        try:
            return json.loads(re.sub(r",\s*([}\]])", r"\1", s))
        except json.JSONDecodeError:
            pass
        return None

    # Strategy 1: direct parse
    r = _try(text)
    if r is not None:
        return r

    # Strategy 2: ```json ... ``` fences
    for m in re.finditer(r"```(?:json)?\s*([\s\S]*?)```", text):
        r = _try(m.group(1))
        if r is not None:
            return r

    # Strategy 3: find first bracket and walk to matching close
    for open_c, close_c, pat in [("[", "]", r"\["), ("{", "}", r"\{")]:
        m = re.search(pat, text)
        if not m:
            continue
        start = m.start()
        depth = 0
        in_str = False
        esc    = False
        end    = start
        for i, ch in enumerate(text[start:], start=start):
            if esc:              esc = False;    continue
            if ch == "\\" and in_str: esc = True; continue
            if ch == '"' and not esc: in_str = not in_str; continue
            if in_str:          continue
            if ch == open_c:    depth += 1
            elif ch == close_c:
                depth -= 1
                if depth == 0:  end = i; break
        if end > start:
            r = _try(text[start:end + 1])
            if r is not None:
                return r

    logger.warning("_extract_json: all strategies failed. First 300:\n%s", text[:300])
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Phase 1 — Auditor (Groq / llama-3.3-70b-versatile)
# ─────────────────────────────────────────────────────────────────────────────

_AUDITOR_SYSTEM = """\
You are a senior legal-technology compliance auditor specialising in GDPR, DPDPA, CCPA, HIPAA, and PCI-DSS.

TASK: Analyse the {language} source code and find every compliance violation.

CRITICAL OUTPUT RULES — your response is machine-parsed:
1. Your ENTIRE response must be a valid JSON array.
2. First character must be [  and last character must be ]
3. NO text, explanation, or markdown outside the JSON.
4. NO ```json fences — raw JSON only.
5. Each object must have EXACTLY these 7 fields:
   {{
     "regulation": "GDPR",
     "article":    "Article 25 — Data Protection by Design",
     "severity":   "CRITICAL",
     "title":      "Short headline under 80 chars",
     "description":"2-4 sentences explaining the violation and legal basis",
     "line_hint":  "The exact line of code containing the violation, or null",
     "remediation":"Specific actionable fix, 1-3 sentences"
   }}
6. severity must be exactly: CRITICAL, HIGH, MEDIUM, LOW, or INFO
7. If no violations: return []

LANGUAGE AWARENESS — you are auditing {language}:
  JavaScript/TypeScript: check console.log(PII), hardcoded secrets, raw card numbers in db inserts,
    missing webhook signature verification, PAN in error responses, localStorage PII
  Python: check print(PII), hardcoded DB credentials, SELECT *, no consent checks, infinite retention
  All: data minimisation, purpose limitation, third-party sharing without DPA, erasure pathways

PII TOKENS: [PII_LABEL_HASH] tokens replaced real values — treat them as real PII."""

async def run_audit(
    sanitized_code: str,
    language:       str = "python",
    regulations:    list[str] | None = None,
) -> AuditReport:
    if regulations is None:
        regulations = ["GDPR", "DPDPA"]

    lang = _normalise_lang(language)
    t0   = time.perf_counter()
    logger.info("Phase 1 Auditor | lang=%s regs=%s mock=%s", lang, regulations, _mock_enabled())

    try:
        _, _, model = _get_phase_config("AUDITOR") if not _mock_enabled() else ("", "", AUDITOR_MODEL)
    except Exception:
        model = AUDITOR_MODEL

    system_prompt = _AUDITOR_SYSTEM.format(language=lang)
    user_message  = (
        f"Audit this {lang} code for violations of: {', '.join(regulations)}.\n\n"
        f"{sanitized_code}\n\n"
        "Return ONLY the raw JSON array starting with [. No other text."
    )

    raw = await _call_llm(
        phase="AUDITOR",
        system_prompt=system_prompt,
        user_message=user_message,
        temperature=0.05,
        max_tokens=4096,
    )

    violations: list[Violation] = []

    if _mock_enabled():
        violations = _mock_violations(sanitized_code, lang, regulations)
    else:
        parsed = _extract_json(raw)
        if isinstance(parsed, list):
            for item in parsed:
                try:
                    violations.append(Violation(
                        regulation  = str(item.get("regulation", "GDPR")),
                        article     = str(item.get("article", "Unknown")),
                        severity    = str(item.get("severity", "MEDIUM")),
                        title       = str(item.get("title", "Unnamed violation")),
                        description = str(item.get("description", "")),
                        line_hint   = item.get("line_hint") or None,
                        remediation = str(item.get("remediation", "")),
                    ))
                except Exception as e:
                    logger.warning("Skipped malformed violation: %s", e)
        else:
            logger.warning("Auditor did not return JSON array — using mock fallback")
            violations = _mock_violations(sanitized_code, lang, regulations)

    critical = sum(1 for v in violations if v.severity == Severity.CRITICAL)
    high     = sum(1 for v in violations if v.severity == Severity.HIGH)
    elapsed  = (time.perf_counter() - t0) * 1000
    logger.info("Phase 1 complete: %d violations (%.0fms)", len(violations), elapsed)

    return AuditReport(
        model=model,
        regulations=regulations,
        violations=violations,
        total_count=len(violations),
        critical_count=critical,
        high_count=high,
        summary=f"Found {len(violations)} violation(s) across {', '.join(regulations)} — {critical} critical, {high} high.",
        elapsed_ms=round(elapsed, 2),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 — Judge (Groq / deepseek-r1-distill-llama-70b)
# This is the actual DeepSeek R1 reasoning model distilled into Llama 70B.
# Confirmed on Groq's docs and free tier. Produces <think> blocks which
# _extract_json strips before parsing.
# ─────────────────────────────────────────────────────────────────────────────

_FINE_TABLE: dict[str, tuple[float, float, str]] = {
    "GDPR":    (500_000,   20_000_000, "GDPR Art. 83(5): up to €20M or 4% global annual turnover"),
    "DPDPA":   (100_000,   27_000_000, "DPDPA §33: up to ₹250 Cr (~€27M) per incident"),
    "CCPA":    (10_000,    5_000_000,  "CCPA §1798.155: up to $7,500 per intentional violation"),
    "HIPAA":   (50_000,    1_500_000,  "HIPAA §1176: $100–$50,000 per violation, $1.5M annual cap"),
    "PCI-DSS": (5_000,     100_000,    "PCI-DSS §12: $5,000–$100,000/month until remediated"),
    "SOC2":    (10_000,    500_000,    "SOC 2: audit/certification penalties"),
}

_JUDGE_SYSTEM = """\
You are a quantitative regulatory risk analyst.

TASK: Score compliance violations using this EXACT formula:
  Severity: CRITICAL=10, HIGH=7, MEDIUM=4, LOW=2, INFO=1
  Likelihood = your estimate [0.0-1.0] of enforcement probability
  Raw Risk = Σ(Severity_i × Likelihood_i)
  Score = min(100, round((Raw Risk / (10 × N)) × 100))  where N = violation count
  Label: 80-100=CRITICAL | 60-79=HIGH | 40-59=MEDIUM | 20-39=LOW | 0-19=MINIMAL

CRITICAL OUTPUT RULES:
1. Your ENTIRE response must be a valid JSON object.
2. First character must be {  and last character must be }
3. NO text, explanation, or markdown outside the JSON.
4. NO ```json fences — raw JSON only.

Required structure:
{{
  "raw_risk_score":   <float>,
  "normalised_score": <int 0-100>,
  "risk_label":       "<CRITICAL|HIGH|MEDIUM|LOW|MINIMAL>",
  "score_breakdown": [
    {{
      "violation_id":    "<id>",
      "violation_title": "<title>",
      "severity":        <int 1-10>,
      "likelihood":      <float 0.0-1.0>,
      "weighted_score":  <float>,
      "rationale":       "<one sentence>"
    }}
  ],
  "rationale": "<3-5 sentence executive summary>"
}}"""

async def run_risk(
    violations:     list[Violation],
    sanitized_code: str,
) -> RiskAssessment:
    t0 = time.perf_counter()
    logger.info("Phase 2 Judge | violations=%d mock=%s", len(violations), _mock_enabled())

    try:
        _, _, model = _get_phase_config("JUDGE") if not _mock_enabled() else ("", "", JUDGE_MODEL)
    except Exception:
        model = JUDGE_MODEL

    violations_json = json.dumps([v.model_dump() for v in violations], indent=2)
    user_message    = (
        f"Score these {len(violations)} violations using the formula in your instructions.\n\n"
        f"{violations_json}\n\n"
        "Return ONLY the raw JSON object starting with {. No other text."
    )

    raw = await _call_llm(
        phase="JUDGE",
        system_prompt=_JUDGE_SYSTEM,
        user_message=user_message,
        temperature=0.6,   # R1 models work best at 0.5-0.7 per Groq docs
        max_tokens=2048,
    )

    regs_hit = {v.regulation for v in violations}
    fine_predictions = [
        FinePrediction(regulation=reg, min_eur=_FINE_TABLE[reg][0],
                       max_eur=_FINE_TABLE[reg][1], basis=_FINE_TABLE[reg][2])
        for reg in sorted(regs_hit) if reg in _FINE_TABLE
    ]

    def _compute() -> tuple[float, int]:
        w = {Severity.CRITICAL: 10, Severity.HIGH: 7, Severity.MEDIUM: 4, Severity.LOW: 2, Severity.INFO: 1}
        raw_val = sum(w.get(v.severity, 1) * 0.7 for v in violations)
        n = max(len(violations), 1)
        return round(raw_val, 2), min(100, round((raw_val / (10 * n)) * 100))

    normalised_score = 0
    raw_risk_score   = 0.0
    rationale        = ""

    if _mock_enabled() or not raw:
        raw_risk_score, normalised_score = _compute()
    else:
        parsed = _extract_json(raw)
        if isinstance(parsed, dict):
            normalised_score = int(parsed.get("normalised_score", 0))
            raw_risk_score   = float(parsed.get("raw_risk_score", 0.0))
            rationale        = str(parsed.get("rationale", ""))
        else:
            logger.warning("Judge returned non-dict — computing from violations")
            raw_risk_score, normalised_score = _compute()

    normalised_score = max(0, min(100, normalised_score))
    if normalised_score >= 80:   risk_label = "CRITICAL"
    elif normalised_score >= 60: risk_label = "HIGH"
    elif normalised_score >= 40: risk_label = "MEDIUM"
    elif normalised_score >= 20: risk_label = "LOW"
    else:                        risk_label = "MINIMAL"

    if not rationale:
        tmin = sum(f.min_eur for f in fine_predictions)
        tmax = sum(f.max_eur for f in fine_predictions)
        rationale = (
            f"Risk score {normalised_score}/100 ({risk_label}) from "
            f"{len(violations)} violation(s) across {len(regs_hit)} framework(s). "
            f"Regulatory exposure: €{tmin:,.0f}–€{tmax:,.0f}."
        )

    elapsed = (time.perf_counter() - t0) * 1000
    logger.info("Phase 2 complete: score=%d %s (%.0fms)", normalised_score, risk_label, elapsed)

    return RiskAssessment(
        model=model,
        raw_risk_score=raw_risk_score,
        normalised_score=normalised_score,
        risk_label=risk_label,
        fine_predictions=fine_predictions,
        total_exposure_min_eur=round(sum(f.min_eur for f in fine_predictions), 2),
        total_exposure_max_eur=round(sum(f.max_eur for f in fine_predictions), 2),
        rationale=rationale,
        elapsed_ms=round(elapsed, 2),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Phase 3 — Architect (Groq / llama-3.3-70b-versatile)
# ─────────────────────────────────────────────────────────────────────────────

_LANG_RULES: dict[str, str] = {
    "javascript": """\
- Use const/let, never var
- Logging: Winston or pino — never console.log for PII
- Secrets: process.env.SECRET_NAME — never hardcode
- SQL: parameterised db.query('SELECT $1', [val])
- Webhooks: stripe.webhooks.constructEvent() for verification
- Payments: accept only Stripe/Braintree tokens (pm_xxx), never raw PANs or CVVs
- Errors: return only requestId in response, log details server-side""",
    "typescript": """\
- Same as JavaScript plus TypeScript interfaces for all data shapes
- Never use `any` for objects containing personal data""",
    "python": """\
- Logging: logging module only — never print() for PII
- Secrets: os.environ.get('KEY') — never hardcode
- SQL: cursor.execute('SELECT %s', (val,)) — parameterised
- Delete: soft-delete with deleted_at timestamp
- Data: explicit field allowlists, never SELECT *""",
    "java": """\
- Logging: SLF4J/Logback — never System.out.println for PII
- Secrets: environment variables or vault
- SQL: PreparedStatement only""",
    "go": """\
- Logging: log/slog structured — never fmt.Println for PII
- Secrets: os.Getenv() — never hardcode
- SQL: parameterised queries with database/sql""",
}

_ARCHITECT_SYSTEM = """\
You are a principal software architect specialising in privacy-by-design and regulatory-compliant {language} code.

TASK: Rewrite the provided {language} source code to fix every listed compliance violation.

CRITICAL OUTPUT RULES:
1. Your ENTIRE response must be a valid JSON object.
2. First character must be {{  and last character must be }}
3. NO text, explanation, or markdown outside the JSON.
4. NO ```json fences — raw JSON only.
5. patched_code must be COMPLETE, RUNNABLE {language} — not a fragment.
6. patched_code must use ONLY {language} syntax — NEVER mix languages.
7. All inline comments: use {comment_char} [COMPLIANCE] REGULATION Art. N — Description

Required JSON structure:
{{
  "patched_code": "<complete {language} source — use \\n for newlines>",
  "diff_hunks": [
    {{
      "hunk_id":    1,
      "original":   "<verbatim snippet from the original code>",
      "patched":    "<the replacement {language} code>",
      "comment":    "<one sentence: what changed and why>",
      "regulation": "<regulation>",
      "article":    "<article>"
    }}
  ],
  "changes_summary": ["<plain English change 1>", "<plain English change 2>"],
  "patch_coverage": <float 0.0-1.0>
}}

{language} RULES:
{lang_rules}

PII TOKENS: Leave [PII_LABEL_HASH] tokens as-is or replace with {secret_pattern}."""

async def run_patch(
    sanitized_code: str,
    violations:     list[Violation],
    language:       str = "python",
) -> PatchResult:
    lang         = _normalise_lang(language)
    comment_char = _comment_char(lang)
    lang_rules   = _LANG_RULES.get(lang, f"Follow {lang} best practices")
    secret_pat   = "process.env.KEY" if _is_js_family(lang) else "os.environ.get('KEY')"

    t0 = time.perf_counter()
    logger.info("Phase 3 Architect | lang=%s violations=%d mock=%s",
                lang, len(violations), _mock_enabled())

    try:
        _, _, model = _get_phase_config("ARCHITECT") if not _mock_enabled() else ("", "", ARCHITECT_MODEL)
    except Exception:
        model = ARCHITECT_MODEL

    system_prompt = _ARCHITECT_SYSTEM.format(
        language=lang,
        comment_char=comment_char,
        lang_rules=lang_rules,
        secret_pattern=secret_pat,
    )

    violations_compact = json.dumps([
        {"id": v.id, "regulation": v.regulation, "severity": v.severity,
         "title": v.title, "remediation": v.remediation}
        for v in violations
    ], indent=2)

    user_message = (
        f"Fix these {len(violations)} violations in the {lang} code below.\n\n"
        f"VIOLATIONS:\n{violations_compact}\n\n"
        f"ORIGINAL {lang.upper()} CODE:\n{sanitized_code}\n\n"
        f"Return ONLY the raw JSON object starting with {{."
    )

    raw = await _call_llm(
        phase="ARCHITECT",
        system_prompt=system_prompt,
        user_message=user_message,
        temperature=0.1,
        max_tokens=8192,
    )

    patched_code:    str            = ""
    diff_hunks:      list[DiffHunk] = []
    changes_summary: list[str]      = []

    if _mock_enabled():
        patched_code, diff_hunks, changes_summary = _mock_patch(sanitized_code, lang, violations)
    elif not raw:
        patched_code, diff_hunks, changes_summary = _safe_fallback(sanitized_code, lang, violations)
    else:
        parsed = _extract_json(raw)
        if isinstance(parsed, dict):
            patched_code    = parsed.get("patched_code", "")
            changes_summary = parsed.get("changes_summary", [])
            for h in parsed.get("diff_hunks", []):
                try:
                    diff_hunks.append(DiffHunk(
                        hunk_id=int(h.get("hunk_id", 1)),
                        original=str(h.get("original", "")),
                        patched=str(h.get("patched", "")),
                        comment=str(h.get("comment", "")),
                        regulation=str(h.get("regulation", "")),
                        article=str(h.get("article", "")),
                    ))
                except Exception as e:
                    logger.warning("Skipped malformed hunk: %s", e)
            if not patched_code:
                patched_code, diff_hunks, changes_summary = _safe_fallback(sanitized_code, lang, violations)
        else:
            logger.warning("Architect non-dict JSON — safe fallback. Raw: %s", raw[:300])
            patched_code, diff_hunks, changes_summary = _safe_fallback(sanitized_code, lang, violations)

    elapsed = (time.perf_counter() - t0) * 1000
    logger.info("Phase 3 complete: %d hunks (%.0fms)", len(diff_hunks), elapsed)

    return PatchResult(
        model=model,
        patched_code=patched_code,
        diff_hunks=diff_hunks,
        changes_summary=changes_summary,
        elapsed_ms=round(elapsed, 2),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Safe fallback — never injects wrong language syntax
# ─────────────────────────────────────────────────────────────────────────────

def _safe_fallback(code, lang, violations):
    c = _comment_char(lang)
    reg_list = ", ".join(sorted({v.regulation for v in violations}))
    lines = [
        f"{c} {'─'*68}",
        f"{c} OXBUILD COMPLIANCE REVIEW — Manual patch required",
        f"{c} Language: {lang} | Regulations: {reg_list}",
        f"{c}",
    ]
    for i, v in enumerate(violations, 1):
        lines.append(f"{c} [{i}] {v.severity} — {v.title}")
        lines.append(f"{c}     Fix: {v.remediation[:80]}")
    lines += [f"{c} {'─'*68}", ""]
    summary = [
        "⚠ Automatic patching could not be applied — see Audit Report tab.",
        "Apply the fixes listed there manually.",
    ] + [f"• {v.title}: {v.remediation[:100]}" for v in violations]
    return "\n".join(lines) + "\n" + code, [], summary


# ─────────────────────────────────────────────────────────────────────────────
# Language-aware mock data (ENABLE_MOCK_LLM=true)
# ─────────────────────────────────────────────────────────────────────────────

def _mock_violations(code: str, lang: str, regulations: list[str]) -> list[Violation]:
    mocks: list[Violation] = []
    lines = code.splitlines()

    def first_line(pat: str) -> str | None:
        for line in lines:
            if re.search(pat, line, re.IGNORECASE):
                return line.strip()[:120]
        return None

    is_js = _is_js_family(lang)

    secret_hint = (
        first_line(r"(sk[_-](live|test)[_-]\w{10,}|whsec_\w+|AKIA[0-9A-Z]{16}|\[PII_API_KEY_)")
        or first_line(r"(secret|password|token|api.?key)\s*[=:]\s*[\"'][^\"']{8,}")
    )
    if secret_hint:
        mocks.append(Violation(
            regulation="GDPR", article="Article 32 — Security of Processing",
            severity=Severity.CRITICAL, title="Hardcoded API secret or credential in source code",
            description="A secret key is hardcoded in source, giving anyone with repo access the credential. GDPR Art. 32 requires appropriate technical security measures.",
            line_hint=secret_hint,
            remediation=f"Move to {'process.env.SECRET_KEY' if is_js else 'os.environ.get(\"SECRET_KEY\")'} and add .env to .gitignore.",
        ))

    log_hint = first_line(r"console\.(log|error|warn)" if is_js else r"print\(")
    if log_hint and re.search(r"(email|card|password|user|name|ssn)", log_hint, re.I):
        mocks.append(Violation(
            regulation="GDPR", article="Article 32 — Security of Processing",
            severity=Severity.HIGH, title="Personal data written to logs in plaintext",
            description=f"PII is written to {'console.log' if is_js else 'print()'} which persists unencrypted in log systems. GDPR Art. 32 requires appropriate confidentiality.",
            line_hint=log_hint,
            remediation="Use a structured logger. Log only opaque user IDs, never raw PII.",
        ))

    card_hint = first_line(r"INSERT.*card_number|cardNumber.*\$\d+") or first_line(r"(card_number|cardNumber|cvv)\s*[,\)]")
    if card_hint:
        mocks.append(Violation(
            regulation="GDPR", article="Article 5(1)(f) — Integrity & Confidentiality",
            severity=Severity.CRITICAL, title="Raw payment card data stored or transmitted",
            description="PANs or CVVs handled by the application. PCI-DSS prohibits storing CVVs and requires PANs to be tokenised. GDPR Art. 5(1)(f) requires confidentiality.",
            line_hint=card_hint,
            remediation="Accept only Stripe/Braintree tokens (pm_xxx). Your server must never receive raw card numbers.",
        ))

    if is_js and first_line(r"(webhook|stripe.*event)") and not first_line(r"constructEvent|timingSafeEqual"):
        mocks.append(Violation(
            regulation="GDPR", article="Article 32 — Security of Processing",
            severity=Severity.HIGH, title="Webhook handler processes unverified payloads",
            description="The webhook route does not verify the cryptographic signature, allowing forged events. GDPR Art. 32 requires integrity of processing.",
            line_hint=first_line(r"req\.body") or first_line(r"webhook"),
            remediation="Use stripe.webhooks.constructEvent(req.rawBody, req.headers['stripe-signature'], WEBHOOK_SECRET).",
        ))

    select_hint = first_line(r"SELECT\s+\*") or first_line(r"fetchall|findAll")
    if select_hint:
        mocks.append(Violation(
            regulation="GDPR", article="Article 25 — Data Protection by Design",
            severity=Severity.HIGH, title="No data minimisation — full records returned",
            description="Queries return complete rows including fields not needed for the operation. GDPR Art. 25 requires minimising personal data to what is strictly necessary.",
            line_hint=select_hint,
            remediation="Use an explicit field allowlist. Never SELECT * on tables containing personal data.",
        ))

    if "DPDPA" in regulations and not first_line(r"consent"):
        mocks.append(Violation(
            regulation="DPDPA", article="Section 6 — Consent Framework",
            severity=Severity.CRITICAL, title="No consent verification before processing personal data",
            description="Personal data is processed without a preceding consent check. DPDPA §6 requires explicit consent before any digital personal data processing.",
            line_hint=None,
            remediation="Add consent.verify(userId, purpose) before every data access path.",
        ))

    if not mocks:
        mocks.append(Violation(
            regulation="GDPR", article="Article 5 — Principles",
            severity=Severity.MEDIUM, title=f"Manual compliance review required ({lang})",
            description=f"No automatic violation patterns detected in this {lang} file. Enable real LLM mode (ENABLE_MOCK_LLM=false) for a complete audit.",
            line_hint=None,
            remediation="Set ENABLE_MOCK_LLM=false in .env for real AI-powered analysis.",
        ))
    return mocks


def _mock_patch(code: str, lang: str, violations: list[Violation]) -> tuple[str, list[DiffHunk], list[str]]:
    c     = _comment_char(lang)
    is_js = _is_js_family(lang)
    lines = code.splitlines()

    def first_line(pat: str) -> str | None:
        for line in lines:
            if re.search(pat, line, re.IGNORECASE):
                return line.strip()[:120]
        return None

    if is_js:
        header = (
            f"{c} {'─'*68}\n{c} OXBUILD COMPLIANCE PATCH — {lang}\n{c} {'─'*68}\n\n"
            "'use strict';\n"
            "const { createLogger, transports, format } = require('winston');\n"
            "const auditLogger = createLogger({ transports: [new transports.Console()], format: format.json() });\n"
            "const SAFE_FIELDS = ['id', 'accountStatus', 'createdAt'];\n\n"
        )
    elif lang == "python":
        header = (
            f"{c} {'─'*68}\n{c} OXBUILD COMPLIANCE PATCH — python\n{c} {'─'*68}\n"
            "from __future__ import annotations\nimport logging\nimport os\n\n"
            "audit_logger = logging.getLogger('oxbuild.data_access')\n"
            "REQUIRED_FIELDS = ('id', 'account_status', 'created_at')\n\n"
        )
    else:
        header = f"{c} {'─'*68}\n{c} OXBUILD COMPLIANCE PATCH — {lang}\n{c} {'─'*68}\n\n"

    hunks: list[DiffHunk] = []
    summary: list[str]    = []
    hid = 1

    if is_js:
        sl = first_line(r"(sk[_-](live|test)[_-]\w+|whsec_|\[PII_API_KEY_)")
        if sl:
            hunks.append(DiffHunk(hunk_id=hid, original=sl,
                patched="const STRIPE_SECRET = process.env.STRIPE_SECRET_KEY;\nconst WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;",
                comment="Hardcoded secrets moved to process.env (GDPR Art. 32)", regulation="GDPR", article="Art. 32"))
            summary.append("Hardcoded secrets replaced with process.env (GDPR Art. 32)"); hid += 1
        cl = first_line(r"console\.(log|error).*?(card|email|cvv)")
        if cl:
            hunks.append(DiffHunk(hunk_id=hid, original=cl,
                patched="auditLogger.info('event', { userId, amount });",
                comment="console.log(PII) replaced with structured logger (GDPR Art. 32)", regulation="GDPR", article="Art. 32"))
            summary.append("console.log(PII) replaced with auditLogger (GDPR Art. 32)"); hid += 1
        if first_line(r"INSERT.*card_number|cardNumber.*VALUES"):
            hunks.append(DiffHunk(hunk_id=hid,
                original=first_line(r"INSERT.*card|card.*VALUES") or "db.query(INSERT ... cardNumber)",
                patched="await db.query('INSERT INTO payment_methods (user_id, stripe_pm_id) VALUES ($1,$2)', [userId, stripePaymentMethodId]);",
                comment="Raw PAN replaced with Stripe payment method token (PCI-DSS Req. 3.2)", regulation="GDPR", article="Art. 5(1)(f)"))
            summary.append("Raw PAN storage replaced with Stripe token (PCI-DSS Req. 3.2)"); hid += 1
        if first_line(r"router\.post.*webhook") and not first_line(r"constructEvent"):
            hunks.append(DiffHunk(hunk_id=hid,
                original=first_line(r"const event\s*=\s*req\.body") or "const event = req.body;",
                patched="const event = stripeClient.webhooks.constructEvent(req.rawBody, req.headers['stripe-signature'], WEBHOOK_SECRET);",
                comment="Added webhook signature verification (GDPR Art. 32)", regulation="GDPR", article="Art. 32"))
            summary.append("Webhook signature verification added (GDPR Art. 32)"); hid += 1
    elif lang == "python":
        if first_line(r"SELECT\s+\*|fetchall"):
            hunks.append(DiffHunk(hunk_id=hid,
                original=first_line(r"SELECT\s+\*|fetchall") or "SELECT * / fetchall",
                patched="results = db.query(*[getattr(User, f) for f in REQUIRED_FIELDS]).filter(User.deleted_at.is_(None)).all()",
                comment="SELECT * replaced with field projection + soft-delete filter (GDPR Art. 25, 17)", regulation="GDPR", article="Art. 25"))
            summary.append("SELECT * replaced with REQUIRED_FIELDS projection (GDPR Art. 25)"); hid += 1
        if first_line(r"print\("):
            hunks.append(DiffHunk(hunk_id=hid,
                original=first_line(r"print\(") or "print(user_data)",
                patched='audit_logger.info("event", extra={"user_id": user_id})',
                comment="print() replaced with audit_logger (GDPR Art. 32)", regulation="GDPR", article="Art. 32"))
            summary.append("print() replaced with audit_logger (GDPR Art. 32)"); hid += 1

    if not hunks:
        summary.append(f"No auto-patches for {lang} in mock mode.")
    summary.append(f"All {len(violations)} violation(s) require attention — see Audit Report tab")
    return header + code, hunks, summary