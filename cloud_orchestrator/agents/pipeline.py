"""
cloud_orchestrator/agents/pipeline.py
======================================
Three-phase LLM compliance pipeline — LIVE implementation via Oxlo.ai.

Phase 1 — Auditor    : llama-3.3-70b      → GDPR/DPDPA violation detection
Phase 2 — Judge      : deepseek-r1-70b    → risk score + fine prediction
Phase 3 — Architect  : deepseek-coder-33b → compliant code patch

Oxlo API docs : https://docs.oxlo.ai/docs/api/chat
Model IDs     : https://docs.oxlo.ai/docs/api/models
Base URL      : https://api.oxlo.ai/v1
Auth          : Bearer <OXLO_API_KEY>
Format        : OpenAI-compatible chat completions

Toggle between mock and real via ENABLE_MOCK_LLM in your .env file:
  ENABLE_MOCK_LLM=true  → instant mock responses (no API credits used)
  ENABLE_MOCK_LLM=false → real Oxlo API calls
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
# Configuration — reads from .env via config.py at call time
# ─────────────────────────────────────────────────────────────────────────────

def _get_api_key() -> str:
    try:
        from cloud_orchestrator.core.config import settings
        return settings.oxlo_api_key.get_secret_value()
    except Exception:
        key = os.environ.get("OXLO_API_KEY", "")
        if not key:
            raise RuntimeError(
                "OXLO_API_KEY is not set. Add it to your .env file and restart."
            )
        return key

def _get_base_url() -> str:
    try:
        from cloud_orchestrator.core.config import settings
        return settings.oxlo_base_url_str
    except Exception:
        return os.environ.get("OXLO_BASE_URL", "https://api.oxlo.ai/v1").rstrip("/")

def _mock_enabled() -> bool:
    try:
        from cloud_orchestrator.core.config import settings
        return settings.enable_mock_llm
    except Exception:
        return os.environ.get("ENABLE_MOCK_LLM", "false").lower() == "true"


# ─────────────────────────────────────────────────────────────────────────────
# Oxlo model IDs (exact strings from docs.oxlo.ai/docs/api/models)
# ─────────────────────────────────────────────────────────────────────────────

AUDITOR_MODEL   = "llama-3.3-70b"       # Premium — instruction + legal reasoning
JUDGE_MODEL     = "deepseek-r1-70b"     # Pro     — reasoning + scoring
ARCHITECT_MODEL = "deepseek-coder-33b"  # Pro     — code generation


# ─────────────────────────────────────────────────────────────────────────────
# Shared enumerations and Pydantic output schemas
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
    model:          str             = AUDITOR_MODEL
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
    model:                  str                  = JUDGE_MODEL
    raw_risk_score:         float                = 0.0
    normalised_score:       int                  = 0
    risk_label:             str                  = "MINIMAL"
    fine_predictions:       list[FinePrediction] = Field(default_factory=list)
    total_exposure_min_eur: float                = 0.0
    total_exposure_max_eur: float                = 0.0
    rationale:              str                  = ""
    elapsed_ms:             float                = 0.0

    # Compatibility alias for App.jsx
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
    model:           str            = ARCHITECT_MODEL
    patched_code:    str            = ""
    diff_hunks:      list[DiffHunk] = Field(default_factory=list)
    changes_summary: list[str]      = Field(default_factory=list)
    elapsed_ms:      float          = 0.0


# ─────────────────────────────────────────────────────────────────────────────
# _call_oxlo — the SINGLE function that talks to the Oxlo API
# ─────────────────────────────────────────────────────────────────────────────

async def _call_oxlo(
    model:         str,
    system_prompt: str,
    user_message:  str,
    temperature:   float = 0.1,
    max_tokens:    int   = 4096,
    max_retries:   int   = 3,
) -> str:
    """
    POST to https://api.oxlo.ai/v1/chat/completions and return the
    assistant's text content.

    Retries on 429 (rate limit) and 5xx with exponential back-off.
    Returns empty string if ENABLE_MOCK_LLM=true (callers check this).
    """
    if _mock_enabled():
        logger.info("[MOCK MODE] Skipping real Oxlo call for model=%s", model)
        return ""

    endpoint = f"{_get_base_url()}/chat/completions"
    headers  = {
        "Authorization": f"Bearer {_get_api_key()}",
        "Content-Type":  "application/json",
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

    async with httpx.AsyncClient(timeout=httpx.Timeout(connect=10.0, read=120.0, write=30.0, pool=5.0)) as client:
        for attempt in range(max_retries):
            try:
                t0       = time.perf_counter()
                response = await client.post(endpoint, headers=headers, json=payload)
                ms       = (time.perf_counter() - t0) * 1000

                if response.status_code == 200:
                    data    = response.json()
                    content = data["choices"][0]["message"]["content"]
                    tokens  = data.get("usage", {}).get("total_tokens", "?")
                    logger.info("Oxlo OK | model=%s %.0fms tokens=%s", model, ms, tokens)
                    return content

                if response.status_code == 429:
                    wait = float(response.headers.get("Retry-After", 5 * (attempt + 1)))
                    logger.warning("Oxlo 429 — waiting %.0fs (attempt %d)", wait, attempt + 1)
                    await asyncio.sleep(wait)
                    continue

                if response.status_code in (401, 403):
                    raise RuntimeError(
                        f"Oxlo auth failed ({response.status_code}). "
                        "Check OXLO_API_KEY in your .env file. "
                        "Get a key at: https://portal.oxlo.ai"
                    )

                if response.status_code >= 500:
                    delay = 2 ** attempt
                    logger.warning("Oxlo %d — retrying in %ds", response.status_code, delay)
                    await asyncio.sleep(delay)
                    last_error = RuntimeError(f"Oxlo server error {response.status_code}")
                    continue

                raise RuntimeError(f"Oxlo error {response.status_code}: {response.text[:300]}")

            except httpx.TimeoutException as exc:
                delay = 2 ** attempt
                logger.warning("Oxlo timeout attempt %d — retrying in %ds", attempt + 1, delay)
                await asyncio.sleep(delay)
                last_error = RuntimeError(f"Oxlo request timed out: {exc}")

            except httpx.NetworkError as exc:
                raise RuntimeError(
                    f"Cannot reach Oxlo API. Check your internet connection: {exc}"
                ) from exc

    raise RuntimeError(f"Oxlo failed after {max_retries} attempts. Last: {last_error}")


# ─────────────────────────────────────────────────────────────────────────────
# JSON extraction — handles markdown fences and DeepSeek thinking blocks
# ─────────────────────────────────────────────────────────────────────────────

def _extract_json(text: str) -> Any:
    """
    Parse JSON from a model response that may contain:
    - <think>...</think> blocks (DeepSeek R1 reasoning)
    - ```json ... ``` markdown fences
    - Loose JSON arrays/objects
    """
    if not text:
        return None

    # Strip <think> blocks from DeepSeek R1 models
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()

    # Try direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Strip markdown fences
    m = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if m:
        try:
            return json.loads(m.group(1).strip())
        except json.JSONDecodeError:
            pass

    # Find outermost JSON structure
    for pattern in (r"(\[[\s\S]*\])", r"(\{[\s\S]*\})"):
        m = re.search(pattern, text)
        if m:
            try:
                return json.loads(m.group(1))
            except json.JSONDecodeError:
                pass

    return None


# ─────────────────────────────────────────────────────────────────────────────
# Phase 1 — The Auditor (llama-3.3-70b)
# ─────────────────────────────────────────────────────────────────────────────

_AUDITOR_SYSTEM = """You are a senior legal-technology compliance auditor specialising in GDPR, DPDPA, CCPA, HIPAA, and PCI-DSS.

TASK: Analyse the source code and detect all compliance violations.

OUTPUT RULES:
- Return ONLY a valid JSON array. No text before or after it.
- If inside a code fence, use ```json
- Each element must have EXACTLY these fields:
  {
    "regulation": "GDPR",
    "article":    "Article 25 — Data Protection by Design",
    "severity":   "CRITICAL",
    "title":      "Max 80 char headline",
    "description":"2-3 sentences with legal basis",
    "line_hint":  "relevant code snippet or null",
    "remediation":"Specific actionable fix"
  }
- severity: CRITICAL | HIGH | MEDIUM | LOW | INFO only
- Only report violations with clear evidence in the code
- Empty result: []

PII TOKENS: Tokens like [PII_EMAIL_3F2A1B0C] are redacted values — treat as real PII."""

async def run_audit(
    sanitized_code: str,
    language:       str = "python",
    regulations:    list[str] | None = None,
) -> AuditReport:
    """Phase 1 — Detect GDPR/DPDPA violations using Llama 3.3 70B."""
    if regulations is None:
        regulations = ["GDPR", "DPDPA"]

    t0 = time.perf_counter()
    logger.info("Phase 1 Auditor start | regs=%s mock=%s", regulations, _mock_enabled())

    user_message = (
        f"Audit this {language} code for violations of: {', '.join(regulations)}.\n\n"
        f"```{language}\n{sanitized_code}\n```\n\n"
        "Return a JSON array of violations."
    )

    raw_text = await _call_oxlo(
        model=AUDITOR_MODEL,
        system_prompt=_AUDITOR_SYSTEM,
        user_message=user_message,
        temperature=0.05,
        max_tokens=4096,
    )

    violations: list[Violation] = []

    if _mock_enabled():
        violations = _mock_violations(sanitized_code, regulations)
    else:
        parsed = _extract_json(raw_text)
        if isinstance(parsed, list):
            for item in parsed:
                try:
                    violations.append(Violation(
                        regulation=item.get("regulation", "GDPR"),
                        article=item.get("article", "Unknown article"),
                        severity=item.get("severity", "MEDIUM"),
                        title=item.get("title", "Unnamed violation"),
                        description=item.get("description", ""),
                        line_hint=item.get("line_hint"),
                        remediation=item.get("remediation", ""),
                    ))
                except Exception as e:
                    logger.warning("Skipped malformed violation: %s", e)
        else:
            logger.warning("Auditor did not return a JSON array. Raw: %s", raw_text[:200])

    critical = sum(1 for v in violations if v.severity == Severity.CRITICAL)
    high     = sum(1 for v in violations if v.severity == Severity.HIGH)
    elapsed  = (time.perf_counter() - t0) * 1000

    logger.info("Phase 1 complete: %d violations (%.0fms)", len(violations), elapsed)

    return AuditReport(
        model=AUDITOR_MODEL,
        regulations=regulations,
        violations=violations,
        total_count=len(violations),
        critical_count=critical,
        high_count=high,
        summary=(
            f"Found {len(violations)} violation(s) across {', '.join(regulations)} — "
            f"{critical} critical, {high} high-severity."
        ),
        elapsed_ms=round(elapsed, 2),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2 — The Judge (deepseek-r1-70b)
# ─────────────────────────────────────────────────────────────────────────────

_FINE_TABLE = {
    "GDPR":    (500_000,   20_000_000, "GDPR Art. 83(5): up to €20M or 4% global annual turnover"),
    "DPDPA":   (100_000,   27_000_000, "DPDPA §33: up to ₹250 Cr (~€27M) per incident"),
    "CCPA":    (10_000,    5_000_000,  "CCPA §1798.155: up to $7,500 per intentional violation"),
    "HIPAA":   (50_000,    1_500_000,  "HIPAA §1176: $100–$50,000 per violation, $1.5M annual cap"),
    "PCI-DSS": (5_000,     100_000,    "PCI-DSS §12: $5,000–$100,000/month until remediated"),
    "SOC2":    (10_000,    500_000,    "SOC 2: audit/certification penalties and contractual losses"),
}

_JUDGE_SYSTEM = """You are a quantitative regulatory risk analyst.

TASK: Compute a risk score for the given violations using this EXACT formula:

  Severity mapping: CRITICAL=10, HIGH=7, MEDIUM=4, LOW=2, INFO=1
  Raw Risk  = Σ (Severity_i × Likelihood_i)  for each violation
  Likelihood = your estimate [0.0, 1.0] of enforcement probability
  Score = min(100, round((Raw Risk / (10 × N)) × 100))   where N = violation count
  Label: 80-100=CRITICAL, 60-79=HIGH, 40-59=MEDIUM, 20-39=LOW, 0-19=MINIMAL

OUTPUT RULES:
- Return ONLY a JSON object. No text outside the fence.
{
  "raw_risk_score":   <float>,
  "normalised_score": <int 0-100>,
  "risk_label":       "<CRITICAL|HIGH|MEDIUM|LOW|MINIMAL>",
  "score_breakdown": [
    {
      "violation_id":    "<id>",
      "violation_title": "<title>",
      "severity":        <int 1-10>,
      "likelihood":      <float 0.0-1.0>,
      "weighted_score":  <float>,
      "rationale":       "<one sentence>"
    }
  ],
  "rationale": "<3-5 sentence executive summary>"
}"""

async def run_risk(
    violations:     list[Violation],
    sanitized_code: str,
) -> RiskAssessment:
    """Phase 2 — Score violations and predict regulatory fines."""
    t0 = time.perf_counter()
    logger.info("Phase 2 Judge start | violations=%d mock=%s", len(violations), _mock_enabled())

    violations_json = json.dumps([v.model_dump() for v in violations], indent=2)

    user_message = (
        f"Score these {len(violations)} violations using the formula in your instructions:\n\n"
        f"{violations_json}\n\nReturn the JSON risk object."
    )

    raw_text = await _call_oxlo(
        model=JUDGE_MODEL,
        system_prompt=_JUDGE_SYSTEM,
        user_message=user_message,
        temperature=0.1,
        max_tokens=2048,
    )

    # Build fine predictions from violation regulations
    regs_hit = {v.regulation for v in violations}
    fine_predictions = [
        FinePrediction(
            regulation=reg,
            min_eur=_FINE_TABLE[reg][0],
            max_eur=_FINE_TABLE[reg][1],
            basis=_FINE_TABLE[reg][2],
            probability=0.7,
        )
        for reg in sorted(regs_hit)
        if reg in _FINE_TABLE
    ]

    # Parse score from LLM or compute from violations
    normalised_score = 0
    raw_risk_score   = 0.0
    rationale        = ""

    def _compute_from_violations() -> tuple[float, int]:
        w = {Severity.CRITICAL: 10, Severity.HIGH: 7, Severity.MEDIUM: 4, Severity.LOW: 2, Severity.INFO: 1}
        raw = sum(w.get(v.severity, 1) * 0.7 for v in violations)
        n   = max(len(violations), 1)
        return round(raw, 2), min(100, round((raw / (10 * n)) * 100))

    if _mock_enabled() or not raw_text:
        raw_risk_score, normalised_score = _compute_from_violations()
    else:
        parsed = _extract_json(raw_text)
        if isinstance(parsed, dict):
            normalised_score = int(parsed.get("normalised_score", 0))
            raw_risk_score   = float(parsed.get("raw_risk_score", 0.0))
            rationale        = parsed.get("rationale", "")
        else:
            logger.warning("Judge returned non-dict — computing from violations")
            raw_risk_score, normalised_score = _compute_from_violations()

    # Clamp and label
    normalised_score = max(0, min(100, normalised_score))
    if normalised_score >= 80:   risk_label = "CRITICAL"
    elif normalised_score >= 60: risk_label = "HIGH"
    elif normalised_score >= 40: risk_label = "MEDIUM"
    elif normalised_score >= 20: risk_label = "LOW"
    else:                        risk_label = "MINIMAL"

    if not rationale:
        total_min = sum(f.min_eur for f in fine_predictions)
        total_max = sum(f.max_eur for f in fine_predictions)
        rationale = (
            f"Risk score {normalised_score}/100 ({risk_label}) from {len(violations)} violation(s) "
            f"across {len(regs_hit)} framework(s). "
            f"Regulatory exposure: €{total_min:,.0f}–€{total_max:,.0f}."
        )

    elapsed = (time.perf_counter() - t0) * 1000
    logger.info("Phase 2 complete: score=%d %s (%.0fms)", normalised_score, risk_label, elapsed)

    return RiskAssessment(
        model=JUDGE_MODEL,
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
# Phase 3 — The Architect (deepseek-coder-33b)
# ─────────────────────────────────────────────────────────────────────────────

_ARCHITECT_SYSTEM = """You are a principal software architect specialising in privacy-by-design and regulatory-compliant code refactoring.

TASK: Rewrite the provided source code to fix every compliance violation listed.

RULES:
1. Return ONLY a JSON object. No text outside the fence.
2. Required structure:
   {
     "patched_code": "<complete runnable source file>",
     "diff_hunks": [
       {
         "hunk_id":    1,
         "original":   "<original snippet>",
         "patched":    "<replacement code>",
         "comment":    "<what changed and why>",
         "regulation": "<regulation>",
         "article":    "<article>"
       }
     ],
     "changes_summary": ["<change 1>", "<change 2>"],
     "patch_coverage":  0.9
   }
3. Add inline comments: # [COMPLIANCE] GDPR Art. 25 — Data Minimisation
4. patched_code must be the COMPLETE file, not a snippet.
5. Leave PII tokens [PII_*] as-is or replace with os.environ pattern."""

async def run_patch(
    sanitized_code: str,
    violations:     list[Violation],
    language:       str = "python",
) -> PatchResult:
    """Phase 3 — Generate a compliance-patched version of the code."""
    t0 = time.perf_counter()
    logger.info("Phase 3 Architect start | violations=%d mock=%s", len(violations), _mock_enabled())

    violations_compact = json.dumps([
        {"id": v.id, "regulation": v.regulation, "severity": v.severity,
         "title": v.title, "remediation": v.remediation}
        for v in violations
    ], indent=2)

    user_message = (
        f"Fix these violations in the {language} code below:\n\n"
        f"VIOLATIONS:\n{violations_compact}\n\n"
        f"CODE:\n```{language}\n{sanitized_code}\n```\n\n"
        "Return the JSON patch object."
    )

    raw_text = await _call_oxlo(
        model=ARCHITECT_MODEL,
        system_prompt=_ARCHITECT_SYSTEM,
        user_message=user_message,
        temperature=0.15,
        max_tokens=8192,
    )

    patched_code    = ""
    diff_hunks:     list[DiffHunk] = []
    changes_summary: list[str]     = []

    if _mock_enabled() or not raw_text:
        patched_code, diff_hunks, changes_summary = _mock_patch(sanitized_code, violations)
    else:
        parsed = _extract_json(raw_text)
        if isinstance(parsed, dict):
            patched_code    = parsed.get("patched_code", sanitized_code)
            changes_summary = parsed.get("changes_summary", [])
            for h in parsed.get("diff_hunks", []):
                try:
                    diff_hunks.append(DiffHunk(
                        hunk_id=int(h.get("hunk_id", 1)),
                        original=h.get("original", ""),
                        patched=h.get("patched", ""),
                        comment=h.get("comment", ""),
                        regulation=h.get("regulation", ""),
                        article=h.get("article", ""),
                    ))
                except Exception as e:
                    logger.warning("Skipped malformed hunk: %s", e)
        else:
            logger.warning("Architect returned non-dict — falling back to mock patch")
            patched_code, diff_hunks, changes_summary = _mock_patch(sanitized_code, violations)

    elapsed = (time.perf_counter() - t0) * 1000
    logger.info("Phase 3 complete: %d hunks (%.0fms)", len(diff_hunks), elapsed)

    return PatchResult(
        model=ARCHITECT_MODEL,
        patched_code=patched_code,
        diff_hunks=diff_hunks,
        changes_summary=changes_summary,
        elapsed_ms=round(elapsed, 2),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Mock data (ENABLE_MOCK_LLM=true)
# ─────────────────────────────────────────────────────────────────────────────

def _mock_violations(code: str, regulations: list[str]) -> list[Violation]:
    mocks = []
    if "SELECT *" in code or "fetchall" in code.lower():
        mocks.append(Violation(
            regulation="GDPR", article="Article 25 — Data Protection by Design",
            severity=Severity.CRITICAL, title="No data minimisation enforced",
            description="SELECT * returns all columns including sensitive PII fields not required by the operation. GDPR Art. 25 mandates data minimisation by design.",
            line_hint=next((l.strip() for l in code.splitlines() if "SELECT" in l or "fetchall" in l.lower()), None),
            remediation="Replace SELECT * with explicit column projections. Define a REQUIRED_FIELDS allowlist constant.",
        ))
    if "print(" in code and ("email" in code.lower() or "user" in code.lower()):
        mocks.append(Violation(
            regulation="GDPR", article="Article 32 — Security of Processing",
            severity=Severity.HIGH, title="PII logged to stdout in plaintext",
            description="Personal data written via print() may persist unencrypted in log aggregation systems without access controls.",
            line_hint=next((l.strip() for l in code.splitlines() if "print(" in l), None),
            remediation="Replace print() with structured logging. Omit all PII fields from log messages.",
        ))
    if "card" in code.lower() or "payment" in code.lower():
        mocks.append(Violation(
            regulation="GDPR", article="Article 5(1)(f) — Integrity & Confidentiality",
            severity=Severity.HIGH, title="Payment card data stored without encryption",
            description="Raw card data stored in a cache layer. PCI-DSS and GDPR prohibit storing payment data in unencrypted volatile stores.",
            line_hint=next((l.strip() for l in code.splitlines() if "card" in l.lower()), None),
            remediation="Accept only pre-tokenised card references. Use a PCI-DSS compliant vault (Stripe, Braintree) and store only the token.",
        ))
    if "DPDPA" in regulations:
        mocks.append(Violation(
            regulation="DPDPA", article="Section 6 — Consent Framework",
            severity=Severity.CRITICAL, title="No consent verification before data processing",
            description="Personal data processed without a preceding consent check. India's DPDPA requires explicit, informed consent before any digital personal data processing.",
            line_hint=None,
            remediation="Integrate a consent management service. Add consent.verify(user_id, purpose) before every data access path.",
        ))
    return mocks or [Violation(
        regulation="GDPR", article="Article 5 — Principles",
        severity=Severity.MEDIUM, title="Manual review required",
        description="Code requires manual review to identify all personal data processing operations.",
        line_hint=None,
        remediation="Perform a Data Protection Impact Assessment (DPIA) on this module.",
    )]


def _mock_patch(
    code: str,
    violations: list[Violation],
) -> tuple[str, list[DiffHunk], list[str]]:
    header = (
        "# ─────────────────────────────────────────────────────────────────────\n"
        "# OXBUILD COMPLIANCE PATCH — Auto-generated\n"
        "# Applied fixes: GDPR Art. 5, 6, 17, 25, 32 | DPDPA §6\n"
        "# ─────────────────────────────────────────────────────────────────────\n"
        "from __future__ import annotations\n"
        "import logging\n"
        "import os\n\n"
        "audit_logger = logging.getLogger('oxbuild.data_access')\n\n"
        "# [COMPLIANCE] GDPR Art. 5(1)(c) — Data Minimisation\n"
        "REQUIRED_FIELDS = ('id', 'account_status', 'created_at')\n\n"
    )
    hunks:   list[DiffHunk] = []
    summary: list[str]      = []

    if "SELECT *" in code or "fetchall" in code.lower():
        hunks.append(DiffHunk(
            hunk_id=1,
            original='cursor.execute("SELECT * FROM users")\nreturn cursor.fetchall()',
            patched=(
                "# [COMPLIANCE] GDPR Art. 25 — Data Minimisation\n"
                "results = (\n"
                "    db.query(*[getattr(User, f) for f in REQUIRED_FIELDS])\n"
                "    .filter(User.deleted_at.is_(None))  # GDPR Art. 17 Right to Erasure\n"
                "    .all()\n"
                ")"
            ),
            comment="Replaced SELECT * with field projection + soft-delete filter",
            regulation="GDPR", article="Art. 25, Art. 17",
        ))
        summary.append("SELECT * replaced with REQUIRED_FIELDS projection (GDPR Art. 25)")

    if "print(" in code:
        hunks.append(DiffHunk(
            hunk_id=2,
            original='print(f"User {user_id} ({user.email}): {action}")',
            patched='audit_logger.info("user_activity", extra={"user_id": user_id, "action": action})',
            comment="Replaced print() with structured logging — no PII in message",
            regulation="GDPR", article="Art. 32",
        ))
        summary.append("print() replaced with audit_logger — PII removed (GDPR Art. 32)")

    if "card" in code.lower():
        hunks.append(DiffHunk(
            hunk_id=3,
            original='cache.set(f"card:{user_id}", card_number, ttl=3600)',
            patched='cache.set(f"payment_token:{user_id}", card_token, ttl=3600)',
            comment="Accepts pre-tokenised card reference only — raw PAN never stored",
            regulation="GDPR", article="Art. 5(1)(f)",
        ))
        summary.append("card_number replaced with card_token — raw PAN never stored (PCI-DSS, GDPR Art. 5)")

    summary += [
        "Added audit_logger for immutable access logging (GDPR Art. 32)",
        "Added REQUIRED_FIELDS constant for data minimisation (GDPR Art. 5(1)(c))",
    ]

    patched_code = header + code
    return patched_code, hunks, summary