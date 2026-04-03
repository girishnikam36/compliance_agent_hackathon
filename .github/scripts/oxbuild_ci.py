#!/usr/bin/env python3
"""
.github/scripts/oxbuild_ci.py
================================
CI runner that calls the Oxbuild API directly from the GitHub Action runner.
Scans source files and fails the build on CRITICAL/HIGH violations.

Usage:
    python oxbuild_ci.py \
        --files src/app.py src/models.py \
        --regulations GDPR DPDPA \
        --fail-on CRITICAL \
        --output-json /tmp/report.json \
        --output-summary /tmp/summary.md
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path


# ── Simple Python PII scanner (no C++ needed in CI) ───────────────────────────

_PII_PATTERNS: dict[str, str] = {
    "EMAIL":   r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    "IPV4":    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
    "API_KEY": r"\b(?:sk-[A-Za-z0-9]{32,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{35}|ghp_[A-Za-z0-9]{36,}|sk_live_[A-Za-z0-9]{24,}|whsec_[A-Za-z0-9]{20,})\b",
}


def sanitize_code(code: str) -> str:
    """Strip PII before sending to the API."""
    result = code
    for label, pattern in _PII_PATTERNS.items():
        def replace(m: re.Match, lbl: str = label) -> str:
            h = hashlib.sha256(m.group(0).encode()).hexdigest()[:8].upper()
            return f"[PII_{lbl}_{h}]"
        result = re.sub(pattern, replace, result)
    return result


def detect_language(path: str) -> str:
    ext = Path(path).suffix.lower()
    return {
        ".py": "python", ".js": "javascript", ".jsx": "javascript",
        ".mjs": "javascript", ".ts": "typescript", ".tsx": "typescript",
        ".java": "java", ".go": "go", ".rs": "rust",
    }.get(ext, "python")


# ── Direct LLM call (no backend server needed in CI) ─────────────────────────

def call_audit_api(sanitized_code: str, language: str, regulations: list[str]) -> dict:
    """Call Groq directly from CI — no need to spin up the FastAPI backend."""
    import urllib.request as req
    import urllib.error

    api_key  = os.environ.get("AUDITOR_API_KEY") or os.environ.get("GROQ_API_KEY", "")
    base_url = os.environ.get("AUDITOR_BASE_URL", "https://api.groq.com/openai/v1")
    model    = os.environ.get("AUDITOR_MODEL", "llama-3.3-70b-versatile")

    if not api_key:
        print("::warning::GROQ_API_KEY secret not set — skipping LLM audit")
        return _local_pattern_audit(sanitized_code, language, regulations)

    system = f"""You are a compliance auditor for {', '.join(regulations)}.
Return ONLY a valid JSON array of violations.
Each violation: {{"regulation":str,"article":str,"severity":str,"title":str,"description":str,"line_hint":str|null,"remediation":str}}
severity: CRITICAL|HIGH|MEDIUM|LOW|INFO. If none: []"""

    payload = json.dumps({
        "model": model,
        "temperature": 0.05,
        "max_tokens": 2048,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": (
                f"Audit this {language} code for {', '.join(regulations)} violations.\n\n"
                f"{sanitized_code}\n\nReturn ONLY the raw JSON array."
            )},
        ],
    }).encode()

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    try:
        request  = req.Request(f"{base_url}/chat/completions", data=payload, headers=headers)
        response = req.urlopen(request, timeout=60)
        data     = json.loads(response.read())
        content  = data["choices"][0]["message"]["content"]

        # Strip <think> blocks (DeepSeek R1)
        content = re.sub(r"<think>[\s\S]*?</think>", "", content).strip()
        # Extract JSON
        m = re.search(r"\[[\s\S]*\]", content)
        if m:
            return {"violations": json.loads(m.group(0)), "model": model}
    except (urllib.error.URLError, json.JSONDecodeError, KeyError) as e:
        print(f"::warning::LLM call failed: {e} — using pattern scan fallback")

    return _local_pattern_audit(sanitized_code, language, regulations)


def _local_pattern_audit(code: str, language: str, regulations: list[str]) -> dict:
    """Fallback: simple regex patterns when API isn't available."""
    violations = []
    lines = code.splitlines()

    checks = [
        (r"print\(.*(?:email|user|card|ssn|record)", "GDPR", "Art. 32", "HIGH",
         "PII in print() call", "Use structured logging instead of print()"),
        (r"SELECT \*", "GDPR", "Art. 25", "HIGH",
         "SELECT * — no data minimisation", "Use explicit field list instead of SELECT *"),
        (r"hashlib\.md5", "GDPR", "Art. 25", "HIGH",
         "Weak MD5 pseudonymisation", "Replace MD5 with HMAC-SHA256 with a secret key"),
        (r"EMERGENCY_OVERRIDE\s*=\s*True", "HIPAA", "§164.312(a)(2)", "CRITICAL",
         "Hardcoded emergency override", "Remove hardcoded True, implement time-limited token"),
        (r"sk_live_|whsec_\w+|AKIA[0-9A-Z]{16}", "GDPR", "Art. 32", "CRITICAL",
         "Hardcoded credential", "Move to environment variable"),
    ]

    for pattern, reg, art, sev, title, rem in checks:
        for line in lines:
            if re.search(pattern, line, re.IGNORECASE):
                violations.append({
                    "regulation": reg, "article": art, "severity": sev,
                    "title": title, "line_hint": line.strip()[:80],
                    "description": f"Pattern detected: {pattern}",
                    "remediation": rem,
                })
                break

    return {"violations": violations, "model": "pattern-scan"}


# ── Report generation ─────────────────────────────────────────────────────────

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def generate_summary_markdown(all_results: list[dict], fail_on: str) -> str:
    total_critical = sum(r["critical_count"] for r in all_results)
    total_high     = sum(r["high_count"]     for r in all_results)
    total_files    = len(all_results)
    total_v        = sum(r["total_count"]    for r in all_results)
    failed         = any(
        r["critical_count"] > 0 if fail_on == "CRITICAL" else
        r["critical_count"] + r["high_count"] > 0
        for r in all_results
    )

    status_icon  = "🔴" if failed else "✅"
    status_label = "FAILED" if failed else "PASSED"

    lines = [
        f"## {status_icon} Oxbuild Compliance Scan — {status_label}",
        "",
        f"| Files scanned | Total violations | Critical | High |",
        f"|---|---|---|---|",
        f"| {total_files} | {total_v} | {total_critical} | {total_high} |",
        "",
    ]

    for r in all_results:
        if r["total_count"] == 0:
            lines.append(f"### ✅ `{r['file']}` — Clean")
            continue
        lines.append(f"### {'🔴' if r['critical_count'] > 0 else '🟡'} `{r['file']}`")
        lines.append(f"**{r['total_count']} violation(s)** — {r['critical_count']} critical, {r['high_count']} high")
        lines.append("")
        for v in sorted(r["violations"], key=lambda x: SEVERITY_ORDER.get(x["severity"], 5)):
            sev   = v["severity"]
            emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}.get(sev, "⚪")
            lines.append(f"- {emoji} **[{sev}]** {v['title']} — {v['regulation']} {v.get('article','')}")
            if v.get("line_hint"):
                lines.append(f"  > `{v['line_hint'][:80]}`")
            lines.append(f"  💡 {v['remediation']}")
        lines.append("")

    lines.extend([
        "---",
        "_Powered by [Oxbuild Compliance Agent](https://github.com/your-org/oxbuild-compliance-agent)_",
    ])
    return "\n".join(lines)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description="Oxbuild CI compliance scanner")
    parser.add_argument("--files",         nargs="+", default=[],      help="Files to scan")
    parser.add_argument("--regulations",   nargs="+", default=["GDPR", "DPDPA"])
    parser.add_argument("--fail-on",       default="CRITICAL",         choices=["CRITICAL", "HIGH"])
    parser.add_argument("--output-json",   default="/tmp/oxbuild.json")
    parser.add_argument("--output-summary",default="/tmp/oxbuild.md")
    args = parser.parse_args()

    if not args.files:
        print("::notice::No files to scan — skipping")
        return 0

    all_results = []
    exit_code   = 0

    for filepath in args.files:
        if not Path(filepath).exists():
            continue

        print(f"\n[oxbuild] Scanning: {filepath}")
        code         = Path(filepath).read_text(encoding="utf-8", errors="replace")
        sanitized    = sanitize_code(code)
        language     = detect_language(filepath)
        audit_result = call_audit_api(sanitized, language, args.regulations)
        violations   = audit_result.get("violations", [])

        critical = sum(1 for v in violations if v["severity"] == "CRITICAL")
        high     = sum(1 for v in violations if v["severity"] == "HIGH")

        result = {
            "file":          filepath,
            "language":      language,
            "model":         audit_result.get("model", "unknown"),
            "violations":    violations,
            "total_count":   len(violations),
            "critical_count":critical,
            "high_count":    high,
        }
        all_results.append(result)

        # Emit GitHub annotations
        for v in violations:
            level = "error" if v["severity"] in ("CRITICAL", "HIGH") else "warning"
            print(f"::{level} file={filepath},title={v['regulation']} {v['severity']}::{v['title']} — {v['remediation']}")

        # Check exit code
        if args.fail_on == "CRITICAL" and critical > 0:
            exit_code = 1
        elif args.fail_on == "HIGH" and (critical + high) > 0:
            exit_code = 1

        print(f"  → {len(violations)} violation(s): {critical} critical, {high} high")

    # Write JSON report
    Path(args.output_json).write_text(json.dumps({
        "summary": {
            "total_files":    len(all_results),
            "total_violations": sum(r["total_count"] for r in all_results),
            "total_critical":   sum(r["critical_count"] for r in all_results),
            "total_high":       sum(r["high_count"] for r in all_results),
            "passed":           exit_code == 0,
        },
        "files": all_results,
    }, indent=2))

    # Write Markdown summary
    summary = generate_summary_markdown(all_results, args.fail_on)
    Path(args.output_summary).write_text(summary)

    print(f"\n[oxbuild] Scan complete — exit code {exit_code}")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())