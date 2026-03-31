"""
health_check.py — Oxbuild Compliance Agent | System Health Check
=================================================================
Run from the project root with uvicorn already running.

Usage:
    python health_check.py              # layers 1-5
    python health_check.py --scanner    # + C++ scanner
    python health_check.py --real       # + real provider API calls
    python health_check.py --all        # everything
    python health_check.py --port 9000  # custom backend port
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; C = "\033[96m"; B = "\033[1m"; X = "\033[0m"

def ok(m):   print(f"  {G}✅ {m}{X}")
def fail(m): print(f"  {R}❌ {m}{X}")
def warn(m): print(f"  {Y}⚠  {m}{X}")
def info(m): print(f"     {C}{m}{X}")
def hdr(m):  print(f"\n{B}{'─'*60}{X}\n{B}  {m}{X}\n{B}{'─'*60}{X}")

PASS = FAIL = 0

def chk(cond, p, f):
    global PASS, FAIL
    if cond: ok(p);   PASS += 1
    else:    fail(f); FAIL += 1
    return cond


# ── Layer 1: Python packages ──────────────────────────────────────────────────

def check_python():
    hdr("Layer 1 — Python Environment")
    v = sys.version_info
    chk(v >= (3, 11), f"Python {v.major}.{v.minor}.{v.micro} (≥3.11)", f"Python {v.major}.{v.minor} too old")
    for name, imp in [("fastapi","fastapi"),("uvicorn","uvicorn"),("pydantic","pydantic"),
                      ("pydantic-settings","pydantic_settings"),("httpx","httpx"),("python-dotenv","dotenv")]:
        try:
            __import__(imp); ok(f"{name} importable"); global PASS; PASS += 1
        except ImportError:
            fail(f"{name} NOT installed — pip install {name}"); global FAIL; FAIL += 1


# ── Layer 2: .env ─────────────────────────────────────────────────────────────

def check_env() -> dict:
    global PASS  # 1. Declare it globally right at the start
    
    hdr("Layer 2 — Configuration (.env)")
    root     = Path(__file__).parent
    env_path = root / ".env"
    chk(env_path.exists(), f".env found at {env_path}", f".env NOT found at {env_path}")
    
    if not env_path.exists():
        warn("Copy .env.example to .env and fill in your API keys")
        return {}

    vals = {}
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            vals[k.strip()] = v.strip()

    # Check per-phase keys
    providers = {
        "AUDITOR":   ("Groq",       "https://console.groq.com"),
        "JUDGE":     ("OpenRouter", "https://openrouter.ai"),
        "ARCHITECT": ("DeepSeek",   "https://platform.deepseek.com"),
    }
    
    for phase, (provider, url) in providers.items():
        key = vals.get(f"{phase}_API_KEY", "")
        chk(
            bool(key) and "your_" not in key and "here" not in key,
            f"{phase}_API_KEY set (provider: {provider})",
            f"{phase}_API_KEY missing or still placeholder — sign up at {url}",
        )
        
        base = vals.get(f"{phase}_BASE_URL", "")
        if base:
            ok(f"{phase}_BASE_URL = {base}")
            PASS += 1  # 2. Safely increment without the global keyword
        else:
            warn(f"{phase}_BASE_URL not set — default will be used")
            
        model = vals.get(f"{phase}_MODEL", "")
        if model:
            ok(f"{phase}_MODEL = {model}")
            PASS += 1  # 3. Safely increment

    mock = vals.get("ENABLE_MOCK_LLM", "true").lower()
    if mock == "true":
        warn("ENABLE_MOCK_LLM=true — using mock responses (no API credits)")
        info("Change to false when ready for real LLM calls")
    else:
        ok("ENABLE_MOCK_LLM=false — real provider API calls will be made")
        PASS += 1  # 4. Safely increment

    return vals

# ── Layer 3: Backend reachability ─────────────────────────────────────────────

def check_backend(base: str) -> bool:
    hdr("Layer 3 — Backend HTTP Reachability")
    try:
        import httpx
    except ImportError:
        fail("httpx not installed"); return False
    try:
        t0 = time.perf_counter()
        r  = httpx.get(f"{base}/api/v1/health", timeout=5.0)
        ms = (time.perf_counter() - t0) * 1000
        chk(r.status_code == 200, f"GET /api/v1/health → {r.status_code} ({ms:.0f}ms)",
            f"GET /api/v1/health → {r.status_code}")
        if r.status_code == 200:
            d = r.json()
            chk(d.get("status") == "ok", "status = ok", f"status = {d.get('status')}")
            chk("uptime_s" in d, f"uptime = {d.get('uptime_s',0):.1f}s", "uptime field missing")
            info(f"Server version: {d.get('version','?')}")
            return True
    except Exception as exc:
        fail(f"Cannot connect to {base}\n       Is uvicorn running?\n"
             f"       cd cloud_orchestrator && uvicorn main:app --port 8000 --reload\n       {exc}")
    return False


# ── Layer 4: Check configured models endpoint ──────────────────────────────────

def check_models(base: str) -> None:
    hdr("Layer 4 — Provider Configuration (/api/v1/models)")
    try:
        import httpx
        r = httpx.get(f"{base}/api/v1/models", timeout=5.0)
        if r.status_code == 200:
            models = r.json()
            for m in models:
                ok(f"Phase {m['phase']}: {m['name']} @ {m['base_url']}")
                global PASS; PASS += 1
        else:
            fail(f"GET /api/v1/models → {r.status_code}")
    except Exception as exc:
        fail(f"Could not fetch models: {exc}")


# ── Layer 5: Full pipeline ────────────────────────────────────────────────────

TEST_CODE = '''import psycopg2
DB_URL = "postgresql://admin:[PII_API_KEY_AABB1122]@[PII_IPV4_CCDD3344]:5432/users"
def get_users():
    cursor.execute("SELECT * FROM users")
    return cursor.fetchall()
def log_action(uid, action):
    print(f"User {uid}: {action}")
def store_card(uid, card):
    cache.set(f"card:{uid}", card, ttl=3600)
'''.strip()

def check_pipeline(base: str) -> dict | None:
    hdr("Layer 5 — Full Audit Pipeline (POST /api/v1/audit)")
    try:
        import httpx
        t0 = time.perf_counter()
        r  = httpx.post(f"{base}/api/v1/audit",
                        json={"sanitized_code": TEST_CODE, "language": "python",
                              "regulations": ["GDPR","DPDPA"]},
                        timeout=60.0)
        ms = (time.perf_counter() - t0) * 1000
        chk(r.status_code == 200, f"POST /api/v1/audit → 200 ({ms:.0f}ms)",
            f"POST /api/v1/audit → {r.status_code}\n{r.text[:200]}")
        if r.status_code == 200:
            return r.json()
    except Exception as exc:
        fail(f"Pipeline request failed: {exc}")
    return None


def check_response(data: dict) -> None:
    hdr("Layer 6 — Response Structure")
    if not data: fail("No data"); return
    for f in ["audit_report","risk_assessment","patch_result"]:
        chk(f in data, f"'{f}' present", f"'{f}' MISSING")
    a = data.get("audit_report", {})
    chk(isinstance(a.get("violations",[]), list), f"violations list ({len(a.get('violations',[]))} items)", "violations not a list")
    chk("summary"        in a, "summary present",        "summary missing")
    chk("critical_count" in a, "critical_count present", "critical_count missing")
    risk = data.get("risk_assessment",{})
    score = risk.get("normalised_score", -1)
    label = risk.get("risk_label","?")
    chk(0 <= score <= 100, f"Risk score {score}/100 ({label})", f"Score {score} out of range")
    chk("fine_predictions" in risk, f"fine_predictions ({len(risk.get('fine_predictions',[]))} entries)", "fine_predictions missing")
    patch = data.get("patch_result",{})
    chk(isinstance(patch.get("patched_code",""), str), "patched_code is string", "patched_code wrong type")
    chk("changes_summary" in patch, "changes_summary present", "changes_summary missing")
    info(f"Violations: {a.get('total_count',0)} | Score: {score}/100 ({label}) | Hunks: {len(patch.get('diff_hunks',[]))}")


# ── Layer 7: C++ scanner ──────────────────────────────────────────────────────

def check_scanner():
    hdr("Layer 7 — C++ Scanner (Phase 0)")
    scanner_dir = Path(__file__).parent / "local_bridge" / "core"
    pdys = list(scanner_dir.glob("_oxscanner*.pyd")) + list(scanner_dir.glob("_oxscanner*.so"))
    chk(bool(pdys), f"Compiled module found: {pdys[0].name if pdys else ''}",
        "No _oxscanner .pyd/.so found\n"
        "       Build: cd local_bridge/core && python setup.py build_ext --inplace")
    if not pdys: return
    sys.path.insert(0, str(scanner_dir))
    try:
        import _oxscanner
        ok(f"_oxscanner v{_oxscanner.__version__} imported"); global PASS; PASS += 1
    except ImportError as e:
        fail(f"_oxscanner import failed: {e}"); return
    test = "email admin@test.com ip 192.168.1.1 key sk-live-abc123def456ghi789"
    san, rmap = _oxscanner.scan_code(test)
    chk("admin@test.com" not in san, "Email redacted", "Email NOT redacted")
    chk("192.168.1.1"    not in san, "IPv4 redacted",  "IPv4 NOT redacted")
    chk(len(rmap) >= 2,  f"Redaction map has {len(rmap)} entries", f"Only {len(rmap)} entries")
    chk(any("EMAIL" in k for k in rmap), "EMAIL token present", "No EMAIL token")
    chk(any("IPV4"  in k for k in rmap), "IPV4 token present",  "No IPV4 token")
    info(f"Sanitized: {san[:80]}")
    restored = _oxscanner.restore_code(san, rmap)
    chk("admin@test.com" in restored, "restore_code() works correctly", "restore_code() failed")


# ── Layer 8: Real provider API calls ──────────────────────────────────────────

def check_real_providers(env: dict):
    global PASS, FAIL  # 1. ALWAYS DECLARE GLOBALS AT THE VERY TOP
    
    hdr("Layer 8 — Real Provider API Connectivity")
    try:
        import httpx
    except ImportError:
        fail("httpx not installed")
        return

    providers = {
        "AUDITOR":   ("Groq",       "llama-3.3-70b-versatile"),
        "JUDGE":     ("OpenRouter", "deepseek/deepseek-r1-0528:free"),
        "ARCHITECT": ("DeepSeek",   "deepseek-chat"),
    }

    for phase, (provider_name, default_model) in providers.items():
        api_key  = env.get(f"{phase}_API_KEY", "")
        base_url = env.get(f"{phase}_BASE_URL", "").rstrip("/")
        model    = env.get(f"{phase}_MODEL", default_model)

        if not api_key or "your_" in api_key or "here" in api_key:
            warn(f"{phase} ({provider_name}): API key not set — skipping")
            continue

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type":  "application/json",
            "HTTP-Referer":  "https://oxbuild.ai",
            "X-Title":       "Oxbuild Health Check",
        }
        payload = {
            "model":      model,
            "max_tokens": 10,
            "messages":   [{"role":"user","content":"Reply with: OK"}],
        }
        
        try:
            t0 = time.perf_counter()
            r  = httpx.post(f"{base_url}/chat/completions", headers=headers, json=payload, timeout=30.0)
            ms = (time.perf_counter() - t0) * 1000
            
            if r.status_code == 200:
                content = r.json()["choices"][0]["message"]["content"]
                ok(f"{phase} ({provider_name}/{model}) → 200 {ms:.0f}ms | '{content[:30]}'")
                PASS += 1  # 2. Safely increment here
            elif r.status_code == 401:
                fail(f"{phase}: 401 Unauthorized — {phase}_API_KEY is invalid")
                FAIL += 1  # 3. Safely increment here
            elif r.status_code == 429:
                warn(f"{phase}: 429 Rate limited — key works but hit limit")
            else:
                fail(f"{phase}: {r.status_code} — {r.text[:150]}")
                FAIL += 1
                
        except Exception as exc:
            fail(f"{phase} ({provider_name}): {exc}")
            FAIL += 1

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--real",    action="store_true")
    ap.add_argument("--scanner", action="store_true")
    ap.add_argument("--all",     action="store_true")
    ap.add_argument("--port",    default="8000")
    args = ap.parse_args()
    base = f"http://localhost:{args.port}"

    print(f"\n{B}{'='*60}{X}")
    print(f"{B}  Oxbuild Compliance Agent — Health Check{X}")
    print(f"{B}{'='*60}{X}")

    check_python()
    env = check_env()
    backend_ok = check_backend(base)

    data = None
    if backend_ok:
        check_models(base)
        data = check_pipeline(base)
        if data:
            check_response(data)

    if args.scanner or args.all:
        check_scanner()

    if args.real or args.all:
        check_real_providers(env)

    total = PASS + FAIL
    print(f"\n{B}{'='*60}{X}")
    print(f"{B}  Results: {PASS}/{total} checks passed{X}")
    if FAIL == 0:
        print(f"  {G}{B}🎉 All systems operational!{X}")
    elif FAIL <= 2:
        print(f"  {Y}{B}⚠  Minor issues — see ❌ lines above{X}")
    else:
        print(f"  {R}{B}🛑 Failures detected — see ❌ lines above{X}")
    print(f"{B}{'='*60}{X}")

    if data:
        a = data.get("audit_report",{})
        r = data.get("risk_assessment",{})
        p = data.get("patch_result",{})
        mock = env.get("ENABLE_MOCK_LLM","true").lower() == "true"
        print(f"\n{B}  Last audit result:{X}")
        print(f"  Mode        : {'MOCK' if mock else 'REAL LLM'}")
        print(f"  Violations  : {a.get('total_count',0)} ({a.get('critical_count',0)} critical)")
        print(f"  Risk score  : {r.get('normalised_score',0)}/100 ({r.get('risk_label','?')})")
        print(f"  Max exposure: €{r.get('total_exposure_max_eur',0):,.0f}")
        print(f"  Diff hunks  : {len(p.get('diff_hunks',[]))}")
        print()

    sys.exit(0 if FAIL == 0 else 1)


if __name__ == "__main__":
    main()