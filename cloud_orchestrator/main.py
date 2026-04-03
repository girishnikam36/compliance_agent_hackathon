"""
cloud_orchestrator/main.py  v4.0
===================================
FastAPI cloud orchestrator — Oxbuild Compliance Agent.

Endpoints
---------
POST /api/v1/scan               Phase 0 — PII sanitization (C++ or Python fallback)
POST /api/v1/audit              Full pipeline  (Phases 1-2-3)
POST /api/v1/audit/report       Phase 1 only
POST /api/v1/audit/risk         Phases 1+2
POST /api/v1/audit/patch        Phases 1+3
POST /api/v1/audit/project      Multi-file / ZIP scan (returns array of FullPipelineResponse)
POST /api/v1/export/pdf         Download PDF report (ReportLab — includes diff + corrected code)
GET  /api/v1/health
GET  /api/v1/models

Run
---
    cd cloud_orchestrator
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload
"""

from __future__ import annotations

import hashlib
import io
import logging
import re
import sys
import time
import uuid
import zipfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any, AsyncGenerator

import uvicorn
from fastapi import Body, FastAPI, File, Form, HTTPException, Request, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, field_validator

from agents.pipeline import (
    AuditReport,
    PatchResult,
    RiskAssessment,
    run_audit,
    run_patch,
    run_risk,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("oxbuild.api")


# ─────────────────────────────────────────────────────────────────────────────
# Phase 0 — PII scanner (C++ preferred, Python regex fallback)
# ─────────────────────────────────────────────────────────────────────────────

_PY_PII: dict[str, str] = {
    "EMAIL":   r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    "IPV4":    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
    "API_KEY": (
        r"\b(?:sk-[A-Za-z0-9]{32,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{35}"
        r"|ghp_[A-Za-z0-9]{36,}|sk_live_[A-Za-z0-9]{24,}|whsec_[A-Za-z0-9]{20,})\b"
    ),
    "PHONE":   r"\b(?:\+?1[\s\-\.]?)?\(?\d{3}\)?[\s\-\.]?\d{3}[\s\-\.]?\d{4}\b",
}


def _py_scan(code: str) -> tuple[str, dict[str, str]]:
    result = code
    rmap: dict[str, str] = {}
    for label, pattern in _PY_PII.items():
        def _repl(m: re.Match, lbl: str = label) -> str:
            orig  = m.group(0)
            for tok, val in rmap.items():
                if val == orig:
                    return tok
            h8    = hashlib.sha256(orig.encode()).hexdigest()[:8].upper()
            token = f"[PII_{lbl}_{h8}]"
            rmap[token] = orig
            return token
        result = re.sub(pattern, _repl, result)
    return result, rmap


def _scan(code: str) -> tuple[str, dict, bool]:
    project_root = Path(__file__).parents[1]
    scanner_dir  = project_root / "local_bridge" / "core"
    if str(scanner_dir) not in sys.path:
        sys.path.insert(0, str(scanner_dir))
    try:
        import _oxscanner  # type: ignore[import]
        san, rmap = _oxscanner.scan_code(code)
        return san, dict(rmap), True
    except ImportError:
        san, rmap = _py_scan(code)
        return san, rmap, False
    except Exception as exc:
        logger.warning("C++ scanner error: %s — Python fallback", exc)
        san, rmap = _py_scan(code)
        return san, rmap, False


# ─────────────────────────────────────────────────────────────────────────────
# Language detection from file extension
# ─────────────────────────────────────────────────────────────────────────────

_EXT_LANG: dict[str, str] = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rs": "rust",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp",
    ".swift": "swift",
    ".kt": "kotlin", ".kts": "kotlin",
}

def _detect_lang(filename: str) -> str:
    return _EXT_LANG.get(Path(filename).suffix.lower(), "python")


# ─────────────────────────────────────────────────────────────────────────────
# Lifespan
# ─────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info("Oxbuild v4.0 — starting up")
    _, _, cpp = _scan("test@example.com")
    logger.info("Phase 0 scanner: %s", "C++ _oxscanner" if cpp else "Python regex fallback")
    try:
        try:
            from cloud_orchestrator.core.config import settings
        except ImportError:
            from core.config import settings  # type: ignore[no-redef]
        logger.info("Auditor   → %s @ %s", settings.auditor_model,   settings.auditor_base_url)
        logger.info("Judge     → %s @ %s", settings.judge_model,     settings.judge_base_url)
        logger.info("Architect → %s @ %s", settings.architect_model, settings.architect_base_url)
        logger.info("Mock LLM  → %s", settings.enable_mock_llm)
    except Exception as e:
        logger.warning("Config log skipped: %s", e)
    yield
    logger.info("Oxbuild — shutdown")


# ─────────────────────────────────────────────────────────────────────────────
# App
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Oxbuild Compliance Agent",
    version="4.0.0",
    description="Local-first compliance auditing pipeline with PDF export and multi-file scan.",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000", "http://localhost:5173",
        "http://localhost:4173", "http://localhost:8000",
        "https://app.oxbuild.ai",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────────────────────────────────────
# Request / Response models
# ─────────────────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    code:     str = Field(..., min_length=1, max_length=500_000)
    language: str = Field(default="unknown")


class ScanResponse(BaseModel):
    sanitized_code: str
    redaction_map:  dict[str, str]
    pii_count:      int
    categories:     list[str]
    elapsed_ms:     float
    scanner_used:   str


class AuditRequest(BaseModel):
    sanitized_code: str = Field(..., min_length=1, max_length=500_000)
    language:       str = Field(default="python")
    regulations:    list[str] = Field(default_factory=lambda: ["GDPR", "DPDPA"])
    metadata:       dict[str, Any] = Field(default_factory=dict)

    @field_validator("language")
    @classmethod
    def normalise_language(cls, v: str) -> str:
        return v.strip().lower()

    @field_validator("regulations")
    @classmethod
    def validate_regulations(cls, v: list[str]) -> list[str]:
        allowed = {"GDPR","DPDPA","CCPA","HIPAA","SOC2","PCI-DSS","ISO27001"}
        for r in v:
            if r.upper() not in allowed:
                raise ValueError(f"Unknown regulation: {r!r}. Allowed: {sorted(allowed)}")
        return [r.upper() for r in v]


class FullPipelineResponse(BaseModel):
    request_id:      str
    elapsed_ms:      float
    audit_report:    AuditReport
    risk_assessment: RiskAssessment
    patch_result:    PatchResult
    file_name:       str | None = None    # for multi-file scan results


class ProjectScanResponse(BaseModel):
    total_files:      int
    scanned_files:    int
    total_violations: int
    total_critical:   int
    files:            list[FullPipelineResponse]
    elapsed_ms:       float


class HealthResponse(BaseModel):
    status:   str   = "ok"
    version:  str   = "4.0.0"
    uptime_s: float = 0.0
    scanner:  str   = "unknown"


class ModelInfo(BaseModel):
    phase:    int
    name:     str
    role:     str
    provider: str
    base_url: str


# ─────────────────────────────────────────────────────────────────────────────
# Middleware
# ─────────────────────────────────────────────────────────────────────────────

_START: float = time.monotonic()


@app.middleware("http")
async def _request_id(request: Request, call_next):
    rid      = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    request.state.request_id = rid
    t0       = time.perf_counter()
    response = await call_next(request)
    elapsed  = (time.perf_counter() - t0) * 1_000
    response.headers["X-Request-ID"]    = rid
    response.headers["X-Response-Time"] = f"{elapsed:.0f}ms"
    logger.info("%s %s → %d [%.0fms] [%s]",
                request.method, request.url.path, response.status_code, elapsed, rid)
    return response


@app.exception_handler(Exception)
async def _global_exc(request: Request, exc: Exception) -> JSONResponse:
    rid = getattr(request.state, "request_id", "unknown")
    logger.exception("Unhandled error [%s]: %s", rid, exc)
    return JSONResponse(status_code=500, content={"detail": str(exc), "request_id": rid})


# ─────────────────────────────────────────────────────────────────────────────
# Helper — run full pipeline for one file
# ─────────────────────────────────────────────────────────────────────────────

async def _run_pipeline(
    code:        str,
    language:    str,
    regulations: list[str],
    req_id:      str,
    file_name:   str | None = None,
) -> FullPipelineResponse:
    t0 = time.perf_counter()
    try:
        audit = await run_audit(code, language, regulations)
        risk  = await run_risk(audit.violations, code)
        patch = await run_patch(code, audit.violations, language)
    except RuntimeError as exc:
        logger.error("Pipeline error [%s]: %s", req_id, exc)
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    elapsed = (time.perf_counter() - t0) * 1000
    return FullPipelineResponse(
        request_id=req_id, elapsed_ms=round(elapsed, 2),
        audit_report=audit, risk_assessment=risk, patch_result=patch,
        file_name=file_name,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Routes — meta
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/v1/health", response_model=HealthResponse, tags=["Meta"])
async def health_check() -> HealthResponse:
    _, _, cpp = _scan("x@y.com")
    return HealthResponse(
        status="ok", version="4.0.0",
        uptime_s=round(time.monotonic() - _START, 2),
        scanner="cpp" if cpp else "python_fallback",
    )


@app.get("/api/v1/models", response_model=list[ModelInfo], tags=["Meta"])
async def list_models() -> list[ModelInfo]:
    import os
    try:
        try:
            from cloud_orchestrator.core.config import settings
        except ImportError:
            from core.config import settings  # type: ignore[no-redef]
        return [
            ModelInfo(phase=1, name=settings.auditor_model,
                      role="Legal Auditor — violation detection",
                      provider="Groq" if "groq" in settings.auditor_base_url else settings.auditor_base_url,
                      base_url=settings.auditor_base_url),
            ModelInfo(phase=2, name=settings.judge_model,
                      role="Risk Judge — Σ(S×L) scoring",
                      provider="Groq" if "groq" in settings.judge_base_url else settings.judge_base_url,
                      base_url=settings.judge_base_url),
            ModelInfo(phase=3, name=settings.architect_model,
                      role="Code Architect — compliance patching",
                      provider="Groq" if "groq" in settings.architect_base_url else settings.architect_base_url,
                      base_url=settings.architect_base_url),
        ]
    except Exception:
        return [
            ModelInfo(phase=1, name=os.environ.get("AUDITOR_MODEL","llama-3.3-70b-versatile"),
                      role="Legal Auditor", provider="Groq",
                      base_url=os.environ.get("AUDITOR_BASE_URL","")),
            ModelInfo(phase=2, name=os.environ.get("JUDGE_MODEL","deepseek-r1-distill-llama-70b"),
                      role="Risk Judge", provider="Groq",
                      base_url=os.environ.get("JUDGE_BASE_URL","")),
            ModelInfo(phase=3, name=os.environ.get("ARCHITECT_MODEL","llama-3.3-70b-versatile"),
                      role="Code Architect", provider="Groq",
                      base_url=os.environ.get("ARCHITECT_BASE_URL","")),
        ]


# ─────────────────────────────────────────────────────────────────────────────
# Routes — Phase 0 Scanner
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/v1/scan", response_model=ScanResponse, tags=["Pipeline"],
          summary="Phase 0 — PII Sanitization")
async def scan_code(body: ScanRequest) -> ScanResponse:
    t0 = time.perf_counter()
    sanitized, rmap, used_cpp = _scan(body.code)
    elapsed    = (time.perf_counter() - t0) * 1000
    categories = sorted({
        tok.split("_")[1]
        for tok in rmap if tok.startswith("[PII_")
    })
    logger.info("Scan | scanner=%s pii=%d cats=%s %.1fms",
                "cpp" if used_cpp else "python", len(rmap), categories, elapsed)
    return ScanResponse(
        sanitized_code=sanitized, redaction_map=rmap,
        pii_count=len(rmap), categories=categories,
        elapsed_ms=round(elapsed, 2),
        scanner_used="cpp" if used_cpp else "python_fallback",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Routes — Audit pipeline
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/v1/audit", response_model=FullPipelineResponse, tags=["Pipeline"],
          summary="Full compliance pipeline — Phases 1, 2, 3")
async def full_audit(
    request: Request,
    body: Annotated[AuditRequest, Body(...)],
) -> FullPipelineResponse:
    logger.info("Pipeline start [%s] lang=%s regs=%s",
                request.state.request_id, body.language, body.regulations)
    return await _run_pipeline(
        body.sanitized_code, body.language,
        body.regulations, request.state.request_id,
    )


@app.post("/api/v1/audit/report", response_model=AuditReport, tags=["Pipeline"])
async def audit_report_only(body: Annotated[AuditRequest, Body(...)]) -> AuditReport:
    try:
        return await run_audit(body.sanitized_code, body.language, body.regulations)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.post("/api/v1/audit/risk", response_model=FullPipelineResponse, tags=["Pipeline"])
async def risk_only(
    request: Request,
    body: Annotated[AuditRequest, Body(...)],
) -> FullPipelineResponse:
    rid = request.state.request_id
    t0  = time.perf_counter()
    try:
        audit = await run_audit(body.sanitized_code, body.language, body.regulations)
        risk  = await run_risk(audit.violations, body.sanitized_code)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return FullPipelineResponse(
        request_id=rid, elapsed_ms=round((time.perf_counter()-t0)*1000, 2),
        audit_report=audit, risk_assessment=risk, patch_result=PatchResult(),
    )


@app.post("/api/v1/audit/patch", response_model=FullPipelineResponse, tags=["Pipeline"])
async def patch_only(
    request: Request,
    body: Annotated[AuditRequest, Body(...)],
) -> FullPipelineResponse:
    rid = request.state.request_id
    t0  = time.perf_counter()
    try:
        audit = await run_audit(body.sanitized_code, body.language, body.regulations)
        patch = await run_patch(body.sanitized_code, audit.violations, body.language)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return FullPipelineResponse(
        request_id=rid, elapsed_ms=round((time.perf_counter()-t0)*1000, 2),
        audit_report=audit, risk_assessment=RiskAssessment(), patch_result=patch,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Routes — Multi-file / ZIP project scan
# ─────────────────────────────────────────────────────────────────────────────

MAX_PROJECT_FILES = 20   # safety cap
MAX_FILE_SIZE     = 200_000   # 200 KB per file


@app.post("/api/v1/audit/project", response_model=ProjectScanResponse, tags=["Pipeline"],
          summary="Multi-file project scan — upload individual files or a .zip")
async def project_scan(
    request:     Request,
    files:       list[UploadFile] = File(..., description="Source files or a single .zip"),
    regulations: str              = Form(default="GDPR,DPDPA",
                                         description="Comma-separated regulation names"),
    language:    str              = Form(default="auto",
                                         description="Language override; 'auto' detects from extension"),
) -> ProjectScanResponse:
    """
    Accept multiple source files OR a single .zip archive.
    Scans each file through the full pipeline.
    Returns an aggregate result with per-file breakdowns.
    """
    regs_list = [r.strip().upper() for r in regulations.split(",") if r.strip()]
    if not regs_list:
        regs_list = ["GDPR", "DPDPA"]

    # Expand zip if provided
    file_entries: list[tuple[str, str]] = []   # (filename, content)

    for upload in files:
        name    = upload.filename or "unknown"
        content = await upload.read()

        if len(content) > 10 * 1024 * 1024:   # 10 MB zip cap
            raise HTTPException(400, f"File {name} exceeds 10 MB limit")

        if name.lower().endswith(".zip"):
            try:
                with zipfile.ZipFile(io.BytesIO(content)) as zf:
                    for zi in zf.infolist():
                        if zi.is_dir():
                            continue
                        fn  = zi.filename
                        ext = Path(fn).suffix.lower()
                        if ext not in _EXT_LANG:
                            continue
                        if zi.file_size > MAX_FILE_SIZE:
                            logger.warning("Skipping oversized zip entry: %s (%d bytes)", fn, zi.file_size)
                            continue
                        fc = zf.read(zi).decode("utf-8", errors="replace")
                        file_entries.append((fn, fc))
            except zipfile.BadZipFile:
                raise HTTPException(400, f"{name} is not a valid zip file")
        else:
            decoded = content.decode("utf-8", errors="replace")
            file_entries.append((name, decoded))

    if not file_entries:
        raise HTTPException(400, "No valid source files found in the upload")

    # Cap total files
    file_entries = file_entries[:MAX_PROJECT_FILES]

    t_project = time.perf_counter()
    results: list[FullPipelineResponse] = []

    for fname, code in file_entries:
        detected_lang = language if language != "auto" else _detect_lang(fname)

        # Phase 0 — scan PII
        sanitized, _, _ = _scan(code)

        rid = f"{request.state.request_id}-{Path(fname).stem[:12]}"
        logger.info("Project scan: %s lang=%s", fname, detected_lang)

        try:
            r = await _run_pipeline(
                sanitized, detected_lang, regs_list, rid, file_name=fname
            )
            results.append(r)
        except HTTPException as exc:
            logger.error("Skipping %s due to pipeline error: %s", fname, exc.detail)

    elapsed = (time.perf_counter() - t_project) * 1000

    return ProjectScanResponse(
        total_files=len(file_entries),
        scanned_files=len(results),
        total_violations=sum(r.audit_report.total_count for r in results),
        total_critical=sum(r.audit_report.critical_count for r in results),
        files=results,
        elapsed_ms=round(elapsed, 2),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Routes — PDF Export
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/v1/export/pdf", tags=["Export"],
          summary="Generate a PDF compliance report",
          response_class=StreamingResponse)
async def export_pdf(
    body: Annotated[dict, Body(...)],
) -> StreamingResponse:
    """
    Accept a FullPipelineResponse JSON body and return a PDF file.

    The PDF includes:
      - Cover page (summary stats, risk gauge)
      - Violation detail cards (colour-coded by severity)
      - Risk score breakdown + regulatory fine predictions
      - Corrected code (full patched file with line numbers)
      - Split diff (side-by-side original vs patched per hunk)

    Install reportlab:
        pip install reportlab
    """
    try:
        from utils.pdf_reporter import build_pdf
    except ImportError:
        try:
            from cloud_orchestrator.utils.pdf_reporter import build_pdf  # type: ignore[no-redef]
        except ImportError:
            raise HTTPException(
                status_code=501,
                detail="reportlab is not installed. Run: pip install reportlab",
            )

    language  = body.get("language", "python")
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    filename  = f"oxbuild_compliance_report_{timestamp}.pdf"

    try:
        pdf_bytes = build_pdf(body, language=language)
    except Exception as exc:
        logger.exception("PDF generation failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {exc}") from exc

    logger.info("PDF export: %d bytes for language=%s", len(pdf_bytes), language)

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length":      str(len(pdf_bytes)),
        },
    )


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True, log_level="info")