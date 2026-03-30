"""
main.py — Oxbuild Compliance Agent | Cloud Orchestrator
========================================================
FastAPI application that orchestrates Phases 1-3 of the compliance pipeline.

Endpoints
---------
POST /api/v1/audit          Full pipeline: audit + risk + patch
POST /api/v1/audit/report   Phase 1 only  (legal violations)
POST /api/v1/audit/risk     Phase 2 only  (risk score + fines)
POST /api/v1/audit/patch    Phase 3 only  (refactored code)
GET  /api/v1/health         Service health check
GET  /api/v1/models         Configured model info

Run
---
    pip install fastapi uvicorn pydantic
    uvicorn cloud_orchestrator.main:app --host 0.0.0.0 --port 8000 --reload
"""

from __future__ import annotations

import logging
import time
import uuid
from contextlib import asynccontextmanager
from typing import Annotated, Any, AsyncGenerator

import uvicorn
from fastapi import Body, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

from agents.pipeline import (
    AuditReport,
    PatchResult,
    RiskAssessment,
    run_audit,
    run_patch,
    run_risk,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger: logging.Logger = logging.getLogger("oxbuild.api")

# ---------------------------------------------------------------------------
# Application lifecycle
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info("Oxbuild Compliance Agent — cloud orchestrator starting…")
    yield
    logger.info("Oxbuild Compliance Agent — shutting down.")

# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Oxbuild Compliance Agent",
    version="1.0.0",
    description=(
        "Cloud orchestrator for legal compliance auditing, "
        "risk scoring, and automated code patching via LLM agents."
    ),
    contact={"name": "Oxbuild Engineering", "email": "eng@oxbuild.ai"},
    license_info={"name": "Proprietary"},
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",     # React dev server (Vite)
        "http://localhost:5173",     # Vite default
        "http://localhost:8000",     # same-origin
        "https://app.oxbuild.ai",    # production frontend
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class AuditRequest(BaseModel):
    """Input payload for any audit endpoint."""
    sanitized_code: str = Field(
        ...,
        min_length=1,
        max_length=500_000,
        description="Pre-sanitized source code (PII already redacted).",
        examples=["def get_user(id): return db.query(User).filter_by(id=id).first()"],
    )
    language: str = Field(
        default="python",
        description="Programming language hint for the LLM auditors.",
        examples=["python", "javascript", "java", "go"],
    )
    regulations: list[str] = Field(
        default_factory=lambda: ["GDPR", "DPDPA"],
        description="Regulatory frameworks to audit against.",
        examples=[["GDPR", "DPDPA", "CCPA", "HIPAA"]],
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional caller-supplied metadata (e.g. file path, repo URL).",
    )

    @field_validator("language")
    @classmethod
    def normalise_language(cls, v: str) -> str:
        return v.strip().lower()

    @field_validator("regulations")
    @classmethod
    def validate_regulations(cls, v: list[str]) -> list[str]:
        allowed = {"GDPR", "DPDPA", "CCPA", "HIPAA", "SOC2", "PCI-DSS", "ISO27001"}
        for reg in v:
            if reg.upper() not in allowed:
                raise ValueError(
                    f"Unknown regulation: {reg!r}. Allowed: {sorted(allowed)}"
                )
        return [r.upper() for r in v]


class FullPipelineResponse(BaseModel):
    """Combined response for the full Phase 1-2-3 pipeline."""
    request_id:     str
    elapsed_ms:     float
    audit_report:   AuditReport
    risk_assessment: RiskAssessment
    patch_result:   PatchResult


class HealthResponse(BaseModel):
    status:  str = "ok"
    version: str = "1.0.0"
    uptime_s: float


class ModelInfo(BaseModel):
    phase:   int
    name:    str
    role:    str
    provider: str


# ---------------------------------------------------------------------------
# Global start time (for uptime)
# ---------------------------------------------------------------------------
_START_TIME: float = time.monotonic()

# ---------------------------------------------------------------------------
# Exception handler
# ---------------------------------------------------------------------------

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    req_id = getattr(request.state, "request_id", "unknown")
    logger.exception("Unhandled error on %s %s [req=%s]",
                     request.method, request.url.path, req_id)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "Internal server error — check orchestrator logs.",
            "request_id": req_id,
        },
    )

# ---------------------------------------------------------------------------
# Middleware — request ID injection
# ---------------------------------------------------------------------------

@app.middleware("http")
async def attach_request_id(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    request.state.request_id = request_id
    t0 = time.perf_counter()
    response = await call_next(request)
    elapsed = (time.perf_counter() - t0) * 1_000
    response.headers["X-Request-ID"]   = request_id
    response.headers["X-Response-Time"] = f"{elapsed:.2f}ms"
    logger.info(
        "%s %s → %d  [%.2fms] [req=%s]",
        request.method, request.url.path,
        response.status_code, elapsed, request_id,
    )
    return response

# ---------------------------------------------------------------------------
# Routes — health & meta
# ---------------------------------------------------------------------------

@app.get(
    "/api/v1/health",
    response_model=HealthResponse,
    tags=["Meta"],
    summary="Service health check",
)
async def health_check() -> HealthResponse:
    return HealthResponse(
        status="ok",
        version="1.0.0",
        uptime_s=round(time.monotonic() - _START_TIME, 2),
    )


@app.get(
    "/api/v1/models",
    response_model=list[ModelInfo],
    tags=["Meta"],
    summary="Configured LLM model info",
)
async def list_models() -> list[ModelInfo]:
    return [
        ModelInfo(
            phase=1,
            name="meta-llama/llama-3.3-70b-instruct",
            role="Legal Auditor — GDPR/DPDPA violation detection",
            provider="Oxlo (via Groq)",
        ),
        ModelInfo(
            phase=2,
            name="gpt-4o",
            role="Risk Judge — Fine prediction & risk scoring",
            provider="Oxlo (via OpenAI)",
        ),
        ModelInfo(
            phase=3,
            name="deepseek-ai/DeepSeek-Coder-V2-Instruct",
            role="Code Architect — Compliant patch generation",
            provider="Oxlo (via DeepSeek API)",
        ),
    ]

# ---------------------------------------------------------------------------
# Routes — audit pipeline
# ---------------------------------------------------------------------------

@app.post(
    "/api/v1/audit",
    response_model=FullPipelineResponse,
    status_code=status.HTTP_200_OK,
    tags=["Pipeline"],
    summary="Full compliance pipeline (Phases 1-2-3)",
    response_description="Combined audit report, risk assessment, and patched code.",
)
async def full_audit(
    request: Request,
    body: Annotated[AuditRequest, Body(...)],
) -> FullPipelineResponse:
    """
    Execute all three pipeline phases sequentially:

    1. **Phase 1 — Auditor** (Llama 3.3 70B): Detects GDPR/DPDPA violations.
    2. **Phase 2 — Judge** (GPT-4o): Calculates risk score and predicts fines.
    3. **Phase 3 — Architect** (DeepSeek-Coder-V2): Generates compliant patched code.
    """
    req_id: str = request.state.request_id
    t0 = time.perf_counter()

    logger.info("Full pipeline start [req=%s] lang=%s regs=%s",
                req_id, body.language, body.regulations)

    try:
        audit: AuditReport = await run_audit(
            sanitized_code=body.sanitized_code,
            language=body.language,
            regulations=body.regulations,
        )
        risk: RiskAssessment = await run_risk(
            violations=audit.violations,
            sanitized_code=body.sanitized_code,
        )
        patch: PatchResult = await run_patch(
            sanitized_code=body.sanitized_code,
            violations=audit.violations,
            language=body.language,
        )
    except Exception as exc:
        logger.error("Pipeline error [req=%s]: %s", req_id, exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Pipeline agent error: {exc}",
        ) from exc

    elapsed_ms = (time.perf_counter() - t0) * 1_000
    logger.info("Full pipeline complete [req=%s] in %.2f ms", req_id, elapsed_ms)

    return FullPipelineResponse(
        request_id=req_id,
        elapsed_ms=round(elapsed_ms, 2),
        audit_report=audit,
        risk_assessment=risk,
        patch_result=patch,
    )


@app.post(
    "/api/v1/audit/report",
    response_model=AuditReport,
    tags=["Pipeline"],
    summary="Phase 1 — Legal Auditor (Llama 3.3 70B)",
)
async def audit_report_only(
    request: Request,
    body: Annotated[AuditRequest, Body(...)],
) -> AuditReport:
    """Run only Phase 1: legal violation detection."""
    try:
        return await run_audit(
            sanitized_code=body.sanitized_code,
            language=body.language,
            regulations=body.regulations,
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.post(
    "/api/v1/audit/risk",
    response_model=RiskAssessment,
    tags=["Pipeline"],
    summary="Phase 2 — Risk Judge (GPT-4o)",
)
async def risk_assessment_only(
    request: Request,
    body: Annotated[AuditRequest, Body(...)],
) -> RiskAssessment:
    """Run only Phase 2: risk scoring and fine prediction."""
    try:
        audit = await run_audit(
            sanitized_code=body.sanitized_code,
            language=body.language,
            regulations=body.regulations,
        )
        return await run_risk(
            violations=audit.violations,
            sanitized_code=body.sanitized_code,
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.post(
    "/api/v1/audit/patch",
    response_model=PatchResult,
    tags=["Pipeline"],
    summary="Phase 3 — Code Architect (DeepSeek-Coder-V2)",
)
async def patch_only(
    request: Request,
    body: Annotated[AuditRequest, Body(...)],
) -> PatchResult:
    """Run Phases 1 + 3: audit then generate a compliant code patch."""
    try:
        audit = await run_audit(
            sanitized_code=body.sanitized_code,
            language=body.language,
            regulations=body.regulations,
        )
        return await run_patch(
            sanitized_code=body.sanitized_code,
            violations=audit.violations,
            language=body.language,
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Development entry-point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )