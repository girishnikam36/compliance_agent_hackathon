"""
cloud_orchestrator/main.py
===========================
FastAPI application — Oxbuild Compliance Agent cloud orchestrator.

Endpoints
---------
POST /api/v1/audit          Full pipeline (Phases 1-2-3)
POST /api/v1/audit/report   Phase 1 only — legal violations
POST /api/v1/audit/risk     Phases 1+2 — violations + risk score
POST /api/v1/audit/patch    Phases 1+3 — violations + patched code
GET  /api/v1/health         Health check
GET  /api/v1/models         Currently configured provider/model info

Run
---
    cd cloud_orchestrator
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload
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

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger: logging.Logger = logging.getLogger("oxbuild.api")


# ─────────────────────────────────────────────────────────────────────────────
# Lifespan — startup / shutdown
# ─────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info("Oxbuild Compliance Agent — starting up")
    try:
        from cloud_orchestrator.core.config import settings
        logger.info("Provider config loaded:")
        logger.info("  Auditor   → %s (%s)", settings.auditor_model, settings.auditor_base_url)
        logger.info("  Judge     → %s (%s)", settings.judge_model, settings.judge_base_url)
        logger.info("  Architect → %s (%s)", settings.architect_model, settings.architect_base_url)
        logger.info("  Mock mode → %s", settings.enable_mock_llm)
    except Exception as e:
        logger.warning("Could not load config for startup log: %s", e)
    yield
    logger.info("Oxbuild Compliance Agent — shutting down")


# ─────────────────────────────────────────────────────────────────────────────
# FastAPI app
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Oxbuild Compliance Agent",
    version="2.0.0",
    description=(
        "Local-first compliance auditing pipeline. "
        "Phase 1: Groq/Llama 3.3 70B — violation detection. "
        "Phase 2: OpenRouter/DeepSeek R1 — risk scoring. "
        "Phase 3: DeepSeek — compliant code patching."
    ),
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:4173",
        "http://localhost:8000",
        "https://app.oxbuild.ai",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────────────────────────────────────
# Request / Response models
# ─────────────────────────────────────────────────────────────────────────────

class AuditRequest(BaseModel):
    sanitized_code: str = Field(
        ...,
        min_length=1,
        max_length=500_000,
        description="Source code with PII already redacted by the local C++ scanner.",
        examples=["def get_user(id):\n    return db.query(User).all()"],
    )
    language: str = Field(
        default="python",
        description="Source language — python, javascript, typescript, java, go, etc.",
    )
    regulations: list[str] = Field(
        default_factory=lambda: ["GDPR", "DPDPA"],
        description="Regulatory frameworks to audit against.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional caller metadata (repo, file path, commit SHA, etc.).",
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
    request_id:      str
    elapsed_ms:      float
    audit_report:    AuditReport
    risk_assessment: RiskAssessment
    patch_result:    PatchResult


class HealthResponse(BaseModel):
    status:   str   = "ok"
    version:  str   = "2.0.0"
    uptime_s: float = 0.0


class ModelInfo(BaseModel):
    phase:    int
    name:     str
    role:     str
    provider: str
    base_url: str


# ─────────────────────────────────────────────────────────────────────────────
# Middleware — request ID + timing
# ─────────────────────────────────────────────────────────────────────────────

_START_TIME: float = time.monotonic()


@app.middleware("http")
async def attach_request_id(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    request.state.request_id = request_id
    t0 = time.perf_counter()
    response = await call_next(request)
    elapsed  = (time.perf_counter() - t0) * 1_000
    response.headers["X-Request-ID"]    = request_id
    response.headers["X-Response-Time"] = f"{elapsed:.2f}ms"
    logger.info(
        "%s %s → %d [%.2fms] [req=%s]",
        request.method, request.url.path,
        response.status_code, elapsed, request_id,
    )
    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    req_id = getattr(request.state, "request_id", "unknown")
    logger.exception("Unhandled error [req=%s]: %s", req_id, exc)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": str(exc), "request_id": req_id},
    )


# ─────────────────────────────────────────────────────────────────────────────
# Routes — health & meta
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/v1/health", response_model=HealthResponse, tags=["Meta"])
async def health_check() -> HealthResponse:
    return HealthResponse(
        status="ok",
        version="2.0.0",
        uptime_s=round(time.monotonic() - _START_TIME, 2),
    )


@app.get("/api/v1/models", response_model=list[ModelInfo], tags=["Meta"])
async def list_models() -> list[ModelInfo]:
    """Return the currently configured provider and model for each phase."""
    try:
        from cloud_orchestrator.core.config import settings
        return [
            ModelInfo(
                phase=1, name=settings.auditor_model,
                role="Legal Auditor — GDPR/DPDPA violation detection",
                provider="Groq (free tier)" if "groq" in settings.auditor_base_url else settings.auditor_base_url,
                base_url=settings.auditor_base_url,
            ),
            ModelInfo(
                phase=2, name=settings.judge_model,
                role="Risk Judge — Σ(Severity×Likelihood) scoring + fine prediction",
                provider="OpenRouter (free)" if "openrouter" in settings.judge_base_url else settings.judge_base_url,
                base_url=settings.judge_base_url,
            ),
            ModelInfo(
                phase=3, name=settings.architect_model,
                role="Code Architect — Compliant patch generation",
                provider="DeepSeek (5M free tokens)" if "deepseek.com" in settings.architect_base_url else settings.architect_base_url,
                base_url=settings.architect_base_url,
            ),
        ]
    except Exception:
        import os
        return [
            ModelInfo(phase=1, name=os.environ.get("AUDITOR_MODEL","llama-3.3-70b-versatile"),
                      role="Legal Auditor", provider="Groq", base_url=os.environ.get("AUDITOR_BASE_URL","")),
            ModelInfo(phase=2, name=os.environ.get("JUDGE_MODEL","deepseek/deepseek-r1-0528:free"),
                      role="Risk Judge", provider="OpenRouter", base_url=os.environ.get("JUDGE_BASE_URL","")),
            ModelInfo(phase=3, name=os.environ.get("ARCHITECT_MODEL","deepseek-chat"),
                      role="Code Architect", provider="DeepSeek", base_url=os.environ.get("ARCHITECT_BASE_URL","")),
        ]


# ─────────────────────────────────────────────────────────────────────────────
# Routes — pipeline
# ─────────────────────────────────────────────────────────────────────────────

@app.post(
    "/api/v1/audit",
    response_model=FullPipelineResponse,
    tags=["Pipeline"],
    summary="Full compliance pipeline — Phases 1, 2, and 3",
)
async def full_audit(
    request: Request,
    body: Annotated[AuditRequest, Body(...)],
) -> FullPipelineResponse:
    req_id = request.state.request_id
    t0     = time.perf_counter()

    logger.info("Full pipeline start [req=%s] lang=%s regs=%s", req_id, body.language, body.regulations)

    try:
        audit = await run_audit(
            sanitized_code=body.sanitized_code,
            language=body.language,
            regulations=body.regulations,
        )
        risk = await run_risk(
            violations=audit.violations,
            sanitized_code=body.sanitized_code,
        )
        patch = await run_patch(
            sanitized_code=body.sanitized_code,
            violations=audit.violations,
            language=body.language,
        )
    except RuntimeError as exc:
        logger.error("Pipeline error [req=%s]: %s", req_id, exc)
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    elapsed_ms = (time.perf_counter() - t0) * 1000
    logger.info("Full pipeline complete [req=%s] in %.0fms", req_id, elapsed_ms)

    return FullPipelineResponse(
        request_id=req_id,
        elapsed_ms=round(elapsed_ms, 2),
        audit_report=audit,
        risk_assessment=risk,
        patch_result=patch,
    )


@app.post("/api/v1/audit/report", response_model=AuditReport, tags=["Pipeline"])
async def audit_report_only(
    request: Request,
    body: Annotated[AuditRequest, Body(...)],
) -> AuditReport:
    """Phase 1 only — legal violation detection."""
    try:
        return await run_audit(
            sanitized_code=body.sanitized_code,
            language=body.language,
            regulations=body.regulations,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.post("/api/v1/audit/risk", response_model=FullPipelineResponse, tags=["Pipeline"])
async def risk_only(
    request: Request,
    body: Annotated[AuditRequest, Body(...)],
) -> FullPipelineResponse:
    """Phases 1+2 — violations and risk scoring."""
    req_id = request.state.request_id
    t0     = time.perf_counter()
    try:
        audit = await run_audit(body.sanitized_code, body.language, body.regulations)
        risk  = await run_risk(audit.violations, body.sanitized_code)
        patch = PatchResult()
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return FullPipelineResponse(
        request_id=req_id, elapsed_ms=round((time.perf_counter()-t0)*1000, 2),
        audit_report=audit, risk_assessment=risk, patch_result=patch,
    )


@app.post("/api/v1/audit/patch", response_model=FullPipelineResponse, tags=["Pipeline"])
async def patch_only(
    request: Request,
    body: Annotated[AuditRequest, Body(...)],
) -> FullPipelineResponse:
    """Phases 1+3 — violations and patched code."""
    req_id = request.state.request_id
    t0     = time.perf_counter()
    try:
        audit = await run_audit(body.sanitized_code, body.language, body.regulations)
        patch = await run_patch(body.sanitized_code, audit.violations, body.language)
        risk  = RiskAssessment()
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return FullPipelineResponse(
        request_id=req_id, elapsed_ms=round((time.perf_counter()-t0)*1000, 2),
        audit_report=audit, risk_assessment=risk, patch_result=patch,
    )


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True, log_level="info")