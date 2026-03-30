"""
local_bridge/api/oxlo_client.py
=================================
Async HTTP client used by the local bridge to communicate with the
Oxbuild cloud orchestrator (FastAPI backend).

Features
--------
• Full async via ``httpx.AsyncClient`` with connection-pool reuse
• Exponential back-off retry with jitter on 429 / 502 / 503 / 504
• Request-ID tracking injected on every request
• Structured error parsing — always raises ``OxloClientError`` subtypes
• Configurable timeout per phase
• Optional synchronous convenience wrapper for non-async callers

Usage
-----
    async with OxloClient() as client:
        response = await client.full_audit(
            sanitized_code="…",
            language="python",
            regulations=["GDPR", "DPDPA"],
        )
        print(response.risk_score)

    # Or synchronous:
    from local_bridge.api.oxlo_client import sync_audit
    result = sync_audit(sanitized_code="…")
"""

from __future__ import annotations

import asyncio
import logging
import random
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncGenerator
from contextlib import asynccontextmanager

import httpx

logger = logging.getLogger("oxbuild.oxlo_client")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_BASE_URL    = "http://localhost:8000/api/v1"
_DEFAULT_TIMEOUT_S   = 120.0
_DEFAULT_MAX_RETRIES = 3
_DEFAULT_BACKOFF_S   = 1.5
_RETRYABLE_STATUSES  = {429, 500, 502, 503, 504}
_CLIENT_VERSION      = "1.0.0"


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------

class OxloClientError(Exception):
    """Base exception for all client-side errors."""
    def __init__(self, message: str, status_code: int | None = None, detail: Any = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.detail      = detail


class OxloAuthError(OxloClientError):
    """Raised on 401/403 — invalid or expired API key."""


class OxloRateLimitError(OxloClientError):
    """Raised on 429 — rate limit exhausted after all retries."""
    def __init__(self, message: str, retry_after_s: float = 60.0) -> None:
        super().__init__(message, status_code=429)
        self.retry_after_s = retry_after_s


class OxloServerError(OxloClientError):
    """Raised on 5xx — upstream pipeline or LLM failure."""


class OxloTimeoutError(OxloClientError):
    """Raised when the request exceeds the configured timeout."""


class OxloValidationError(OxloClientError):
    """Raised on 422 — request payload failed server-side validation."""
    def __init__(self, message: str, errors: list[dict[str, Any]]) -> None:
        super().__init__(message, status_code=422)
        self.errors = errors


class OxloNetworkError(OxloClientError):
    """Raised on network-level failures (DNS, connection refused, etc.)."""


# ---------------------------------------------------------------------------
# Response dataclasses (light mirrors of the cloud schemas — no pydantic dep)
# ---------------------------------------------------------------------------

@dataclass
class ViolationResult:
    id:           str
    regulation:   str
    article:      str
    severity:     str
    title:        str
    description:  str
    line_hint:    str | None
    remediation:  str
    cwe_id:       str | None = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ViolationResult":
        return cls(
            id          = d.get("id", ""),
            regulation  = d.get("regulation", ""),
            article     = d.get("article", ""),
            severity    = d.get("severity", "INFO"),
            title       = d.get("title", ""),
            description = d.get("description", ""),
            line_hint   = d.get("line_hint"),
            remediation = d.get("remediation", ""),
            cwe_id      = d.get("cwe_id"),
        )


@dataclass
class AuditReportResult:
    model:            str
    regulations:      list[str]
    violations:       list[ViolationResult]
    total_count:      int
    critical_count:   int
    high_count:       int
    compliance_grade: str
    summary:          str
    elapsed_ms:       float

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AuditReportResult":
        return cls(
            model            = d.get("model", ""),
            regulations      = d.get("regulations", []),
            violations       = [ViolationResult.from_dict(v) for v in d.get("violations", [])],
            total_count      = d.get("total_count", 0),
            critical_count   = d.get("critical_count", 0),
            high_count       = d.get("high_count", 0),
            compliance_grade = d.get("compliance_grade", "F"),
            summary          = d.get("summary", ""),
            elapsed_ms       = d.get("elapsed_ms", 0.0),
        )


@dataclass
class RiskAssessmentResult:
    model:                  str
    raw_risk_score:         float
    normalised_score:       int
    risk_label:             str
    total_exposure_min_eur: float
    total_exposure_max_eur: float
    total_expected_loss_eur: float
    rationale:              str
    elapsed_ms:             float

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "RiskAssessmentResult":
        return cls(
            model                   = d.get("model", ""),
            raw_risk_score          = d.get("raw_risk_score", 0.0),
            normalised_score        = d.get("normalised_score", 0),
            risk_label              = d.get("risk_label", "MINIMAL"),
            total_exposure_min_eur  = d.get("total_exposure_min_eur", 0.0),
            total_exposure_max_eur  = d.get("total_exposure_max_eur", 0.0),
            total_expected_loss_eur = d.get("total_expected_loss_eur", 0.0),
            rationale               = d.get("rationale", ""),
            elapsed_ms              = d.get("elapsed_ms", 0.0),
        )


@dataclass
class PatchResultData:
    model:            str
    patched_code:     str
    diff_hunks:       list[dict[str, Any]]
    changes_summary:  list[str]
    imports_added:    list[str]
    is_partial:       bool
    patch_coverage:   float
    elapsed_ms:       float

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "PatchResultData":
        return cls(
            model           = d.get("model", ""),
            patched_code    = d.get("patched_code", ""),
            diff_hunks      = d.get("diff_hunks", []),
            changes_summary = d.get("changes_summary", []),
            imports_added   = d.get("imports_added", []),
            is_partial      = d.get("is_partial", False),
            patch_coverage  = d.get("patch_coverage", 1.0),
            elapsed_ms      = d.get("elapsed_ms", 0.0),
        )


@dataclass
class FullAuditResult:
    """Complete pipeline result returned by the full audit endpoint."""
    request_id:      str
    elapsed_ms:      float
    risk_score:      int
    risk_label:      str
    violation_count: int
    compliance_grade: str
    audit_report:    AuditReportResult
    risk_assessment: RiskAssessmentResult
    patch_result:    PatchResultData
    raw:             dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "FullAuditResult":
        return cls(
            request_id       = d.get("meta", {}).get("request_id", d.get("request_id", "")),
            elapsed_ms       = d.get("meta", {}).get("total_elapsed_ms", d.get("elapsed_ms", 0.0)),
            risk_score       = d.get("risk_score", 0),
            risk_label       = d.get("risk_label", "MINIMAL"),
            violation_count  = d.get("violation_count", 0),
            compliance_grade = d.get("compliance_grade", "F"),
            audit_report     = AuditReportResult.from_dict(d.get("audit_report", {})),
            risk_assessment  = RiskAssessmentResult.from_dict(d.get("risk_assessment", {})),
            patch_result     = PatchResultData.from_dict(d.get("patch_result", {})),
            raw              = d,
        )


# ---------------------------------------------------------------------------
# Retry logic
# ---------------------------------------------------------------------------

def _jittered_backoff(attempt: int, base_s: float) -> float:
    """Exponential back-off with ±25% random jitter."""
    delay = base_s * (2 ** attempt)
    jitter = delay * random.uniform(-0.25, 0.25)
    return max(0.1, delay + jitter)


# ---------------------------------------------------------------------------
# Main async client
# ---------------------------------------------------------------------------

class OxloClient:
    """
    Async HTTP client for the Oxbuild cloud orchestrator.

    Intended to be used as an async context manager:

        async with OxloClient(base_url="http://…", api_key="…") as client:
            result = await client.full_audit(code)

    Or as a long-lived object (call ``await client.aclose()`` when done):

        client = OxloClient()
        result = await client.full_audit(code)
        await client.aclose()
    """

    def __init__(
        self,
        base_url:    str   = _DEFAULT_BASE_URL,
        api_key:     str   = "",
        timeout_s:   float = _DEFAULT_TIMEOUT_S,
        max_retries: int   = _DEFAULT_MAX_RETRIES,
        backoff_s:   float = _DEFAULT_BACKOFF_S,
    ) -> None:
        self._base_url    = base_url.rstrip("/")
        self._api_key     = api_key
        self._timeout_s   = timeout_s
        self._max_retries = max_retries
        self._backoff_s   = backoff_s
        self._client: httpx.AsyncClient | None = None

    # ── Lifecycle ────────────────────────────────────────────────────────

    def _build_client(self) -> httpx.AsyncClient:
        headers = {
            "Content-Type":  "application/json",
            "Accept":        "application/json",
            "User-Agent":    f"oxbuild-local-bridge/{_CLIENT_VERSION}",
        }
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        return httpx.AsyncClient(
            base_url=self._base_url,
            headers=headers,
            timeout=httpx.Timeout(
                connect=10.0,
                read=self._timeout_s,
                write=30.0,
                pool=5.0,
            ),
            follow_redirects=True,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )

    async def __aenter__(self) -> "OxloClient":
        self._client = self._build_client()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    # ── Internal request engine ──────────────────────────────────────────

    async def _request(
        self,
        method:   str,
        path:     str,
        payload:  dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Execute an HTTP request with retry logic and structured error handling.

        Returns the parsed JSON response body on success.
        Raises an ``OxloClientError`` subtype on all failure modes.
        """
        if self._client is None:
            self._client = self._build_client()

        request_id = str(uuid.uuid4())
        last_exc: Exception | None = None

        for attempt in range(self._max_retries + 1):
            try:
                logger.debug(
                    "→ %s %s [attempt %d/%d] [req=%s]",
                    method, path, attempt + 1, self._max_retries + 1, request_id
                )
                response = await self._client.request(
                    method,
                    path,
                    json=payload,
                    headers={"X-Request-ID": request_id},
                )

                # ── Success
                if response.is_success:
                    logger.debug(
                        "← %d %s in %.0fms [req=%s]",
                        response.status_code, path,
                        response.elapsed.total_seconds() * 1000,
                        request_id,
                    )
                    return response.json()

                # ── Parse error body
                try:
                    err_body: dict[str, Any] = response.json()
                except Exception:
                    err_body = {"detail": response.text}

                detail  = err_body.get("detail", response.text)
                code    = response.status_code

                # ── Auth errors — no retry
                if code in (401, 403):
                    raise OxloAuthError(
                        f"Authentication failed ({code}): {detail}",
                        status_code=code,
                        detail=err_body,
                    )

                # ── Validation error — no retry
                if code == 422:
                    raise OxloValidationError(
                        f"Request validation failed: {detail}",
                        errors=err_body.get("detail", []),
                    )

                # ── Retryable errors
                if code in _RETRYABLE_STATUSES and attempt < self._max_retries:
                    delay = _jittered_backoff(attempt, self._backoff_s)
                    logger.warning(
                        "Retryable %d on %s — backing off %.2fs [req=%s]",
                        code, path, delay, request_id,
                    )
                    if code == 429:
                        retry_after = float(
                            response.headers.get("Retry-After", delay)
                        )
                        await asyncio.sleep(retry_after)
                    else:
                        await asyncio.sleep(delay)
                    last_exc = OxloServerError(
                        f"Server error {code}: {detail}", status_code=code
                    )
                    continue

                # ── Permanent server error
                if code >= 500:
                    raise OxloServerError(
                        f"Orchestrator error {code}: {detail}",
                        status_code=code,
                        detail=err_body,
                    )

                # ── Unexpected client error
                raise OxloClientError(
                    f"Unexpected response {code}: {detail}",
                    status_code=code,
                    detail=err_body,
                )

            except (OxloClientError, OxloAuthError, OxloValidationError):
                raise  # never retry typed client errors

            except httpx.TimeoutException as exc:
                last_exc = OxloTimeoutError(
                    f"Request timed out after {self._timeout_s}s: {exc}"
                )
                if attempt < self._max_retries:
                    delay = _jittered_backoff(attempt, self._backoff_s)
                    logger.warning("Timeout — retrying in %.2fs [req=%s]", delay, request_id)
                    await asyncio.sleep(delay)
                    continue
                raise OxloTimeoutError(
                    f"Request timed out after {self._timeout_s}s (all retries exhausted)"
                ) from exc

            except httpx.NetworkError as exc:
                last_exc = OxloNetworkError(f"Network error: {exc}")
                if attempt < self._max_retries:
                    delay = _jittered_backoff(attempt, self._backoff_s)
                    logger.warning("Network error — retrying in %.2fs [req=%s]", delay, request_id)
                    await asyncio.sleep(delay)
                    continue
                raise OxloNetworkError(
                    f"Network error (all retries exhausted): {exc}"
                ) from exc

        # All retries exhausted — raise the last captured exception
        if last_exc:
            raise last_exc
        raise OxloClientError("All retries exhausted with no specific error captured.")

    # ── Public API ───────────────────────────────────────────────────────

    async def health_check(self) -> dict[str, Any]:
        """
        Verify the cloud orchestrator is reachable and healthy.

        Returns
        -------
        dict containing ``status``, ``version``, and ``uptime_s``.

        Raises
        ------
        OxloNetworkError  — orchestrator is unreachable.
        """
        return await self._request("GET", "/health")

    async def full_audit(
        self,
        sanitized_code: str,
        language:       str = "python",
        regulations:    list[str] | None = None,
        context:        str | None = None,
        metadata:       dict[str, Any] | None = None,
    ) -> FullAuditResult:
        """
        Execute the complete Phase 1-2-3 pipeline.

        Parameters
        ----------
        sanitized_code : str
            Source code with PII already redacted by the local C++ scanner.
        language       : str
            Programming language (default: "python").
        regulations    : list[str]
            Regulatory frameworks to audit against (default: ["GDPR", "DPDPA"]).
        context        : str | None
            Optional plain-English description of the code's purpose.
        metadata       : dict | None
            Caller-supplied metadata (repo URL, file path, commit SHA, etc.).

        Returns
        -------
        FullAuditResult
            Structured result containing all three phase outputs.
        """
        payload: dict[str, Any] = {
            "sanitized_code": sanitized_code,
            "language":       language,
            "regulations":    regulations or ["GDPR", "DPDPA"],
        }
        if context:
            payload["context"] = context
        if metadata:
            payload["metadata"] = metadata

        logger.info(
            "Submitting full audit | lang=%s regs=%s chars=%d",
            language, payload["regulations"], len(sanitized_code),
        )

        raw = await self._request("POST", "/audit", payload)
        result = FullAuditResult.from_dict(raw)

        logger.info(
            "Full audit complete | score=%d label=%s violations=%d elapsed=%.0fms",
            result.risk_score, result.risk_label,
            result.violation_count, result.elapsed_ms,
        )
        return result

    async def audit_report_only(
        self,
        sanitized_code: str,
        language:       str = "python",
        regulations:    list[str] | None = None,
    ) -> dict[str, Any]:
        """Phase 1 only — legal violation detection."""
        return await self._request("POST", "/audit/report", {
            "sanitized_code": sanitized_code,
            "language":       language,
            "regulations":    regulations or ["GDPR", "DPDPA"],
        })

    async def risk_assessment_only(
        self,
        sanitized_code: str,
        language:       str = "python",
        regulations:    list[str] | None = None,
    ) -> dict[str, Any]:
        """Phases 1+2 — audit and risk scoring."""
        return await self._request("POST", "/audit/risk", {
            "sanitized_code": sanitized_code,
            "language":       language,
            "regulations":    regulations or ["GDPR", "DPDPA"],
        })

    async def patch_only(
        self,
        sanitized_code: str,
        language:       str = "python",
        regulations:    list[str] | None = None,
    ) -> dict[str, Any]:
        """Phases 1+3 — audit and code patching."""
        return await self._request("POST", "/audit/patch", {
            "sanitized_code": sanitized_code,
            "language":       language,
            "regulations":    regulations or ["GDPR", "DPDPA"],
        })


# ---------------------------------------------------------------------------
# Synchronous wrapper (for non-async callers, e.g. tests, CLI scripts)
# ---------------------------------------------------------------------------

def sync_audit(
    sanitized_code: str,
    base_url:       str = _DEFAULT_BASE_URL,
    api_key:        str = "",
    language:       str = "python",
    regulations:    list[str] | None = None,
    context:        str | None = None,
    metadata:       dict[str, Any] | None = None,
) -> FullAuditResult:
    """
    Synchronous convenience wrapper around ``OxloClient.full_audit``.

    Creates an event loop, executes the audit, and returns the result.
    Do NOT call this from inside an existing async event loop.

    Parameters
    ----------
    sanitized_code : str  — PII-redacted source code.
    base_url       : str  — Cloud orchestrator base URL.
    api_key        : str  — Optional bearer token.
    language       : str  — Source language hint.
    regulations    : list — Regulatory frameworks.

    Returns
    -------
    FullAuditResult
    """
    async def _run() -> FullAuditResult:
        async with OxloClient(
            base_url=base_url,
            api_key=api_key,
        ) as client:
            return await client.full_audit(
                sanitized_code=sanitized_code,
                language=language,
                regulations=regulations,
                context=context,
                metadata=metadata,
            )

    return asyncio.run(_run())


# ---------------------------------------------------------------------------
# Context manager shortcut for one-shot usage
# ---------------------------------------------------------------------------

@asynccontextmanager
async def get_client(
    base_url:    str = _DEFAULT_BASE_URL,
    api_key:     str = "",
    timeout_s:   float = _DEFAULT_TIMEOUT_S,
    max_retries: int   = _DEFAULT_MAX_RETRIES,
) -> AsyncGenerator[OxloClient, None]:
    """
    Async context manager that yields a configured OxloClient.

    Usage:
        async with get_client() as client:
            result = await client.full_audit(code)
    """
    client = OxloClient(
        base_url=base_url,
        api_key=api_key,
        timeout_s=timeout_s,
        max_retries=max_retries,
    )
    async with client:
        yield client