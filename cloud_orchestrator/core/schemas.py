"""
cloud_orchestrator/core/schemas.py
====================================
Complete Pydantic v2 data-model layer for the Oxbuild Compliance Agent.

All models are:
  - Strictly typed with Python type hints
  - JSON-serialisable (used directly in FastAPI response_model)
  - Self-documenting via Field descriptions and json_schema_extra examples

Hierarchy
---------
AuditRequest
  └── code: str, language, regulations, metadata

AuditResponse
  ├── audit_report: AuditReport
  │     └── violations: list[Violation]
  ├── risk_assessment: RiskAssessment
  │     ├── score_breakdown: list[RiskFactor]
  │     └── fine_predictions: list[FinePrediction]
  └── patch_result: PatchResult
        └── diff_hunks: list[DiffHunk]
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    Field,
    field_validator,
    model_validator,
    ConfigDict,
)


# ---------------------------------------------------------------------------
# Shared enumerations
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    """Violation severity aligned with CVSS / regulatory risk bands."""
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

    @property
    def numeric(self) -> int:
        """Map severity to a 1-10 integer for the Judge risk formula."""
        return {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2, "INFO": 1}[self.value]


class Regulation(str, Enum):
    GDPR    = "GDPR"
    DPDPA   = "DPDPA"
    CCPA    = "CCPA"
    HIPAA   = "HIPAA"
    SOC2    = "SOC2"
    PCI_DSS = "PCI-DSS"
    ISO27001 = "ISO27001"


class RiskLabel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    MINIMAL  = "MINIMAL"

    @classmethod
    def from_score(cls, score: float) -> "RiskLabel":
        if score >= 80: return cls.CRITICAL
        if score >= 60: return cls.HIGH
        if score >= 40: return cls.MEDIUM
        if score >= 20: return cls.LOW
        return cls.MINIMAL


class PipelinePhase(str, Enum):
    SCANNER   = "scanner"
    AUDITOR   = "auditor"
    JUDGE     = "judge"
    ARCHITECT = "architect"


# ---------------------------------------------------------------------------
# Shared base model — strict mode, slot-optimised
# ---------------------------------------------------------------------------

class OxBase(BaseModel):
    model_config = ConfigDict(
        frozen=False,
        use_enum_values=True,
        populate_by_name=True,
        str_strip_whitespace=True,
        validate_assignment=True,
    )


# ---------------------------------------------------------------------------
# ── Request models ──────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

class AuditRequest(OxBase):
    """
    Inbound payload for every audit endpoint.

    The ``sanitized_code`` field must already have PII replaced by
    ``[PII_<LABEL>_<HASH>]`` tokens by the local C++ scanner before
    this request reaches the cloud orchestrator.
    """

    sanitized_code: Annotated[str, Field(
        min_length=1,
        max_length=500_000,
        description=(
            "Source code with PII already redacted by the local C++ scanner. "
            "Tokens look like: [PII_EMAIL_3F2A1B0C], [PII_IPV4_A1B2C3D4]."
        ),
        examples=["def get_user(id):\n    return db.query(User).filter_by(id=id).first()"],
    )]

    language: Annotated[str, Field(
        default="python",
        min_length=1,
        max_length=32,
        description="Source language hint passed to the Architect for formatting.",
        examples=["python", "typescript", "java", "go", "rust"],
    )]

    regulations: Annotated[list[Regulation], Field(
        default_factory=lambda: [Regulation.GDPR, Regulation.DPDPA],
        min_length=1,
        max_length=7,
        description="Regulatory frameworks the Auditor must check against.",
    )]

    context: Annotated[str | None, Field(
        default=None,
        max_length=2_000,
        description=(
            "Optional plain-English description of what the code does. "
            "Helps the Auditor produce more precise violation descriptions."
        ),
    )]

    metadata: Annotated[dict[str, Any], Field(
        default_factory=dict,
        description="Caller-supplied key-value pairs (e.g. repo, file_path, commit_sha).",
    )]

    @field_validator("language", mode="before")
    @classmethod
    def normalise_language(cls, v: str) -> str:
        return v.strip().lower()

    @field_validator("sanitized_code")
    @classmethod
    def reject_unredacted_pii(cls, v: str) -> str:
        """
        Heuristic guard: reject code that still contains obvious raw emails
        or API key patterns — indicates the C++ scanner was bypassed.
        """
        raw_email = re.compile(
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
        )
        raw_key = re.compile(
            r"\b(?:sk-[A-Za-z0-9]{32,}|AKIA[0-9A-Z]{16})\b"
        )
        if raw_email.search(v) or raw_key.search(v):
            raise ValueError(
                "sanitized_code appears to contain unredacted PII (raw email or API key). "
                "Ensure the local C++ scanner runs before submitting to the cloud API."
            )
        return v

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "sanitized_code": (
                    "def process_user(uid):\n"
                    "    conn = db.connect('[PII_IPV4_A1B2C3D4]')\n"
                    "    return conn.query('SELECT * FROM users WHERE id=%s', uid)"
                ),
                "language": "python",
                "regulations": ["GDPR", "DPDPA"],
                "context": "Data access layer for a SaaS user profile service.",
                "metadata": {"repo": "acme/backend", "file": "db/users.py"},
            }
        }
    )


# ---------------------------------------------------------------------------
# ── Phase 0: Scanner output (echoed in the response) ───────────────────────
# ---------------------------------------------------------------------------

class PiiToken(OxBase):
    """A single PII redaction token produced by the C++ scanner."""
    token:    str = Field(..., description="The opaque replacement token, e.g. [PII_EMAIL_3F2A1B0C].")
    category: str = Field(..., description="PII category, e.g. EMAIL, API_KEY, IPV4.")
    hash_hex: str = Field(..., description="8-char FNV-1a hex digest of the original value.")

    @classmethod
    def from_token_string(cls, token: str) -> "PiiToken":
        """Parse a token string into a structured PiiToken."""
        # Format: [PII_<CATEGORY>_<HASH8>]
        inner = token.strip("[]")
        parts = inner.split("_")
        hash_hex = parts[-1] if len(parts) >= 3 else "00000000"
        category = "_".join(parts[1:-1]) if len(parts) >= 3 else "UNKNOWN"
        return cls(token=token, category=category, hash_hex=hash_hex)


class ScanSummary(OxBase):
    """Metadata about the Phase 0 local scan (echoed, not computed by cloud)."""
    token_count:     int        = Field(0, ge=0)
    categories_found: list[str] = Field(default_factory=list)
    tokens:          list[PiiToken] = Field(default_factory=list)
    elapsed_ms:      float      = Field(0.0, ge=0.0)


# ---------------------------------------------------------------------------
# ── Phase 1: Audit report ───────────────────────────────────────────────────
# ---------------------------------------------------------------------------

class Violation(OxBase):
    """A single legal / compliance violation detected by the Auditor."""

    id: str = Field(
        default_factory=lambda: str(uuid.uuid4())[:8].upper(),
        description="Short unique ID for referencing this violation in UI / logs.",
    )
    regulation: Regulation = Field(..., description="Regulatory framework violated.")
    article:    str        = Field(..., max_length=120, description="Specific article or clause.")
    severity:   Severity   = Field(..., description="Violation severity level.")
    title:      str        = Field(..., max_length=160, description="Concise violation headline.")
    description: str       = Field(..., max_length=2_000, description="Detailed explanation.")
    article_url: str | None = Field(None, description="Link to the regulatory article text.")
    line_hint:  str | None = Field(None, max_length=256, description="Relevant code snippet.")
    remediation: str       = Field(..., max_length=1_000, description="Actionable fix guidance.")
    cwe_id:     str | None = Field(None, description="Optional CWE identifier, e.g. 'CWE-312'.")

    @property
    def severity_numeric(self) -> int:
        """Numeric severity for the Judge's risk formula (1-10)."""
        return Severity(self.severity).numeric


class AuditReport(OxBase):
    """Phase 1 structured output from the Auditor (Llama 3.3 70B)."""

    model:           str             = Field("meta-llama/llama-3.3-70b-instruct")
    regulations:     list[str]       = Field(default_factory=list)
    violations:      list[Violation] = Field(default_factory=list)
    total_count:     int             = Field(0, ge=0)
    critical_count:  int             = Field(0, ge=0)
    high_count:      int             = Field(0, ge=0)
    medium_count:    int             = Field(0, ge=0)
    low_count:       int             = Field(0, ge=0)
    compliance_grade: str            = Field("F", description="Letter grade A-F based on violation count/severity.")
    summary:         str             = Field("", description="Executive-summary paragraph.")
    prompt_tokens:   int             = Field(0, ge=0, description="Tokens consumed by Auditor prompt.")
    completion_tokens: int           = Field(0, ge=0)
    elapsed_ms:      float           = Field(0.0, ge=0.0)

    @model_validator(mode="after")
    def compute_derived_counts(self) -> "AuditReport":
        v = self.violations
        self.total_count    = len(v)
        self.critical_count = sum(1 for x in v if x.severity == Severity.CRITICAL)
        self.high_count     = sum(1 for x in v if x.severity == Severity.HIGH)
        self.medium_count   = sum(1 for x in v if x.severity == Severity.MEDIUM)
        self.low_count      = sum(1 for x in v if x.severity == Severity.LOW)
        self.compliance_grade = self._grade()
        return self

    def _grade(self) -> str:
        if self.critical_count > 0:            return "F"
        if self.high_count > 2:                return "D"
        if self.high_count > 0:                return "C"
        if self.medium_count > 3:              return "C"
        if self.medium_count > 0:              return "B"
        if self.total_count == 0:              return "A"
        return "B"


# ---------------------------------------------------------------------------
# ── Phase 2: Risk assessment ────────────────────────────────────────────────
# ---------------------------------------------------------------------------

class RiskFactor(OxBase):
    """
    A single term in the Judge's linear risk formula:

        Risk = Σ (Severity × Likelihood)

    where Severity ∈ [1, 10] and Likelihood ∈ [0.0, 1.0].
    """
    violation_id:  str   = Field(..., description="Reference to Violation.id.")
    violation_title: str = Field(..., description="Copy of Violation.title for readability.")
    severity:      int   = Field(..., ge=1, le=10, description="Numeric severity (1-10).")
    likelihood:    float = Field(..., ge=0.0, le=1.0, description="Estimated exploit/breach likelihood.")
    weighted_score: float = Field(0.0, description="severity × likelihood (auto-computed).")
    rationale:     str   = Field("", description="One-sentence justification for the likelihood estimate.")

    @model_validator(mode="after")
    def compute_weighted_score(self) -> "RiskFactor":
        self.weighted_score = round(self.severity * self.likelihood, 4)
        return self


class FinePrediction(OxBase):
    """Regulatory fine exposure estimate for one framework."""
    regulation:   str   = Field(...)
    min_eur:      float = Field(..., ge=0.0)
    max_eur:      float = Field(..., ge=0.0)
    basis:        str   = Field(..., description="Legal basis for the fine range.")
    probability:  float = Field(..., ge=0.0, le=1.0, description="Estimated probability of enforcement action.")
    expected_eur: float = Field(0.0, description="max_eur × probability (expected loss).")

    @model_validator(mode="after")
    def compute_expected(self) -> "FinePrediction":
        self.expected_eur = round(self.max_eur * self.probability, 2)
        return self


class RiskAssessment(OxBase):
    """Phase 2 structured output from the Judge (GPT-4o)."""

    model:                  str              = Field("gpt-4o")
    raw_risk_score:         float            = Field(..., ge=0.0, description="Σ(Severity × Likelihood) before normalisation.")
    normalised_score:       int              = Field(..., ge=0, le=100, description="raw_risk_score normalised to 0-100.")
    risk_label:             RiskLabel        = Field(...)
    score_breakdown:        list[RiskFactor] = Field(default_factory=list)
    fine_predictions:       list[FinePrediction] = Field(default_factory=list)
    total_exposure_min_eur: float            = Field(0.0, ge=0.0)
    total_exposure_max_eur: float            = Field(0.0, ge=0.0)
    total_expected_loss_eur: float           = Field(0.0, ge=0.0)
    rationale:              str              = Field("")
    prompt_tokens:          int              = Field(0, ge=0)
    completion_tokens:      int              = Field(0, ge=0)
    elapsed_ms:             float            = Field(0.0, ge=0.0)

    @model_validator(mode="after")
    def aggregate_exposure(self) -> "RiskAssessment":
        self.total_exposure_min_eur  = round(sum(f.min_eur      for f in self.fine_predictions), 2)
        self.total_exposure_max_eur  = round(sum(f.max_eur      for f in self.fine_predictions), 2)
        self.total_expected_loss_eur = round(sum(f.expected_eur for f in self.fine_predictions), 2)
        self.risk_label = RiskLabel.from_score(self.normalised_score)
        return self


# ---------------------------------------------------------------------------
# ── Phase 3: Patch result ───────────────────────────────────────────────────
# ---------------------------------------------------------------------------

class DiffHunk(OxBase):
    """A before/after code block produced by the Architect."""
    hunk_id:    int = Field(..., ge=1)
    original:   str = Field(..., description="The problematic original snippet.")
    patched:    str = Field(..., description="The compliant replacement snippet.")
    comment:    str = Field(..., description="One-line explanation of the change.")
    regulation: str = Field("", description="Primary regulation this hunk addresses.")
    article:    str = Field("", description="Specific article citation.")


class PatchResult(OxBase):
    """Phase 3 structured output from the Architect (DeepSeek-Coder-V2)."""

    model:            str           = Field("deepseek-ai/DeepSeek-Coder-V2-Instruct")
    patched_code:     str           = Field("", description="Full refactored source file.")
    diff_hunks:       list[DiffHunk]= Field(default_factory=list)
    changes_summary:  list[str]     = Field(default_factory=list)
    imports_added:    list[str]     = Field(default_factory=list, description="New import statements injected.")
    is_partial:       bool          = Field(False, description="True if only portions of the file could be patched.")
    patch_coverage:   float         = Field(1.0, ge=0.0, le=1.0, description="Fraction of violations addressed (0.0-1.0).")
    prompt_tokens:    int           = Field(0, ge=0)
    completion_tokens: int          = Field(0, ge=0)
    elapsed_ms:       float         = Field(0.0, ge=0.0)


# ---------------------------------------------------------------------------
# ── Top-level pipeline envelope ─────────────────────────────────────────────
# ---------------------------------------------------------------------------

class PipelineMetadata(OxBase):
    """Timing and identity metadata for a full pipeline run."""
    request_id:   str      = Field(default_factory=lambda: str(uuid.uuid4()))
    pipeline_version: str  = Field("1.0.0")
    started_at:   datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at:  datetime | None = Field(None)
    total_elapsed_ms: float = Field(0.0, ge=0.0)
    phases_completed: list[PipelinePhase] = Field(default_factory=list)


class AuditResponse(OxBase):
    """
    Top-level response model for ``POST /api/v1/audit``.

    Contains the outputs of all three pipeline phases plus
    an echo of the scan summary and pipeline metadata.
    """

    meta:            PipelineMetadata = Field(default_factory=PipelineMetadata)
    scan_summary:    ScanSummary      = Field(default_factory=ScanSummary)
    audit_report:    AuditReport      = Field(...)
    risk_assessment: RiskAssessment   = Field(...)
    patch_result:    PatchResult      = Field(...)

    # Convenience top-level accessors (duplicated for API ergonomics)
    risk_score:     int      = Field(0, ge=0, le=100)
    risk_label:     str      = Field("")
    violation_count: int     = Field(0, ge=0)
    compliance_grade: str    = Field("F")

    @model_validator(mode="after")
    def propagate_summary_fields(self) -> "AuditResponse":
        self.risk_score      = self.risk_assessment.normalised_score
        self.risk_label      = str(self.risk_assessment.risk_label)
        self.violation_count = self.audit_report.total_count
        self.compliance_grade = self.audit_report.compliance_grade
        return self


# ---------------------------------------------------------------------------
# ── Partial / single-phase response models ──────────────────────────────────
# ---------------------------------------------------------------------------

class AuditOnlyResponse(OxBase):
    """Response for ``POST /api/v1/audit/report`` (Phase 1 only)."""
    request_id:   str         = Field(default_factory=lambda: str(uuid.uuid4()))
    audit_report: AuditReport = Field(...)
    elapsed_ms:   float       = Field(0.0)


class RiskOnlyResponse(OxBase):
    """Response for ``POST /api/v1/audit/risk`` (Phases 1+2)."""
    request_id:      str            = Field(default_factory=lambda: str(uuid.uuid4()))
    audit_report:    AuditReport    = Field(...)
    risk_assessment: RiskAssessment = Field(...)
    elapsed_ms:      float          = Field(0.0)


class PatchOnlyResponse(OxBase):
    """Response for ``POST /api/v1/audit/patch`` (Phases 1+3)."""
    request_id:   str         = Field(default_factory=lambda: str(uuid.uuid4()))
    audit_report: AuditReport = Field(...)
    patch_result: PatchResult = Field(...)
    elapsed_ms:   float       = Field(0.0)


# ---------------------------------------------------------------------------
# ── Error envelope ───────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

class ErrorDetail(OxBase):
    """Structured error payload returned on 4xx/5xx responses."""
    request_id: str          = Field(default_factory=lambda: str(uuid.uuid4()))
    code:       str          = Field(..., description="Machine-readable error code.")
    message:    str          = Field(..., description="Human-readable error message.")
    phase:      PipelinePhase | None = Field(None, description="Pipeline phase where the error occurred.")
    detail:     Any          = Field(None, description="Additional structured context.")