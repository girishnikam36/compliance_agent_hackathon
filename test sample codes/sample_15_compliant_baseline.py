"""
test_samples/sample_05_compliant_baseline.py
=============================================
EXPLOIT CATEGORY : NONE — This is the COMPLIANT baseline
SEVERITY PROFILE : 0 CRITICAL · 0 HIGH · at most 1 LOW (informational)
REGULATIONS      : GDPR, DPDPA
LANGUAGE         : Python

What this file simulates:
  The correct, GDPR-compliant version of sample_01.
  Use this to verify that the Oxbuild auditor produces near-zero
  violations when the code actually follows best practices.

EXPECTED RESULT:
  Risk Score  : 0–15 (MINIMAL)
  Violations  : 0–1 (at most informational)
  Patched Code: "No critical changes required"

HOW TO TEST:
  Paste into Oxbuild UI and click "Sanitize & Audit".
  This validates that the system does NOT over-flag clean code.
"""

from __future__ import annotations
from typing import Optional
from enum import Enum
import logging
import os

# ── Structured audit logger — no PII in messages ──────────────────────────────
audit_logger = logging.getLogger("app.data_access")

# ── Credentials from environment — never hardcoded ────────────────────────────
DB_HOST     = os.environ["DB_HOST"]
DB_USER     = os.environ["DB_USER"]
DB_PASSWORD = os.environ["DB_PASSWORD"]
DB_NAME     = os.environ["DB_NAME"]

# ── Data minimisation — explicit field allowlist ───────────────────────────────
# GDPR Art. 5(1)(c) — only fields required for each operation
class UserFields:
    PROFILE  = ("id", "display_name", "account_status", "created_at")
    BILLING  = ("id", "billing_tier", "subscription_expires_at")
    INTERNAL = ("id",)


class ProcessingPurpose(Enum):
    PROFILE_DISPLAY  = "profile_display"
    BILLING_CHECK    = "billing_check"
    AUTHENTICATION   = "authentication"


# ── Consent check — required before every data access ────────────────────────
class ConsentManager:
    @staticmethod
    def verify(user_id: int, purpose: ProcessingPurpose) -> bool:
        """Returns True only if the user has granted consent for this purpose."""
        from db import ConsentRecord
        record = ConsentRecord.objects.filter(
            user_id=user_id,
            purpose=purpose.value,
            is_active=True,
            expires_at__gt=datetime.now(),
        ).first()
        return record is not None


# ── Compliant user fetch — minimal fields, consent-gated ──────────────────────
def get_user_profile(
    user_id:          int,
    requesting_user_id: int,
    purpose:          ProcessingPurpose = ProcessingPurpose.PROFILE_DISPLAY,
) -> Optional[dict]:
    """
    Fetch user profile with:
    - Consent verification
    - Role-based access control
    - Data minimisation (only PROFILE fields)
    - Soft-delete filter
    - Audit logging without PII
    """
    # 1. Verify consent
    if not ConsentManager.verify(user_id, purpose):
        audit_logger.warning(
            "Profile access denied — no consent",
            extra={"requester_id": requesting_user_id, "purpose": purpose.value},
        )
        return None

    # 2. Role-based access: users can only read their own profile
    if requesting_user_id != user_id and not is_admin(requesting_user_id):
        audit_logger.warning(
            "Profile access denied — unauthorised",
            extra={"requester_id": requesting_user_id, "target_id": user_id},
        )
        return None

    # 3. Fetch only required fields — no SELECT *
    from db import User
    user = (
        User.objects
        .only(*UserFields.PROFILE)
        .filter(id=user_id, deleted_at__isnull=True)   # soft-delete filter
        .first()
    )

    # 4. Audit log — no PII in the log message
    audit_logger.info(
        "Profile accessed",
        extra={"user_id": user_id, "requester_id": requesting_user_id, "purpose": purpose.value},
    )

    return {field: getattr(user, field) for field in UserFields.PROFILE} if user else None


# ── Compliant erasure — cascades all stores ───────────────────────────────────
def delete_user(user_id: int, requested_by: int) -> dict:
    """
    GDPR Art. 17 compliant deletion:
    - Soft-delete (immediate)
    - Hard-delete scheduled after legal retention period
    - Suppression list entry
    - Audit trail created
    """
    from db import User, DeletionRequest, SuppressionList
    import datetime

    # Create deletion request record (immutable audit trail)
    deletion = DeletionRequest.objects.create(
        user_id=user_id,
        requested_by=requested_by,
        requested_at=datetime.datetime.now(datetime.timezone.utc),
        scheduled_hard_delete=datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=30),  # 30-day grace period
    )

    # Soft-delete immediately
    User.objects.filter(id=user_id).update(
        deleted_at=datetime.datetime.now(datetime.timezone.utc),
        anonymised_at=None,
    )

    # Add to suppression list so deleted user cannot be re-created
    SuppressionList.objects.get_or_create(user_id=user_id)

    # Log without PII
    audit_logger.info(
        "User deletion initiated",
        extra={"user_id": user_id, "deletion_request_id": deletion.id},
    )

    return {"status": "scheduled", "deletion_request_id": deletion.id}
