"""
test_samples/sample_03_django_healthcare.py
============================================
EXPLOIT CATEGORY : Healthcare / HIPAA + GDPR Art. 9 (Special Categories)
SEVERITY PROFILE : 4 CRITICAL · 2 HIGH
REGULATIONS      : HIPAA, GDPR (special category data), DPDPA
LANGUAGE         : Python (Django)

What this file simulates:
  A Django-based electronic health record (EHR) API view.
  Medical data is the highest-risk PII category under every regulation.
  Violations simulate what happens when a developer ships a health app
  without understanding HIPAA Technical Safeguards.

HOW TO TEST:
  Paste into Oxbuild UI.
  C++ scanner redacts:
    patient@hospital.org     → [PII_EMAIL_xxxxxxxx]
    172.16.0.10              → [PII_IPV4_xxxxxxxx]
    Basic YWRtaW46...        → [PII_API_KEY_xxxxxxxx]  (Base64 auth token)
  Expected violations: 6+  (highest violation count of all samples)
"""

from django.http import JsonResponse
from django.views import View
from django.db import models
import logging
import hashlib

# ── EXPLOIT 1: PHI logged at DEBUG level ─────────────────────────────────────
# HIPAA 45 CFR §164.312(b) — Audit Controls
# GDPR Art. 9(1) — Special category data (health data)
logger = logging.getLogger(__name__)

EHR_API_KEY     = "Basic YWRtaW46U3VwZXJTZWNyZXQxMjM="   # base64 admin:SuperSecret123
EHR_HOST        = "172.16.0.10"
ADMIN_CONTACT   = "patient@hospital.org"

class PatientRecordView(View):

    # ── EXPLOIT 2: No RBAC — any authenticated user can read any record ───────
    # HIPAA 45 CFR §164.312(a)(1) — Access Control
    # GDPR Art. 25 — Data Protection by Design
    def get(self, request, patient_id):
        """Return full patient record — no role check, no minimum necessary."""
        # No: check if requesting_user has permission to access patient_id
        # No: limit fields to what the requesting role actually needs
        patient = Patient.objects.get(id=patient_id)   # raises 404 but no AuthZ

        record = {
            "id":           patient.id,
            "name":         patient.full_name,
            "ssn":          patient.social_security_number,   # SSN in API response
            "dob":          str(patient.date_of_birth),
            "diagnosis":    patient.diagnosis_code,
            "medications":  patient.medications,
            "insurance_id": patient.insurance_policy_number,
            "notes":        patient.clinical_notes,            # full clinical notes
        }

        # Logs complete PHI record including SSN and diagnosis
        logger.debug(f"Patient record accessed: {record}")    # CRITICAL HIPAA violation
        return JsonResponse(record)

    # ── EXPLOIT 3: PHI transmitted over HTTP (no TLS enforcement) ────────────
    # HIPAA 45 CFR §164.312(e)(1) — Transmission Security
    def post(self, request):
        """Create patient record — no TLS check, no encryption at rest."""
        data = request.POST
        patient = Patient.objects.create(
            full_name=data['name'],
            social_security_number=data['ssn'],      # SSN stored as plaintext
            date_of_birth=data['dob'],
            diagnosis_code=data['diagnosis'],
            medications=data['medications'],
            insurance_policy_number=data['insurance_id'],
            clinical_notes=data['notes'],
            # No field_level_encryption=True
            # No created_by audit field
        )
        logger.info(f"Created patient {patient.id}: {data['name']} SSN:{data['ssn']}")
        return JsonResponse({"id": patient.id})


# ── EXPLOIT 4: Weak pseudonymisation (reversible MD5 hash) ───────────────────
# GDPR Art. 25 — Pseudonymisation requirement
# HIPAA 45 CFR §164.514(b) — De-identification
def pseudonymise_patient(patient_id: int) -> str:
    """Pseudonymise a patient ID using MD5 — trivially reversible, not compliant."""
    return hashlib.md5(str(patient_id).encode()).hexdigest()
    # GDPR requires pseudonymisation to be irreversible without the key
    # MD5 of sequential integers is trivially brute-forceable


# ── EXPLOIT 5: Bulk PHI export with no access logging ────────────────────────
# HIPAA 45 CFR §164.312(b) — Audit Controls
# GDPR Art. 5(1)(b) — Purpose Limitation
def export_all_patients_for_research(researcher_email: str):
    """Export all patient records to a researcher — no consent, no audit."""
    patients = Patient.objects.all().values()    # all records, all fields
    # No: consent check for research use
    # No: anonymisation or de-identification
    # No: audit log of who exported what
    # No: data sharing agreement reference
    import csv, io
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=list(patients[0].keys()))
    writer.writerows(patients)
    send_email(researcher_email, "Patient Data Export", output.getvalue())


# ── EXPLOIT 6: Emergency override bypasses all access controls permanently ────
# HIPAA 45 CFR §164.312(a)(2)(ii) — Emergency Access Procedure
EMERGENCY_OVERRIDE_ACTIVE = True   # hardcoded True — was meant to be temporary

def get_patient_emergency(patient_id: int):
    if EMERGENCY_OVERRIDE_ACTIVE:
        # Bypasses ALL access controls — never logs, never expires
        return Patient.objects.get(id=patient_id).__dict__
