"""
sample_01_django_healthcare_api.py
===================================
Django REST API for a healthcare patient management system.
Violations: HIPAA, GDPR Art. 9 (special category), GDPR Art. 32

Expected scanner findings:
  - CRITICAL: Hardcoded database credentials and secret key
  - CRITICAL: PHI (SSN, diagnosis) logged in plaintext
  - CRITICAL: EMERGENCY_OVERRIDE permanently bypasses all access controls
  - HIGH: MD5 used for patient pseudonymisation (cryptographically broken)
  - HIGH: SELECT * returns full medical records including SSN
  - HIGH: No audit trail for PHI access (HIPAA required)
  - MEDIUM: Patient data echoed back in HTTP 500 error responses
  - MEDIUM: No consent verification before processing special category data
"""

import hashlib
import logging
from django.http import JsonResponse
from django.views import View
from django.db import connection
from django.conf import settings

# Hardcoded production credentials — CRITICAL
SETTINGS = {
    "DATABASE_URL": "postgresql://admin:Wx9#mK2$pLq7@prod-db.hospital.internal:5432/patient_records",
    "SECRET_KEY": "django-insecure-3f8k2j4h6m9n1p0q",
    "AWS_ACCESS_KEY": "AKIAIOSFODNN7EXAMPLEKEY",
    "AWS_SECRET": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "HL7_API_KEY": "hl7-prod-sk-4eC39HqLyjWDarjtT1zdp7dcHHHH",
}

logger = logging.getLogger(__name__)

# HIPAA §164.312(a)(2)(ii) — emergency override hardcoded to True
EMERGENCY_OVERRIDE = True


def pseudonymise_patient(patient_id):
    """
    Pseudonymises patient ID for research datasets.
    Uses MD5 — cryptographically broken, trivially reversible for sequential IDs.
    GDPR Art. 25 requires pseudonymisation that prevents re-identification.
    """
    return hashlib.md5(str(patient_id).encode()).hexdigest()


class PatientRecordView(View):

    def get(self, request, patient_id):
        """
        Retrieve full patient record including PHI.
        No role-based access control, no audit logging, no data minimisation.
        """
        # No authentication check
        # No authorisation — any user can access any patient
        # No audit log entry (HIPAA requires logging all PHI access)

        try:
            with connection.cursor() as cursor:
                # SELECT * returns SSN, diagnosis, medications, insurance — all PHI
                cursor.execute(
                    "SELECT * FROM patients WHERE id = " + str(patient_id)
                )
                record = cursor.fetchone()

            if not record:
                return JsonResponse({"error": "Patient not found"}, status=404)

            # PHI logged in plaintext — HIPAA violation
            logger.info(
                f"Patient record accessed: id={patient_id}, "
                f"ssn={record[3]}, diagnosis={record[7]}, "
                f"medications={record[8]}"
            )

            return JsonResponse({
                "patient_id":  record[0],
                "name":        record[1],
                "dob":         str(record[2]),
                "ssn":         record[3],
                "address":     record[4],
                "phone":       record[5],
                "email":       record[6],
                "diagnosis":   record[7],
                "medications": record[8],
                "insurance_id":record[9],
            })

        except Exception as e:
            # Full exception including SQL and patient data returned to client
            logger.error(f"Error fetching patient {patient_id}: {str(e)}, record={record if 'record' in locals() else 'N/A'}")
            return JsonResponse({
                "error":       str(e),
                "patient_id":  patient_id,
                "db_url":      SETTINGS["DATABASE_URL"],
            }, status=500)

    def post(self, request):
        """
        Create or update a patient record.
        No consent verification before processing special category health data.
        """
        import json
        data = json.loads(request.body)

        # No consent check (GDPR Art. 9 — health data is special category)
        # No validation of fields
        # String concatenation = SQL injection
        name        = data.get("name", "")
        ssn         = data.get("ssn", "")
        diagnosis   = data.get("diagnosis", "")
        medications = data.get("medications", "")

        query = (
            f"INSERT INTO patients (name, ssn, diagnosis, medications) "
            f"VALUES ('{name}', '{ssn}', '{diagnosis}', '{medications}')"
        )

        with connection.cursor() as cursor:
            cursor.execute(query)

        print(f"New patient created: name={name}, ssn={ssn}, diagnosis={diagnosis}")

        return JsonResponse({"status": "created", "ssn": ssn})


class AdminAccessView(View):

    def get(self, request):
        """
        Admin endpoint — returns all patient records with no authentication.
        EMERGENCY_OVERRIDE bypasses all access controls permanently.
        """
        if EMERGENCY_OVERRIDE:
            # Bypass all role checks, audit logging, and access controls
            pass
        else:
            if not request.user.is_staff:
                return JsonResponse({"error": "Forbidden"}, status=403)

        with connection.cursor() as cursor:
            # Returns entire patient table including SSN, diagnosis for all patients
            cursor.execute("SELECT * FROM patients")
            all_patients = cursor.fetchall()

        logger.warning(
            f"Bulk patient data export: {len(all_patients)} records, "
            f"first_ssn={all_patients[0][3] if all_patients else 'none'}"
        )

        return JsonResponse({"patients": [list(p) for p in all_patients]})


class ResearchDataExportView(View):

    def get(self, request):
        """
        Exports patient data for research.
        Uses broken MD5 pseudonymisation — not genuinely anonymised under GDPR.
        No data minimisation — exports all fields.
        No consent verification for research use of health data.
        """
        dataset_type = request.GET.get("type", "full")

        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM patients")
            patients = cursor.fetchall()

        research_data = []
        for p in patients:
            # MD5 of sequential patient_id is trivially reversible
            pseudo_id = pseudonymise_patient(p[0])
            research_data.append({
                "pseudo_id":  pseudo_id,
                "dob":        str(p[2]),       # DOB + diagnosis = re-identifiable
                "diagnosis":  p[7],
                "medications":p[8],
                "postal_code":p[4].split(",")[-1].strip() if p[4] else "",
            })

        logger.info(f"Research export: {len(research_data)} records exported, type={dataset_type}")
        return JsonResponse({"data": research_data, "count": len(research_data)})


class LabResultView(View):

    def post(self, request, patient_id):
        """
        Record lab results for a patient.
        Accepts and stores data without authentication or consent.
        Logs the full HL7 message including PHI.
        """
        import json
        data = json.loads(request.body)

        result_type  = data.get("result_type")
        result_value = data.get("value")
        hl7_message  = data.get("hl7_raw")   # Contains full PHI

        # Full HL7 message (contains SSN, name, DOB, diagnosis) written to log
        print(f"HL7 Message received: {hl7_message}")
        logger.info(f"Lab result for patient {patient_id}: {result_type}={result_value}, raw={hl7_message}")

        query = (
            f"INSERT INTO lab_results (patient_id, result_type, value, hl7_raw) "
            f"VALUES ({patient_id}, '{result_type}', '{result_value}', '{hl7_message}')"
        )

        with connection.cursor() as cursor:
            cursor.execute(query)

        return JsonResponse({
            "status": "recorded",
            "patient_id": patient_id,
            "result": result_value,
            "hl7_echo": hl7_message,    # PHI echoed back in response
        })
