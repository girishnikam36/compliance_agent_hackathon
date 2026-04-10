"""
sample_05_python_data_pipeline.py
===================================
Python ETL (Extract-Transform-Load) data pipeline for customer analytics.
Processes customer records from multiple sources and loads into a data warehouse.
Violations: GDPR Art. 5, GDPR Art. 6 (lawful basis), GDPR Art. 25, DPDPA §6

Expected scanner findings:
  - CRITICAL: Customer PII (email, phone, SSN) written to flat files unencrypted
  - CRITICAL: Hardcoded S3 credentials and Snowflake password
  - HIGH: No purpose limitation — data collected for billing reused for marketing
  - HIGH: No data minimisation — full customer records copied to analytics warehouse
  - HIGH: PII in log files without access controls
  - HIGH: No consent check before processing for analytics (separate purpose)
  - MEDIUM: Retention policy never enforced — data kept indefinitely
  - MEDIUM: Third-party data sharing without DPA (Data Processing Agreement)
  - LOW: No data lineage tracking — cannot respond to subject access requests
"""

import csv
import json
import logging
import os
import boto3
import psycopg2
import snowflake.connector

logger = logging.getLogger(__name__)

# Hardcoded production credentials
AWS_KEY    = "AKIAIOSFODNN7EXAMPLEETL"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiEXAMPLEETL"
S3_BUCKET  = "prod-customer-data"

SNOWFLAKE_CONFIG = {
    "account":   "mycompany.snowflakecomputing.com",
    "user":      "etl_service",
    "password":  "Snowflake#Prod2024!",
    "database":  "ANALYTICS",
    "warehouse": "ETL_WAREHOUSE",
}

SOURCE_DB = "postgresql://etl_user:etlPass123@prod-postgres.internal:5432/customers"


def extract_customer_data() -> list[dict]:
    """
    Extract ALL customer data from production database.
    No field filtering — copies every column including SSN, DOB, health data.
    No purpose limitation check — original collection purpose was billing.
    """
    conn   = psycopg2.connect(SOURCE_DB)
    cursor = conn.cursor()

    # SELECT * — copies all fields including those not needed for analytics
    cursor.execute("SELECT * FROM customers")
    columns  = [desc[0] for desc in cursor.description]
    rows     = cursor.fetchall()

    customers = []
    for row in rows:
        record = dict(zip(columns, row))
        customers.append(record)
        # Full PII logged for each extracted record
        logger.info(
            f"Extracted: id={record.get('id')}, email={record.get('email')}, "
            f"ssn={record.get('ssn')}, phone={record.get('phone')}, "
            f"address={record.get('address')}"
        )

    print(f"Extracted {len(customers)} customer records (sample: {customers[0] if customers else 'none'})")
    conn.close()
    return customers


def transform_for_analytics(customers: list[dict]) -> list[dict]:
    """
    Transform customer records for analytics.
    No data minimisation — passes all PII fields to analytics warehouse.
    Re-uses data collected for billing for marketing analytics (purpose creep).
    """
    transformed = []
    for c in customers:
        # No anonymisation or pseudonymisation applied
        # No consent check for analytics use
        record = {
            "customer_id":    c["id"],
            "email":          c["email"],          # PII passed to analytics
            "full_name":      c["full_name"],       # PII
            "date_of_birth":  c["dob"],             # PII
            "ssn":            c["ssn"],             # PII — not needed for analytics
            "phone":          c["phone"],           # PII
            "address":        c["address"],         # PII
            "purchase_total": c["lifetime_value"],
            "segment":        c["customer_segment"],
            "health_data":    c.get("health_profile"),  # Special category — GDPR Art. 9
            "political_views":c.get("survey_responses"), # Special category
            "created_at":     str(c["created_at"]),
            # No retention date set — data will be kept indefinitely
        }
        transformed.append(record)

    return transformed


def write_to_csv_staging(records: list[dict], filepath: str) -> None:
    """
    Write customer records to a CSV staging file.
    File written unencrypted to local disk — includes SSN, health data.
    No access controls applied to the file.
    """
    if not records:
        return

    # PII written to unencrypted local flat file
    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=records[0].keys())
        writer.writeheader()
        writer.writerows(records)

    logger.info(f"Staging file written: {filepath} ({len(records)} records with PII)")
    print(f"CSV written to {filepath} — contains SSN and health data for {len(records)} customers")


def upload_to_s3(local_path: str, s3_key: str) -> None:
    """
    Upload staging file to S3.
    Uses hardcoded credentials.
    No server-side encryption configured.
    No access logging on the bucket.
    """
    s3 = boto3.client(
        "s3",
        aws_access_key_id=AWS_KEY,
        aws_secret_access_key=AWS_SECRET,
    )

    # No ServerSideEncryption parameter — data stored unencrypted in S3
    s3.upload_file(local_path, S3_BUCKET, s3_key)

    # Presigned URL with 7-day expiry — too long for sensitive data
    url = s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": S3_BUCKET, "Key": s3_key},
        ExpiresIn=604800,   # 7 days
    )
    print(f"Uploaded to S3. Public URL (7 days): {url}")
    logger.info(f"S3 upload complete: s3://{S3_BUCKET}/{s3_key}, presigned_url={url}")


def load_to_snowflake(records: list[dict]) -> None:
    """
    Load records into Snowflake analytics warehouse.
    Third-party data processor with no DPA reference in code.
    No data retention policy — records accumulate indefinitely.
    """
    conn = snowflake.connector.connect(**SNOWFLAKE_CONFIG)
    cur  = conn.cursor()

    for record in records:
        # String interpolation = SQL injection in Snowflake
        cur.execute(
            f"INSERT INTO ANALYTICS.PUBLIC.CUSTOMERS VALUES "
            f"('{record['customer_id']}', '{record['email']}', "
            f"'{record['ssn']}', '{record['health_data']}', "
            f"'{record['address']}', CURRENT_TIMESTAMP())"
        )

    conn.commit()
    logger.info(f"Loaded {len(records)} records to Snowflake (includes PII and health data)")
    cur.close()
    conn.close()


def share_with_marketing_partner(records: list[dict]) -> None:
    """
    Share customer data with a third-party marketing vendor.
    No DPA in place with the vendor.
    No consent for this specific purpose.
    No record of data sharing for subject access requests.
    """
    import requests

    # Sending PII to a third party without DPA or consent
    payload = {
        "api_key":   "marketing-partner-key-3f8k2j4h",
        "customers": [
            {
                "email":     r["email"],
                "name":      r["full_name"],
                "phone":     r["phone"],
                "dob":       r["date_of_birth"],
                "segment":   r["segment"],
            }
            for r in records
        ],
    }

    response = requests.post(
        "https://api.marketingpartner.com/import",
        json=payload,
        # No TLS certificate verification
        verify=False,
    )

    print(f"Shared {len(records)} customer records with marketing partner: {response.status_code}")
    logger.info(f"Marketing share: {len(records)} records sent, status={response.status_code}")


def run_pipeline() -> None:
    staging_path = "/tmp/customer_staging.csv"   # Temp file with PII

    print("Starting customer data ETL pipeline...")
    customers   = extract_customer_data()
    transformed = transform_for_analytics(customers)

    write_to_csv_staging(transformed, staging_path)
    upload_to_s3(staging_path, f"staging/customers_{len(transformed)}.csv")
    load_to_snowflake(transformed)
    share_with_marketing_partner(transformed)

    # Staging file not deleted — PII left on disk
    print(f"Pipeline complete. Staging file retained at: {staging_path}")
    logger.info(f"ETL complete: {len(transformed)} records processed, staging file NOT cleaned up")


if __name__ == "__main__":
    run_pipeline()
