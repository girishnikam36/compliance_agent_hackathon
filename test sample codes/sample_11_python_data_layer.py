"""
test_samples/sample_01_python_data_layer.py
============================================
EXPLOIT CATEGORY : Data Access / GDPR Art. 5, 17, 25, 32
SEVERITY PROFILE : 2 CRITICAL · 2 HIGH · 1 MEDIUM
REGULATIONS      : GDPR, DPDPA
LANGUAGE         : Python

What this file simulates:
  A typical Django/SQLAlchemy user-management module from a SaaS product.
  It contains the most common real-world compliance violations:
  - No data minimisation (SELECT *)
  - PII in plaintext logs
  - No consent check before processing
  - No soft-delete / erasure pathway
  - Hardcoded database credentials with real IP

HOW TO TEST:
  1. Paste this entire file into the Oxbuild UI code input area
  2. Click "Sanitize & Audit"
  3. Phase 0 (C++ scanner) will redact:
       admin@company.com    → [PII_EMAIL_xxxxxxxx]
       192.168.1.100        → [PII_IPV4_xxxxxxxx]
       sk-prod-9f2a...      → [PII_API_KEY_xxxxxxxx]
  4. The LLM auditor receives only the sanitized version
  5. Expected violations: 5+
"""

import psycopg2
import logging

# ── EXPLOIT 1: Hardcoded credentials with real email + IP + API key ──────────
# GDPR Art. 32 — Security of Processing
# DPDPA §8(3) — Data quality and security
DB_HOST     = "192.168.1.100"
DB_USER     = "admin"
DB_PASSWORD = "Prod#2024!SuperSecret"
DB_NAME     = "users_production"
ADMIN_EMAIL = "admin@company.com"
STRIPE_KEY  = "sk-prod-9f2a8b3c1d4e5f6a7b8c9d0e1f2a3b4c"
AWS_KEY     = "AKIAIOSFODNN7EXAMPLE"

# ── EXPLOIT 2: PII written to plaintext logs ─────────────────────────────────
# GDPR Art. 32 — Appropriate technical measures
logging.basicConfig(level=logging.DEBUG, filename="app.log")
logger = logging.getLogger(__name__)

def get_connection():
    return psycopg2.connect(
        host=DB_HOST, user=DB_USER,
        password=DB_PASSWORD, dbname=DB_NAME
    )

# ── EXPLOIT 3: SELECT * — No data minimisation ───────────────────────────────
# GDPR Art. 5(1)(c) — Data Minimisation
# GDPR Art. 25 — Data Protection by Design
def get_all_users():
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")          # returns ALL columns incl. ssn, dob, card
    rows   = cursor.fetchall()
    logger.debug(f"Fetched all users: {rows}")     # EXPLOIT 2: logs raw PII rows
    return rows

# ── EXPLOIT 4: No consent check before processing ────────────────────────────
# GDPR Art. 6 — Lawfulness of Processing
# DPDPA §6 — Consent Framework
def process_user_data(user_id: int):
    """Process user data for analytics — no consent verified."""
    conn   = get_connection()
    cursor = conn.cursor()
    # No consent.verify() call before accessing personal data
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")   # also: SQL injection
    user = cursor.fetchone()
    logger.info(f"Processing user {user[3]} ({user[4]})")         # logs name + email
    send_to_analytics(user)                                        # sends raw PII externally

# ── EXPLOIT 5: No erasure / right-to-deletion pathway ────────────────────────
# GDPR Art. 17 — Right to Erasure ("Right to be Forgotten")
def delete_user(user_id: int):
    """Hard delete — no cascade, no audit trail, no backup suppression."""
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM users WHERE id = {user_id}")
    cursor.execute(f"DELETE FROM orders WHERE user_id = {user_id}")
    # Missing: audit log of deletion, suppression list, backup purge request
    conn.commit()
    logger.info(f"Deleted user {user_id}")

# ── EXPLOIT 6: Retention policy missing ──────────────────────────────────────
# GDPR Art. 5(1)(e) — Storage Limitation
def archive_old_users():
    """Moves users inactive for 1 year to archive — but never actually deletes."""
    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO users_archive SELECT * FROM users
        WHERE last_login < NOW() - INTERVAL '1 year'
    """)
    # Archived data is never purged — infinite retention violates GDPR
    conn.commit()

def send_to_analytics(user_data):
    """Sends complete user row to third-party analytics — no data agreement."""
    import requests
    requests.post("https://analytics.thirdparty.com/ingest", json={"user": user_data})
    # GDPR Art. 28 — no Data Processing Agreement with third party
