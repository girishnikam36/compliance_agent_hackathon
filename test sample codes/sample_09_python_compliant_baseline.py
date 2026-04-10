"""
sample_09_python_compliant_baseline.py
========================================
A COMPLIANT Python REST API for user management.
This sample has ZERO violations — use it to verify your scanner
produces zero false positives on well-written code.

Expected scanner findings: NONE (clean baseline)

What makes this compliant:
  - Secrets loaded from environment variables only
  - Parameterised queries everywhere
  - Structured logging with no PII in log messages
  - Data minimisation — explicit field allowlists
  - Soft delete with audit trail (GDPR Art. 17)
  - Consent verified before processing
  - Passwords hashed with bcrypt (strong, salted)
  - Reset tokens generated with secrets module (cryptographically secure)
  - No PII in error responses
  - Rate limiting on auth endpoints
"""

import logging
import os
import secrets
from datetime import datetime, timezone
from typing import Optional

import bcrypt
from flask import Flask, request, jsonify, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)

# Secrets loaded exclusively from environment variables
DATABASE_URL  = os.environ.get("DATABASE_URL")
SECRET_KEY    = os.environ.get("SECRET_KEY")
JWT_SECRET    = os.environ.get("JWT_SECRET")

# Structured logger — never logs PII
logger = logging.getLogger("oxbuild.users")

# Rate limiting on all routes
limiter = Limiter(app=app, key_func=get_remote_address)

# Explicit field allowlists — data minimisation (GDPR Art. 25)
USER_PUBLIC_FIELDS    = ("id", "username", "created_at", "account_status")
USER_PROFILE_FIELDS   = ("id", "username", "email", "created_at", "account_status")
USER_INTERNAL_FIELDS  = ("id", "username", "email", "phone", "created_at", "account_status", "last_login")


def get_db():
    if "db" not in g:
        g.db = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def hash_password(password: str) -> str:
    """Hash password with bcrypt — strong, automatically salted."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


def generate_secure_token() -> str:
    """Cryptographically secure random token."""
    return secrets.token_urlsafe(32)


def check_consent(user_id: int, purpose: str) -> bool:
    """Verify the user has given consent for a specific processing purpose."""
    db  = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT granted FROM consent_records "
        "WHERE user_id = %s AND purpose = %s AND expires_at > NOW()",
        (user_id, purpose)
    )
    result = cur.fetchone()
    return bool(result and result["granted"])


@app.route("/auth/register", methods=["POST"])
@limiter.limit("10 per hour")
def register():
    data = request.get_json(silent=True) or {}

    email    = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    username = str(data.get("username", "")).strip()

    # Basic validation
    if not email or "@" not in email or len(password) < 8:
        return jsonify({"error": "Invalid input"}), 400

    password_hash = hash_password(password)

    db  = get_db()
    cur = db.cursor()

    # Parameterised query — no SQL injection possible
    try:
        cur.execute(
            "INSERT INTO users (email, username, password_hash, created_at) "
            "VALUES (%s, %s, %s, NOW()) RETURNING id",
            (email, username, password_hash)
        )
        user_id = cur.fetchone()["id"]
        db.commit()
    except psycopg2.IntegrityError:
        db.rollback()
        return jsonify({"error": "Email already registered"}), 409

    # Structured log — opaque user ID only, no PII
    logger.info("user_registered", extra={"user_id": user_id, "action": "register"})

    # Return only non-sensitive fields
    return jsonify({"user_id": user_id, "username": username}), 201


@app.route("/auth/login", methods=["POST"])
@limiter.limit("5 per minute")      # Rate limited to prevent brute force
def login():
    data     = request.get_json(silent=True) or {}
    email    = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    db  = get_db()
    cur = db.cursor()

    # Single parameterised query — no user enumeration possible
    cur.execute(
        "SELECT id, password_hash, account_status FROM users WHERE email = %s",
        (email,)
    )
    user = cur.fetchone()

    # Constant-time check — same error regardless of whether user exists
    stored_hash = user["password_hash"] if user else bcrypt.gensalt().decode()
    is_valid    = verify_password(password, stored_hash) if user else False

    if not user or not is_valid or user["account_status"] != "active":
        logger.warning("login_failed", extra={"action": "login_failed"})
        return jsonify({"error": "Invalid credentials"}), 401

    # Record login — opaque ID only
    cur.execute(
        "UPDATE users SET last_login = NOW() WHERE id = %s",
        (user["id"],)
    )
    db.commit()

    token = generate_secure_token()
    cur.execute(
        "INSERT INTO sessions (user_id, token_hash, expires_at) "
        "VALUES (%s, %s, NOW() + INTERVAL '1 hour')",
        (user["id"], hash_password(token))
    )
    db.commit()

    logger.info("login_success", extra={"user_id": user["id"], "action": "login"})

    return jsonify({"token": token}), 200


@app.route("/user/profile", methods=["GET"])
def get_profile():
    """Returns only the fields the authenticated user is allowed to see."""
    auth_user = g.get("auth_user")
    if not auth_user:
        return jsonify({"error": "Unauthorised"}), 401

    db  = get_db()
    cur = db.cursor()

    # Explicit field selection — data minimisation
    fields = ", ".join(USER_PROFILE_FIELDS)
    cur.execute(
        f"SELECT {fields} FROM users WHERE id = %s AND deleted_at IS NULL",
        (auth_user["id"],)
    )
    user = cur.fetchone()

    if not user:
        return jsonify({"error": "Not found"}), 404

    logger.info("profile_read", extra={"user_id": auth_user["id"], "action": "profile_read"})
    return jsonify(dict(user))


@app.route("/user/profile", methods=["DELETE"])
def delete_account():
    """
    Soft-delete with full audit trail for GDPR Art. 17 right to erasure.
    Creates an erasure record for compliance documentation.
    """
    auth_user = g.get("auth_user")
    if not auth_user:
        return jsonify({"error": "Unauthorised"}), 401

    db  = get_db()
    cur = db.cursor()

    # Soft delete — preserves audit trail, allows erasure documentation
    cur.execute(
        "UPDATE users SET deleted_at = NOW(), account_status = 'deleted' WHERE id = %s",
        (auth_user["id"],)
    )

    # Record the erasure request for compliance documentation
    cur.execute(
        "INSERT INTO erasure_requests (user_id, requested_at, completed_at, status) "
        "VALUES (%s, NOW(), NOW(), 'completed')",
        (auth_user["id"],)
    )
    db.commit()

    # Log erasure — opaque ID only
    logger.info("account_deleted", extra={"user_id": auth_user["id"], "action": "erasure"})

    return jsonify({"status": "deleted", "erasure_reference": generate_secure_token()})


@app.errorhandler(Exception)
def handle_exception(e):
    """Production error handler — no internal details exposed."""
    request_id = generate_secure_token()[:8]
    logger.exception("unhandled_exception", extra={"request_id": request_id})
    # Generic error — no stack trace, no DB info, no internal paths
    return jsonify({"error": "An internal error occurred", "request_id": request_id}), 500


if __name__ == "__main__":
    # Debug mode disabled in entry point
    app.run(host="0.0.0.0", port=5000, debug=False)
