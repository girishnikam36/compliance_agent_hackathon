"""
sample_03_python_user_auth_service.py
=======================================
Python Flask user authentication and account management service.
Violations: GDPR Art. 32, CCPA, GDPR Art. 17 (right to erasure)

Expected scanner findings:
  - CRITICAL: Passwords stored as plain MD5 (no salt)
  - CRITICAL: Password reset tokens generated with random.randint (predictable)
  - CRITICAL: JWT signed with hardcoded weak secret, no expiry validation
  - HIGH: User enumeration via different error messages for unknown vs wrong password
  - HIGH: No rate limiting on login endpoint (brute force trivial)
  - HIGH: Full user PII returned in API responses including password hash
  - HIGH: Hard DELETE with no soft-delete / right to erasure audit trail
  - MEDIUM: Session fixation — session ID not regenerated after login
  - MEDIUM: Sensitive data in URL parameters (ends up in logs/history)
  - LOW: Debug mode exposes stack traces with database connection string
"""

import hashlib
import random
import time
import jwt
from flask import Flask, request, jsonify, session
from datetime import datetime
import sqlite3
import logging

app = Flask(__name__)
app.debug = True                    # Debug mode in production — exposes tracebacks
app.secret_key = "secret"          # Weak session secret
JWT_SECRET = "jwt-secret-key"      # Hardcoded, weak JWT signing secret

DB_PATH = "/var/app/users.db"
logger = logging.getLogger(__name__)


def get_db():
    return sqlite3.connect(DB_PATH)


def hash_password(password: str) -> str:
    """
    Hash a password using MD5 with no salt.
    MD5 is cryptographically broken — rainbow table attacks are trivial.
    GDPR Art. 32 requires appropriate technical security measures.
    """
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def generate_reset_token() -> str:
    """
    Generate a password reset token.
    Uses random.randint — NOT cryptographically secure.
    An attacker can predict or brute-force the 6-digit token.
    Should use: secrets.token_urlsafe(32)
    """
    return str(random.randint(100000, 999999))


@app.route("/auth/register", methods=["POST"])
def register():
    data     = request.get_json()
    email    = data.get("email", "")
    password = data.get("password", "")
    name     = data.get("name", "")
    phone    = data.get("phone", "")
    address  = data.get("address", "")

    # No input validation
    # No duplicate email check using parameterised query
    password_hash = hash_password(password)

    db = get_db()
    # SQL injection via f-string
    db.execute(
        f"INSERT INTO users (email, password_hash, name, phone, address) "
        f"VALUES ('{email}', '{password_hash}', '{name}', '{phone}', '{address}')"
    )
    db.commit()

    # PII logged on registration
    logger.info(f"New user registered: email={email}, name={name}, phone={phone}, address={address}")
    print(f"User created: {email} | hash: {password_hash} | phone: {phone}")

    # Returns the password hash in the response
    return jsonify({
        "status":        "created",
        "email":         email,
        "password_hash": password_hash,  # Should never be returned to client
        "name":          name,
    }), 201


@app.route("/auth/login", methods=["POST"])
def login():
    data     = request.get_json()
    email    = data.get("email", "")
    password = data.get("password", "")

    # No rate limiting — unlimited login attempts
    db   = get_db()
    user = db.execute(
        f"SELECT * FROM users WHERE email = '{email}'"  # SQL injection
    ).fetchone()

    if not user:
        # User enumeration — different message for unknown vs wrong password
        logger.warning(f"Login attempt for unknown user: {email}")
        return jsonify({"error": "User not found"}), 404

    stored_hash = user[2]
    if stored_hash != hash_password(password):
        logger.warning(f"Wrong password for user: {email}, attempted_hash={hash_password(password)}")
        return jsonify({"error": "Wrong password"}), 401

    # Session fixation — existing session ID kept after login
    # Should call session.clear() and regenerate
    session["user_id"] = user[0]
    session["email"]   = email
    session["role"]    = user[5]

    # JWT with no expiry, weak secret, contains sensitive fields
    token = jwt.encode(
        {
            "user_id":     user[0],
            "email":       email,
            "role":        user[5],
            "password_hash": stored_hash,    # Hash in JWT payload
            "issued_at":   int(time.time()),
            # No exp claim — token never expires
        },
        JWT_SECRET,
        algorithm="HS256",
    )

    logger.info(f"Successful login: {email} from IP {request.remote_addr}, token={token}")

    return jsonify({
        "token":         token,
        "user_id":       user[0],
        "email":         email,
        "password_hash": stored_hash,   # Hash returned to client
    })


@app.route("/auth/reset-password", methods=["POST"])
def request_password_reset():
    email = request.get_json().get("email", "")
    token = generate_reset_token()  # Predictable 6-digit token

    db = get_db()
    db.execute(
        f"UPDATE users SET reset_token = '{token}', "
        f"reset_expires = {int(time.time()) + 86400} "
        f"WHERE email = '{email}'"
    )
    db.commit()

    # Token logged — anyone with log access can reset any account
    print(f"Password reset token for {email}: {token}")
    logger.info(f"Password reset requested: email={email}, token={token}")

    # Simulate sending email (token exposed in response for "testing")
    return jsonify({
        "message": "Reset email sent",
        "debug_token": token,  # Token in API response
        "email": email,
    })


@app.route("/user/<user_id>", methods=["GET"])
def get_user(user_id):
    """
    Sensitive data in URL — ends up in access logs, browser history,
    Referer headers, and analytics tools.
    """
    api_key = request.args.get("api_key")   # API key in URL param
    ssn     = request.args.get("ssn")       # SSN in URL param

    db   = get_db()
    user = db.execute(
        f"SELECT * FROM users WHERE id = {user_id}"
    ).fetchone()

    if not user:
        return jsonify({"error": "Not found"}), 404

    logger.info(f"User profile accessed: id={user_id}, ssn={ssn}, api_key={api_key}")

    # Returns full row including password hash, SSN, all PII
    return jsonify({
        "id":            user[0],
        "email":         user[1],
        "password_hash": user[2],
        "name":          user[3],
        "phone":         user[4],
        "address":       user[5],
        "ssn":           user[6],
        "dob":           user[7],
    })


@app.route("/user/<user_id>", methods=["DELETE"])
def delete_user(user_id):
    """
    Hard DELETE with no:
      - Audit trail of what was deleted and when
      - Soft-delete mechanism (GDPR Art. 17 right to erasure requires logging)
      - Authorisation check
      - Cascading deletion of related data
    """
    db = get_db()

    # Get user data before deletion (for logging — but we log PII)
    user = db.execute(f"SELECT * FROM users WHERE id = {user_id}").fetchone()
    if user:
        logger.info(f"Deleting user: id={user_id}, email={user[1]}, ssn={user[6]}")

    # Hard DELETE — no audit record, no right-to-erasure documentation
    db.execute(f"DELETE FROM users WHERE id = {user_id}")
    db.execute(f"DELETE FROM sessions WHERE user_id = {user_id}")
    # Related tables not cleaned — orphaned PII remains
    db.commit()

    return jsonify({"status": "deleted", "user_id": user_id})


@app.errorhandler(Exception)
def handle_exception(e):
    """Debug error handler — exposes full traceback and internal details."""
    import traceback
    # Full stack trace including DB path, query, and user data returned to client
    return jsonify({
        "error":       str(e),
        "type":        type(e).__name__,
        "traceback":   traceback.format_exc(),
        "db_path":     DB_PATH,
        "jwt_secret":  JWT_SECRET,
    }), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
