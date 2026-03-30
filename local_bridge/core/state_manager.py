"""
local_bridge/core/state_manager.py
=====================================
Persistent, dual-backend vault for the PII redaction map.

The StateManager stores the ``Map<token, original_value>`` produced by the
C++ scanner so that the Reconstructor can restore original values after the
cloud agents return patched code.

Storage backends (both maintained simultaneously for safety):
  • PRIMARY   — SQLite database at ``state_db_path``.
                Indexed, fast, supports concurrent readers, survives crashes.
  • SECONDARY — JSON file at ``state_json_backup_path``.
                Human-readable, diff-friendly, portable backup.

Schema (SQLite):
    Table: redaction_sessions
      session_id TEXT PRIMARY KEY
      created_at TEXT
      language   TEXT
      metadata   TEXT (JSON blob)

    Table: redaction_tokens
      token      TEXT PRIMARY KEY
      original   TEXT NOT NULL
      category   TEXT
      hash_hex   TEXT
      session_id TEXT REFERENCES redaction_sessions(session_id)
      created_at TEXT

Design decisions
----------------
• All writes are atomic (SQLite transactions + JSON atomic overwrite).
• The vault is append-only by default. Tokens are never updated in place;
  a new scan session creates new rows. Old sessions are pruned by age.
• Sessions allow the Reconstructor to scope lookups to a specific scan.
• The JSON backup is written as a pretty-printed snapshot for auditability.
• No external dependencies — stdlib only (sqlite3, json, pathlib).
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator, Iterator

logger = logging.getLogger("oxbuild.state_manager")

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

_DEFAULT_DB_PATH   = Path("local_bridge/data/state.db")
_DEFAULT_JSON_PATH = Path("local_bridge/data/state_backup.json")
_SCHEMA_VERSION    = 2


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class StateManagerError(Exception):
    """Base exception for all StateManager failures."""


class SessionNotFoundError(StateManagerError):
    """Raised when a requested session_id does not exist in the vault."""


class VaultCorruptionError(StateManagerError):
    """Raised when the SQLite or JSON store is in an inconsistent state."""


# ---------------------------------------------------------------------------
# StateManager
# ---------------------------------------------------------------------------

class StateManager:
    """
    Thread-safe, dual-backend persistent vault for PII redaction maps.

    Parameters
    ----------
    db_path        : Path  — SQLite database file path.
    json_path      : Path  — JSON backup file path.
    max_sessions   : int   — Maximum number of sessions to retain.
                             Oldest sessions are pruned on ``save``.

    Usage
    -----
        sm = StateManager()
        session_id = sm.save(
            redaction_map={"[PII_EMAIL_3F2A1B0C]": "alice@example.com"},
            language="python",
        )
        original = sm.get_original("[PII_EMAIL_3F2A1B0C]")
        full_map = sm.load_all(session_id=session_id)
        sm.delete_session(session_id)
    """

    def __init__(
        self,
        db_path:        Path = _DEFAULT_DB_PATH,
        json_path:      Path = _DEFAULT_JSON_PATH,
        max_sessions:   int  = 50,
    ) -> None:
        self._db_path    = Path(db_path)
        self._json_path  = Path(json_path)
        self._max_sessions = max(1, max_sessions)
        self._lock       = threading.RLock()

        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._json_path.parent.mkdir(parents=True, exist_ok=True)

        self._init_db()
        self._migrate_if_needed()
        logger.debug("StateManager ready: db=%s json=%s", self._db_path, self._json_path)

    # ── Database setup ───────────────────────────────────────────────────

    def _init_db(self) -> None:
        """Create tables if they don't exist."""
        with self._connect() as conn:
            conn.executescript("""
                PRAGMA journal_mode=WAL;
                PRAGMA foreign_keys=ON;
                PRAGMA synchronous=NORMAL;

                CREATE TABLE IF NOT EXISTS schema_version (
                    version    INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS redaction_sessions (
                    session_id TEXT    PRIMARY KEY,
                    created_at TEXT    NOT NULL,
                    language   TEXT    NOT NULL DEFAULT 'unknown',
                    token_count INTEGER NOT NULL DEFAULT 0,
                    metadata   TEXT    NOT NULL DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS redaction_tokens (
                    token      TEXT NOT NULL,
                    original   TEXT NOT NULL,
                    category   TEXT NOT NULL DEFAULT 'UNKNOWN',
                    hash_hex   TEXT NOT NULL DEFAULT '',
                    session_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (session_id)
                        REFERENCES redaction_sessions(session_id)
                        ON DELETE CASCADE,
                    PRIMARY KEY (token, session_id)
                );

                CREATE INDEX IF NOT EXISTS idx_tokens_session
                    ON redaction_tokens(session_id);

                CREATE INDEX IF NOT EXISTS idx_tokens_hash
                    ON redaction_tokens(hash_hex);
            """)
            # Record schema version if not already present
            conn.execute(
                "INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES (?, ?)",
                (_SCHEMA_VERSION, _utcnow()),
            )
            conn.commit()

    def _migrate_if_needed(self) -> None:
        """Apply any pending schema migrations."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT MAX(version) FROM schema_version"
            ).fetchone()
            current = row[0] if row and row[0] else 0
            if current < _SCHEMA_VERSION:
                logger.info(
                    "Migrating schema from v%d → v%d", current, _SCHEMA_VERSION
                )
                # Future migrations go here
                conn.execute(
                    "INSERT OR REPLACE INTO schema_version (version, applied_at) VALUES (?,?)",
                    (_SCHEMA_VERSION, _utcnow()),
                )
                conn.commit()

    # ── Context managers ─────────────────────────────────────────────────

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        """Yield a thread-local SQLite connection with WAL mode enabled."""
        conn = sqlite3.connect(
            str(self._db_path),
            check_same_thread=False,
            timeout=10.0,
        )
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    # ── Write operations ─────────────────────────────────────────────────

    def save(
        self,
        redaction_map: dict[str, str],
        language:      str = "unknown",
        session_id:    str | None = None,
        metadata:      dict[str, Any] | None = None,
    ) -> str:
        """
        Persist a redaction map to both SQLite and JSON.

        Parameters
        ----------
        redaction_map : dict[str, str]
            Token → original value mapping from the C++ scanner.
        language      : str
            Programming language of the scanned file.
        session_id    : str | None
            Use an existing session ID (or generate a new one).
        metadata      : dict | None
            Arbitrary caller metadata (repo, file path, commit SHA, etc.).

        Returns
        -------
        str — The session ID under which the map was stored.

        Raises
        ------
        StateManagerError — On database or I/O failure.
        TypeError         — If redaction_map is not a dict.
        """
        if not isinstance(redaction_map, dict):
            raise TypeError("redaction_map must be a dict[str, str]")

        if not session_id:
            session_id = str(uuid.uuid4())

        now      = _utcnow()
        meta_str = json.dumps(metadata or {})

        with self._lock:
            try:
                with self._connect() as conn:
                    # Upsert session
                    conn.execute(
                        """
                        INSERT INTO redaction_sessions
                            (session_id, created_at, language, token_count, metadata)
                        VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT(session_id) DO UPDATE SET
                            token_count = excluded.token_count,
                            metadata    = excluded.metadata
                        """,
                        (session_id, now, language, len(redaction_map), meta_str),
                    )

                    # Insert tokens
                    for token, original in redaction_map.items():
                        category, hash_hex = _parse_token(token)
                        conn.execute(
                            """
                            INSERT OR REPLACE INTO redaction_tokens
                                (token, original, category, hash_hex, session_id, created_at)
                            VALUES (?, ?, ?, ?, ?, ?)
                            """,
                            (token, original, category, hash_hex, session_id, now),
                        )

                    conn.commit()

                logger.info(
                    "Saved %d token(s) | session=%s lang=%s",
                    len(redaction_map), session_id, language,
                )

                # Prune old sessions
                self._prune_sessions()

                # Write JSON backup
                self._write_json_backup()

                return session_id

            except sqlite3.Error as exc:
                logger.error("SQLite write error: %s", exc)
                raise StateManagerError(f"Failed to save redaction map: {exc}") from exc

    def delete_session(self, session_id: str) -> int:
        """
        Remove a session and all its tokens from the vault.

        Returns the number of tokens deleted.
        Raises SessionNotFoundError if the session does not exist.
        """
        with self._lock:
            try:
                with self._connect() as conn:
                    # Check existence
                    row = conn.execute(
                        "SELECT session_id FROM redaction_sessions WHERE session_id = ?",
                        (session_id,),
                    ).fetchone()
                    if not row:
                        raise SessionNotFoundError(
                            f"Session not found: {session_id!r}"
                        )

                    # CASCADE delete handles tokens
                    deleted = conn.execute(
                        "SELECT COUNT(*) FROM redaction_tokens WHERE session_id = ?",
                        (session_id,),
                    ).fetchone()[0]

                    conn.execute(
                        "DELETE FROM redaction_sessions WHERE session_id = ?",
                        (session_id,),
                    )
                    conn.commit()

                self._write_json_backup()
                logger.info("Deleted session %s (%d tokens)", session_id, deleted)
                return deleted

            except SessionNotFoundError:
                raise
            except sqlite3.Error as exc:
                raise StateManagerError(f"Failed to delete session: {exc}") from exc

    def purge_all(self) -> None:
        """
        Delete ALL sessions and tokens from the vault.
        WARNING: This operation is irreversible.
        """
        with self._lock:
            try:
                with self._connect() as conn:
                    conn.execute("DELETE FROM redaction_tokens")
                    conn.execute("DELETE FROM redaction_sessions")
                    conn.commit()
                self._write_json_backup()
                logger.warning("Vault purged — all sessions deleted.")
            except sqlite3.Error as exc:
                raise StateManagerError(f"Failed to purge vault: {exc}") from exc

    # ── Read operations ──────────────────────────────────────────────────

    def get_original(
        self,
        token:      str,
        session_id: str | None = None,
    ) -> str | None:
        """
        Look up the original value for a single token.

        Parameters
        ----------
        token      : str       — The PII token, e.g. "[PII_EMAIL_3F2A1B0C]".
        session_id : str | None — Scope lookup to a specific session.

        Returns
        -------
        str | None — The original value, or None if not found.
        """
        try:
            with self._connect() as conn:
                if session_id:
                    row = conn.execute(
                        "SELECT original FROM redaction_tokens WHERE token = ? AND session_id = ?",
                        (token, session_id),
                    ).fetchone()
                else:
                    # Return the most recent entry across all sessions
                    row = conn.execute(
                        """
                        SELECT rt.original FROM redaction_tokens rt
                        JOIN redaction_sessions rs ON rt.session_id = rs.session_id
                        WHERE rt.token = ?
                        ORDER BY rs.created_at DESC LIMIT 1
                        """,
                        (token,),
                    ).fetchone()
                return row["original"] if row else None
        except sqlite3.Error as exc:
            logger.error("SQLite read error: %s", exc)
            return None

    def load_all(self, session_id: str | None = None) -> dict[str, str]:
        """
        Load the complete redaction map from the vault.

        Parameters
        ----------
        session_id : str | None
            If provided, only tokens from this session are returned.
            If None, the most recent session's tokens are returned.

        Returns
        -------
        dict[str, str] — token → original value mapping.

        Raises
        ------
        StateManagerError    — On database failure.
        SessionNotFoundError — If session_id is given but not found.
        """
        try:
            with self._connect() as conn:
                if session_id:
                    # Verify session exists
                    row = conn.execute(
                        "SELECT session_id FROM redaction_sessions WHERE session_id = ?",
                        (session_id,),
                    ).fetchone()
                    if not row:
                        raise SessionNotFoundError(
                            f"Session not found: {session_id!r}"
                        )
                    rows = conn.execute(
                        "SELECT token, original FROM redaction_tokens WHERE session_id = ?",
                        (session_id,),
                    ).fetchall()
                else:
                    # Most recent session
                    latest = conn.execute(
                        "SELECT session_id FROM redaction_sessions ORDER BY created_at DESC LIMIT 1"
                    ).fetchone()
                    if not latest:
                        return {}
                    rows = conn.execute(
                        "SELECT token, original FROM redaction_tokens WHERE session_id = ?",
                        (latest["session_id"],),
                    ).fetchall()

                return {row["token"]: row["original"] for row in rows}

        except SessionNotFoundError:
            raise
        except sqlite3.Error as exc:
            raise StateManagerError(f"Failed to load vault: {exc}") from exc

    def list_sessions(self) -> list[dict[str, Any]]:
        """
        Return metadata for all stored sessions, newest first.

        Returns
        -------
        list of dicts with keys: session_id, created_at, language, token_count, metadata.
        """
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    """
                    SELECT session_id, created_at, language, token_count, metadata
                    FROM redaction_sessions
                    ORDER BY created_at DESC
                    """
                ).fetchall()
                return [
                    {
                        "session_id":  row["session_id"],
                        "created_at":  row["created_at"],
                        "language":    row["language"],
                        "token_count": row["token_count"],
                        "metadata":    json.loads(row["metadata"]),
                    }
                    for row in rows
                ]
        except sqlite3.Error as exc:
            raise StateManagerError(f"Failed to list sessions: {exc}") from exc

    def get_session_count(self) -> int:
        """Return the total number of stored sessions."""
        with self._connect() as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM redaction_sessions"
            ).fetchone()[0]

    def get_token_count(self) -> int:
        """Return the total number of stored tokens across all sessions."""
        with self._connect() as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM redaction_tokens"
            ).fetchone()[0]

    # ── Internal helpers ─────────────────────────────────────────────────

    def _prune_sessions(self) -> None:
        """Remove oldest sessions if max_sessions is exceeded."""
        try:
            with self._connect() as conn:
                count = conn.execute(
                    "SELECT COUNT(*) FROM redaction_sessions"
                ).fetchone()[0]

                if count > self._max_sessions:
                    excess = count - self._max_sessions
                    conn.execute(
                        """
                        DELETE FROM redaction_sessions WHERE session_id IN (
                            SELECT session_id FROM redaction_sessions
                            ORDER BY created_at ASC LIMIT ?
                        )
                        """,
                        (excess,),
                    )
                    conn.commit()
                    logger.info("Pruned %d old session(s).", excess)
        except sqlite3.Error as exc:
            logger.warning("Session pruning failed: %s", exc)

    def _write_json_backup(self) -> None:
        """
        Overwrite the JSON backup file with the current vault contents.
        Uses atomic rename to prevent partial writes.
        """
        try:
            with self._connect() as conn:
                sessions = conn.execute(
                    "SELECT * FROM redaction_sessions ORDER BY created_at DESC"
                ).fetchall()

                data: dict[str, Any] = {
                    "_schema_version": _SCHEMA_VERSION,
                    "_written_at":     _utcnow(),
                    "sessions":        {},
                }

                for session in sessions:
                    sid = session["session_id"]
                    tokens_rows = conn.execute(
                        "SELECT token, original, category FROM redaction_tokens WHERE session_id = ?",
                        (sid,),
                    ).fetchall()
                    data["sessions"][sid] = {
                        "created_at":  session["created_at"],
                        "language":    session["language"],
                        "token_count": session["token_count"],
                        "metadata":    json.loads(session["metadata"]),
                        "tokens":      {r["token"]: r["original"] for r in tokens_rows},
                    }

            # Atomic write via temp file
            tmp_path = self._json_path.with_suffix(".tmp")
            tmp_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            tmp_path.replace(self._json_path)
            logger.debug("JSON backup written: %s", self._json_path)

        except Exception as exc:
            logger.warning("JSON backup write failed: %s", exc)

    def restore_from_json_backup(self) -> int:
        """
        Restore the vault from the JSON backup file.
        Returns the number of tokens restored.
        Useful for disaster recovery when the SQLite file is corrupted.
        """
        if not self._json_path.exists():
            raise StateManagerError(f"JSON backup not found: {self._json_path}")

        try:
            data = json.loads(self._json_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise VaultCorruptionError(f"JSON backup is malformed: {exc}") from exc

        total = 0
        for session_id, session_data in data.get("sessions", {}).items():
            tokens: dict[str, str] = session_data.get("tokens", {})
            if tokens:
                self.save(
                    redaction_map=tokens,
                    language=session_data.get("language", "unknown"),
                    session_id=session_id,
                    metadata=session_data.get("metadata"),
                )
                total += len(tokens)

        logger.info("Restored %d token(s) from JSON backup.", total)
        return total


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _utcnow() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _parse_token(token: str) -> tuple[str, str]:
    """
    Extract (category, hash_hex) from a token string.
    Returns ("UNKNOWN", "") on malformed input.
    """
    import re
    m = re.match(r"\[PII_([A-Z0-9_]+)_([0-9A-F]{8})\]", token, re.IGNORECASE)
    if m:
        return m.group(1).upper(), m.group(2).upper()
    return "UNKNOWN", ""


# ---------------------------------------------------------------------------
# Module-level singleton factory
# ---------------------------------------------------------------------------

_default_manager: StateManager | None = None
_manager_lock = threading.Lock()


def get_state_manager(
    db_path:   Path = _DEFAULT_DB_PATH,
    json_path: Path = _DEFAULT_JSON_PATH,
) -> StateManager:
    """
    Return (and cache) the default StateManager singleton.
    Thread-safe via a module-level lock.

    Usage:
        from local_bridge.core.state_manager import get_state_manager
        sm = get_state_manager()
        session = sm.save(redaction_map)
    """
    global _default_manager
    if _default_manager is None:
        with _manager_lock:
            if _default_manager is None:
                _default_manager = StateManager(
                    db_path=db_path,
                    json_path=json_path,
                )
    return _default_manager