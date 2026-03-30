"""
local_bridge/core/reconstructor.py
====================================
Reconstructs the final, de-anonymised code by replacing PII tokens
(e.g. ``[PII_EMAIL_3F2A1B0C]``) back to their original values using the
redaction map stored in the local StateManager vault.

Design goals
------------
• ROBUST:  Handles partial matches, overlapping tokens, malformed tokens,
           and missing vault entries gracefully — never silently corrupts code.
• AUDITABLE: Every substitution is logged; unresolvable tokens are reported
             rather than silently left in place.
• IDEMPOTENT: Running reconstruct() twice on already-restored code is safe
              (no double-substitution possible since restored values are not
              in token format).
• ZERO-TRUST: The reconstructor never contacts external services. All data
              comes from the local StateManager.

Token format expected:
    [PII_<CATEGORY>_<HASH8>]
    e.g. [PII_EMAIL_3F2A1B0C]
         [PII_API_KEY_7E8F9A0B]
         [PII_IPV4_A1B2C3D4]
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Callable

from local_bridge.core.state_manager import StateManager, StateManagerError

logger = logging.getLogger("oxbuild.reconstructor")

# ---------------------------------------------------------------------------
# Compiled token pattern — matches any valid [PII_*_*] token
# ---------------------------------------------------------------------------

_TOKEN_PATTERN: re.Pattern[str] = re.compile(
    r"\[PII_([A-Z0-9_]+)_([0-9A-F]{8})\]",
    re.IGNORECASE,
)

# Token format constant (must match scanner.cpp)
_TOKEN_FORMAT = "[PII_{category}_{hash}]"


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SubstitutionRecord:
    """Audit record for a single token → original substitution."""
    token:       str
    original:    str
    category:    str
    hash_hex:    str
    occurrences: int     # how many times this token appeared in the code


@dataclass
class ReconstructionResult:
    """
    Full result of a reconstruction operation.

    Attributes
    ----------
    restored_code      : str   — Final code with all resolved tokens replaced.
    substitutions      : list  — One record per unique resolved token.
    unresolved_tokens  : list  — Tokens found in code but absent from the vault.
    partial_tokens     : list  — Malformed token-like strings that could not be parsed.
    substitution_count : int   — Total number of individual replacements made.
    is_complete        : bool  — True if every token was resolved (no unresolved).
    """
    restored_code:      str
    substitutions:      list[SubstitutionRecord] = field(default_factory=list)
    unresolved_tokens:  list[str]                = field(default_factory=list)
    partial_tokens:     list[str]                = field(default_factory=list)
    substitution_count: int                      = 0
    is_complete:        bool                     = True

    @property
    def resolved_count(self) -> int:
        return len(self.substitutions)

    @property
    def unresolved_count(self) -> int:
        return len(self.unresolved_tokens)

    def summary(self) -> str:
        status = "COMPLETE" if self.is_complete else f"PARTIAL ({self.unresolved_count} unresolved)"
        return (
            f"Reconstruction {status} — "
            f"{self.resolved_count} unique tokens resolved, "
            f"{self.substitution_count} total substitutions, "
            f"{self.unresolved_count} unresolved."
        )


# ---------------------------------------------------------------------------
# Main reconstructor class
# ---------------------------------------------------------------------------

class Reconstructor:
    """
    Reverses PII redaction by replacing tokens with original values.

    Parameters
    ----------
    state_manager : StateManager
        Provides access to the local token → original value vault.
    on_unresolved : Callable[[str], str] | None
        Optional callback invoked when a token cannot be resolved.
        Receives the token string; its return value replaces the token.
        If None, unresolved tokens are left in place and logged as warnings.
    """

    def __init__(
        self,
        state_manager:  StateManager,
        on_unresolved:  Callable[[str], str] | None = None,
    ) -> None:
        self._sm           = state_manager
        self._on_unresolved = on_unresolved or self._default_unresolved_handler

    # ── Public interface ─────────────────────────────────────────────────

    def reconstruct(
        self,
        sanitized_code: str,
        session_id:     str | None = None,
        strict:         bool = False,
    ) -> ReconstructionResult:
        """
        Replace all PII tokens in ``sanitized_code`` with their originals.

        Parameters
        ----------
        sanitized_code : str
            Code containing ``[PII_*_*]`` tokens.
        session_id     : str | None
            If provided, only tokens from this specific scan session are
            resolved. Useful when multiple sessions exist in the vault.
        strict         : bool
            If True, raise ``ReconstructionError`` on any unresolved token
            instead of leaving it in place.

        Returns
        -------
        ReconstructionResult

        Raises
        ------
        ReconstructionError
            If ``strict=True`` and any token cannot be resolved.
        TypeError
            If ``sanitized_code`` is not a string.
        """
        if not isinstance(sanitized_code, str):
            raise TypeError(
                f"sanitized_code must be str, got {type(sanitized_code).__name__!r}"
            )

        # Phase 1: Find all tokens in the code
        found_tokens = self._extract_tokens(sanitized_code)
        logger.debug("Found %d unique token(s) in code.", len(found_tokens))

        if not found_tokens:
            logger.info("No PII tokens found — code is already fully restored.")
            return ReconstructionResult(
                restored_code=sanitized_code,
                is_complete=True,
            )

        # Phase 2: Load the vault (full or session-scoped)
        try:
            vault: dict[str, str] = self._sm.load_all(session_id=session_id)
        except StateManagerError as exc:
            logger.error("StateManager load failed: %s", exc)
            raise ReconstructionError(
                f"Cannot load redaction vault: {exc}"
            ) from exc

        # Phase 3: Build substitution plan
        plan:            dict[str, str]          = {}  # token → original
        substitutions:   list[SubstitutionRecord] = []
        unresolved:      list[str]               = []
        partial_tokens:  list[str]               = []

        for token_info in found_tokens:
            token = token_info["token"]

            # Try vault lookup
            original = self._resolve_token(token, vault)

            if original is not None:
                plan[token] = original
                substitutions.append(SubstitutionRecord(
                    token       = token,
                    original    = original,
                    category    = token_info["category"],
                    hash_hex    = token_info["hash_hex"],
                    occurrences = token_info["occurrences"],
                ))
            else:
                # Token not in vault — apply fallback
                fallback = self._on_unresolved(token)
                plan[token] = fallback

                if fallback == token:
                    # Token left in place — it's unresolved
                    unresolved.append(token)
                    logger.warning(
                        "Unresolved token: %s (no matching vault entry). "
                        "Token left in place.",
                        token,
                    )
                else:
                    logger.info(
                        "Token %s replaced by fallback handler: %r",
                        token, fallback,
                    )

        # Phase 4: Apply all substitutions in one pass
        # Sort by token length descending to avoid partial substring collisions
        sorted_tokens = sorted(plan.keys(), key=len, reverse=True)
        restored = sanitized_code
        total_subs = 0

        for token in sorted_tokens:
            replacement = plan[token]
            count = restored.count(token)
            if count > 0:
                restored = restored.replace(token, replacement)
                total_subs += count
                logger.debug("Replaced %dx: %s → %r", count, token, replacement[:40])

        # Phase 5: Second-pass scan for any partial/malformed token remnants
        partial_tokens = self._find_partial_tokens(restored)
        if partial_tokens:
            logger.warning(
                "%d partial/malformed token-like strings remain: %s",
                len(partial_tokens), partial_tokens[:5],
            )

        is_complete = len(unresolved) == 0 and len(partial_tokens) == 0
        result = ReconstructionResult(
            restored_code      = restored,
            substitutions      = substitutions,
            unresolved_tokens  = unresolved,
            partial_tokens     = partial_tokens,
            substitution_count = total_subs,
            is_complete        = is_complete,
        )

        logger.info(result.summary())

        if strict and not is_complete:
            raise ReconstructionError(
                f"Strict reconstruction failed: {result.unresolved_count} unresolved token(s). "
                f"Unresolved: {unresolved}"
            )

        return result

    def reconstruct_from_map(
        self,
        sanitized_code: str,
        redaction_map:  dict[str, str],
        strict:         bool = False,
    ) -> ReconstructionResult:
        """
        Reconstruct using an explicitly provided redaction map instead of
        loading from the StateManager vault.

        Useful when the caller already has the map in memory (e.g. from
        the C++ scanner's return value) and doesn't need vault persistence.

        Parameters
        ----------
        sanitized_code : str
        redaction_map  : dict[str, str]  — token → original mapping.
        strict         : bool
        """
        if not isinstance(redaction_map, dict):
            raise TypeError("redaction_map must be a dict")

        found_tokens    = self._extract_tokens(sanitized_code)
        plan:           dict[str, str]          = {}
        substitutions:  list[SubstitutionRecord] = []
        unresolved:     list[str]               = []

        for token_info in found_tokens:
            token    = token_info["token"]
            original = redaction_map.get(token)

            if original is not None:
                plan[token] = original
                substitutions.append(SubstitutionRecord(
                    token       = token,
                    original    = original,
                    category    = token_info["category"],
                    hash_hex    = token_info["hash_hex"],
                    occurrences = token_info["occurrences"],
                ))
            else:
                fallback = self._on_unresolved(token)
                plan[token] = fallback
                if fallback == token:
                    unresolved.append(token)

        sorted_tokens = sorted(plan.keys(), key=len, reverse=True)
        restored = sanitized_code
        total_subs = 0
        for token in sorted_tokens:
            count = restored.count(token)
            restored = restored.replace(token, plan[token])
            total_subs += count

        partial_tokens = self._find_partial_tokens(restored)
        is_complete    = len(unresolved) == 0 and len(partial_tokens) == 0

        result = ReconstructionResult(
            restored_code      = restored,
            substitutions      = substitutions,
            unresolved_tokens  = unresolved,
            partial_tokens     = partial_tokens,
            substitution_count = total_subs,
            is_complete        = is_complete,
        )

        if strict and not is_complete:
            raise ReconstructionError(
                f"Strict reconstruction failed: {result.unresolved_count} unresolved token(s)."
            )

        return result

    # ── Private helpers ──────────────────────────────────────────────────

    def _extract_tokens(self, code: str) -> list[dict[str, str | int]]:
        """
        Find all well-formed PII tokens in code.
        Returns a list of dicts with 'token', 'category', 'hash_hex', 'occurrences'.
        Deduplicates by token string.
        """
        seen:   set[str]           = set()
        result: list[dict[str, str | int]] = []

        for match in _TOKEN_PATTERN.finditer(code):
            token    = match.group(0)
            category = match.group(1).upper()
            hash_hex = match.group(2).upper()

            if token not in seen:
                seen.add(token)
                result.append({
                    "token":       token,
                    "category":    category,
                    "hash_hex":    hash_hex,
                    "occurrences": code.count(token),
                })

        return result

    def _resolve_token(
        self,
        token: str,
        vault: dict[str, str],
    ) -> str | None:
        """
        Attempt multiple lookup strategies to find the original value:

        1. Exact key match (primary path).
        2. Case-insensitive key match (handles vault/code case drift).
        3. Hash-only match (token category may differ between scanner versions).
        """
        # Strategy 1: Exact match
        if token in vault:
            return vault[token]

        # Strategy 2: Case-insensitive
        token_lower = token.lower()
        for k, v in vault.items():
            if k.lower() == token_lower:
                logger.debug("Case-insensitive match: %s → %s", token, k)
                return v

        # Strategy 3: Hash-only — extract the 8-char hex and search all keys
        m = _TOKEN_PATTERN.match(token)
        if m:
            hash_hex = m.group(2).upper()
            for k, v in vault.items():
                km = _TOKEN_PATTERN.match(k)
                if km and km.group(2).upper() == hash_hex:
                    logger.debug(
                        "Hash-only match: %s matched vault key %s", token, k
                    )
                    return v

        return None

    def _find_partial_tokens(self, code: str) -> list[str]:
        """
        Detect malformed or partially-reconstructed token-like strings
        that survived substitution (e.g. "[PII_" without closing "]").
        These indicate corrupted vault entries or scanner version mismatches.
        """
        # Pattern for incomplete token prefix — not a full valid token
        partial_pattern = re.compile(r"\[PII_[A-Z0-9_]*(?!\])", re.IGNORECASE)
        partials = partial_pattern.findall(code)
        # Filter out any that are actually valid complete tokens
        return [p for p in partials if not _TOKEN_PATTERN.match(p + "]")]

    @staticmethod
    def _default_unresolved_handler(token: str) -> str:
        """
        Default behaviour for unresolved tokens: leave them in place.
        This is the safest option — better to have a visible [PII_*] marker
        than to silently substitute a wrong value.
        """
        return token  # return token unchanged


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------

class ReconstructionError(Exception):
    """Raised when strict reconstruction fails due to unresolved tokens."""


# ---------------------------------------------------------------------------
# Module-level convenience function
# ---------------------------------------------------------------------------

def reconstruct(
    sanitized_code: str,
    redaction_map:  dict[str, str],
    strict:         bool = False,
) -> ReconstructionResult:
    """
    Stateless convenience wrapper — reconstructs code using an explicit map.

    Does not require a StateManager instance. Suitable for one-shot usage
    when the redaction map is already available in memory.

    >>> result = reconstruct(
    ...     "[PII_EMAIL_3F2A1B0C] logged in",
    ...     {"[PII_EMAIL_3F2A1B0C]": "alice@example.com"},
    ... )
    >>> result.restored_code
    'alice@example.com logged in'
    >>> result.is_complete
    True
    """
    # Create a no-op StateManager (not used when map is explicit)
    class _NullStateManager:
        def load_all(self, session_id=None):
            return {}

    r = Reconstructor(state_manager=_NullStateManager())  # type: ignore[arg-type]
    return r.reconstruct_from_map(sanitized_code, redaction_map, strict=strict)