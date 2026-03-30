"""
scanner_wrapper.py — Oxbuild Compliance Agent | Phase 0 Python Interface
=========================================================================
Thin, type-safe Python wrapper around the compiled C++ pybind11 module
``_oxscanner``.  Adds runtime fallback, structured results, logging, and
batch-processing utilities.

Build the native module first:
    cd local_bridge/core
    cmake -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build --target install_module

Then import this module:
    from local_bridge.core.scanner_wrapper import OxScanner, ScanResult
"""

from __future__ import annotations

import importlib
import logging
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger: logging.Logger = logging.getLogger("oxbuild.scanner")

# ---------------------------------------------------------------------------
# Native extension loader
# ---------------------------------------------------------------------------
# The compiled .so / .pyd lives in the same directory as this file.
_MODULE_DIR: Final[Path] = Path(__file__).parent.resolve()

def _load_native_module():  # type: ignore[return]
    """
    Attempt to import the compiled _oxscanner extension.
    Adds the build directory to sys.path if necessary so that the module
    can be found after a cmake build without a full install.
    """
    # 1. Already importable?
    try:
        import _oxscanner  # type: ignore[import]
        return _oxscanner
    except ModuleNotFoundError:
        pass

    # 2. Look for the .so / .pyd next to this file
    for pattern in ("_oxscanner*.so", "_oxscanner*.pyd"):
        matches = list(_MODULE_DIR.glob(pattern))
        if matches:
            if str(_MODULE_DIR) not in sys.path:
                sys.path.insert(0, str(_MODULE_DIR))
            try:
                return importlib.import_module("_oxscanner")
            except ModuleNotFoundError:
                pass

    # 3. Check build/ subdirectory (cmake default)
    build_dir = _MODULE_DIR / "build"
    if build_dir.exists():
        for pattern in ("_oxscanner*.so", "_oxscanner*.pyd"):
            matches = list(build_dir.rglob(pattern))
            if matches:
                ext_dir = matches[0].parent
                if str(ext_dir) not in sys.path:
                    sys.path.insert(0, str(ext_dir))
                try:
                    return importlib.import_module("_oxscanner")
                except ModuleNotFoundError:
                    pass

    raise ImportError(
        "\n\nCould not load the '_oxscanner' native extension.\n"
        "Build it with:\n"
        "    cd local_bridge/core\n"
        "    cmake -B build -DCMAKE_BUILD_TYPE=Release\n"
        "    cmake --build build --target install_module\n"
    )


_native: object = _load_native_module()

# ---------------------------------------------------------------------------
# Public data models
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class PiiMatch:
    """Represents a single redacted PII value."""
    token:    str   # e.g. "[PII_EMAIL_3F2A1B0C]"
    original: str   # e.g. "alice@example.com"
    category: str   # e.g. "EMAIL"

    @classmethod
    def from_token(cls, token: str, original: str) -> "PiiMatch":
        # Token format: [PII_<CATEGORY>_<HASH>]
        parts = token.strip("[]").split("_")
        # parts = ["PII", "EMAIL", "3F2A1B0C"]  or ["PII", "API", "KEY", ...]
        if len(parts) >= 3:
            # Join everything between PII and the trailing HASH as the category
            category = "_".join(parts[1:-1])
        else:
            category = "UNKNOWN"
        return cls(token=token, original=original, category=category)


@dataclass(slots=True)
class ScanResult:
    """
    Structured result of a Phase 0 scan operation.

    Attributes
    ----------
    sanitized_code : str
        Source code with all PII replaced by opaque tokens.
    redaction_map  : dict[str, str]
        Maps each token to its original value.
    matches        : list[PiiMatch]
        Structured PII match objects (derived from redaction_map).
    elapsed_ms     : float
        Wall-clock time of the C++ scan in milliseconds.
    original_length : int
        Character length of the input.
    sanitized_length: int
        Character length of the sanitized output.
    """
    sanitized_code:   str
    redaction_map:    dict[str, str]
    matches:          list[PiiMatch] = field(default_factory=list)
    elapsed_ms:       float = 0.0
    original_length:  int   = 0
    sanitized_length: int   = 0

    @property
    def pii_count(self) -> int:
        """Number of unique PII values detected."""
        return len(self.matches)

    @property
    def categories(self) -> list[str]:
        """Sorted list of unique PII categories found."""
        return sorted({m.category for m in self.matches})

    def summary(self) -> str:
        """Human-readable one-line scan summary."""
        return (
            f"Scan complete in {self.elapsed_ms:.2f} ms — "
            f"{self.pii_count} PII token(s) found "
            f"({', '.join(self.categories) or 'none'}) | "
            f"{self.original_length} → {self.sanitized_length} chars"
        )


# ---------------------------------------------------------------------------
# Main wrapper class
# ---------------------------------------------------------------------------

class OxScanner:
    """
    High-level Python interface for the Oxbuild C++ PII scanner.

    Usage
    -----
    >>> scanner = OxScanner()
    >>> result = scanner.scan("Contact us at admin@example.com or 192.168.1.1")
    >>> result.pii_count
    2
    >>> all(m.token in result.sanitized_code for m in result.matches)
    True
    >>> "admin@example.com" not in result.sanitized_code
    True

    Restore original values:
    >>> restored = scanner.restore(result.sanitized_code, result.redaction_map)
    >>> restored == "Contact us at admin@example.com or 192.168.1.1"
    True
    """

    def __init__(self, log_level: int = logging.INFO) -> None:
        logger.setLevel(log_level)
        logger.debug("OxScanner initialised — native module: %s", _native.__file__)  # type: ignore[attr-defined]

    # ------------------------------------------------------------------
    # Primary interface
    # ------------------------------------------------------------------

    def scan(self, source: str) -> ScanResult:
        """
        Sanitize source code, replacing all detected PII with opaque tokens.

        Parameters
        ----------
        source : str
            Raw source code (any language / encoding).

        Returns
        -------
        ScanResult
            Structured result containing sanitized code, redaction map,
            PII matches, and performance metadata.

        Raises
        ------
        TypeError
            If ``source`` is not a ``str``.
        RuntimeError
            If the underlying C++ call raises an unexpected exception.
        """
        if not isinstance(source, str):
            raise TypeError(f"source must be str, got {type(source).__name__!r}")

        original_length: int = len(source)
        t0 = time.perf_counter()

        try:
            sanitized_code, redaction_map = _native.scan_code(source)  # type: ignore[attr-defined]
        except Exception as exc:
            logger.error("C++ scan_code raised: %s", exc)
            raise RuntimeError(f"Native scanner error: {exc}") from exc

        elapsed_ms: float = (time.perf_counter() - t0) * 1_000

        matches: list[PiiMatch] = [
            PiiMatch.from_token(token, original)
            for token, original in redaction_map.items()
        ]

        result = ScanResult(
            sanitized_code=sanitized_code,
            redaction_map=dict(redaction_map),
            matches=matches,
            elapsed_ms=elapsed_ms,
            original_length=original_length,
            sanitized_length=len(sanitized_code),
        )

        logger.info(result.summary())
        return result

    def restore(
        self,
        sanitized: str,
        redaction_map: dict[str, str],
    ) -> str:
        """
        Reverse a previous sanitization using the stored redaction map.

        Parameters
        ----------
        sanitized     : str  — Sanitized code string.
        redaction_map : dict — Token → original value mapping.

        Returns
        -------
        str — Source with PII values restored.
        """
        if not isinstance(sanitized, str):
            raise TypeError(f"sanitized must be str, got {type(sanitized).__name__!r}")
        if not isinstance(redaction_map, dict):
            raise TypeError("redaction_map must be a dict")

        return _native.restore_code(sanitized, redaction_map)  # type: ignore[attr-defined]

    # ------------------------------------------------------------------
    # Batch processing
    # ------------------------------------------------------------------

    def scan_batch(self, sources: list[str]) -> list[ScanResult]:
        """
        Scan a list of source strings and return a result per item.

        Parameters
        ----------
        sources : list[str]

        Returns
        -------
        list[ScanResult]
        """
        if not isinstance(sources, list):
            raise TypeError("sources must be a list of str")
        return [self.scan(s) for s in sources]

    # ------------------------------------------------------------------
    # Utility / introspection
    # ------------------------------------------------------------------

    @staticmethod
    def native_version() -> str:
        """Return the version of the loaded native _oxscanner module."""
        return str(getattr(_native, "__version__", "unknown"))

    def __repr__(self) -> str:
        return f"OxScanner(native_module={self.native_version()!r})"


# ---------------------------------------------------------------------------
# Module-level convenience instance
# ---------------------------------------------------------------------------
_default_scanner: OxScanner | None = None


def scan(source: str) -> ScanResult:
    """
    Module-level convenience function — uses a cached OxScanner instance.

    >>> result = scan("key = 'AKIAIOSFODNN7EXAMPLE'")
    >>> result.pii_count >= 1
    True
    """
    global _default_scanner
    if _default_scanner is None:
        _default_scanner = OxScanner()
    return _default_scanner.scan(source)


# ---------------------------------------------------------------------------
# CLI entry-point for quick testing
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse
    import json

    ap = argparse.ArgumentParser(description="Oxbuild PII Scanner — CLI")
    ap.add_argument("--code", "-c", type=str, help="Code string to scan")
    ap.add_argument("--file", "-f", type=str, help="Path to source file")
    ap.add_argument("--json",  action="store_true", help="Output JSON")
    args = ap.parse_args()

    if args.file:
        raw = Path(args.file).read_text(encoding="utf-8")
    elif args.code:
        raw = args.code
    else:
        raw = sys.stdin.read()

    scanner = OxScanner(log_level=logging.DEBUG)
    result  = scanner.scan(raw)

    if args.json:
        payload = {
            "sanitized_code":   result.sanitized_code,
            "redaction_map":    result.redaction_map,
            "pii_count":        result.pii_count,
            "categories":       result.categories,
            "elapsed_ms":       round(result.elapsed_ms, 3),
            "original_length":  result.original_length,
            "sanitized_length": result.sanitized_length,
        }
        print(json.dumps(payload, indent=2))
    else:
        print("─" * 60)
        print(result.summary())
        print("─" * 60)
        print("\nSanitized Code:\n")
        print(result.sanitized_code)
        if result.matches:
            print("\nRedaction Map:")
            for m in result.matches:
                print(f"  [{m.category}] {m.token} → {m.original!r}")