/**
 * scanner.cpp — Oxbuild Compliance Agent | Phase 0: Local PII Pre-Processor
 *
 * C++17 std::regex engine exposed via pybind11.
 * Detects: Emails, API Keys (generic bearer/secret patterns), IPv4 addresses.
 * Replaces each unique match with a deterministic [PII_HASH_<N>] token.
 * Returns: (sanitized_code: str, redaction_map: dict[str, str])
 *
 * Build: see CMakeLists.txt
 * Standards: C++17 | pybind11 v2.11+
 */

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <regex>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace py = pybind11;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Deterministic 32-bit FNV-1a hash of a string.
 * Used to produce stable, reproducible token suffixes across runs.
 */
static std::uint32_t fnv1a_32(const std::string& s) noexcept {
    constexpr std::uint32_t FNV_PRIME    = 0x01000193u;
    constexpr std::uint32_t FNV_OFFSET   = 0x811c9dc5u;
    std::uint32_t hash = FNV_OFFSET;
    for (unsigned char c : s) {
        hash ^= static_cast<std::uint32_t>(c);
        hash *= FNV_PRIME;
    }
    return hash;
}

/** Format a uint32 as an 8-char uppercase hex string. */
static std::string to_hex8(std::uint32_t v) {
    static constexpr char HEX[] = "0123456789ABCDEF";
    std::string out(8, '0');
    for (int i = 7; i >= 0; --i) {
        out[static_cast<std::size_t>(i)] = HEX[v & 0xFu];
        v >>= 4;
    }
    return out;
}

// ---------------------------------------------------------------------------
// Redaction rule descriptor
// ---------------------------------------------------------------------------

struct RedactionRule {
    std::string  label;    // Human-readable category name used in the token
    std::regex   pattern;  // Compiled regex
};

// ---------------------------------------------------------------------------
// Build the ordered list of redaction rules.
// Rules are applied in order; each match is only replaced once.
// ---------------------------------------------------------------------------

static std::vector<RedactionRule> build_rules() {
    // All patterns use ECMAScript syntax (default for std::regex).
    // Compiled once at module load via static initialisation.

    return {
        // --- Emails ---------------------------------------------------
        // RFC-5321 simplified: local@domain.tld
        {
            "EMAIL",
            std::regex(
                R"([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})",
                std::regex::ECMAScript | std::regex::optimize
            )
        },

        // --- API / Secret keys ----------------------------------------
        // Generic bearer tokens: "Bearer <token>" or standalone 20-64 char
        // hex/base64 strings that look like secrets.
        // Pattern 1: Authorization header values
        {
            "API_KEY",
            std::regex(
                R"((?:Bearer|Token|Authorization:\s*(?:Bearer|Token))\s+([A-Za-z0-9\-_\.]{20,256}))",
                std::regex::ECMAScript | std::regex::optimize
            )
        },
        // Pattern 2: Common SDK / env-var style key assignments
        //   api_key = "sk-..."  |  SECRET_KEY = "abc123..."
        {
            "API_KEY",
            std::regex(
                R"((?:api[_\-]?key|secret[_\-]?key|auth[_\-]?token|access[_\-]?token|private[_\-]?key)\s*[=:]\s*["']([A-Za-z0-9\-_\.\/+]{16,256})["'])",
                std::regex::ECMAScript | std::regex::icase | std::regex::optimize
            )
        },
        // Pattern 3: OpenAI / Anthropic / AWS style prefixed keys
        {
            "API_KEY",
            std::regex(
                R"(\b(?:sk-[A-Za-z0-9]{32,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{35}|gh[pousr]_[A-Za-z0-9]{36,})\b)",
                std::regex::ECMAScript | std::regex::optimize
            )
        },

        // --- IPv4 addresses -------------------------------------------
        // Strict octet validation (0-255)
        {
            "IPV4",
            std::regex(
                R"(\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])\b)",
                std::regex::ECMAScript | std::regex::optimize
            )
        },

        // --- Phone numbers (E.164 / common formats) -------------------
        {
            "PHONE",
            std::regex(
                R"(\b(?:\+?1[\s\-\.]?)?\(?\d{3}\)?[\s\-\.]?\d{3}[\s\-\.]?\d{4}\b)",
                std::regex::ECMAScript | std::regex::optimize
            )
        },

        // --- AWS-style ARNs ------------------------------------------
        {
            "AWS_ARN",
            std::regex(
                R"(arn:[a-z0-9\-]+:[a-z0-9\-]+:[a-z0-9\-]*:[0-9]{12}:[^\s"']+)",
                std::regex::ECMAScript | std::regex::optimize
            )
        },
    };
}

// ---------------------------------------------------------------------------
// Core scan function
// ---------------------------------------------------------------------------

/**
 * scan_code(source: str) -> tuple[str, dict[str, str]]
 *
 * @param source  Raw source code string (UTF-8).
 * @returns A pair:
 *   .first  — Sanitized source with all PII replaced by [PII_<LABEL>_<HASH>] tokens.
 *   .second — Redaction map: token -> original value.
 */
static std::pair<std::string, std::map<std::string, std::string>>
scan_code(const std::string& source) {

    static const std::vector<RedactionRule> RULES = build_rules();

    std::string                        result = source;
    std::map<std::string, std::string> redaction_map;

    for (const auto& rule : RULES) {
        std::string   processed;
        processed.reserve(result.size());

        auto it    = std::sregex_iterator(result.cbegin(), result.cend(), rule.pattern);
        auto end   = std::sregex_iterator{};
        auto pos   = result.cbegin();

        for (; it != end; ++it) {
            const std::smatch& match = *it;

            // The "value" to redact is group 1 if captured, otherwise group 0.
            std::string original = (match.size() > 1 && match[1].length() > 0)
                                       ? match[1].str()
                                       : match[0].str();

            // Build deterministic token
            std::uint32_t hash  = fnv1a_32(original);
            std::string   token = "[PII_" + rule.label + "_" + to_hex8(hash) + "]";

            // Copy everything up to the full match start
            processed.append(pos, match[0].first);

            if (match.size() > 1 && match[1].length() > 0) {
                // Replace only the captured group, keep surrounding text intact
                processed.append(match.prefix().first, match[1].first);  // before group
                processed.append(token);
                // After the group, up to end of full match — append the suffix
                std::string suffix(match[1].second, match[0].second);
                processed.append(suffix);
            } else {
                processed.append(token);
            }

            pos = match[0].second;

            // Register in map (first occurrence wins; stable across repeated runs)
            redaction_map.emplace(token, original);
        }

        // Append the remainder of the string after the last match
        processed.append(pos, result.cend());
        result = std::move(processed);
    }

    return {result, redaction_map};
}

// ---------------------------------------------------------------------------
// Additional utility: restore_code — reverses redaction using the map
// ---------------------------------------------------------------------------

static std::string
restore_code(const std::string& sanitized,
             const std::map<std::string, std::string>& redaction_map) {
    std::string result = sanitized;
    for (const auto& [token, original] : redaction_map) {
        std::string::size_type pos = 0;
        while ((pos = result.find(token, pos)) != std::string::npos) {
            result.replace(pos, token.length(), original);
            pos += original.length();
        }
    }
    return result;
}

// ---------------------------------------------------------------------------
// pybind11 module definition — compiled module name: _oxscanner
// ---------------------------------------------------------------------------

PYBIND11_MODULE(_oxscanner, m) {
    m.doc() = R"pbdoc(
        _oxscanner — Oxbuild Compliance Agent | Phase 0 PII Pre-Processor
        ------------------------------------------------------------------
        High-speed C++17 regex engine for sanitizing source code before
        transmission to cloud LLM auditors.

        Functions
        ---------
        scan_code(source: str) -> tuple[str, dict[str, str]]
            Redacts PII (emails, API keys, IPv4, phones, ARNs) and returns
            a (sanitized_source, redaction_map) tuple.

        restore_code(sanitized: str, redaction_map: dict[str, str]) -> str
            Reverses redaction by re-inserting original values.
    )pbdoc";

    m.def(
        "scan_code",
        &scan_code,
        py::arg("source"),
        R"pbdoc(
            Scan and sanitize source code.

            Parameters
            ----------
            source : str
                Raw source code (any language).

            Returns
            -------
            tuple[str, dict[str, str]]
                (sanitized_code, {token: original_value})
        )pbdoc"
    );

    m.def(
        "restore_code",
        &restore_code,
        py::arg("sanitized"),
        py::arg("redaction_map"),
        R"pbdoc(
            Restore original values in a sanitized string.

            Parameters
            ----------
            sanitized    : str
            redaction_map: dict[str, str]

            Returns
            -------
            str  — Source with all tokens replaced by originals.
        )pbdoc"
    );

    // Module-level metadata
    m.attr("__version__") = "1.0.0";
    m.attr("__author__")  = "Oxbuild Compliance Agent";
}