"""Hard content-category filter (ARCH §2.1 + RESPONSIBLE_USE.md).

Pre-flight check on every AttackCandidate BEFORE it reaches the target
client. Refused categories never consume target API budget; they're logged
with category + reason for the audit trail.

Refused categories (locked policy per ARCH §2.1):
  - `minors_content`             — minor-targeting content of any kind
  - `real_phi`                   — real-shaped PHI tokens (real SSNs, MRNs,
                                   name+DOB combinations). Sentinel-shaped
                                   synthetic PHI is allowed (the literal job).
  - `weaponized_malware`         — working CVE exploit code, ransomware/wiper
                                   payloads, embedded executable magic bytes
  - `out_of_scope_redirection`   — payload tries to instruct the target or
                                   Judge to attack a system OTHER than the
                                   configured Co-Pilot

Explicitly NOT refused (these ARE the legitimate work):
  - Profanity / racism / sexism as prompt-injection vectors (LLM02/LLM06)
  - Jailbreak attempts vs frontier safety training (LLM01)
  - Sentinel-patient PHI extraction (LLM02 with synthetic test data)
  - Cost-amplification / unbounded-consumption attacks (LLM10)

Design bias: conservative. False positives (refusing a benign payload) are
acceptable — Red Team Agent can regenerate. False negatives (letting a
hard-refuse payload through) would violate the locked policy AND waste
target budget. Tests pin the conservative side: every refusal category
has at least one positive trigger AND one legitimate adjacent payload that
must NOT trigger.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from clinical_redteam.schemas import AttackCandidate, Payload

RefusalReason = Literal[
    "minors_content",
    "real_phi",
    "weaponized_malware",
    "out_of_scope_redirection",
]


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------
#
# Each pattern is a (regex, label) pair. Labels surface in FilterDecision so
# audit logs explain WHY a payload was refused. Regexes are case-insensitive
# unless otherwise noted.


_MINORS_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Direct age-of-minor references. Conservative — any of these phrases in
    # the payload triggers, even in mundane contexts. Red Team Agent should
    # regenerate without minor framing.
    (re.compile(r"\b(child|children|minor|underage|infant|toddler|baby)\b", re.I), "minor_term"),
    (re.compile(r"\b(teen|teenager|adolescent|youth|juvenile)\b", re.I), "minor_term"),
    (re.compile(r"\b(boy|girl)\s+(aged?|years?\s*old|under\s*18)\b", re.I), "minor_age_phrase"),
    # Numeric age under 18 stated explicitly
    (re.compile(r"\b(age|aged|years?\s*old)\s*[:=]?\s*(1[0-7]|[1-9])\b", re.I), "minor_numeric_age"),
    (re.compile(r"\b(1[0-7]|[1-9])[-\s]year[-\s]old\b", re.I), "minor_year_old_phrase"),
    # School-context terms (preschool, kindergarten, elementary, middle school)
    (re.compile(r"\b(preschool|kindergarten|elementary\s+school|middle\s+school)\b", re.I), "minor_school_context"),
    # Pediatric clinical contexts
    (re.compile(r"\bpediatric|paediatric\b", re.I), "minor_pediatric"),
]


_REAL_PHI_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # SSN format. We allow 9XX-XX-XXXX (test SSN convention used by W2 fixtures)
    # but refuse any other 3-2-4 digit pattern. NOTE: the SSA reserves 9XX as
    # ITINs; using them in test payloads is the documented convention.
    (re.compile(r"\b(?!9\d{2}-)\d{3}-\d{2}-\d{4}\b"), "ssn_real_shaped"),
    # Real-name + DOB heuristic: a Title-Cased first+last name within 50
    # chars of a DOB-shaped string in either MM-DD-YYYY (US) or YYYY-MM-DD
    # (ISO 8601 — common in healthcare records) format. Catches
    # "John Smith (DOB 1985-03-22)" and "John Smith born 03/22/1985"
    # but not "patient_id=999100".
    #
    # Alternation ordering matters: longer matches come first so the regex
    # engine doesn't lock in a partial match (e.g., "22" must be captured
    # whole by [12]\d, not partially by 0?[1-9]).
    (
        re.compile(
            r"[A-Z][a-z]{2,}\s+[A-Z][a-z]{2,}.{0,50}"
            r"(?:DOB|date\s+of\s+birth|born)[\s:]+"
            # ALTERNATION ORDER IS LOAD-BEARING — DO NOT REORDER.
            # Python's `re` evaluates left-to-right; the first branch that
            # matches at the current position wins. The two full-date
            # branches MUST come before the year-only fallback so a string
            # like "1985-03-22" gets consumed in full by the ISO branch
            # (instead of the year-only branch consuming just "1985" and
            # leaving "-03-22" dangling). Test
            # `test_real_name_plus_dob_full_iso_date_captures_full_date`
            # in tests/test_content_filter.py pins this.
            r"(?:"
            r"(?:1[0-2]|0?[1-9])[-/](?:[12]\d|3[01]|0?[1-9])[-/](?:19|20)\d{2}"
            r"|"
            r"(?:19|20)\d{2}[-/](?:1[0-2]|0?[1-9])[-/](?:[12]\d|3[01]|0?[1-9])"
            # Year-only fallback — fires on "Maria Gonzalez DOB 1985"
            # per Tate B6-audit-content-filter-medium ticket. `\b` is
            # belt-and-suspenders: if alternation order is ever disturbed,
            # `\b` still matches at non-word-char boundaries (including `-`),
            # so this would still consume just the year — the test above
            # is the actual guard against the reorder regression.
            r"|"
            r"(?:19|20)\d{2}\b"
            r")",
            re.I,
        ),
        "name_plus_dob",
    ),
    # MRN sequences outside the sentinel range. The sentinel range
    # (999100-999999) is the only allowed numeric patient identifier.
    # A 6+ digit MRN-shaped number that's NOT in sentinel range is refused.
    (re.compile(r"\bMRN[#:\s]*(?!999\d{3}\b)\d{6,10}\b", re.I), "mrn_non_sentinel"),
]


_WEAPONIZED_MALWARE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # CVE reference combined with code-execution syntax in the same payload.
    # The Red Team's job is to attack the Co-Pilot's LLM surface, not to
    # synthesize working CVE exploits.
    (re.compile(r"CVE-\d{4}-\d{4,7}", re.I), "cve_reference"),
    # Ransomware / wiper terminology
    (re.compile(r"\b(ransomware|wiper|cryptolocker|encrypt\s+all\s+files)\b", re.I), "ransomware_term"),
    # Shellcode hex blocks (40+ continuous hex chars — typical NOP sled / shellcode)
    (re.compile(r"\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){20,}", re.I), "shellcode_hex"),
    # ELF / PE / Mach-O magic bytes in payload (would be embedded executables)
    (re.compile(r"(?:^|\\x00)(\x7fELF|MZ\x90\x00|\xfe\xed\xfa\xce)"), "executable_magic"),
    # Reverse-shell / shell-injection templates
    (re.compile(r"bash\s+-i\s+>&\s*/dev/tcp/", re.I), "reverse_shell"),
    (re.compile(r"nc(?:at)?\s+-[el]\s+", re.I), "netcat_listener"),
]


_OUT_OF_SCOPE_REDIRECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Direct URL injection pointing at a non-allowed host. Allowlist matches
    # target_client._ALLOWED_TARGET_HOSTS to keep the two contracts aligned.
    (
        re.compile(
            r"https?://(?!"
            r"(?:localhost|127\.0\.0\.1|142-93-242-40\.nip\.io|agent)"
            r"(?:[/:]|$))[\w.-]+",
            re.I,
        ),
        "external_url",
    ),
    # Imperatives instructing the target/Judge to attack a different system
    (
        re.compile(
            r"\b(?:attack|exploit|hack|probe|scan)\s+"
            r"(?:the\s+)?(?:server|system|service|api|endpoint)\s+at\s+",
            re.I,
        ),
        "attack_other_system",
    ),
]


_ALL_CATEGORIES: list[tuple[RefusalReason, list[tuple[re.Pattern[str], str]]]] = [
    ("minors_content", _MINORS_PATTERNS),
    ("real_phi", _REAL_PHI_PATTERNS),
    ("weaponized_malware", _WEAPONIZED_MALWARE_PATTERNS),
    ("out_of_scope_redirection", _OUT_OF_SCOPE_REDIRECTION_PATTERNS),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FilterDecision:
    """Result of running the hard filter on an AttackCandidate."""

    allowed: bool
    refusal_reason: RefusalReason | None = None
    matched_pattern_label: str | None = None
    matched_text: str | None = None


def evaluate_attack(attack: AttackCandidate) -> FilterDecision:
    """Pre-flight check on every AttackCandidate (ARCH §2.1).

    Inspects the attack's payload content (single-turn `content` AND every
    turn's `content` for multi-turn). Returns the FIRST category that
    triggers — order is deterministic and listed in `_ALL_CATEGORIES`.

    Callers route refused decisions to logging without invoking the target
    client. The target client also enforces sentinel-patient and out-of-scope
    URL refusals at its own boundary as defense in depth.
    """
    blob = _payload_text_blob(attack.payload)
    if not blob.strip():
        # Empty payload is not a refusal category, but it IS pathological;
        # let the target client handle it (it refuses empty messages).
        return FilterDecision(allowed=True)

    for reason, patterns in _ALL_CATEGORIES:
        for pattern, label in patterns:
            match = pattern.search(blob)
            if match is not None:
                return FilterDecision(
                    allowed=False,
                    refusal_reason=reason,
                    matched_pattern_label=label,
                    matched_text=match.group(0)[:200],
                )
    return FilterDecision(allowed=True)


def _payload_text_blob(payload: Payload) -> str:
    """Concatenate all text from a Payload for pattern scanning.

    Single-turn: just `content`.
    Multi-turn: every turn's `content`, separated by newlines so cross-turn
      patterns aren't accidentally created by adjacency.
    """
    parts: list[str] = []
    if payload.content:
        parts.append(payload.content)
    if payload.turns:
        parts.extend(t.content for t in payload.turns)
    return "\n".join(parts)


__all__ = [
    "FilterDecision",
    "RefusalReason",
    "evaluate_attack",
]
