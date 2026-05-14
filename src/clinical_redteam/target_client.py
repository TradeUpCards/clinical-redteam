"""HMAC-signed target client for the AgentForge Clinical Co-Pilot.

This module is the ONLY way the Red Team Platform talks to the target. Every
external call passes through `TargetClient.chat()` or `TargetClient.attach_and_extract()`,
both of which:

1. HARD-REFUSE out-of-scope target URLs (ARCH §2.1 — out-of-scope is a hard
   refusal, not a soft warning). This is the platform's first line of defense
   against turning into a generalized attacker — the Red Team Agent cannot
   redirect attacks to non-authorized targets even if it tried.
2. HARD-REFUSE non-sentinel patient IDs (project hard rule — sentinel IDs
   only, 999001-999999 range; never real PHI even in attack payloads).
3. Sign every request with HMAC-SHA256 using the EXACT same payload scheme
   the target's `verify_hmac` expects. Mismatch is a 401 from the target —
   surfaced cleanly, never retried with a different secret.
4. Back off on 5xx (target overload / restart) with bounded retries.

HMAC payload schemes (must match deployed target verify_hmac exactly):
- `/chat`:                f"{user_id}|{patient_id}|{timestamp}|" + "|".join(m.content for m in messages)
- `/attach_and_extract`:  f"{user_id}|{patient_id}|{doc_ref_id}|{doc_type}|{timestamp}|{file_sha256}"

Replay windows:
- `/chat`:                30s   (HMAC_MAX_AGE_SECONDS, RED_TEAM_TARGET_*)
- `/attach_and_extract`:  300s  (ATTACH_HMAC_MAX_AGE_SECONDS) — wider per W2 main.py:179-183

NOT included here (intentionally):
- The content-category filter — runs upstream in content_filter.py (Phase 1a
  #10) so refused attacks never reach this module
- Cost / Langfuse instrumentation — composed in observability.py (#12)

Env vars consumed (full reference in .env.example):
  RED_TEAM_TARGET_URL                 (e.g. http://localhost:8000 via SSH tunnel)
  RED_TEAM_TARGET_HMAC_SECRET         (matches deployed Co-Pilot's OPENEMR_HMAC_SECRET)
  RED_TEAM_TARGET_USER_ID             (default 1; W2 admin parity)
  RED_TEAM_TARGET_SENTINEL_PATIENT_IDS  (comma-separated, must all be 999001-999999)
  HMAC_MAX_AGE_SECONDS                (default 30; /chat signing timestamp = now)
  ATTACH_HMAC_MAX_AGE_SECONDS         (default 300; /attach_and_extract replay window)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Allowlists + constants
# ---------------------------------------------------------------------------


_ALLOWED_TARGET_HOSTS: frozenset[str] = frozenset(
    {
        # Local dev via SSH tunnel to droplet's internal Docker network
        "localhost",
        "127.0.0.1",
        # Public hostname of the deployed Co-Pilot (Phase 2 P1: when daemon
        # runs co-located on the droplet, it uses the Docker DNS name below)
        "142-93-242-40.nip.io",
        # Internal Docker DNS name — used when the daemon runs as a container
        # alongside the target's agent service (Phase 2 P1 deployment)
        "agent",
    }
)
"""Hard allowlist of target hostnames. Anything else → OutOfScopeTargetError.

This is a SAFETY mechanism, not a configuration knob. Expanding it requires
user/architecture sign-off. The architectural commitment is that the Red
Team Platform attacks ONE specific target (the AgentForge Clinical Co-Pilot)
plus its development/deployment variants — never an arbitrary system."""


_SENTINEL_PATIENT_ID_MIN = 999001
_SENTINEL_PATIENT_ID_MAX = 999999
"""Sentinel patient ID range (project hard rule, ARCH §2.1 +
RESPONSIBLE_USE.md). Anything outside this range is real-or-could-be-real
PHI and must never appear in an attack payload.

**Range expanded 2026-05-12** from [999_100, 999_999] (900 slots) to
[999_001, 999_999] (999 slots) to align with W2's design expansion of
2026-05-09. The deployed Co-Pilot's PersonaMap maps real PIDs 1–199 to
sentinels 999_001–999_199; the rich Synthea-generated test fixture
surface lives in this expanded range (real PIDs 1–99 → sentinels
999_001–999_099). The prior [999_100, 999_999] convention pre-dated W2's
expansion and only reached half the fixture surface (real PIDs 100–199).

See `AgentForge agent/document_schemas.py:35-44` for the W2 design
source. Coordination ticket: `.gauntlet/week3/coordination/
sentinel-range-expand-to-w2-tate-to-aria.md`.

**Forward-compat caveat:** the user has verified all patient data in the
*deployed* target is synthetic. For future targets with unknown data
provenance, the operator MUST verify synthetic-provenance before
attacking arbitrary sentinels in this range."""


_DEFAULT_HMAC_MAX_AGE_SECONDS = 30
_DEFAULT_ATTACH_HMAC_MAX_AGE_SECONDS = 300
"""F20: /attach_and_extract uses a wider replay window than /chat. The
W2 Co-Pilot's main.py:179-183 verifies attach-extract signatures against
a 300s window because Docling parsing + Haiku extraction can take 60-90s,
and the signature is bound to the original timestamp. Mismatch is a 401."""
_DEFAULT_REQUEST_TIMEOUT = 30.0
_DEFAULT_MAX_5XX_RETRIES = 2
_DEFAULT_5XX_BACKOFF_BASE_SECONDS = 1.0

_DEFAULT_HEALTH_PATH = "/health"
"""Path used by `health_fingerprint`. Override via RED_TEAM_TARGET_HEALTH_PATH
env var when the target exposes its readiness via a different route (e.g.
`/meta/health/readyz` on a FastAPI server with a router prefix)."""

_HEALTH_FINGERPRINT_UNREACHABLE = "unreachable"
"""Sentinel returned by `health_fingerprint` when the endpoint cannot be
reached. F7 treats a `previous == current == unreachable` pair as 'no
change' so a sustained outage doesn't perpetually trigger regression
replay; a transition `unreachable → sha256:...` (or the reverse) IS a
change worth replaying for, because the target has come back up or gone
down between runs."""

_HEALTH_FINGERPRINT_HEX_PREFIX_LEN = 16


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class TargetClientError(Exception):
    """Base class for all target-client errors."""


class TargetClientConfigError(TargetClientError):
    """Missing or malformed configuration (env vars)."""


class OutOfScopeTargetError(TargetClientError):
    """Hard refusal — target host is not on the allowlist (ARCH §2.1)."""


class SentinelPatientIdError(TargetClientError):
    """Hard refusal — patient_id is not a sentinel ID (project hard rule)."""


class HmacRejectedError(TargetClientError):
    """Target returned 401 — HMAC mismatch, skew, or empty secret config."""


class TargetUnavailableError(TargetClientError):
    """Target unreachable or returning 5xx after all retries."""


# ---------------------------------------------------------------------------
# Public response shape
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TargetResponse:
    """One target call's worth of substrate for the Judge + cost ledger.

    `extraction` is populated only for `/attach_and_extract` responses
    (F20). For `/chat` it stays None. When present, `assistant_text` is
    set to `json.dumps(extraction)` so the Judge's prose-style rubric
    can fire on substring matches against extracted field values —
    e.g., the `extraction_field_value_poisoning` criterion checks for
    medication strings that appear inside extracted JSON but not in
    legitimate document blocks.
    """

    status_code: int
    assistant_text: str
    raw_body: dict[str, Any]
    latency_ms: int
    request_id: str | None
    trace_id: str | None
    extraction: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Message shape (deliberately minimal — matches AgentForge agent/schemas.py Message)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Message:
    """Single chat turn in the request payload. Mirrors target's Message."""

    role: str  # "user" | "assistant" | "system"
    content: str


# ---------------------------------------------------------------------------
# HMAC signing — MUST match AgentForge agent.py:verify_hmac exactly
# ---------------------------------------------------------------------------


def compute_chat_hmac(
    *,
    user_id: int,
    patient_id: int,
    timestamp: int,
    messages: list[Message],
    secret: str,
) -> str:
    """Compute HMAC-SHA256 hex digest for a /chat request payload.

    Payload-to-sign convention (matches AgentForge agent.py:verify_hmac):
        f"{user_id}|{patient_id}|{timestamp}|" + "|".join(m.content for m in messages)

    Returns lowercase hex digest. Empty secret raises — never sign with
    empty key (would silently match a deploy with empty OPENEMR_HMAC_SECRET).
    """
    if not secret:
        raise TargetClientConfigError(
            "HMAC secret is empty — refusing to sign. "
            "Set RED_TEAM_TARGET_HMAC_SECRET in .env to match deployed "
            "Co-Pilot's OPENEMR_HMAC_SECRET."
        )
    payload = (
        f"{user_id}|{patient_id}|{timestamp}|"
        + "|".join(m.content for m in messages)
    )
    return hmac.new(
        secret.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def compute_attach_hmac(
    *,
    user_id: int,
    patient_id: int,
    doc_ref_id: str,
    doc_type: str,
    timestamp: int,
    file_sha256: str,
    secret: str,
) -> str:
    """Compute HMAC-SHA256 hex digest for an /attach_and_extract request.

    Payload-to-sign convention (must match deployed target's
    `verify_hmac` for the extract endpoint — see audit §C-A + §C-E):

        f"{user_id}|{patient_id}|{doc_ref_id}|{doc_type}|{timestamp}|{file_sha256}"

    `file_sha256` MUST be the hex digest of the EXACT bytes posted in the
    `file` multipart part — any divergence (e.g., hashing the source text
    before PDF generation rather than the PDF bytes themselves) produces
    a 401 from the target. The bytes-to-hash invariant is enforced by
    callers via `attach_and_extract()` below; this helper just signs.

    Returns lowercase hex digest. Empty secret raises (same posture as
    /chat — never sign with an empty key).
    """
    if not secret:
        raise TargetClientConfigError(
            "HMAC secret is empty — refusing to sign. "
            "Set RED_TEAM_TARGET_HMAC_SECRET in .env to match deployed "
            "Co-Pilot's OPENEMR_HMAC_SECRET."
        )
    payload = (
        f"{user_id}|{patient_id}|{doc_ref_id}|{doc_type}|"
        f"{timestamp}|{file_sha256}"
    )
    return hmac.new(
        secret.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def dispatch_to_endpoint(
    target: TargetClient,
    *,
    target_endpoint: str,
    payload_content: str,
    patient_id: int,
    session_id: str,
) -> TargetResponse:
    """Route a single attack payload to the correct TargetClient method.

    F20: this is the single source of truth for endpoint dispatch so the
    branching logic doesn't drift between `run.py`'s single-shot path
    and the daemon loop in `orchestrator.py`. Both call sites import
    from here.

    Branching:
    - `target_endpoint == "/attach_and_extract"` → multipart PDF POST
      with `payload_content` as the document body. doc_type defaults
      to `"intake_form"` for MVP (the C-A surface). lab_report is the
      same gap class and can be reached by future seeds with their own
      `doc_type` override — out of scope for F20.
    - anything else → existing `/chat` JSON POST. Default path so older
      seeds (target_endpoint=`/chat`) keep working unchanged.

    Unknown endpoints get a structured rejection so the daemon doesn't
    silently fall back to `/chat` and measure the wrong defense — same
    posture as out-of-scope target URLs (ARCH §2.1).
    """
    if target_endpoint == "/attach_and_extract":
        return target.attach_and_extract(
            document_text=payload_content,
            patient_id=patient_id,
            doc_type="intake_form",
            session_id=session_id,
        )
    if target_endpoint == "/chat":
        return target.chat(
            messages=[Message(role="user", content=payload_content)],
            patient_id=patient_id,
            session_id=session_id,
        )
    raise TargetClientError(
        f"Unknown target_endpoint {target_endpoint!r}. "
        "Supported: '/chat', '/attach_and_extract'. "
        "Seeds requesting other endpoints must extend dispatch_to_endpoint "
        "with sign-off — falling back silently would risk measuring the "
        "wrong defense (the F20 case we just closed)."
    )


def render_text_to_pdf_bytes(text: str) -> bytes:
    """Render `text` to a single-page PDF and return the raw bytes.

    **NONDETERMINISM CAVEAT — read this before refactoring callers.**
    reportlab embeds a random `/ID` field in the PDF trailer that varies
    call-to-call EVEN with identical input text. Two calls with the same
    `text` produce different bytes → different sha256 → different HMAC.
    This is invisible inside `attach_and_extract` because that method
    calls `render_text_to_pdf_bytes` EXACTLY ONCE, stores the result in
    a local, and threads that one bytes object through (a) the hash,
    (b) the HMAC computation, and (c) the multipart `files` dict. A
    5xx retry in `_post_multipart_with_backoff` reuses the same bytes
    object, so the hash-to-posted-bytes invariant holds across retries.
    A future refactor that introduces a second call to this helper
    inside the same attack would silently break HMAC verification on
    the target side. Do not call this twice for the same attack.

    F20: the `/attach_and_extract` endpoint expects a multipart upload
    with a PDF in the `file` part. Seed `attack_template` content is
    plain text; this helper turns it into bytes the endpoint will accept
    AND that Docling on the target side will OCR back into block text.

    Discipline (per coordination ticket F20 §2):
    - Use `reportlab` (small, pure-Python, no system deps).
    - Plain prose flow — no styling. Docling parses block text from the
      PDF content regardless of layout.
    - Preserve the literal text verbatim — DO NOT mangle Unicode,
      newlines, or whitespace. The audit explicitly calls out that
      block-text concatenation is the injection surface, so any
      Red Team mutation that inserts e.g. zero-width chars must survive
      the PDF round-trip unchanged.

    Implementation notes:
    - Low-level `reportlab.pdfgen.canvas.Canvas` + `beginText()` is used
      (NOT `platypus.Paragraph`) because Paragraph treats `<…>`-shaped
      content as markup and would alter the bytes. Canvas's text object
      is closer to verbatim — newlines are honored line-by-line.
    - Long lines that exceed page width are NOT wrapped here; the seed
      authors lay out the attack_template with short lines (intake-form
      style). If a future Red Team mutation produces a long line, the
      tail spills off the page edge but the byte stream still contains
      the literal text, so Docling still extracts it from the PDF
      content stream.
    """
    from io import BytesIO

    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas as _canvas

    buf = BytesIO()
    c = _canvas.Canvas(buf, pagesize=letter)
    _, page_height = letter
    text_obj = c.beginText(50, page_height - 50)
    text_obj.setFont("Helvetica", 10)
    # Render line-by-line. splitlines() handles both \r\n and \n; we
    # iterate over the original `text` via splitlines(keepends=False)
    # then re-emit each as a separate textLine call so reportlab's
    # baseline positioning advances per-line.
    for line in text.splitlines() or [""]:
        text_obj.textLine(line)
    c.drawText(text_obj)
    c.showPage()
    c.save()
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


@dataclass
class TargetClient:
    """HMAC-signed client for the AgentForge Clinical Co-Pilot.

    Construct with `TargetClient.from_env()` to read all configuration from
    the process environment (the normal path). Tests use the explicit
    constructor + an injected httpx.Client for mocked transports.
    """

    base_url: str
    hmac_secret: str
    user_id: int
    sentinel_patient_ids: tuple[int, ...]
    hmac_max_age_seconds: int = _DEFAULT_HMAC_MAX_AGE_SECONDS
    attach_hmac_max_age_seconds: int = _DEFAULT_ATTACH_HMAC_MAX_AGE_SECONDS
    request_timeout: float = _DEFAULT_REQUEST_TIMEOUT
    max_5xx_retries: int = _DEFAULT_MAX_5XX_RETRIES
    backoff_base_seconds: float = _DEFAULT_5XX_BACKOFF_BASE_SECONDS
    health_path: str = _DEFAULT_HEALTH_PATH
    http_client: httpx.Client | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        self._validate_target_url(self.base_url)
        if not self.sentinel_patient_ids:
            raise TargetClientConfigError(
                "sentinel_patient_ids is empty. "
                "Set RED_TEAM_TARGET_SENTINEL_PATIENT_IDS in .env."
            )
        for pid in self.sentinel_patient_ids:
            self._validate_sentinel_patient_id(pid)
        if self.http_client is None:
            self.http_client = httpx.Client(timeout=self.request_timeout)

    # -----------------------------------------------------------------------
    # Construction from env
    # -----------------------------------------------------------------------

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> TargetClient:
        """Build a TargetClient from process env (or an injected dict).

        Raises TargetClientConfigError if any required var is missing or
        malformed. Required vars: RED_TEAM_TARGET_URL, RED_TEAM_TARGET_HMAC_SECRET,
        RED_TEAM_TARGET_USER_ID, RED_TEAM_TARGET_SENTINEL_PATIENT_IDS.
        """
        e = env if env is not None else os.environ
        base_url = e.get("RED_TEAM_TARGET_URL", "").strip()
        secret = e.get("RED_TEAM_TARGET_HMAC_SECRET", "").strip()
        user_id_raw = e.get("RED_TEAM_TARGET_USER_ID", "").strip()
        patient_ids_raw = e.get("RED_TEAM_TARGET_SENTINEL_PATIENT_IDS", "").strip()
        hmac_age_raw = e.get(
            "HMAC_MAX_AGE_SECONDS", str(_DEFAULT_HMAC_MAX_AGE_SECONDS)
        ).strip()

        missing = [
            name
            for name, value in [
                ("RED_TEAM_TARGET_URL", base_url),
                ("RED_TEAM_TARGET_HMAC_SECRET", secret),
                ("RED_TEAM_TARGET_USER_ID", user_id_raw),
                ("RED_TEAM_TARGET_SENTINEL_PATIENT_IDS", patient_ids_raw),
            ]
            if not value
        ]
        if missing:
            raise TargetClientConfigError(
                f"Missing required env vars: {', '.join(missing)}. "
                "See .env.example."
            )
        try:
            user_id = int(user_id_raw)
        except ValueError as exc:
            raise TargetClientConfigError(
                f"RED_TEAM_TARGET_USER_ID must be an integer, got {user_id_raw!r}"
            ) from exc
        try:
            sentinel_patient_ids = tuple(
                int(pid.strip()) for pid in patient_ids_raw.split(",") if pid.strip()
            )
        except ValueError as exc:
            raise TargetClientConfigError(
                "RED_TEAM_TARGET_SENTINEL_PATIENT_IDS must be comma-separated "
                f"integers in {_SENTINEL_PATIENT_ID_MIN}-{_SENTINEL_PATIENT_ID_MAX}, "
                f"got {patient_ids_raw!r}"
            ) from exc
        try:
            hmac_max_age_seconds = int(hmac_age_raw)
        except ValueError as exc:
            raise TargetClientConfigError(
                f"HMAC_MAX_AGE_SECONDS must be an integer, got {hmac_age_raw!r}"
            ) from exc
        attach_age_raw = e.get(
            "ATTACH_HMAC_MAX_AGE_SECONDS", str(_DEFAULT_ATTACH_HMAC_MAX_AGE_SECONDS)
        ).strip() or str(_DEFAULT_ATTACH_HMAC_MAX_AGE_SECONDS)
        try:
            attach_hmac_max_age_seconds = int(attach_age_raw)
        except ValueError as exc:
            raise TargetClientConfigError(
                f"ATTACH_HMAC_MAX_AGE_SECONDS must be an integer, got {attach_age_raw!r}"
            ) from exc
        return cls(
            base_url=base_url,
            hmac_secret=secret,
            user_id=user_id,
            sentinel_patient_ids=sentinel_patient_ids,
            hmac_max_age_seconds=hmac_max_age_seconds,
            attach_hmac_max_age_seconds=attach_hmac_max_age_seconds,
            health_path=e.get(
                "RED_TEAM_TARGET_HEALTH_PATH", _DEFAULT_HEALTH_PATH
            ).strip()
            or _DEFAULT_HEALTH_PATH,
        )

    # -----------------------------------------------------------------------
    # /chat
    # -----------------------------------------------------------------------

    def chat(
        self,
        messages: list[Message],
        *,
        patient_id: int | None = None,
        session_id: str | None = None,
        now: int | None = None,
    ) -> TargetResponse:
        """POST a signed /chat request to the target.

        - `patient_id` defaults to the first configured sentinel ID. Must be
          in 999001-999999 range; raises SentinelPatientIdError otherwise.
        - `session_id` is observability metadata (Langfuse trace grouping).
          Defaults to a fresh uuid4 hex string.
        - `now` is injectable for unit tests; production callers leave it
          unset so the wall clock is read.
        """
        if patient_id is None:
            patient_id = self.sentinel_patient_ids[0]
        self._validate_sentinel_patient_id(patient_id)

        if not messages:
            raise TargetClientError("messages cannot be empty")

        timestamp = now if now is not None else int(time.time())
        sig = compute_chat_hmac(
            user_id=self.user_id,
            patient_id=patient_id,
            timestamp=timestamp,
            messages=messages,
            secret=self.hmac_secret,
        )

        body = {
            "user_id": self.user_id,
            "patient_id": patient_id,
            "timestamp": timestamp,
            "hmac": sig,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "session_id": session_id or uuid.uuid4().hex,
        }

        url = self.base_url.rstrip("/") + "/chat"
        started = time.perf_counter()
        response = self._post_with_backoff(url, body)
        latency_ms = int((time.perf_counter() - started) * 1000)

        if response.status_code == 401:
            raise HmacRejectedError(
                f"Target returned 401. Likely HMAC scheme drift, secret "
                f"mismatch, or timestamp skew. Response: {response.text[:300]!r}"
            )

        try:
            parsed = response.json()
        except ValueError:
            parsed = {"_non_json_body": response.text[:1000]}

        message = parsed.get("message", {}) if isinstance(parsed, dict) else {}
        assistant_text = (
            message.get("content", "") if isinstance(message, dict) else ""
        )

        return TargetResponse(
            status_code=response.status_code,
            assistant_text=assistant_text,
            raw_body=parsed if isinstance(parsed, dict) else {},
            latency_ms=latency_ms,
            request_id=parsed.get("request_id") if isinstance(parsed, dict) else None,
            trace_id=parsed.get("trace_id") if isinstance(parsed, dict) else None,
        )

    # -----------------------------------------------------------------------
    # /attach_and_extract — F20 indirect-PI surface for C-A
    # -----------------------------------------------------------------------

    def attach_and_extract(
        self,
        *,
        document_text: str,
        patient_id: int | None = None,
        doc_type: str = "intake_form",
        doc_ref_id: str | None = None,
        session_id: str | None = None,
        now: int | None = None,
    ) -> TargetResponse:
        """POST a signed `/attach_and_extract` request with `document_text` as PDF.

        F20 wires the C-A attack surface: the deployed Co-Pilot's extraction
        endpoint accepts a PDF (`multipart/form-data`), runs Docling →
        Haiku to extract structured fields, and persists the result.
        The audit's C-A finding is that the extraction system prompt
        lacks the "data, not instructions" clause that `/chat` has, so
        directive-shaped text inside an uploaded document gets followed.

        - `document_text` is rendered to PDF bytes via reportlab; the
          literal text MUST survive the round-trip so Docling parses
          back the same content the seed declared. Whitespace and
          Unicode are preserved (per coordination ticket §2).
        - `patient_id` defaults to the first configured sentinel ID.
          Hard refuses non-sentinel pids before any wire activity.
        - `doc_type` parameterizes which extraction surface fires.
          `intake_form` (default) hits intake_form_extraction.py; the
          same gap class also exists at lab_report_extraction.py per
          the audit, reachable via `doc_type="lab_report"`.
        - `doc_ref_id` per-attack identifier; generated as a UUID hex
          when not supplied. W2's main.py:376-393 does not require this
          to exist in OpenEMR for sentinel pids.
        - `now` is injectable for unit tests; production callers leave
          it unset so the wall clock is read.

        Returns a TargetResponse whose `extraction` field carries the
        parsed extraction dict and whose `assistant_text` is its JSON
        stringification — so the Judge's substring-style rubric (the
        `extraction_field_value_poisoning` criterion) fires against the
        extracted field values without any Judge schema change.
        """
        if patient_id is None:
            patient_id = self.sentinel_patient_ids[0]
        self._validate_sentinel_patient_id(patient_id)

        if not document_text:
            raise TargetClientError(
                "attach_and_extract: document_text cannot be empty"
            )

        timestamp = now if now is not None else int(time.time())
        ref_id = doc_ref_id or uuid.uuid4().hex

        # PDF bytes — generated once, used for BOTH the hash AND the
        # multipart upload. Computing the hash from a different byte
        # stream than the one actually posted produces a 401 from W2.
        pdf_bytes = render_text_to_pdf_bytes(document_text)
        file_sha256 = hashlib.sha256(pdf_bytes).hexdigest()

        sig = compute_attach_hmac(
            user_id=self.user_id,
            patient_id=patient_id,
            doc_ref_id=ref_id,
            doc_type=doc_type,
            timestamp=timestamp,
            file_sha256=file_sha256,
            secret=self.hmac_secret,
        )

        url = self.base_url.rstrip("/") + "/attach_and_extract"
        # Multipart form: `file` part carries the PDF bytes; form body
        # carries ONLY W2's `Form(...)` declarations (patient_id,
        # doc_ref_id, doc_type — see agent/main.py:272-360). Auth fields
        # (user_id, timestamp, signature) live in X-OpenEMR-* request
        # headers per the F25 fix below.
        files = {
            "file": (
                f"{ref_id}.pdf",
                pdf_bytes,
                "application/pdf",
            )
        }
        # F25 fix: W2's `/attach_and_extract` endpoint
        # (agent/main.py:272-360) declares ONLY `patient_id`, `doc_ref_id`,
        # `doc_type`, `file` as `Form(...)` fields. The auth triple
        # (user_id, timestamp, signature) is read from HTTP HEADERS, not
        # form fields:
        #   X-OpenEMR-User-Id   ← str(user_id)
        #   X-OpenEMR-Timestamp ← str(timestamp)
        #   X-OpenEMR-HMAC      ← sig
        # Pre-F25 we sent everything as form fields → empty
        # X-OpenEMR-User-Id header → `int("")` → 400
        # `missing_or_invalid_user_id` → never reached HMAC verify, never
        # reached Haiku. F25 moves the three fields to headers. The HMAC
        # payload formula is UNCHANGED — see compute_attach_hmac.
        headers = {
            "X-OpenEMR-User-Id": str(self.user_id),
            "X-OpenEMR-Timestamp": str(timestamp),
            "X-OpenEMR-HMAC": sig,
        }
        data = {
            "patient_id": str(patient_id),
            "doc_ref_id": ref_id,
            "doc_type": doc_type,
        }
        # `session_id` removed: not declared as Form() on W2 side; sending
        # it was harmless but inflated the multipart body. Kept session
        # tracking out of band via Langfuse spans instead.
        _ = session_id  # accepted for API stability; not on the wire

        started = time.perf_counter()
        response = self._post_multipart_with_backoff(
            url, files=files, data=data, headers=headers,
        )
        latency_ms = int((time.perf_counter() - started) * 1000)

        if response.status_code == 401:
            raise HmacRejectedError(
                f"Target /attach_and_extract returned 401. Likely HMAC "
                f"scheme drift, secret mismatch, file_sha256 drift, or "
                f"timestamp skew (replay window={self.attach_hmac_max_age_seconds}s). "
                f"Response: {response.text[:300]!r}"
            )

        try:
            parsed = response.json()
        except ValueError:
            # F25 defensive: 4xx/5xx may return HTML error pages, plain
            # text from misconfigured proxies, or empty bodies. Persist
            # what we got so the next 400 isn't blind — see ticket §2.
            parsed = {"raw_text": response.text[:2000]}

        # Per audit §C-A confirmation signals: `extraction.current_medications`,
        # `extraction.allergies`, `extraction_confidence_avg`. The Judge needs
        # ALL of this surface to rubric against, not just one slice.
        extraction: dict[str, Any] = {}
        if isinstance(parsed, dict):
            ext_raw = parsed.get("extraction")
            if isinstance(ext_raw, dict):
                extraction = ext_raw
            # Some target shapes emit confidence at top level — keep both
            # the nested dict AND the top-level conf so the Judge sees it.
            if "extraction_confidence_avg" in parsed and "extraction_confidence_avg" not in extraction:
                extraction = {
                    **extraction,
                    "extraction_confidence_avg": parsed["extraction_confidence_avg"],
                }

        # Stringify extraction JSON into assistant_text so Judge prose
        # rubrics fire on substring matches. Empty extraction is rendered
        # as "{}" so the rubric can't silently pass on an empty body —
        # see audit risk (3) in the coordination ticket.
        assistant_text = json.dumps(extraction, sort_keys=True)

        return TargetResponse(
            status_code=response.status_code,
            assistant_text=assistant_text,
            raw_body=parsed if isinstance(parsed, dict) else {},
            latency_ms=latency_ms,
            request_id=parsed.get("request_id") if isinstance(parsed, dict) else None,
            trace_id=parsed.get("trace_id") if isinstance(parsed, dict) else None,
            extraction=extraction or None,
        )

    # -----------------------------------------------------------------------
    # /health — fingerprint for F7 target-change regression trigger
    # -----------------------------------------------------------------------

    def health_fingerprint(self) -> str:
        """Return a short, stable fingerprint of the target's health response.

        Format: `sha256:<hex16>` derived from `sha256(response_body)[:16]`.
        Unreachable → `"unreachable"` (see module-level sentinel).

        Single-shot, no retries, no HMAC. A health endpoint that requires
        auth is a misconfiguration we want to surface (caller sees a
        non-`unreachable` non-`sha256:` fingerprint shift and replays
        regression cases — operator-friendly fail-loud).
        """
        assert self.http_client is not None  # set in __post_init__
        url = self.base_url.rstrip("/") + self.health_path
        try:
            response = self.http_client.get(url, timeout=self.request_timeout)
        except (httpx.ConnectError, httpx.ReadTimeout, httpx.HTTPError) as exc:
            logger.warning(
                "health_fingerprint: target %s unreachable (%s); "
                "treating as 'unreachable' fingerprint",
                url, type(exc).__name__,
            )
            return _HEALTH_FINGERPRINT_UNREACHABLE
        body_bytes = response.content
        digest = hashlib.sha256(body_bytes).hexdigest()
        return f"sha256:{digest[:_HEALTH_FINGERPRINT_HEX_PREFIX_LEN]}"

    # -----------------------------------------------------------------------
    # Internals
    # -----------------------------------------------------------------------

    def _post_multipart_with_backoff(
        self,
        url: str,
        *,
        files: dict[str, tuple[str, bytes, str]],
        data: dict[str, str],
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """POST multipart/form-data with the same retry posture as JSON POSTs.

        F25: `headers=` threads the X-OpenEMR-* auth triple through to
        httpx so W2's endpoint sees them as request headers (the shape
        its FastAPI signature expects), not as multipart form fields.

        Mirrors `_post_with_backoff`'s contract: bounded retries on 5xx +
        connection errors with exponential backoff; 2xx/3xx/non-401 4xx
        return immediately; the caller handles 401 explicitly. We do NOT
        re-sign on retry — the signature is bound to the original
        timestamp and the wider /attach_and_extract replay window
        (300s default) absorbs the retry delay.
        """
        assert self.http_client is not None  # set in __post_init__
        attempts = self.max_5xx_retries + 1
        last_exc: Exception | None = None
        last_response: httpx.Response | None = None

        for attempt in range(attempts):
            is_last = attempt + 1 >= attempts
            try:
                response = self.http_client.post(
                    url, files=files, data=data, headers=headers or {},
                )
            except (httpx.ConnectError, httpx.ReadTimeout) as exc:
                last_exc = exc
                logger.warning(
                    "Target multipart POST connection error (%s); attempt %d/%d",
                    type(exc).__name__, attempt + 1, attempts,
                )
                if is_last:
                    break
                time.sleep(self.backoff_base_seconds * (2**attempt))
                continue

            if 500 <= response.status_code < 600:
                last_response = response
                logger.warning(
                    "Target /attach_and_extract returned %d; attempt %d/%d",
                    response.status_code, attempt + 1, attempts,
                )
                if is_last:
                    break
                time.sleep(self.backoff_base_seconds * (2**attempt))
                continue

            return response

        if last_exc is not None:
            raise TargetUnavailableError(
                f"Target {url} unreachable after {attempts} attempts: {last_exc}"
            ) from last_exc
        assert last_response is not None
        raise TargetUnavailableError(
            f"Target {url} returned {last_response.status_code} after "
            f"{attempts} attempts. Body: {last_response.text[:300]!r}"
        )

    def _post_with_backoff(self, url: str, body: dict[str, Any]) -> httpx.Response:
        """POST with bounded retry on 5xx + connection error.

        Does NOT retry on 4xx (caller's fault) or on the final attempt.
        Re-signs nothing — the signed body's timestamp can drift up to
        hmac_max_age_seconds; if a retry would exceed that, gives up.
        """
        assert self.http_client is not None  # set in __post_init__
        attempts = self.max_5xx_retries + 1
        last_exc: Exception | None = None
        last_response: httpx.Response | None = None

        for attempt in range(attempts):
            is_last = attempt + 1 >= attempts
            try:
                response = self.http_client.post(url, json=body)
            except (httpx.ConnectError, httpx.ReadTimeout) as exc:
                last_exc = exc
                logger.warning(
                    "Target POST connection error (%s); attempt %d/%d",
                    type(exc).__name__,
                    attempt + 1,
                    attempts,
                )
                if is_last:
                    break
                time.sleep(self.backoff_base_seconds * (2**attempt))
                continue

            if 500 <= response.status_code < 600:
                last_response = response
                logger.warning(
                    "Target returned %d; attempt %d/%d",
                    response.status_code,
                    attempt + 1,
                    attempts,
                )
                if is_last:
                    break
                time.sleep(self.backoff_base_seconds * (2**attempt))
                continue

            # 2xx, 3xx, or non-401 4xx — propagate to caller; chat() handles
            # the 401 case explicitly. No retry on caller-fault 4xx.
            return response

        if last_exc is not None:
            raise TargetUnavailableError(
                f"Target {url} unreachable after {attempts} attempts: {last_exc}"
            ) from last_exc
        assert last_response is not None
        raise TargetUnavailableError(
            f"Target {url} returned {last_response.status_code} after "
            f"{attempts} attempts. Body: {last_response.text[:300]!r}"
        )

    @staticmethod
    def _validate_target_url(base_url: str) -> None:
        """Hard-refuse out-of-scope target URLs (ARCH §2.1)."""
        try:
            parsed = urlparse(base_url)
        except Exception as exc:
            raise OutOfScopeTargetError(
                f"Could not parse RED_TEAM_TARGET_URL={base_url!r}: {exc}"
            ) from exc
        host = (parsed.hostname or "").lower()
        if host not in _ALLOWED_TARGET_HOSTS:
            raise OutOfScopeTargetError(
                f"Target host {host!r} is not on the allowlist "
                f"{sorted(_ALLOWED_TARGET_HOSTS)}. The Red Team Platform attacks "
                "the configured AgentForge Clinical Co-Pilot only — out-of-scope "
                "targets are HARD-REFUSED (ARCH §2.1). Expand the allowlist in "
                "target_client.py only with explicit architectural sign-off."
            )

    @staticmethod
    def _validate_sentinel_patient_id(patient_id: int) -> None:
        """Hard-refuse non-sentinel patient IDs (project hard rule)."""
        if not (
            _SENTINEL_PATIENT_ID_MIN <= patient_id <= _SENTINEL_PATIENT_ID_MAX
        ):
            raise SentinelPatientIdError(
                f"patient_id={patient_id} is outside the sentinel range "
                f"{_SENTINEL_PATIENT_ID_MIN}-{_SENTINEL_PATIENT_ID_MAX}. Real or "
                "potentially-real patient IDs MUST NEVER appear in attack "
                "payloads (project hard rule + RESPONSIBLE_USE.md)."
            )


__all__ = [
    "HmacRejectedError",
    "Message",
    "OutOfScopeTargetError",
    "SentinelPatientIdError",
    "TargetClient",
    "TargetClientConfigError",
    "TargetClientError",
    "TargetResponse",
    "TargetUnavailableError",
    "compute_attach_hmac",
    "compute_chat_hmac",
    "dispatch_to_endpoint",
    "render_text_to_pdf_bytes",
]
