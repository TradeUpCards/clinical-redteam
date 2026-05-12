"""Langfuse observability + PHI scrubber (ARCH §9.1, ARCH §10.1).

Every external agent call emits a Langfuse span tagged with the AgentTrace
shape (ARCH §12.6). The PHI scrubber runs PRE-SEND on every inputs / outputs /
metadata payload so sentinel patient IDs, SSN-shaped strings, and name+DOB
combos never leave the process in cleartext.

No-op mode: if LANGFUSE_* env vars are absent, this module degrades to a
no-op context manager + sink. That lets unit tests + dev runs work without
network or keys. Production daemons populate the env to enable real tracing.

Hard-rule reminder: no raw target responses logged at high/critical severity
(ARCH §10.1). The Documentation Agent strips response bodies to
structure-only summaries before emitting verdict spans. THIS module enforces
the scrub pass on whatever payload it receives — it does not know severity,
so callers are responsible for sending structure-only summaries when the
verdict warrants.
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Protocol

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PHI scrubber
# ---------------------------------------------------------------------------


_SENTINEL_PID_PATTERN = re.compile(r"\b999[1-9]\d{2}\b")
_REAL_SSN_PATTERN = re.compile(r"\b(?!9\d{2}-)\d{3}-\d{2}-\d{4}\b")
# Alternation ordering matters: longer matches must come first so the
# regex engine doesn't lock in a partial match (e.g., "22" should be
# captured whole by [12]\d, not partially by 0?[1-9]).
_NAME_PLUS_DOB_PATTERN = re.compile(
    r"[A-Z][a-z]{2,}\s+[A-Z][a-z]{2,}.{0,50}"
    r"(?:DOB|date\s+of\s+birth|born)[\s:]+"
    # ALTERNATION ORDER IS LOAD-BEARING — mirrors content_filter.py. Full-
    # date branches MUST come before year-only fallback so "1985-03-22"
    # gets fully consumed (not just "1985" leaving "-03-22" in the output).
    r"(?:"
    r"(?:1[0-2]|0?[1-9])[-/](?:[12]\d|3[01]|0?[1-9])[-/](?:19|20)\d{2}"
    r"|"
    r"(?:19|20)\d{2}[-/](?:1[0-2]|0?[1-9])[-/](?:[12]\d|3[01]|0?[1-9])"
    # Year-only after name + DOB keyword (Tate B6-audit-content-filter
    # ticket — same pattern, same rationale as content_filter.py).
    r"|"
    r"(?:19|20)\d{2}\b"
    r")",
    re.I,
)


def scrub_phi(value: Any) -> Any:
    """Recursively replace PHI patterns with sentinel tokens.

    Walks dicts / lists / strings; leaves other types alone. Patterns:
    - 999XXX sentinel patient IDs → "[sentinel-pid-redacted]"
      (sentinel data is synthetic by design but we strip the specific id
      so a leaked observability stream doesn't index by patient ID)
    - Real-shaped SSNs (NOT 9XX test SSNs) → "[ssn-redacted]"
    - Name + DOB combos → "[name+dob-redacted]"
    """
    if isinstance(value, str):
        scrubbed = _SENTINEL_PID_PATTERN.sub("[sentinel-pid-redacted]", value)
        scrubbed = _REAL_SSN_PATTERN.sub("[ssn-redacted]", scrubbed)
        scrubbed = _NAME_PLUS_DOB_PATTERN.sub("[name+dob-redacted]", scrubbed)
        return scrubbed
    if isinstance(value, dict):
        return {k: scrub_phi(v) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub_phi(item) for item in value]
    if isinstance(value, tuple):
        return tuple(scrub_phi(item) for item in value)
    return value


# ---------------------------------------------------------------------------
# Span handle protocol (so tests can mock without depending on Langfuse types)
# ---------------------------------------------------------------------------


class SpanHandle(Protocol):
    """Minimal surface used by callers; satisfied by both Langfuse spans
    and the no-op stub."""

    def update(self, **kwargs: Any) -> None: ...
    def end(self, **kwargs: Any) -> None: ...


@dataclass
class _NoopSpan:
    """Yielded when Langfuse is not configured (no-op mode)."""

    name: str

    def update(self, **kwargs: Any) -> None:
        return None

    def end(self, **kwargs: Any) -> None:
        return None


# ---------------------------------------------------------------------------
# Observability surface
# ---------------------------------------------------------------------------


@dataclass
class Observability:
    """Lazy-initialized Langfuse client + span helper.

    `Observability.from_env()` reads LANGFUSE_PUBLIC_KEY / _SECRET_KEY /
    _HOST. If either key is empty, we stay in no-op mode — `agent_span()`
    still yields a `_NoopSpan` so caller code is identical across modes.
    """

    public_key: str | None
    secret_key: str | None
    host: str
    session_id: str | None = None
    _client: Any = None

    @classmethod
    def from_env(
        cls, *, session_id: str | None = None, env: dict[str, str] | None = None
    ) -> Observability:
        e = env if env is not None else os.environ
        return cls(
            public_key=e.get("LANGFUSE_PUBLIC_KEY", "").strip() or None,
            secret_key=e.get("LANGFUSE_SECRET_KEY", "").strip() or None,
            host=e.get("LANGFUSE_HOST", "https://cloud.langfuse.com").strip(),
            session_id=session_id,
        )

    @property
    def is_active(self) -> bool:
        return bool(self.public_key and self.secret_key)

    def _ensure_client(self) -> Any:
        if not self.is_active:
            return None
        if self._client is None:
            from langfuse import Langfuse  # imported lazily so no-op mode skips it

            self._client = Langfuse(
                public_key=self.public_key,
                secret_key=self.secret_key,
                host=self.host,
            )
        return self._client

    # ----------------------------------------------------------------- spans

    @contextmanager
    def agent_span(
        self,
        *,
        agent_name: str,
        agent_version: str,
        agent_role: str,
        attack_id: str | None = None,
        category: str | None = None,
        model_used: str | None = None,
        inputs: dict[str, Any] | None = None,
    ) -> Iterator[SpanHandle]:
        """Context manager wrapping one agent action in a Langfuse span.

        All `inputs` + later `.update(output=...)` payloads pass through
        scrub_phi() before reaching the wire. Span attributes match the
        AgentTrace shape (ARCH §12.6).
        """
        scrubbed_inputs = scrub_phi(inputs) if inputs else None
        metadata = scrub_phi(
            {
                "agent_name": agent_name,
                "agent_version": agent_version,
                "agent_role": agent_role,
                "attack_id": attack_id,
                "category": category,
                "model_used": model_used,
                "session_id": self.session_id,
            }
        )

        client = self._ensure_client()
        if client is None:
            yield _NoopSpan(name=agent_name)
            return

        span = client.start_observation(
            name=agent_name,
            as_type="agent",
            input=scrubbed_inputs,
            metadata=metadata,
        )
        wrapped = _ScrubbingSpanWrapper(span=span)
        try:
            yield wrapped
        except Exception as exc:
            wrapped.update(level="ERROR", status_message=str(exc)[:500])
            wrapped.end()
            raise
        else:
            wrapped.end()

    def flush(self) -> None:
        """Flush buffered events to Langfuse. Call before process exit."""
        client = self._ensure_client()
        if client is not None:
            try:
                client.flush()
            except Exception as exc:  # noqa: BLE001 — observability failures shouldn't crash
                logger.warning("Langfuse flush failed: %s", exc)


@dataclass
class _ScrubbingSpanWrapper:
    """Wraps a Langfuse span so every .update(output=, metadata=) call passes
    its payload through the PHI scrubber before forwarding."""

    span: Any

    def update(self, **kwargs: Any) -> None:
        scrubbed = {k: scrub_phi(v) for k, v in kwargs.items()}
        self.span.update(**scrubbed)

    def end(self, **kwargs: Any) -> None:
        scrubbed = {k: scrub_phi(v) for k, v in kwargs.items()}
        self.span.end(**scrubbed)


__all__ = [
    "Observability",
    "SpanHandle",
    "scrub_phi",
]
