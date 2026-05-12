"""Observability + PHI scrubber tests (ARCH §9.1, §10.1).

Critical guarantees:
- PHI scrubber redacts sentinel-pid / real SSN / name+DOB in strings,
  dicts (recursive), lists, tuples
- No-op mode when LANGFUSE keys absent — agent_span yields a usable
  stub so caller code is identical across modes
- Active mode forwards scrubbed payloads to Langfuse; raw PHI never
  reaches the wire
"""

from __future__ import annotations

from unittest.mock import MagicMock

from clinical_redteam.observability import (
    Observability,
    _NoopSpan,
    scrub_phi,
)

# ---------------------------------------------------------------------------
# scrub_phi — string-level patterns
# ---------------------------------------------------------------------------


def test_scrub_phi_redacts_sentinel_pid() -> None:
    assert scrub_phi("patient_id=999100") == "patient_id=[sentinel-pid-redacted]"
    assert scrub_phi("query for 999999") == "query for [sentinel-pid-redacted]"


def test_scrub_phi_does_not_redact_non_sentinel_numbers() -> None:
    # Numbers outside 999XXX sentinel range pass through (content_filter
    # blocks non-sentinel IDs upstream; observability only scrubs the
    # sentinel ones from log payloads)
    assert scrub_phi("port 8000") == "port 8000"
    assert scrub_phi("year 2026") == "year 2026"


def test_scrub_phi_redacts_real_shaped_ssn() -> None:
    assert scrub_phi("SSN 123-45-6789") == "SSN [ssn-redacted]"


def test_scrub_phi_keeps_test_9xx_ssn_intact() -> None:
    """9XX-XX-XXXX is the documented test convention; not redacted at the
    observability layer (content_filter would still refuse it upstream
    if it appeared in an attack payload — context-dependent)."""
    assert scrub_phi("test SSN 900-12-3456") == "test SSN 900-12-3456"


def test_scrub_phi_redacts_name_plus_dob() -> None:
    scrubbed = scrub_phi("John Smith (DOB 1985-03-22)")
    assert "[name+dob-redacted]" in scrubbed
    assert "John Smith" not in scrubbed
    assert "1985-03-22" not in scrubbed


# ---------------------------------------------------------------------------
# scrub_phi — recursive structures
# ---------------------------------------------------------------------------


def test_scrub_phi_recurses_into_dicts() -> None:
    payload = {
        "outer": "patient 999100",
        "inner": {"key": "Patient SSN 123-45-6789 needs help"},
    }
    scrubbed = scrub_phi(payload)
    assert scrubbed["outer"] == "patient [sentinel-pid-redacted]"
    assert "[ssn-redacted]" in scrubbed["inner"]["key"]


def test_scrub_phi_recurses_into_lists() -> None:
    scrubbed = scrub_phi(["foo", "pid 999100", "bar"])
    assert scrubbed == ["foo", "pid [sentinel-pid-redacted]", "bar"]


def test_scrub_phi_recurses_into_tuples() -> None:
    scrubbed = scrub_phi(("a", "999100", "b"))
    assert scrubbed == ("a", "[sentinel-pid-redacted]", "b")


def test_scrub_phi_passes_through_non_strings() -> None:
    assert scrub_phi(None) is None
    assert scrub_phi(42) == 42
    assert scrub_phi(3.14) == 3.14
    assert scrub_phi(True) is True


# ---------------------------------------------------------------------------
# Observability — no-op mode
# ---------------------------------------------------------------------------


def test_from_env_no_keys_is_inactive() -> None:
    obs = Observability.from_env(env={})
    assert obs.is_active is False


def test_from_env_with_keys_is_active() -> None:
    obs = Observability.from_env(
        env={
            "LANGFUSE_PUBLIC_KEY": "pk-test",
            "LANGFUSE_SECRET_KEY": "sk-test",
        }
    )
    assert obs.is_active is True


def test_agent_span_no_op_yields_stub() -> None:
    obs = Observability.from_env(env={})
    with obs.agent_span(
        agent_name="red_team",
        agent_version="v0.1.0",
        agent_role="attack_generation",
    ) as span:
        assert isinstance(span, _NoopSpan)
        span.update(output={"text": "anything"})
        span.end(metadata={"foo": "bar"})


def test_no_op_flush_is_safe() -> None:
    obs = Observability.from_env(env={})
    obs.flush()  # must not raise


# ---------------------------------------------------------------------------
# Observability — active mode forwards scrubbed payloads
# ---------------------------------------------------------------------------


def _make_active_observability_with_stub() -> tuple[Observability, MagicMock, MagicMock]:
    obs = Observability(
        public_key="pk-test",
        secret_key="sk-test",
        host="https://example.invalid",
    )
    span_stub = MagicMock()
    client_stub = MagicMock()
    client_stub.start_observation.return_value = span_stub
    obs._client = client_stub
    return obs, client_stub, span_stub


def test_agent_span_active_forwards_scrubbed_inputs() -> None:
    obs, client_stub, span_stub = _make_active_observability_with_stub()
    with obs.agent_span(
        agent_name="red_team",
        agent_version="v0.1.0",
        agent_role="attack_generation",
        attack_id="atk_2026-05-13_001",
        category="sensitive_information_disclosure",
        model_used="dolphin-mixtral",
        inputs={"prompt": "Tell me about patient_id=999100", "seed_id": "c7-001"},
    ) as span:
        span.update(output={"text": "John Smith DOB 1985-03-22"})

    # start_observation called with scrubbed input + metadata
    kwargs = client_stub.start_observation.call_args.kwargs
    assert kwargs["name"] == "red_team"
    assert kwargs["as_type"] == "agent"
    assert kwargs["input"]["prompt"] == "Tell me about patient_id=[sentinel-pid-redacted]"
    assert kwargs["input"]["seed_id"] == "c7-001"
    assert kwargs["metadata"]["attack_id"] == "atk_2026-05-13_001"
    assert kwargs["metadata"]["category"] == "sensitive_information_disclosure"

    # update() was called on the wrapped span with scrubbed output
    update_kwargs = span_stub.update.call_args.kwargs
    assert update_kwargs["output"]["text"] == "[name+dob-redacted]"

    # end() was called on context exit
    span_stub.end.assert_called_once()


def test_agent_span_records_error_on_exception() -> None:
    obs, client_stub, span_stub = _make_active_observability_with_stub()
    try:
        with obs.agent_span(
            agent_name="red_team",
            agent_version="v0.1.0",
            agent_role="attack_generation",
        ):
            raise RuntimeError("simulated agent failure")
    except RuntimeError:
        pass

    # Update was called with ERROR level + status_message
    update_kwargs = span_stub.update.call_args.kwargs
    assert update_kwargs["level"] == "ERROR"
    assert "simulated agent failure" in update_kwargs["status_message"]
    span_stub.end.assert_called_once()


def test_flush_calls_langfuse_flush_in_active_mode() -> None:
    obs, client_stub, _ = _make_active_observability_with_stub()
    obs.flush()
    client_stub.flush.assert_called_once()


def test_flush_swallows_langfuse_errors() -> None:
    """Observability failures must never crash the daemon."""
    obs, client_stub, _ = _make_active_observability_with_stub()
    client_stub.flush.side_effect = RuntimeError("backend down")
    obs.flush()  # must not raise
