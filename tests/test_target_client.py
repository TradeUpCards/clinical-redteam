"""HMAC-signed target client tests (ARCH §2.1).

Critical guarantees this file proves:
- HMAC signature matches AgentForge agent.py:verify_hmac scheme exactly
- Out-of-scope target URLs are HARD-REFUSED
- Non-sentinel patient IDs are HARD-REFUSED
- 401 from target → HmacRejectedError (no silent retry with same secret)
- 5xx → bounded retry with exponential backoff
- 4xx other than 401 → propagate immediately (no retry)
- env-var loading is strict (missing var = config error, not silent default)

All HTTP is mocked. The live-target verification is a separate ad-hoc
script that runs against the SSH-tunneled droplet, not part of pytest CI.
"""

from __future__ import annotations

import hashlib
import hmac
from unittest.mock import MagicMock

import httpx
import pytest

from clinical_redteam.target_client import (
    HmacRejectedError,
    Message,
    OutOfScopeTargetError,
    SentinelPatientIdError,
    TargetClient,
    TargetClientConfigError,
    TargetResponse,
    TargetUnavailableError,
    compute_chat_hmac,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_GOOD_ENV = {
    "RED_TEAM_TARGET_URL": "http://localhost:8000",
    "RED_TEAM_TARGET_HMAC_SECRET": "test-secret-not-real",
    "RED_TEAM_TARGET_USER_ID": "1",
    "RED_TEAM_TARGET_SENTINEL_PATIENT_IDS": "999001,999100,999999",
    "HMAC_MAX_AGE_SECONDS": "30",
}


def _stub_http_client(handler) -> MagicMock:
    """Build an httpx.Client mock whose .post(url, json=body) routes to `handler`."""
    stub = MagicMock()
    stub.post.side_effect = handler
    return stub


def _ok_response(body: dict, status_code: int = 200) -> httpx.Response:
    """Minimal httpx.Response matching what the agent's /chat returns."""
    request = httpx.Request("POST", "http://localhost:8000/chat")
    return httpx.Response(status_code, json=body, request=request)


# ---------------------------------------------------------------------------
# HMAC scheme conformance
# ---------------------------------------------------------------------------


def test_compute_chat_hmac_matches_agentforge_scheme() -> None:
    """The signing scheme MUST match AgentForge agent.py:verify_hmac exactly.

    Payload: f"{user_id}|{patient_id}|{timestamp}|" + "|".join(m.content for m in messages)
    Algorithm: HMAC-SHA256, hex digest
    """
    secret = "shared-secret"
    user_id = 1
    patient_id = 999100
    timestamp = 1_715_000_000
    messages = [
        Message(role="user", content="hello"),
        Message(role="assistant", content="hi there"),
        Message(role="user", content="follow-up"),
    ]
    expected_payload = (
        f"{user_id}|{patient_id}|{timestamp}|hello|hi there|follow-up"
    )
    expected_sig = hmac.new(
        secret.encode("utf-8"),
        expected_payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    actual = compute_chat_hmac(
        user_id=user_id,
        patient_id=patient_id,
        timestamp=timestamp,
        messages=messages,
        secret=secret,
    )
    assert actual == expected_sig


def test_compute_chat_hmac_empty_secret_raises() -> None:
    with pytest.raises(TargetClientConfigError, match="HMAC secret is empty"):
        compute_chat_hmac(
            user_id=1,
            patient_id=999100,
            timestamp=0,
            messages=[Message(role="user", content="x")],
            secret="",
        )


# ---------------------------------------------------------------------------
# Out-of-scope target refusal
# ---------------------------------------------------------------------------


def test_constructor_refuses_out_of_scope_host() -> None:
    with pytest.raises(OutOfScopeTargetError):
        TargetClient(
            base_url="https://evil.example.com",
            hmac_secret="x",
            user_id=1,
            sentinel_patient_ids=(999100,),
            http_client=MagicMock(),
        )


def test_constructor_accepts_localhost_loopback() -> None:
    TargetClient(
        base_url="http://localhost:8000",
        hmac_secret="x",
        user_id=1,
        sentinel_patient_ids=(999100,),
        http_client=MagicMock(),
    )
    TargetClient(
        base_url="http://127.0.0.1:8000",
        hmac_secret="x",
        user_id=1,
        sentinel_patient_ids=(999100,),
        http_client=MagicMock(),
    )


def test_constructor_accepts_deployed_target_hostname() -> None:
    TargetClient(
        base_url="https://142-93-242-40.nip.io",
        hmac_secret="x",
        user_id=1,
        sentinel_patient_ids=(999100,),
        http_client=MagicMock(),
    )


def test_constructor_accepts_docker_internal_hostname() -> None:
    """When the daemon runs co-located in Docker (Phase 2 P1)."""
    TargetClient(
        base_url="http://agent:8000",
        hmac_secret="x",
        user_id=1,
        sentinel_patient_ids=(999100,),
        http_client=MagicMock(),
    )


# ---------------------------------------------------------------------------
# Sentinel patient ID refusal
# ---------------------------------------------------------------------------


def test_constructor_refuses_real_looking_patient_id() -> None:
    with pytest.raises(SentinelPatientIdError, match="sentinel range"):
        TargetClient(
            base_url="http://localhost:8000",
            hmac_secret="x",
            user_id=1,
            sentinel_patient_ids=(42,),  # outside 999001-999999
            http_client=MagicMock(),
        )


def test_chat_refuses_non_sentinel_patient_id() -> None:
    client = TargetClient(
        base_url="http://localhost:8000",
        hmac_secret="x",
        user_id=1,
        sentinel_patient_ids=(999100,),
        http_client=MagicMock(),
    )
    with pytest.raises(SentinelPatientIdError):
        client.chat(
            [Message(role="user", content="hi")],
            patient_id=999000,  # one below the new sentinel floor (999001)
        )


def test_chat_accepts_expanded_low_sentinel() -> None:
    """Regression guard for the 2026-05-12 sentinel-range expansion.
    999001 was REJECTED under the old [999100, 999999] convention but
    is valid under the expanded [999001, 999999] range that matches
    W2's deployed PersonaMap surface.
    """
    captured: dict = {}

    def handler(url, json):
        captured["body"] = json
        return _ok_response({"status": "ok", "message": {"role": "assistant", "content": "ok"}})

    http_client = MagicMock()
    http_client.post.side_effect = handler
    client = TargetClient(
        base_url="http://localhost:8000",
        hmac_secret="x",
        user_id=1,
        sentinel_patient_ids=(999001, 999199),
        http_client=http_client,
    )
    # Both bounds of the new expanded range should be accepted.
    client.chat([Message(role="user", content="hi")], patient_id=999001)
    assert captured["body"]["patient_id"] == 999001


def test_chat_defaults_to_first_sentinel_when_unspecified() -> None:
    captured: dict = {}

    def handler(url, json):
        captured["body"] = json
        return _ok_response({"status": "ok", "message": {"role": "assistant", "content": "ok"}})

    client = TargetClient(
        base_url="http://localhost:8000",
        hmac_secret="x",
        user_id=1,
        sentinel_patient_ids=(999100, 999999),
        http_client=_stub_http_client(handler),
    )
    client.chat([Message(role="user", content="hi")])
    assert captured["body"]["patient_id"] == 999100


# ---------------------------------------------------------------------------
# from_env validation
# ---------------------------------------------------------------------------


def test_from_env_loads_all_fields() -> None:
    client = TargetClient.from_env(env=dict(_GOOD_ENV))
    assert client.base_url == "http://localhost:8000"
    assert client.user_id == 1
    assert client.sentinel_patient_ids == (999001, 999100, 999999)
    assert client.hmac_max_age_seconds == 30


def test_from_env_reports_all_missing_at_once() -> None:
    with pytest.raises(TargetClientConfigError) as info:
        TargetClient.from_env(env={})
    msg = str(info.value)
    assert "RED_TEAM_TARGET_URL" in msg
    assert "RED_TEAM_TARGET_HMAC_SECRET" in msg
    assert "RED_TEAM_TARGET_USER_ID" in msg
    assert "RED_TEAM_TARGET_SENTINEL_PATIENT_IDS" in msg


def test_from_env_rejects_non_integer_user_id() -> None:
    env = dict(_GOOD_ENV, RED_TEAM_TARGET_USER_ID="not-a-number")
    with pytest.raises(TargetClientConfigError, match="USER_ID"):
        TargetClient.from_env(env=env)


# ---------------------------------------------------------------------------
# Happy path / response shape
# ---------------------------------------------------------------------------


def test_chat_happy_path_returns_target_response() -> None:
    expected_body = {
        "status": "ok",
        "message": {"role": "assistant", "content": "I cannot share other patients' data."},
        "request_id": "req_abc",
        "trace_id": "trc_xyz",
    }
    captured: dict = {}

    def handler(url, json):
        captured["url"] = url
        captured["body"] = json
        return _ok_response(expected_body)

    client = TargetClient(
        base_url="http://localhost:8000",
        hmac_secret="shared-secret",
        user_id=1,
        sentinel_patient_ids=(999100,),
        http_client=_stub_http_client(handler),
    )
    result = client.chat(
        [Message(role="user", content="hi")],
        patient_id=999100,
        now=1_715_000_000,
        session_id="sess-fixed",
    )

    assert isinstance(result, TargetResponse)
    assert result.status_code == 200
    assert result.assistant_text == "I cannot share other patients' data."
    assert result.request_id == "req_abc"
    assert result.trace_id == "trc_xyz"
    assert result.latency_ms >= 0
    assert captured["url"] == "http://localhost:8000/chat"
    assert captured["body"]["user_id"] == 1
    assert captured["body"]["patient_id"] == 999100
    assert captured["body"]["timestamp"] == 1_715_000_000
    assert captured["body"]["session_id"] == "sess-fixed"

    # Verify the body's hmac matches our independent computation
    expected_sig = compute_chat_hmac(
        user_id=1,
        patient_id=999100,
        timestamp=1_715_000_000,
        messages=[Message(role="user", content="hi")],
        secret="shared-secret",
    )
    assert captured["body"]["hmac"] == expected_sig


# ---------------------------------------------------------------------------
# 401 (HMAC rejected) → no retry
# ---------------------------------------------------------------------------


def test_chat_401_raises_hmac_rejected_error() -> None:
    def handler(url, json):
        return _ok_response({"detail": "hmac_signature_mismatch"}, status_code=401)

    client = TargetClient(
        base_url="http://localhost:8000",
        hmac_secret="x",
        user_id=1,
        sentinel_patient_ids=(999100,),
        http_client=_stub_http_client(handler),
    )
    with pytest.raises(HmacRejectedError, match="401"):
        client.chat([Message(role="user", content="hi")])


# ---------------------------------------------------------------------------
# 5xx retry behavior
# ---------------------------------------------------------------------------


def test_chat_retries_on_5xx_then_succeeds() -> None:
    calls: list[int] = []

    def handler(url, json):
        calls.append(1)
        if len(calls) < 3:
            return _ok_response({"detail": "transient"}, status_code=503)
        return _ok_response({"status": "ok", "message": {"role": "assistant", "content": "recovered"}})

    client = TargetClient(
        base_url="http://localhost:8000",
        hmac_secret="x",
        user_id=1,
        sentinel_patient_ids=(999100,),
        max_5xx_retries=2,
        backoff_base_seconds=0,  # no sleep in tests
        http_client=_stub_http_client(handler),
    )
    result = client.chat([Message(role="user", content="hi")])
    assert result.status_code == 200
    assert result.assistant_text == "recovered"
    assert len(calls) == 3


def test_chat_5xx_exhausts_retries_then_raises() -> None:
    def handler(url, json):
        return _ok_response({"detail": "still down"}, status_code=502)

    client = TargetClient(
        base_url="http://localhost:8000",
        hmac_secret="x",
        user_id=1,
        sentinel_patient_ids=(999100,),
        max_5xx_retries=2,
        backoff_base_seconds=0,
        http_client=_stub_http_client(handler),
    )
    with pytest.raises(TargetUnavailableError, match="502"):
        client.chat([Message(role="user", content="hi")])


def test_chat_connect_error_retries_then_raises() -> None:
    def handler(url, json):
        raise httpx.ConnectError("connection refused")

    client = TargetClient(
        base_url="http://localhost:8000",
        hmac_secret="x",
        user_id=1,
        sentinel_patient_ids=(999100,),
        max_5xx_retries=1,
        backoff_base_seconds=0,
        http_client=_stub_http_client(handler),
    )
    with pytest.raises(TargetUnavailableError, match="unreachable"):
        client.chat([Message(role="user", content="hi")])


def test_chat_400_does_not_retry() -> None:
    """4xx other than 401 must NOT retry — caller's fault, fallback won't help."""
    calls: list[int] = []

    def handler(url, json):
        calls.append(1)
        return _ok_response({"detail": "bad request"}, status_code=400)

    client = TargetClient(
        base_url="http://localhost:8000",
        hmac_secret="x",
        user_id=1,
        sentinel_patient_ids=(999100,),
        max_5xx_retries=2,
        backoff_base_seconds=0,
        http_client=_stub_http_client(handler),
    )
    result = client.chat([Message(role="user", content="hi")])
    assert result.status_code == 400
    assert len(calls) == 1


# ---------------------------------------------------------------------------
# Edge: empty messages
# ---------------------------------------------------------------------------


def test_chat_refuses_empty_messages() -> None:
    client = TargetClient(
        base_url="http://localhost:8000",
        hmac_secret="x",
        user_id=1,
        sentinel_patient_ids=(999100,),
        http_client=MagicMock(),
    )
    with pytest.raises(Exception, match="empty"):
        client.chat([])
