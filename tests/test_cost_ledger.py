"""Cost ledger tests (ARCH §8.1)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from clinical_redteam.cost_ledger import (
    LEDGER_FILENAME,
    CostCapExceededError,
    CostLedger,
    CostLedgerError,
)


def test_create_persists_empty_ledger(tmp_path: Path) -> None:
    ledger = CostLedger.create(run_dir=tmp_path, cost_cap_usd=10.0)
    assert ledger.ledger_path == tmp_path / LEDGER_FILENAME
    assert ledger.ledger_path.exists()
    assert ledger.total_usd == 0.0
    assert all(v == 0 for v in ledger.by_tier_usd.values())


def test_record_updates_totals_and_persists(tmp_path: Path) -> None:
    ledger = CostLedger.create(run_dir=tmp_path, cost_cap_usd=10.0)
    ledger.record(
        tier="red_team",
        model_used="dolphin-mixtral",
        cost_usd=0.0023,
        tokens_input=120,
        tokens_output=80,
        related_id="atk_2026-05-13_001",
    )
    ledger.record(
        tier="judge",
        model_used="claude-sonnet-4",
        cost_usd=0.012,
        tokens_input=420,
        tokens_output=150,
        related_id="ver_2026-05-13_001",
    )
    assert ledger.total_usd == pytest.approx(0.0143)
    assert ledger.by_tier_usd["red_team"] == pytest.approx(0.0023)
    assert ledger.by_tier_usd["judge"] == pytest.approx(0.012)
    assert ledger.by_tier_calls["red_team"] == 1
    assert ledger.by_tier_calls["judge"] == 1
    assert ledger.by_tier_calls["documentation"] == 0

    on_disk = json.loads(ledger.ledger_path.read_text())
    assert on_disk["total_usd"] == pytest.approx(0.0143)
    assert len(on_disk["entries"]) == 2


def test_record_rejects_negative_cost(tmp_path: Path) -> None:
    ledger = CostLedger.create(run_dir=tmp_path, cost_cap_usd=10.0)
    with pytest.raises(CostLedgerError, match="non-negative"):
        ledger.record(
            tier="red_team",
            model_used="m",
            cost_usd=-0.01,
            tokens_input=0,
            tokens_output=0,
        )


def test_record_rejects_unknown_tier(tmp_path: Path) -> None:
    ledger = CostLedger.create(run_dir=tmp_path, cost_cap_usd=10.0)
    with pytest.raises(CostLedgerError, match="Unknown tier"):
        ledger.record(
            tier="rogue",  # type: ignore[arg-type]
            model_used="m",
            cost_usd=0.001,
            tokens_input=0,
            tokens_output=0,
        )


def test_would_exceed_cap(tmp_path: Path) -> None:
    ledger = CostLedger.create(run_dir=tmp_path, cost_cap_usd=1.0)
    ledger.record(
        tier="red_team", model_used="m", cost_usd=0.9, tokens_input=0, tokens_output=0
    )
    assert ledger.would_exceed_cap(0.05) is False
    assert ledger.would_exceed_cap(0.2) is True


def test_assert_within_cap_raises_when_exceeded(tmp_path: Path) -> None:
    ledger = CostLedger.create(run_dir=tmp_path, cost_cap_usd=1.0)
    ledger.record(
        tier="red_team", model_used="m", cost_usd=0.9, tokens_input=0, tokens_output=0
    )
    ledger.assert_within_cap(0.05)  # ok
    with pytest.raises(CostCapExceededError) as info:
        ledger.assert_within_cap(0.2)
    assert info.value.cap == 1.0
    assert info.value.total == pytest.approx(1.1)


def test_soft_cap_trips_at_50_percent(tmp_path: Path) -> None:
    ledger = CostLedger.create(run_dir=tmp_path, cost_cap_usd=10.0)
    assert ledger.soft_cap_tripped() is False
    ledger.record(
        tier="red_team", model_used="m", cost_usd=4.99, tokens_input=0, tokens_output=0
    )
    assert ledger.soft_cap_tripped() is False
    ledger.record(
        tier="red_team", model_used="m", cost_usd=0.02, tokens_input=0, tokens_output=0
    )
    assert ledger.soft_cap_tripped() is True


def test_load_reads_back_full_state(tmp_path: Path) -> None:
    ledger = CostLedger.create(run_dir=tmp_path, cost_cap_usd=10.0)
    ledger.record(
        tier="red_team", model_used="m1", cost_usd=0.5, tokens_input=10, tokens_output=20
    )
    ledger.record(
        tier="judge", model_used="m2", cost_usd=1.2, tokens_input=30, tokens_output=40
    )

    loaded = CostLedger.load(run_dir=tmp_path)
    assert loaded.total_usd == pytest.approx(1.7)
    assert loaded.by_tier_usd["red_team"] == pytest.approx(0.5)
    assert loaded.by_tier_usd["judge"] == pytest.approx(1.2)
    assert loaded.by_tier_calls["red_team"] == 1
    assert loaded.by_tier_calls["judge"] == 1
    assert len(loaded.entries) == 2


def test_load_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(CostLedgerError, match="No cost ledger"):
        CostLedger.load(run_dir=tmp_path)


def test_load_schema_mismatch_raises(tmp_path: Path) -> None:
    ledger = CostLedger.create(run_dir=tmp_path, cost_cap_usd=10.0)
    raw = json.loads(ledger.ledger_path.read_text())
    raw["schema_version"] = 99
    ledger.ledger_path.write_text(json.dumps(raw))
    with pytest.raises(CostLedgerError, match="schema_version"):
        CostLedger.load(run_dir=tmp_path)
