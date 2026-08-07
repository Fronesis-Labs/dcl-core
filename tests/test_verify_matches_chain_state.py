"""
Confirms dcl_core.verify.verify_chain() (standalone, offline, dict-based)
agrees with ChainState.verify() (SQLite-backed, production) on the exact
same data. If these two ever disagree, cross-language SDK verification
(TS, and anyone else implementing PROTOCOL.md) silently breaks — this is
the guard against that.
"""

import tempfile
import os

from dcl_core.chain import ChainState
from dcl_core.verify import verify_chain, recompute_tx_hash, GENESIS
from dcl_core.seal import format_seal


def _make_chain(n=5):
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    cs = ChainState(db_path=path)
    for i in range(n):
        cs.append(
            verdict="COMMIT" if i % 2 == 0 else "NO_COMMIT",
            input_hash=f"0x{'a' * 63}{i}",
            policy_hash=f"0x{'b' * 63}{i}",
            agent_id=f"agent-{i}",
            reason=f"reason {i}",
            confidence=0.9 + i * 0.001,
            task_type="test",
            drift_context={"environment": "test", "step": i},
        )
    return cs, path


def test_standalone_verify_matches_chain_state_on_clean_chain():
    cs, path = _make_chain(5)
    try:
        clean, bad_index, reason = cs.verify()
        assert clean is True

        records = cs.export()
        result = verify_chain(records)
        assert result.clean is True
        assert result.bad_index is None
    finally:
        os.remove(path)


def test_recompute_tx_hash_matches_stored_hash_for_every_record():
    cs, path = _make_chain(3)
    try:
        for record in cs.export():
            assert recompute_tx_hash(record) == record["tx_hash"]
    finally:
        os.remove(path)


def test_standalone_verify_catches_tampered_row():
    cs, path = _make_chain(4)
    try:
        records = cs.export()
        records[2]["confidence"] = 0.111111  # tamper without touching tx_hash

        result = verify_chain(records)
        assert result.clean is False
        assert result.bad_index == 2
        assert "content hash" in result.reason or "recomputed" in result.reason
    finally:
        os.remove(path)


def test_genesis_prev_hash_constant_matches_chain_state():
    assert GENESIS == ChainState.GENESIS


def test_format_seal_basic_shape():
    seal = format_seal(
        tx_hash="0x" + "a" * 64,
        input_hash="0x" + "b" * 64,
        timestamp=1754400000.123456,
    )
    assert seal["seal_text"].startswith("🔒 Verified by Leibniz Layer | Fronesis Labs")
    assert seal["verify_url"] == "https://x402.fronesislabs.com/verify/" + "a" * 64
    assert "2025-08-05" in seal["seal_text"] or "2025" in seal["seal_text"]


def test_format_seal_white_label_omits_network():
    seal = format_seal(
        tx_hash="0x" + "c" * 64,
        input_hash="0x" + "d" * 64,
        timestamp=1754400000.0,
        brand="My Audit Layer",
        verify_base_url="https://example.com/verify",
        network="",
    )
    assert "My Audit Layer" in seal["seal_text"]
    assert "—" not in seal["seal_text"]
    assert seal["verify_url"] == "https://example.com/verify/" + "c" * 64
