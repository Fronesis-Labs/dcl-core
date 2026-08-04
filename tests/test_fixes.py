"""
Regression tests for the two fixes:
  1. ChainState.verify() must detect content tampering, not just broken links.
  2. Super-Hash consensus must resist the XOR-forgeability attack.
"""

import os
import tempfile

import pytest

from dcl_core.chain import ChainState
from dcl_core.consensus import compute_super_hash, verify_super_hash, ConsensusRound


def make_chain():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.remove(path)  # let sqlite create it fresh
    return ChainState(path), path


def test_clean_chain_verifies():
    chain, path = make_chain()
    chain.append("COMMIT", "ih1", "ph1", "agent-1", "ok", 0.95, "test")
    chain.append("COMMIT", "ih2", "ph1", "agent-1", "ok", 0.90, "test")
    clean, bad_idx, reason = chain.verify()
    assert clean is True
    assert bad_idx is None


def test_detects_content_tamper_not_just_link_break():
    """This is the core regression: editing a field WITHOUT touching
    tx_hash/prev_hash used to pass the old verify(). It must now fail."""
    chain, path = make_chain()
    chain.append("NO_COMMIT", "ih1", "ph1", "agent-1", "policy violation", 0.10, "test")

    # Simulate an attacker with direct DB access flipping the verdict,
    # leaving tx_hash and prev_hash untouched.
    conn = chain._conn
    conn.execute("UPDATE chain SET verdict = 'COMMIT', confidence = 0.99 WHERE idx = 0")
    conn.commit()

    clean, bad_idx, reason = chain.verify()
    assert clean is False
    assert bad_idx == 0
    assert "recomputed hash" in reason


def test_detects_broken_link():
    chain, path = make_chain()
    chain.append("COMMIT", "ih1", "ph1", "agent-1", "ok", 0.95, "test")
    chain.append("COMMIT", "ih2", "ph1", "agent-1", "ok", 0.90, "test")

    conn = chain._conn
    conn.execute("UPDATE chain SET prev_hash = 'deadbeef' WHERE idx = 1")
    conn.commit()

    clean, bad_idx, reason = chain.verify()
    assert clean is False
    assert bad_idx == 1


def test_super_hash_order_independent():
    contributions = {"org-a": "h_a", "org-b": "h_b", "org-c": "h_c"}
    h1 = compute_super_hash(contributions)
    h2 = compute_super_hash({"org-c": "h_c", "org-a": "h_a", "org-b": "h_b"})
    assert h1 == h2


def test_super_hash_xor_forgery_no_longer_trivial():
    """Under the old XOR scheme, a party submitting last could pick h_tM
    such that h_t1 ^ h_t2 ^ ... ^ h_tM equals any target value, by solving
    h_tM = target ^ (h_t1 ^ ... ^ h_t(M-1)). Demonstrate that trick no
    longer forges the new (concatenation-based) Super-Hash."""
    h_a = "aa" * 32
    h_b = "bb" * 32
    target = "11" * 32  # attacker's desired forged super-hash (hex string)

    # The old XOR-forgery move: compute h_c that would XOR the others to `target`.
    def xor_hex(x: str, y: str) -> str:
        return format(int(x, 16) ^ int(y, 16), f"0{len(x)}x")

    forged_h_c = xor_hex(xor_hex(h_a, h_b), target)

    # Under the fixed scheme this forged value does not produce `target`.
    forged_super_hash = compute_super_hash({"org-a": h_a, "org-b": h_b, "org-c": forged_h_c})
    assert forged_super_hash != "0x" + target


def test_consensus_round_requires_all_parties_before_sealing():
    round_ = ConsensusRound(expected_parties={"org-a", "org-b"})
    round_.submit("org-a", "h_a")
    assert round_.is_complete is False
    with pytest.raises(RuntimeError):
        round_.seal()

    round_.submit("org-b", "h_b")
    assert round_.is_complete is True
    super_hash, contributions = round_.seal()
    assert verify_super_hash(contributions, super_hash)
