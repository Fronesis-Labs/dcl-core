"""
dcl_core.verify — standalone, offline chain verification.

This is the Python counterpart to `verifyChain()` / `recomputeTxHash()` /
`canonicalContent()` in `@fronesis-labs/dcl-sdk` (TypeScript). It operates
on plain dicts (the same shape `ChainState.export()` / `get_by_tx()`
return) — no SQLite, no network. Anyone holding a chain export (their own,
or fetched from someone else's server) can independently confirm it wasn't
tampered with, without trusting the server that handed it to them.

Implements PROTOCOL.md §1 (canonical content string), §2 (chain linking),
§3 (verification algorithm). `canonical_content()` here and
`ChainState._content_for_hash()` in chain.py must stay byte-identical —
that invariant is what `tests/test_verify_matches_chain_state.py` checks.
"""

import hashlib
import json
from dataclasses import dataclass
from typing import Optional

GENESIS = "0" * 64


def sha256hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def canonical_content(record: dict) -> str:
    """§1 — the exact pipe-delimited string that gets SHA-256 hashed.

    `record` must have: index, verdict, input_hash, policy_hash, prev_hash,
    agent_id, reason, confidence, task_type, timestamp, drift_context.
    """
    drift_context = record.get("drift_context") or {}
    drift_context_json = json.dumps(drift_context, sort_keys=True)
    return "|".join(
        [
            str(record["index"]),
            record["verdict"],
            record["input_hash"],
            record["policy_hash"],
            record["prev_hash"],
            record["agent_id"],
            record["reason"],
            f"{record['confidence']:.6f}",
            record["task_type"],
            f"{record['timestamp']:.6f}",
            drift_context_json,
        ]
    )


def recompute_tx_hash(record: dict) -> str:
    """§1.2 — recomputes tx_hash for a single record from its stored fields."""
    return "0x" + sha256hex(canonical_content(record))


@dataclass
class VerifyResult:
    clean: bool
    bad_index: Optional[int] = None
    reason: Optional[str] = None


def verify_chain(records: list) -> VerifyResult:
    """§3 — full verification: chain-link continuity AND per-record
    content-hash recomputation. Catches direct-DB edits that a server's
    own /audit response can't be trusted to admit to.
    """
    sorted_records = sorted(records, key=lambda r: r["index"])
    expected_prev = GENESIS

    for r in sorted_records:
        if r["prev_hash"] != expected_prev:
            return VerifyResult(
                clean=False,
                bad_index=r["index"],
                reason="prev_hash does not match preceding tx_hash (link broken)",
            )
        recomputed = recompute_tx_hash(r)
        if recomputed != r["tx_hash"]:
            return VerifyResult(
                clean=False,
                bad_index=r["index"],
                reason="stored tx_hash does not match recomputed hash of row content (row was edited)",
            )
        expected_prev = r["tx_hash"]

    return VerifyResult(clean=True)
