# DCL Core

[![PyPI version](https://img.shields.io/pypi/v/dcl-core)](https://pypi.org/project/dcl-core/)
[![Python versions](https://img.shields.io/pypi/pyversions/dcl-core)](https://pypi.org/project/dcl-core/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/Fronesis-Labs/dcl-core/blob/main/LICENSE)

**Don't trust the agent. Trust the proof.**

Python reference implementation of the tamper-evident record chain and
multi-party consensus primitives behind DCL — the audit layer for
autonomous AI agent decisions. Given a chain record, `dcl-core` recomputes
its hash locally and tells you if it was tampered with. No API key, no
network call, no trust placed in whoever is showing you the record.

Part of the Deterministic Commitment Layer / Leibniz Layer™ ecosystem by
Fronesis Labs.

## Why This Package Is Free

Verifying that an audit record hasn't been altered is a different problem
from generating the verdict in the first place — and it's the one part of
an audit system that *must* be independently checkable, or the audit trail
isn't really independent. If you can only verify a record by paying the
same party who might have edited it, that's not verification, it's trust
with extra steps.

So the protocol itself is open, Apache-2.0, and has no server dependency
for its core function. `dcl-core` is the reference implementation for
Python; [`@fronesis-labs/dcl-sdk`](https://github.com/Fronesis-Labs/dcl-sdk)
is the byte-for-byte-compatible equivalent for TypeScript/JavaScript. DCL's
paid layer — running an agent's output through policy and getting a
verdict — lives separately in
[`dcl-webhook`](https://github.com/Fronesis-Labs/dcl-webhook).

This is a clean-history consolidation: the single-agent chain logic
previously duplicated inside `dcl-webhook`, and the multi-agent consensus
logic from `dcl-v2`, unified into one module with two known issues fixed.

## Two Integrity Fixes Worth Knowing About

### 1. `ChainState.verify()` now catches content tampering, not just broken links

The chain logic previously embedded in `dcl-webhook/dcl_core.py` only
checked that `prev_hash` pointers linked correctly between rows. It never
recomputed a row's hash from its own stored fields. That meant a party with
direct database access could edit `verdict`, `confidence`, or `reason` on
an existing row — without touching `tx_hash`/`prev_hash` — and `verify()`
would still report the chain as clean. That defeated the core tamper-evident
claim.

`verify()` here recomputes each row's hash from all of its stored fields
and compares it against the stored `tx_hash`. Editing any field now breaks
verification. See
`tests/test_fixes.py::test_detects_content_tamper_not_just_link_break`.

### 2. Multi-party consensus no longer forgeable via XOR

`dcl-v2`'s original formula was `H*_t = hash(h_t1 ⊕ h_t2 ⊕ ... ⊕ h_tM)`.
XOR is commutative and reversible: a party submitting last — or able to
observe the running combination — could solve for a contribution that
forces the final Super-Hash to any target value, without breaking any hash
function. Cheap arithmetic forgery, not a cryptographic break, but a real
one.

`compute_super_hash()` instead sorts contributions by party ID and hashes
their length-prefixed concatenation. Order no longer matters (no
last-mover advantage) and the XOR-forgery trick no longer works. See
`tests/test_fixes.py::test_super_hash_xor_forgery_no_longer_trivial`.

## Structure

```
dcl_core/
├── __init__.py
├── chain.py       ChainState — append-only chain, content-hash verify()
├── consensus.py   ConsensusRound, compute_super_hash — multi-party consensus
├── seal.py        format_seal() — human-readable "Verified by..." seal, mirrors dcl-sdk's seal.ts
└── verify.py      verify_chain() — standalone offline chain verification, mirrors dcl-sdk's verify.ts
tests/
└── test_fixes.py  Regression tests for both fixes above
```

## Quick Start

```bash
pip install -e .
python -m pytest tests/ -v
```

```python
from dcl_core import ChainState

chain = ChainState("audit.db")
tx_hash, idx = chain.append(
    verdict="COMMIT", input_hash="0xabc...", policy_hash="0xdef...",
    agent_id="agent-1", reason="policy checks passed", confidence=0.95,
    task_type="generation",
)

clean, bad_index, reason = chain.verify()
```

```python
from dcl_core import ConsensusRound, verify_super_hash

round_ = ConsensusRound(expected_parties={"org-a", "org-b", "org-c"})
round_.submit("org-a", h_a)
round_.submit("org-b", h_b)
round_.submit("org-c", h_c)
super_hash, contributions = round_.seal()
assert verify_super_hash(contributions, super_hash)
```

## Scope

This repo publishes the **protocol layer only** — record format, hash-chain
verification, and consensus combination. Scoring/policy engines (behavioral
fingerprinting, epistemic validation thresholds, reputation weighting) stay
in separate, closed modules that build on top of this.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
