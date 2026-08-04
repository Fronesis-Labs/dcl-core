"""
dcl_core.consensus — cross-organizational Super-Hash consensus (from dcl-v2).

Fix vs the original formula H*_t = hash(h_t1 XOR h_t2 XOR ... XOR h_tM):

XOR is commutative and reversible. Any party that contributes last (or that
can observe the running combination before submitting) can solve for a
value h_tM such that the final H*_t equals whatever they want — without
breaking any individual party's hash function. That means a dishonest party
could forge apparent consensus cheaply, via arithmetic on XOR, not via a
cryptographic break.

Fix: combine contributions by hashing their SORTED, length-prefixed
concatenation instead of XOR-ing them. Sorting makes the result independent
of submission order (so no party gains an advantage by going last), and
concatenation removes the XOR-invertibility problem. This is a Merkle-style
combine, not full tree construction — sufficient for a fixed, known set of M
parties; swap in a real Merkle tree if M grows large or is dynamic.
"""

import hashlib
from typing import Dict, Tuple


def sha256hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def compute_super_hash(party_hashes: Dict[str, str]) -> str:
    """Combine per-party hashes into a single cross-organizational commitment.

    party_hashes: mapping of party_id -> that party's local hash (h_ti) for
    timestep t. Order of insertion does not matter — contributions are
    sorted by party_id before combining, so no party can bias the result by
    controlling submission order.
    """
    if not party_hashes:
        raise ValueError("compute_super_hash requires at least one party contribution")

    # Sort by party_id for order-independence, then length-prefix each hash
    # to prevent ambiguous concatenation (e.g. "ab"+"c" vs "a"+"bc").
    parts = []
    for party_id in sorted(party_hashes.keys()):
        h = party_hashes[party_id]
        parts.append(f"{len(party_id)}:{party_id}:{len(h)}:{h}")

    combined = "|".join(parts)
    return "0x" + sha256hex(combined)


def verify_super_hash(party_hashes: Dict[str, str], claimed_super_hash: str) -> bool:
    """Recompute the Super-Hash from party contributions and compare."""
    return compute_super_hash(party_hashes) == claimed_super_hash


class ConsensusRound:
    """Collects per-party hash contributions for one timestep and seals them
    only once all expected parties have submitted (commit-reveal shape:
    collect first, combine once, never recombine on partial data)."""

    def __init__(self, expected_parties: set):
        self.expected_parties = set(expected_parties)
        self._contributions: Dict[str, str] = {}
        self._sealed_super_hash: str | None = None

    def submit(self, party_id: str, h_t: str) -> None:
        if self._sealed_super_hash is not None:
            raise RuntimeError("round already sealed; cannot accept further contributions")
        if party_id not in self.expected_parties:
            raise ValueError(f"unexpected party_id: {party_id}")
        self._contributions[party_id] = h_t

    @property
    def is_complete(self) -> bool:
        return set(self._contributions.keys()) == self.expected_parties

    def seal(self) -> Tuple[str, Dict[str, str]]:
        if not self.is_complete:
            missing = self.expected_parties - set(self._contributions.keys())
            raise RuntimeError(f"cannot seal: missing contributions from {missing}")
        self._sealed_super_hash = compute_super_hash(self._contributions)
        return self._sealed_super_hash, dict(self._contributions)
