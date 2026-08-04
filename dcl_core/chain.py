"""
dcl_core.chain — append-only tamper-evident record chain.

Fix vs the version previously embedded in dcl-webhook's dcl_core.py:
  - verify() now RECOMPUTES tx_hash from each row's stored content and
    compares it to the stored tx_hash. The old version only checked that
    prev_hash pointers were linked correctly, which meant an attacker with
    direct DB access could edit a row's `verdict`/`confidence`/`reason`
    without touching tx_hash/prev_hash, and verify() would still report the
    chain as clean. That defeated the core "tamper-evident" claim.
  - The timestamp used inside the hashed content is now the SAME value
    stored in the `timestamp` column (previously two separate time.time()
    calls were made, one for hashing and one for storage, making the hash
    permanently unreproducible from stored fields).

Patch (this file): added export() — a plain metadata dump of the full
chain, oldest first. This is read-only access to already-stored fields
(the same shape get_by_tx() returns), not scoring/policy logic, so it
belongs in the open protocol layer. webhook_server.py's GET /chain/export
was calling _chain.export() against a ChainState that never defined it —
this closes that gap.
"""

import hashlib
import json
import sqlite3
import time
from typing import Optional, Tuple


def sha256hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


class TamperDetectedError(Exception):
    """Raised when a stored record's hash does not match its recomputed hash."""

    def __init__(self, index: int, reason: str):
        self.index = index
        self.reason = reason
        super().__init__(f"Tamper detected at index {index}: {reason}")


class ChainState:
    """SQLite-backed tamper-evident chain. Stores METADATA ONLY — never raw content."""

    GENESIS = "0" * 64
    HASH_LEN = 64  # full sha256 hex length; do not truncate (previous version cut to 32)

    def __init__(self, db_path: str = "dcl_chain.db"):
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS chain (
                idx INTEGER PRIMARY KEY,
                tx_hash TEXT UNIQUE NOT NULL,
                prev_hash TEXT NOT NULL,
                verdict TEXT NOT NULL,
                input_hash TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                confidence REAL NOT NULL,
                task_type TEXT NOT NULL,
                timestamp REAL NOT NULL,
                drift_context TEXT NOT NULL
            )
            """
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_tx_hash ON chain(tx_hash)")
        self._conn.commit()

    @staticmethod
    def _content_for_hash(
        idx: int,
        verdict: str,
        input_hash: str,
        policy_hash: str,
        prev_hash: str,
        agent_id: str,
        reason: str,
        confidence: float,
        task_type: str,
        timestamp: float,
        drift_context_json: str,
    ) -> str:
        """Canonical, order-fixed serialization of everything that must be tamper-evident.

        Every field that can be independently edited in the DB is included here.
        The old version only hashed idx/verdict/input_hash/policy_hash/prev_hash/time —
        agent_id, reason, confidence, task_type, and drift_context were NOT part of the
        hash, so editing any of those fields directly in SQLite was invisible to verify().
        """
        return "|".join(
            [
                str(idx),
                verdict,
                input_hash,
                policy_hash,
                prev_hash,
                agent_id,
                reason,
                f"{confidence:.6f}",
                task_type,
                f"{timestamp:.6f}",
                drift_context_json,
            ]
        )

    def append(
        self,
        verdict: str,
        input_hash: str,
        policy_hash: str,
        agent_id: str,
        reason: str,
        confidence: float,
        task_type: str,
        drift_context: Optional[dict] = None,
    ) -> Tuple[str, int]:
        last = self._conn.execute(
            "SELECT tx_hash FROM chain ORDER BY idx DESC LIMIT 1"
        ).fetchone()
        prev_hash = last[0] if last else self.GENESIS
        new_idx = self._conn.execute(
            "SELECT COALESCE(MAX(idx), -1) + 1 FROM chain"
        ).fetchone()[0]

        timestamp = time.time()
        drift_context = drift_context or {}
        drift_context_json = json.dumps(drift_context, sort_keys=True)

        content = self._content_for_hash(
            new_idx, verdict, input_hash, policy_hash, prev_hash,
            agent_id, reason, confidence, task_type, timestamp, drift_context_json,
        )
        tx_hash = "0x" + sha256hex(content)  # full 64 hex chars, not truncated

        self._conn.execute(
            """
            INSERT INTO chain (idx, tx_hash, prev_hash, verdict, input_hash, policy_hash,
                                agent_id, reason, confidence, task_type, timestamp, drift_context)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (new_idx, tx_hash, prev_hash, verdict, input_hash, policy_hash,
             agent_id, reason, confidence, task_type, timestamp, drift_context_json),
        )
        self._conn.commit()
        return tx_hash, new_idx

    def get_by_tx(self, tx_hash: str) -> Optional[dict]:
        row = self._conn.execute(
            """
            SELECT idx, tx_hash, prev_hash, verdict, input_hash, policy_hash,
                   agent_id, reason, confidence, task_type, timestamp, drift_context
            FROM chain WHERE tx_hash = ?
            """,
            (tx_hash,),
        ).fetchone()
        if not row:
            return None
        return self._row_to_dict(row)

    def export(self) -> list:
        """Full chain dump, oldest first. Metadata only — never raw content.

        Same field shape as get_by_tx(), for every row in the chain. Read-only
        access to already-stored data; not scoring/policy logic, so it stays
        in the open protocol layer alongside append()/get_by_tx()/verify().
        """
        rows = self._conn.execute(
            """
            SELECT idx, tx_hash, prev_hash, verdict, input_hash, policy_hash,
                   agent_id, reason, confidence, task_type, timestamp, drift_context
            FROM chain ORDER BY idx
            """
        ).fetchall()
        return [self._row_to_dict(row) for row in rows]

    @staticmethod
    def _row_to_dict(row) -> dict:
        return {
            "index": row[0], "tx_hash": row[1], "prev_hash": row[2], "verdict": row[3],
            "input_hash": row[4], "policy_hash": row[5], "agent_id": row[6], "reason": row[7],
            "confidence": row[8], "task_type": row[9], "timestamp": row[10],
            "drift_context": json.loads(row[11]),
        }

    def verify(self) -> Tuple[bool, Optional[int], Optional[str]]:
        """Full integrity check: link continuity AND content-hash recomputation.

        Returns (is_clean, first_bad_index_or_None, reason_or_None).
        """
        rows = self._conn.execute(
            """
            SELECT idx, tx_hash, prev_hash, verdict, input_hash, policy_hash,
                   agent_id, reason, confidence, task_type, timestamp, drift_context
            FROM chain ORDER BY idx
            """
        ).fetchall()

        expected_prev = self.GENESIS
        for row in rows:
            (idx, tx_hash, prev_hash, verdict, input_hash, policy_hash,
             agent_id, reason, confidence, task_type, timestamp, drift_context_json) = row

            # 1. Chain linkage
            if prev_hash != expected_prev:
                return False, idx, "prev_hash does not match preceding tx_hash (link broken)"

            # 2. Content integrity — recompute and compare
            recomputed_content = self._content_for_hash(
                idx, verdict, input_hash, policy_hash, prev_hash,
                agent_id, reason, confidence, task_type, timestamp, drift_context_json,
            )
            recomputed_hash = "0x" + sha256hex(recomputed_content)
            if recomputed_hash != tx_hash:
                return False, idx, "stored tx_hash does not match recomputed hash of row content (row was edited)"

            expected_prev = tx_hash

        return True, None, None

    def __len__(self):
        return self._conn.execute("SELECT COUNT(*) FROM chain").fetchone()[0]
