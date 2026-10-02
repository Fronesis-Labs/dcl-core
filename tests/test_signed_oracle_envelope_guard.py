"""DCLGuard acceptance of signed Oracle decision envelopes.

The published fixture signature is checked as-is. The private seed is used
only by this file when a second signed body is required. It is never passed
to DCLGuard or OracleTrustConfig.
"""

from __future__ import annotations

import base64
import json
import unittest
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dcl import DCLGuard, OracleTrustConfig
from dcl.guard import Decision, OracleHttpResponse, request_digest
from dcl.signed_envelope import _canonical_bytes
from test_dcl_guard import EffectServer

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = ROOT / "tests" / "fixtures" / "signed_oracle_decision_envelope_v1.json"
KNOWN_URL = "https://API.Example.com:443/orders?b=2&a=1#fragment"
KNOWN_BODY = {"z": 1, "a": "é"}
INSIDE_WINDOW = datetime(2026, 10, 2, 0, 0, 30, tzinfo=timezone.utc)


def _load() -> dict:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _trust(fixture: dict, key_id: str | None = None, hex_key: str | None = None) -> OracleTrustConfig:
    return OracleTrustConfig.from_hex(
        {key_id or fixture["envelope"]["key_id"]: hex_key or fixture["public_key_hex"]}
    )


def _wrapper(fixture: dict, envelope: dict | None = None, signature: dict | None = None) -> dict:
    return {
        "envelope": dict(envelope or fixture["envelope"]),
        "signature": dict(signature or fixture["signature"]),
    }


def _sign(fixture: dict, envelope: dict) -> dict:
    """Sign a test envelope. The seed does not enter the guard."""
    seed = bytes.fromhex(fixture["private_seed_hex"])
    payload = _canonical_bytes(envelope)
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(payload)
    return _wrapper(
        fixture,
        envelope,
        {
            "algorithm": "Ed25519",
            "key_id": envelope["key_id"],
            "value": base64.b64encode(signature).decode("ascii"),
        },
    )


@contextmanager
def _clock(moment: datetime) -> Iterator[None]:
    with patch("dcl.signed_envelope._utc_now", return_value=moment):
        yield


class SignedEnvelopeGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = _load()

    def test_trust_config_accepts_only_32_byte_public_keys(self) -> None:
        trust = _trust(self.fixture)
        self.assertEqual(trust.keys[self.fixture["envelope"]["key_id"]], bytes.fromhex(self.fixture["public_key_hex"]))
        self.assertNotEqual(bytes.fromhex(self.fixture["public_key_hex"]), bytes.fromhex(self.fixture["private_seed_hex"]))
        with self.assertRaises(ValueError):
            OracleTrustConfig.from_hex({"oracle-2026-01": "-----BEGIN PUBLIC KEY-----"})
        with self.assertRaises(ValueError):
            OracleTrustConfig({"oracle-2026-01": b"\x00" * 31})
        with self.assertRaises(ValueError):
            OracleTrustConfig({"not a key": b"\x00" * 32})

    def test_valid_signed_commit_uses_the_published_vector(self) -> None:
        calls: list[str] = []

        def execute(url: str, payload: object, headers: object, timeout: float) -> tuple[int, str]:
            calls.append(url)
            return 200, "ok"

        with _clock(INSIDE_WINDOW), patch("dcl.guard._execute_post", side_effect=execute):
            result = self._guard().post(KNOWN_URL, json=KNOWN_BODY)
        self.assertTrue(result.decision.allowed)
        self.assertEqual(result.decision.verdict, "COMMIT")
        self.assertEqual(result.decision.reason, "signed envelope verified")
        self.assertEqual(result.decision.trace_id, "tr_test_vector_v1")
        self.assertIsNone(result.decision.tx_hash)
        self.assertEqual(result.decision.request_digest, self.fixture["envelope"]["request_digest"])
        self.assertEqual(result.decision.request_digest, request_digest("POST", KNOWN_URL, KNOWN_BODY))
        self.assertNotIn("policy_id", Decision.__dataclass_fields__)
        self.assertTrue(result.executed)
        self.assertEqual(calls, [KNOWN_URL])

    def test_valid_signed_no_commit_does_not_call_the_target(self) -> None:
        effect = EffectServer()
        try:
            envelope = dict(self.fixture["envelope"])
            envelope["request_digest"] = request_digest("POST", effect.url, {"n": 1})
            envelope["verdict"] = "NO_COMMIT"
            result = self._post(effect, _sign(self.fixture, envelope), trust=self._trust())
            self.assertFalse(result.decision.allowed)
            self.assertEqual(result.decision.verdict, "NO_COMMIT")
            self.assertEqual(result.decision.reason, "signed envelope verified")
            self.assertEqual(result.decision.trace_id, envelope["trace_id"])
            self.assertIsNone(result.decision.tx_hash)
            self.assertFalse(result.executed)
            self.assertEqual(effect.hits, [])
        finally:
            effect.close()

    def test_wrong_signature_is_rejected(self) -> None:
        raw = bytearray(base64.b64decode(self.fixture["signature_base64"]))
        raw[-1] ^= 0x01
        signature = dict(self.fixture["signature"])
        signature["value"] = base64.b64encode(bytes(raw)).decode("ascii")
        self._assert_rejected(_wrapper(self.fixture, signature=signature), "signed envelope rejected")

    def test_modified_canonical_payload_is_rejected(self) -> None:
        envelope = dict(self.fixture["envelope"])
        envelope["nonce"] = "ff" * 16
        self._assert_rejected(_wrapper(self.fixture, envelope), "signed envelope rejected")

    def test_extra_envelope_field_is_rejected(self) -> None:
        envelope = dict(self.fixture["envelope"])
        envelope["note"] = "not signed"
        self._assert_rejected(_wrapper(self.fixture, envelope), "signed envelope rejected")

    def test_extra_wrapper_field_is_not_an_unsigned_commit(self) -> None:
        body = _wrapper(self.fixture)
        body["verdict"] = "COMMIT"
        body["reason"] = "All policy checks passed"
        body["request_digest"] = self.fixture["envelope"]["request_digest"]
        self._assert_rejected(body, "signed envelope rejected")

    def test_unknown_key_id_is_rejected(self) -> None:
        trust = OracleTrustConfig.from_hex({"other-key": self.fixture["public_key_hex"]})
        self._assert_rejected(_wrapper(self.fixture), "untrusted oracle key", trust=trust)

    def test_mismatched_signature_key_id_is_rejected(self) -> None:
        signature = dict(self.fixture["signature"])
        signature["key_id"] = "other-key"
        trust = OracleTrustConfig.from_hex(
            {
                self.fixture["envelope"]["key_id"]: self.fixture["public_key_hex"],
                "other-key": self.fixture["public_key_hex"],
            }
        )
        self._assert_rejected(_wrapper(self.fixture, signature=signature), "signed envelope rejected", trust=trust)

    def test_malformed_base64_and_short_signature_are_rejected(self) -> None:
        missing_padding = dict(self.fixture["signature"])
        missing_padding["value"] = "abcd"
        self._assert_rejected(_wrapper(self.fixture, signature=missing_padding), "signed envelope rejected")
        short = dict(self.fixture["signature"])
        short["value"] = base64.b64encode(b"\x00" * 32).decode("ascii")
        self._assert_rejected(_wrapper(self.fixture, signature=short), "signed envelope rejected")

    def test_expired_envelope_is_rejected(self) -> None:
        self._assert_rejected(
            _wrapper(self.fixture),
            "signed envelope expired",
            moment=datetime(2026, 10, 2, 0, 1, 0, tzinfo=timezone.utc),
        )

    def test_future_issued_envelope_is_rejected(self) -> None:
        self._assert_rejected(
            _wrapper(self.fixture),
            "signed envelope not yet valid",
            moment=datetime(2026, 10, 1, 23, 59, 59, tzinfo=timezone.utc),
        )

    def test_lifetime_over_60_seconds_is_rejected(self) -> None:
        envelope = dict(self.fixture["envelope"])
        issued = datetime(2026, 10, 2, 0, 0, 0, tzinfo=timezone.utc)
        envelope["expires_at"] = (issued + timedelta(seconds=61)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self._assert_rejected(_wrapper(self.fixture, envelope), "signed envelope lifetime")

    def test_request_digest_mismatch_does_not_call_the_target(self) -> None:
        effect = EffectServer()
        try:
            result = self._post(effect, _wrapper(self.fixture), trust=self._trust(), payload={"n": 1})
            self.assertFalse(result.decision.allowed)
            self.assertEqual(result.decision.verdict, "NO_COMMIT")
            self.assertEqual(result.decision.reason, "request digest mismatch")
            self.assertEqual(result.decision.trace_id, "tr_test_vector_v1")
            self.assertIsNone(result.decision.tx_hash)
            self.assertEqual(effect.hits, [])
        finally:
            effect.close()

    def test_invalid_verdict_is_rejected(self) -> None:
        envelope = dict(self.fixture["envelope"])
        envelope["verdict"] = "COMMITTED"
        self._assert_rejected(_wrapper(self.fixture, envelope), "signed envelope rejected")

    def test_invalid_policy_version_is_rejected(self) -> None:
        envelope = dict(self.fixture["envelope"])
        envelope["policy_version"] = "1.0.0"
        self._assert_rejected(_wrapper(self.fixture, envelope), "signed envelope rejected")

    def test_invalid_nonce_is_rejected(self) -> None:
        envelope = dict(self.fixture["envelope"])
        envelope["nonce"] = "00112233445566778899AABBCCDDEEFF"
        self._assert_rejected(_wrapper(self.fixture, envelope), "signed envelope rejected")

    def test_signed_wrapper_without_trust_is_not_accepted(self) -> None:
        effect = EffectServer()
        try:
            result = self._post(effect, _wrapper(self.fixture), trust=None)
            self.assertFalse(result.decision.allowed)
            self.assertEqual(result.decision.verdict, "NO_COMMIT")
            self.assertEqual(result.decision.reason, "malformed oracle response")
            self.assertEqual(effect.hits, [])
        finally:
            effect.close()

    def test_unsigned_commit_is_unchanged_when_trust_is_set(self) -> None:
        effect = EffectServer()
        try:
            result = self._post_unsigned(effect, "COMMIT", "ok", trace_id="plain-trace")
            self.assertTrue(result.decision.allowed)
            self.assertEqual(result.decision.verdict, "COMMIT")
            self.assertEqual(result.decision.reason, "ok")
            self.assertEqual(result.decision.trace_id, "plain-trace")
            self.assertEqual(result.decision.tx_hash, "0xabc")
            self.assertTrue(result.executed)
            self.assertEqual(len(effect.hits), 1)
        finally:
            effect.close()

    def test_unsigned_no_commit_is_unchanged_when_trust_is_set(self) -> None:
        effect = EffectServer()
        try:
            result = self._post_unsigned(effect, "NO_COMMIT", "denied", trace_id="plain-trace")
            self.assertFalse(result.decision.allowed)
            self.assertEqual(result.decision.verdict, "NO_COMMIT")
            self.assertEqual(result.decision.reason, "denied")
            self.assertEqual(result.decision.trace_id, "plain-trace")
            self.assertFalse(result.executed)
            self.assertEqual(effect.hits, [])
        finally:
            effect.close()

    def _trust(self) -> OracleTrustConfig:
        return _trust(self.fixture)

    def _guard(self, body: dict | None = None, trust: OracleTrustConfig | None | object = ...) -> DCLGuard:
        payload = _wrapper(self.fixture) if body is None else body
        encoded = json.dumps(payload).encode("utf-8")
        selected = self._trust() if trust is ... else trust

        def transport(url: str, request: dict, timeout: float) -> OracleHttpResponse:
            return OracleHttpResponse(status=200, body=encoded)

        return DCLGuard("https://oracle.example", transport=transport, trust=selected)  # type: ignore[arg-type]

    def _post(
        self,
        effect: EffectServer,
        body: dict,
        trust: OracleTrustConfig | None | object = ...,
        payload: dict | None = None,
    ):
        guard = self._guard(body, trust)
        with _clock(INSIDE_WINDOW):
            return guard.post(effect.url, json={"n": 1} if payload is None else payload)

    def _post_unsigned(self, effect: EffectServer, verdict: str, reason: str, trace_id: str):
        def transport(url: str, body: dict, timeout: float) -> OracleHttpResponse:
            encoded = json.dumps(
                {
                    "verdict": verdict,
                    "reason": reason,
                    "request_digest": body["request_digest"],
                    "trace_id": trace_id,
                    "tx_hash": "0xabc",
                }
            ).encode("utf-8")
            return OracleHttpResponse(status=200, body=encoded)

        guard = DCLGuard("https://oracle.example", transport=transport, trust=self._trust())
        return guard.post(effect.url, json={"n": 1})

    def _assert_rejected(
        self,
        body: dict,
        reason: str,
        *,
        trust: OracleTrustConfig | None = None,
        moment: datetime = INSIDE_WINDOW,
    ) -> None:
        effect = EffectServer()
        try:
            guard = self._guard(body, self._trust() if trust is None else trust)
            with _clock(moment):
                result = guard.post(effect.url, json={"n": 1})
            self.assertFalse(result.decision.allowed)
            self.assertEqual(result.decision.verdict, "NO_COMMIT")
            self.assertEqual(result.decision.reason, reason)
            self.assertFalse(result.executed)
            self.assertEqual(effect.hits, [])
        finally:
            effect.close()


if __name__ == "__main__":
    unittest.main()
