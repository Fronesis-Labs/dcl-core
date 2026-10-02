"""Check the signed-envelope v1 vector without wiring it into DCLGuard.

The canonical payload is rebuilt in this file. The signature is checked
with OpenSSL's Ed25519 verifier, not with a helper in ``dcl``.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from dcl.guard import request_digest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "signed_oracle_decision_envelope_v1.json"
GUARD_SOURCES = (
    ROOT / "dcl" / "guard.py",
    ROOT / "packages" / "dcl" / "src" / "guard.ts",
)

FIELD_ORDER = (
    "expires_at",
    "issued_at",
    "key_id",
    "nonce",
    "policy_id",
    "policy_version",
    "request_digest",
    "schema_version",
    "trace_id",
    "verdict",
)

KNOWN_DIGEST = "102854ec6909e5be3774fffbfc7bee1922341a2dede88277f7e30f12bc3a8123"
KNOWN_PREIMAGE = 'POST\nhttps://api.example.com/orders?a=1&b=2\n{"a":"é","z":1}'


def _json_string(value: str) -> str:
    """JSON string encoding required by the envelope spec."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def canonical_payload(envelope: dict[str, object]) -> str:
    """Build the signed UTF-8 text from the fixed allowlist."""
    if set(envelope) != set(FIELD_ORDER):
        raise ValueError("envelope fields must be exactly the v1 allowlist")
    members = []
    for name in FIELD_ORDER:
        value = envelope[name]
        if not isinstance(value, str):
            raise ValueError("envelope values must be strings")
        members.append(_json_string(name) + ":" + _json_string(value))
    return "{" + ",".join(members) + "}"


def _openssl_accepts(payload: bytes, signature: bytes, pem: str) -> bool:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "pub.pem").write_text(pem, encoding="ascii")
        (root / "msg.bin").write_bytes(payload)
        (root / "sig.bin").write_bytes(signature)
        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(root / "pub.pem"),
                "-rawin",
                "-in",
                str(root / "msg.bin"),
                "-sigfile",
                str(root / "sig.bin"),
            ],
            check=False,
            capture_output=True,
        )
    return result.returncode == 0


class SignedEnvelopeVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_canonical_payload_matches_the_fixture_bytes(self) -> None:
        payload = canonical_payload(self.fixture["envelope"])
        self.assertEqual(payload, self.fixture["canonical_payload"])
        raw = payload.encode("utf-8")
        self.assertEqual(len(raw), 339)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), self.fixture["canonical_sha256"])
        self.assertNotIn(" ", payload)
        self.assertNotIn("\n", payload)

    def test_request_digest_is_the_existing_digest_without_a_prefix(self) -> None:
        digest = self.fixture["envelope"]["request_digest"]
        self.assertEqual(digest, KNOWN_DIGEST)
        self.assertEqual(hashlib.sha256(KNOWN_PREIMAGE.encode("utf-8")).hexdigest(), digest)
        self.assertEqual(
            request_digest(
                "POST",
                "https://API.Example.com:443/orders?b=2&a=1#fragment",
                {"z": 1, "a": "é"},
            ),
            digest,
        )
        self.assertFalse(digest.startswith("sha256:"))
        self.assertFalse(digest.startswith("0x"))

    def test_unicode_json_strings_are_not_escaped(self) -> None:
        encoded = _json_string("é")
        self.assertEqual(encoded, '"é"')
        self.assertEqual(encoded.encode("utf-8"), b'"\xc3\xa9"')
        self.assertNotIn("\\u00e9", encoded)

    def test_extra_fields_are_not_part_of_the_signed_payload(self) -> None:
        extra = dict(self.fixture["envelope"])
        extra["note"] = "not signed"
        with self.assertRaises(ValueError):
            canonical_payload(extra)
        self.assertNotIn("note", self.fixture["canonical_payload"])

    def test_openssl_verifies_the_signature_and_rejects_a_changed_byte(self) -> None:
        payload = self.fixture["canonical_payload"].encode("utf-8")
        signature = self._signature_bytes()
        pem = self.fixture["public_key_pem"]
        self.assertTrue(self.fixture["verification_result"])
        self.assertTrue(_openssl_accepts(payload, signature, pem))
        mutated = payload[:-1] + bytes([payload[-1] ^ 0x01])
        self.assertFalse(_openssl_accepts(mutated, signature, pem))
        self.assertFalse(_openssl_accepts(payload + b" ", signature, pem))

    def test_signature_key_id_matches_the_envelope(self) -> None:
        self.assertEqual(self.fixture["signature"]["algorithm"], "Ed25519")
        self.assertEqual(self.fixture["signature"]["key_id"], self.fixture["envelope"]["key_id"])
        self.assertEqual(self.fixture["signature"]["value"], self.fixture["signature_base64"])

    def test_production_guard_does_not_embed_the_test_key(self) -> None:
        seed = self.fixture["private_seed_hex"]
        for path in GUARD_SOURCES:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn(seed, text)
            self.assertNotIn("Ed25519", text)
            self.assertNotIn("signed_oracle_decision_envelope", text)

    def _signature_bytes(self) -> bytes:
        import base64

        signature = base64.b64decode(self.fixture["signature_base64"], validate=True)
        self.assertEqual(len(signature), 64)
        return signature


if __name__ == "__main__":
    unittest.main()
