"""Verify a signed Oracle decision envelope v1.

The guard calls this only after an HTTP 200 body has been parsed. Flat
unsigned Oracle JSON never enters here. A body that merely looks like a
wrapper is failed closed and is not read as an unsigned verdict.

Nonce shape is checked. This module does not store nonces and does not
claim replay protection. ``tx_hash`` is not an envelope field.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_FIELD_ORDER = (
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
_SIGNATURE_FIELDS = frozenset({"algorithm", "key_id", "value"})
_WRAPPER_FIELDS = frozenset({"envelope", "signature"})

_KEY_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_POLICY_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_POLICY_VERSION = re.compile(r"^[1-9][0-9]{0,8}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_NONCE = re.compile(r"^[0-9a-f]{32}$")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_SIGNATURE_B64 = re.compile(r"^[A-Za-z0-9+/]{86}==$")
_PUBLIC_KEY_HEX = re.compile(r"^[0-9a-fA-F]{64}$")

_ALGORITHM = "Ed25519"
_VERIFIED = "signed envelope verified"


class _Rejected(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def _utc_now() -> datetime:
    """Process UTC clock. Tests may replace this. There is no skew allowance."""
    return datetime.now(timezone.utc)


def _as_utc(moment: datetime) -> datetime:
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


@dataclass(frozen=True)
class OracleTrustConfig:
    """Public Ed25519 keys supplied by the caller.

    ``keys`` maps ``key_id`` to exactly 32 raw public-key bytes. A private
    seed, PEM, JWK, or wallet address is not a value of this mapping.
    ``policy_id`` and ``policy_version`` are not trust-config fields.
    The Oracle response cannot add a key to this mapping.
    """

    keys: Mapping[str, bytes]

    def __post_init__(self) -> None:
        if isinstance(self.keys, (str, bytes)) or not isinstance(self.keys, Mapping):
            raise ValueError("trust keys must be a mapping of key_id to public-key bytes")
        normalized: dict[str, bytes] = {}
        for key_id, public_key in self.keys.items():
            if not isinstance(key_id, str) or _KEY_ID.fullmatch(key_id) is None:
                raise ValueError("trust key_id is not a v1 key id")
            if type(public_key) is not bytes or len(public_key) != 32:
                raise ValueError("trust public key must be 32 bytes")
            normalized[key_id] = public_key
        object.__setattr__(self, "keys", MappingProxyType(normalized))

    @classmethod
    def from_hex(cls, keys: Mapping[str, str]) -> OracleTrustConfig:
        """Build a config from 64-character public-key hex strings."""
        if isinstance(keys, (str, bytes)) or not isinstance(keys, Mapping):
            raise ValueError("trust keys must be a mapping of key_id to public-key hex")
        raw: dict[str, bytes] = {}
        for key_id, hex_key in keys.items():
            if not isinstance(hex_key, str) or _PUBLIC_KEY_HEX.fullmatch(hex_key) is None:
                raise ValueError("trust public key hex must be 64 hexadecimal characters")
            raw[key_id] = bytes.fromhex(hex_key)
        return cls(raw)


def looks_like_signed_wrapper(data: Mapping[str, object]) -> bool:
    """True when the body should be judged only as a signed wrapper."""
    return "envelope" in data or "signature" in data


@dataclass(frozen=True)
class SignedVerdict:
    """Fields the guard copies onto ``Decision``. ``tx_hash`` is intentionally absent."""

    allowed: bool
    verdict: str
    reason: str
    trace_id: str | None = None
    request_digest: str | None = None


def decision_from_signed_wrapper(
    data: Mapping[str, object],
    *,
    expected_digest: str | None,
    trust: OracleTrustConfig | None,
) -> SignedVerdict:
    """Verify one wrapper. Invalid input is ``NO_COMMIT`` and is not reread."""
    if trust is None:
        return SignedVerdict(False, "NO_COMMIT", "malformed oracle response")
    try:
        envelope = _verified_envelope(data, trust)
    except _Rejected as exc:
        return SignedVerdict(False, "NO_COMMIT", exc.reason)

    returned = envelope["request_digest"]
    if not expected_digest or returned != expected_digest:
        reason = "request digest missing" if not expected_digest else "request digest mismatch"
        return SignedVerdict(
            False,
            "NO_COMMIT",
            reason,
            trace_id=envelope["trace_id"],
            request_digest=returned,
        )
    verdict = envelope["verdict"]
    return SignedVerdict(
        verdict == "COMMIT",
        verdict,
        _VERIFIED,
        trace_id=envelope["trace_id"],
        request_digest=returned,
    )


def _verified_envelope(
    data: Mapping[str, object],
    trust: OracleTrustConfig,
) -> Mapping[str, str]:
    if set(data) != _WRAPPER_FIELDS:
        raise _Rejected("signed envelope rejected")
    envelope = data["envelope"]
    signature = data["signature"]
    if not isinstance(envelope, dict) or not isinstance(signature, dict):
        raise _Rejected("signed envelope rejected")
    if set(envelope) != set(_FIELD_ORDER) or set(signature) != _SIGNATURE_FIELDS:
        raise _Rejected("signed envelope rejected")
    fields = _string_fields(envelope)
    _check_lifetime(fields)
    if signature.get("algorithm") != _ALGORITHM:
        raise _Rejected("signed envelope rejected")
    signature_key = signature.get("key_id")
    if signature_key != fields["key_id"]:
        raise _Rejected("signed envelope rejected")
    public_key = trust.keys.get(fields["key_id"])
    if type(public_key) is not bytes or len(public_key) != 32:
        raise _Rejected("untrusted oracle key")
    raw_signature = _decode_signature(signature.get("value"))
    payload = _canonical_bytes(fields)
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(raw_signature, payload)
    except (InvalidSignature, ValueError) as exc:
        raise _Rejected("signed envelope rejected") from exc
    _check_current_time(fields)
    return fields


def _string_fields(envelope: Mapping[str, object]) -> dict[str, str]:
    fields: dict[str, str] = {}
    for name in _FIELD_ORDER:
        value = envelope[name]
        if not isinstance(value, str):
            raise _Rejected("signed envelope rejected")
        fields[name] = value
    if fields["schema_version"] != "1":
        raise _Rejected("signed envelope rejected")
    if _KEY_ID.fullmatch(fields["key_id"]) is None:
        raise _Rejected("signed envelope rejected")
    if not _valid_trace_id(fields["trace_id"]):
        raise _Rejected("signed envelope rejected")
    if _DIGEST.fullmatch(fields["request_digest"]) is None:
        raise _Rejected("signed envelope rejected")
    if fields["verdict"] not in ("COMMIT", "NO_COMMIT"):
        raise _Rejected("signed envelope rejected")
    if _POLICY_ID.fullmatch(fields["policy_id"]) is None:
        raise _Rejected("signed envelope rejected")
    if _POLICY_VERSION.fullmatch(fields["policy_version"]) is None:
        raise _Rejected("signed envelope rejected")
    if _NONCE.fullmatch(fields["nonce"]) is None:
        raise _Rejected("signed envelope rejected")
    if _parse_timestamp(fields["issued_at"]) is None or _parse_timestamp(fields["expires_at"]) is None:
        raise _Rejected("signed envelope rejected")
    return fields


def _valid_trace_id(value: str) -> bool:
    if not 1 <= len(value) <= 128:
        return False
    for character in value:
        code = ord(character)
        if code <= 0x1F or code == 0x7F:
            return False
    return True


def _parse_timestamp(value: str) -> datetime | None:
    if _TIMESTAMP.fullmatch(value) is None:
        return None
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc)


def _check_lifetime(fields: Mapping[str, str]) -> None:
    issued = _parse_timestamp(fields["issued_at"])
    expires = _parse_timestamp(fields["expires_at"])
    if issued is None or expires is None:
        raise _Rejected("signed envelope rejected")
    span = expires - issued
    if span < timedelta(seconds=1) or span > timedelta(seconds=60):
        raise _Rejected("signed envelope lifetime")


def _check_current_time(fields: Mapping[str, str]) -> None:
    issued = _parse_timestamp(fields["issued_at"])
    expires = _parse_timestamp(fields["expires_at"])
    if issued is None or expires is None:
        raise _Rejected("signed envelope rejected")
    current = _as_utc(_utc_now())
    if current < issued:
        raise _Rejected("signed envelope not yet valid")
    if current >= expires:
        raise _Rejected("signed envelope expired")


def _decode_signature(value: object) -> bytes:
    if not isinstance(value, str) or _SIGNATURE_B64.fullmatch(value) is None:
        raise _Rejected("signed envelope rejected")
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise _Rejected("signed envelope rejected") from exc
    if len(raw) != 64 or base64.b64encode(raw).decode("ascii") != value:
        raise _Rejected("signed envelope rejected")
    return raw


def _canonical_bytes(fields: Mapping[str, str]) -> bytes:
    members = []
    for name in _FIELD_ORDER:
        members.append(
            json.dumps(name, ensure_ascii=False, separators=(",", ":"))
            + ":"
            + json.dumps(fields[name], ensure_ascii=False, separators=(",", ":"))
        )
    return ("{" + ",".join(members) + "}").encode("utf-8")
