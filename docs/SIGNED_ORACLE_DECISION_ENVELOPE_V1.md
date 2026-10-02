# Signed Oracle decision envelope v1

Status: specification only. `DCLGuard` does not parse, sign, or verify this envelope. The production Oracle is unchanged. No nonce store is added here.

This document is the contract a later Python and TypeScript implementation must follow byte for byte. It is not an instruction to turn verification on.

## Compatibility

Until a separate migration PR:

- The current unsigned Oracle JSON remains the live guard behavior.
- `examples/production_web2_proof.json` and `examples/production_web2_negative_proof.json` stay as recorded. They are not rewritten into envelopes.
- `oracle.tx_hash` keeps its name and its meaning: the DCL audit-chain id (`0x` plus SHA-256 of the canonical chain record). It is not a Base transaction hash, and it is not a field of this envelope.
- Audit Event v1.0 is unchanged. This envelope is not an audit event and is not an input to `verify_chain()`.
- The HTTP request digest is unchanged. `request_digest(method, url, body)` is still SHA-256 hex of `METHOD`, the canonical URL, and the canonical JSON body. This envelope does not redefine that preimage, that canonicalization, or that encoding.

## Envelope

A decision envelope is a JSON object with exactly these fields. Every value is a JSON string. Numbers, booleans, nulls, arrays, and nested objects are invalid in v1.

| Field | Type and constraint |
| --- | --- |
| `schema_version` | Exactly `1`. |
| `key_id` | 1 to 64 characters from `A-Z`, `a-z`, `0-9`, `.`, `_`, and `-`. Names the Ed25519 public key the verifier must use. |
| `trace_id` | 1 to 128 Unicode code points, none of them C0 controls or DEL. The Oracle assigns it. Producers must not copy `tx_hash` into this field. The signature binds this string. |
| `request_digest` | Exactly 64 lowercase hexadecimal characters. This is the existing DCL request digest, with no `sha256:` prefix and no `0x` prefix. |
| `verdict` | Exactly `COMMIT` or exactly `NO_COMMIT`. |
| `policy_id` | 1 to 64 characters: a leading `a-z` or `0-9`, then `a-z`, `0-9`, `.`, `_`, or `-`. |
| `policy_version` | A decimal string without a leading zero, 1 to 9 digits (`1` through `999999999`). It is a string, not a JSON number. |
| `issued_at` | UTC timestamp, pattern `YYYY-MM-DDTHH:MM:SSZ`. No fractional seconds and no numeric offset. It must be a real civil date. |
| `expires_at` | Same timestamp form. It must be strictly later than `issued_at`, and `expires_at - issued_at` must be from 1 to 60 seconds inclusive. |
| `nonce` | Exactly 32 lowercase hexadecimal characters (16 bytes). The signature covers it. This document does not store it. |

Any missing field, extra field, or value that fails its constraint makes the envelope invalid.

Illustrative object. This display order is not the signed byte order. The signed order is fixed in the next section.

```json
{
  "schema_version": "1",
  "key_id": "oracle-2026-01",
  "trace_id": "tr_test_vector_v1",
  "request_digest": "102854ec6909e5be3774fffbfc7bee1922341a2dede88277f7e30f12bc3a8123",
  "verdict": "COMMIT",
  "policy_id": "default",
  "policy_version": "1",
  "issued_at": "2026-10-02T00:00:00Z",
  "expires_at": "2026-10-02T00:01:00Z",
  "nonce": "00112233445566778899aabbccddeeff"
}
```

`request_digest` in that object is the published digest of `POST`, `https://API.Example.com:443/orders?b=2&a=1#fragment`, and `{"z":1,"a":"é"}`. The envelope carries that digest string. It does not re-encode the HTTP request.

## Signed response wrapper

The signed response is a JSON object with exactly two fields, `envelope` and `signature`. The signature object has exactly three fields.

```json
{
  "envelope": {
    "schema_version": "1",
    "key_id": "oracle-2026-01",
    "trace_id": "tr_test_vector_v1",
    "request_digest": "102854ec6909e5be3774fffbfc7bee1922341a2dede88277f7e30f12bc3a8123",
    "verdict": "COMMIT",
    "policy_id": "default",
    "policy_version": "1",
    "issued_at": "2026-10-02T00:00:00Z",
    "expires_at": "2026-10-02T00:01:00Z",
    "nonce": "00112233445566778899aabbccddeeff"
  },
  "signature": {
    "algorithm": "Ed25519",
    "key_id": "oracle-2026-01",
    "value": "H7e0gIhzXyMApYBHonFILLghvEURPdt9Z4b1j5cA4fT1ZRdNxA6gKhc42YReQRMX2N/8lutmTw745woDWeACAw=="
  }
}
```

`signature.algorithm` is exactly `Ed25519`. `signature.key_id` must be identical to `envelope.key_id`. `signature.value` is standard base64 (RFC 4648, with `=` padding, no whitespace, not base64url) of the 64-byte signature. For a 64-byte signature that encoding is 88 characters and ends in `==`.

Extra wrapper fields, missing wrapper fields, and a `key_id` mismatch are invalid. Those fields are not part of the signed bytes.

Wire key order inside `envelope` is not part of the signature. The verifier rebuilds the signed bytes from the allowlisted values. A different order of the same ten fields is the same message. An extra field is a different, invalid envelope, not an extension of the message.

## Canonical signing payload

This canonical form is only for the decision envelope. It is not RFC 8785 JCS. It is not `dcl.guard.canonical_json()`, and it is not the request-digest preimage. Implementations must not pass the envelope through a general JSON canonicalizer that signs whatever keys are present.

The signed message is the UTF-8 bytes of one JSON object constructed as follows.

1. Reject the envelope unless its key set is exactly the ten names below.
2. Emit those keys in this fixed order, which is also ascending Unicode code-point order for these ASCII names:
   `expires_at`, `issued_at`, `key_id`, `nonce`, `policy_id`, `policy_version`, `request_digest`, `schema_version`, `trace_id`, `verdict`.
3. Encode each key and each value with JSON string rules (RFC 8259): quotation mark, reverse solidus, and the control characters U+0000 through U+001F are escaped (`\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`, and `\u00XX` for the other controls). Solidus is not escaped. Every other code point, including non-ASCII characters, is written as its Unicode character. Do not use `\u` escapes for non-ASCII characters.
4. Join with `:` between a key and its value and `,` between members. No space, no newline, no trailing comma, no BOM.

The test vector's signed bytes are this UTF-8 string and nothing else (339 bytes):

```text
{"expires_at":"2026-10-02T00:01:00Z","issued_at":"2026-10-02T00:00:00Z","key_id":"oracle-2026-01","nonce":"00112233445566778899aabbccddeeff","policy_id":"default","policy_version":"1","request_digest":"102854ec6909e5be3774fffbfc7bee1922341a2dede88277f7e30f12bc3a8123","schema_version":"1","trace_id":"tr_test_vector_v1","verdict":"COMMIT"}
```

SHA-256 of those bytes, for identification only, is `b4228c3e61e5c850b3213f3bab6acf78fd5e6729928d474027d9e0af283184f0`. Ed25519 does not sign that hash. It signs the 339 raw bytes.

Not signed: HTTP headers, the URL, TLS transcripts, the wrapper, the `signature` object, whitespace added around the JSON, any field outside the ten names, and `tx_hash`. An implementation that sorts an open-ended object would let an extra field change the signed bytes without a spec change. v1 forbids that. Extra fields fail validation and are omitted from the payload.

A string containing `é` (U+00E9) encodes as the UTF-8 bytes `C3 A9` inside the quotes, not as the six characters `\u00e9`. The signed test vector itself is ASCII. That Unicode rule is what a later implementation must use if `trace_id` is not ASCII.

## Security semantics

The algorithm is Pure Ed25519 (RFC 8032). The message is the canonical UTF-8 payload above. Callers do not prehash it. This is not Ed25519ph.

`key_id` selects the public key from a verifier trust configuration that this document does not distribute. An unknown `key_id` fails closed. The test key published below is not a production trust anchor and must not be configured for a live Oracle, including under the label `oracle-2026-01`.

`issued_at` and `expires_at` bound the decision. A verifier uses its own UTC clock, with no skew allowance in v1. The envelope is inside its window only when `issued_at <= now < expires_at`. A clock that disagrees with the Oracle can reject a fresh envelope. That rejection is fail-closed.

`nonce` makes two otherwise identical decisions different signed messages. Replay protection is a separate future guard layer: a guard that has accepted a `(key_id, nonce)` pair must reject a second presentation of that pair. This repository does not define or ship the memory, cache, or database for that check.

The signature binds `trace_id` because those characters are inside the canonical payload. A verifier must take the trace id from the verified envelope, not from an unsigned neighbor field, and must not fill it from `tx_hash`.

The signature binds `request_digest` the same way. The guard still computes the existing digest locally. A verified envelope whose `request_digest` differs from that local digest is not authorization for the request the guard is about to send.

The signature does not replace HTTPS/TLS. TLS authenticates the connection to the configured Oracle origin. The signature authenticates the decision bytes under `key_id`. Either check can fail while the other succeeds. The guard continues to require the configured HTTPS transport. A signature is also not `verify_chain()` and does not make `oracle.tx_hash` a Base transaction.

A side effect may be treated as `COMMIT` only when all of the following are true:

- the wrapper and envelope match this document;
- `signature.algorithm` is `Ed25519` and `signature.key_id` equals `envelope.key_id`;
- Pure Ed25519 verification succeeds over the canonical bytes and the public key registered for that `key_id`;
- every field constraint above holds, including the time window;
- `envelope.request_digest` equals the guard's locally computed request digest;
- `envelope.trace_id` is the trace id taken from that verified envelope;
- `envelope.verdict` is exactly `COMMIT`.

A valid signature over `NO_COMMIT` is a verified denial, not a `COMMIT`. Any failed check is a denial. The current code does none of these checks.

The nonce replay layer is an additional future denial. It is not one of the checks this release implements, and a missing store must not be filled in by calling the signature check a replay check.

## Test vector

Fixture: [tests/fixtures/signed_oracle_decision_envelope_v1.json](../tests/fixtures/signed_oracle_decision_envelope_v1.json).

The private key is the 32-byte Ed25519 seed `8e9dd37ff470a8a5448e1dbe8143066d3f5f0c6090a6bd982b016473898d570b`, which is SHA-256 of the ASCII label `dcl-core signed oracle decision envelope v1 TEST KEY ONLY`. The public key is `11dee386caeaa68cb3c77e5ea1aa0e99cd1054818e819d94068e02b379cbb6f9`. The signature over the 339 canonical bytes is:

```text
H7e0gIhzXyMApYBHonFILLghvEURPdt9Z4b1j5cA4fT1ZRdNxA6gKhc42YReQRMX2N/8lutmTw745woDWeACAw==
```

Verification result: valid.

That signature was checked without a library helper in `dcl` or `packages/dcl`: OpenSSL 3 `pkeyutl -verify`, Node `crypto.verify` (Pure Ed25519), and PyNaCl (libsodium) all accepted those bytes and rejected the same signature over the payload with one extra trailing byte. Production code does not read this seed. The tests under `tests/test_signed_oracle_envelope_vector.py` and `packages/dcl/test/signed-envelope-vector.test.ts` rebuild the canonical payload and check the signature. They do not connect it to `DCLGuard`.
