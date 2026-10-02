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
That claim is `verify_chain()` on a full chain record. The Web2 proof
later in this document only confirms the sequence this client observed.

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

## Web2 HTTP side effect

Web2 agents that need a COMMIT / NO_COMMIT gate in front of an HTTP side effect can use `DCLGuard`:

```python
from dcl import DCLGuard

guard = DCLGuard(oracle_url="https://webhook.fronesislabs.com")

result = guard.post(
    "https://api.example.com/send",
    json={"to": "user@example.com", "subject": "Hello"},
)

# result.executed is True only for exact COMMIT, a matching digest,
# and a non-redirect response from that URL.
# A target redirect sets request_sent True and executed False:
# the digested host may already have seen the POST.
```

`from dcl import DCLGuard` is the public guard import. `from dcl_core import ChainState` is the chain import. This distribution publishes both packages (`pyproject.toml` includes `dcl` and `dcl_core*`). They are not the same module.

`post()` accepts `json=`. It does not accept `data=` or `files=`. A missing JSON body is hashed as an empty string, not as JSON `null`.

### Request binding

`dcl.guard.request_digest()` is SHA-256 (hex, no `0x`) of this preimage, UTF-8:

```text
METHOD
canonical URL
canonical JSON body
```

`METHOD` is stripped and uppercased. The digest includes the HTTP method, the canonical URL, and the canonical JSON body.

The digest does not include HTTP headers, `Authorization`, `Content-Type`, x402 headers, cookies, `User-Agent`, other transport metadata, TLS metadata, or the network connection. `post()` can still send `headers=` to the target after COMMIT. Those headers are not sent to the Oracle and are not in the digest.

The Oracle receives the action, the target, and the JSON body in the `response` field, not only the digest, because checks such as jailbreak evaluate that text. On the production Oracle that text is sent to `https://webhook.fronesislabs.com`, which is the same disclosure as publishing the decision on the public audit board.

If a header changes what the request means, the Oracle decision is not cryptographically bound to that header.

### Canonicalization

This is this package's own deterministic scheme. It is not RFC 8785 JCS.

- `dcl.guard.canonical_json()`: sorted object keys, compact separators `( ",", ":" )`, `ensure_ascii=False`. Array order is preserved. No Unicode normalization.
- `dcl.guard.canonical_url()`: strip surrounding whitespace, lowercase scheme and hostname, drop the fragment, omit default ports 80 and 443, keep any other port, sort decoded query pairs and encode them again, keep the path, and use `/` when the path is empty.

A published vector is tested by hashing that exact preimage, not by calling `request_digest()` twice. Method `POST`, URL `https://API.Example.com:443/orders?b=2&a=1#fragment`, JSON `{"z":1,"a":"é"}` canonicalizes to:

```text
POST
https://api.example.com/orders?a=1&b=2
{"a":"é","z":1}
```

SHA-256: `102854ec6909e5be3774fffbfc7bee1922341a2dede88277f7e30f12bc3a8123`.

Semantically similar URLs or JSON values that this scheme does not normalize (path percent-encoding, object key duplicates, `1` versus `1.0`) produce different digests. That is the current scheme, not an accident to paper over.

### Enforcement boundary

This is library-level enforcement inside the process that calls `DCLGuard.post()`. It does not enforce anything at the network. An application can still POST the same URL with another client and skip the guard.

### Oracle trust boundary

Three different things:

1. Request-digest binding: the guard compares the digest it computed with the `request_digest` string in the Oracle JSON.
2. Oracle transport and trust: the default client uses HTTPS/TLS to the configured Oracle URL and does not follow Oracle redirects. Unsigned JSON remains supported. When OracleTrustConfig is configured, the guard verifies the Oracle signed wrapper before accepting the response.
3. Audit-chain verification: `dcl_core.verify_chain()` recomputes a chain record hash. The guard does not do that.

Python `DCLGuard` with `trust=OracleTrustConfig(...)` verifies a signed wrapper. Without `trust`, it uses the current unsigned path. The TypeScript guard is still unsigned. Nonce replay protection is not implemented. HTTPS/TLS to the configured Oracle endpoint is still required. This does not mean every Oracle response is cryptographically signed.

### Signed decision envelope

[Signed Oracle decision envelope v1](docs/SIGNED_ORACLE_DECISION_ENVELOPE_V1.md) is the contract. Python `DCLGuard` verifies it only when the caller passes `trust=OracleTrustConfig(...)`. `trust=None`, the default, keeps the current unsigned Oracle JSON. Passing `trust` does not reject that unsigned JSON. A signed wrapper without `trust` stays a denial. The TypeScript guard does not verify envelopes yet.

The signed message is the UTF-8 canonical bytes of the ten-field envelope, not the HTTP headers and not `oracle.tx_hash`. The public key comes from `trust.keys`, not from the Oracle body. Unknown `key_id` is a denial. `COMMIT` after a signed wrapper requires a valid Ed25519 signature plus the envelope's `request_digest`, `trace_id`, `issued_at`, and `expires_at` checks. Nonce format is checked and is not stored; that is not replay protection. The signature does not replace HTTPS/TLS. The request-digest algorithm, Audit Event v1.0, and the production proof JSON stay as they are. `oracle.tx_hash` remains the audit-chain hash, not a Base transaction.

`verdict` must be exactly `COMMIT` or exactly `NO_COMMIT`. `COMMITTED`, `commit`, `COMMIT `, and any other string are denials. `allowed` is true only when `verdict == "COMMIT"`.

### Failure behavior

These outcomes are fail-closed in `tests/test_dcl_guard.py` and `packages/dcl/test/guard.test.ts`. `result.executed` is false and the target server used by the test receives no request, except the target-redirect case noted below:

- Oracle HTTP 402, including a body that says `COMMIT`
- Oracle HTTP 404 and HTTP 500
- Oracle timeout
- Oracle connection failure
- any other exception from the Oracle transport
- malformed JSON, JSON that is not an object, missing verdict, unknown verdict, missing or non-string `reason`
- `COMMIT` with no `request_digest`, an empty digest, or a different digest
- `NO_COMMIT`
- Oracle HTTP redirect (not followed)
- target HTTP redirect (not followed; see below)

### Redirect behavior

The default Oracle client (`_urllib_transport`, and `redirect: "manual"` in TypeScript) does not follow a 3xx from the Oracle. The guard then denies the side effect. A custom `transport` is responsible for its own Oracle requests; the guard still will not call the target unless that transport returns exact `COMMIT` plus the matching digest.

The target POST also does not follow redirects. `urllib` redirect codes are turned into `TargetRedirectRefused` (TypeScript uses `redirect: "manual"`). `Location` is not requested.

Known case: `request_sent` is true and `executed` is false (`requestSent` in TypeScript). The POST to the digested URL has already been sent, so that host may have seen the request. `executed: false` does not mean the request never left this process. The redirect destination is not contacted.

### Production proof

Live runs against `https://webhook.fronesislabs.com` and `https://httpbin.org/post`, from commit `79390fc93f9ecf0baebe96e750d25e133ff1ef3e`:

[Production proof](examples/production_web2_proof.py)

Positive path, `2026-10-02T06:45:16Z`: Oracle 402 → x402 payment → `COMMIT` with `request_digest` `841bae2cf5392e1c55c4be5bae4187722df1af40166b1f8fc5c485d515b70019` → target POST 200.

Negative path, `2026-10-02T06:46:17Z`: Oracle 402 → x402 payment → `NO_COMMIT` (`forbidden: 'jailbreak'`) with `request_digest` `bc6bc2e1d5e9101a177d0d07469670d81699305e41e23b6fe6ff46d70b8b806e` → the guard did not call the target.

Evidence:

- [production_web2_proof.json](examples/production_web2_proof.json)
- [production_web2_negative_proof.json](examples/production_web2_negative_proof.json)

`oracle.tx_hash` is the identifier the Oracle returned. In the DCL chain, `ChainState.append` sets that field to `0x` plus the SHA-256 of the canonical audit-chain record. It is not a Base blockchain transaction hash. Positive: `0xaa13b48b6089eb31c9050719b61705d2a33dce911e0299b32c5244cb8821db83`. Negative: `0xa244dccca0682a89441f99bc982ec1f260a2493f667e80c72bd1c4a22d846689`.

`payment.tx_hash` on the positive proof is the x402 settlement transaction: `0x33f8af305b255b1a5d15b891f036b5940a47afa90fe9742201ea35af28ce2ad1`.

These two JSON files, from commit `79390fc93f9ecf0baebe96e750d25e133ff1ef3e` at `2026-10-02T06:45:16Z` and `2026-10-02T06:46:17Z`, are the current evidence. This repository does not contain an earlier proof note. A write-up that cites commit `8b620d0` or different hashes is a previous run, not a second canonical proof. The identifier that note called an Oracle transaction reference is the audit-chain hash (`oracle.tx_hash`), not a Base transaction.

### Evidence limitations

The production proof shows what this client observed: the 402, one Oracle payment, the Oracle JSON, the digest comparison, the COMMIT or NO_COMMIT branch, and whether `DCLGuard.post()` then called the target.

The negative proof's `target.called: false` means this client did not run the target POST after `NO_COMMIT`. `httpbin.org` does not provide an independent call counter in this proof. The proof does not show that no other client reached httpbin.

The JSON does not contain the audit-chain fields `verify_chain()` needs (`index`, `prev_hash`, `input_hash`, `policy_hash`, `confidence`, `timestamp`, `drift_context`, and the rest of the canonical record). It is not an offline cryptographic proof of the Oracle verdict, and it does not authenticate the Oracle response.

It also does not provide network-level enforcement or stop another code path from skipping `DCLGuard`.

### Payment

x402 payment is not part of `DCLGuard`. The proof script passes `examples/oracle_x402_transport.py` as the Oracle `transport`. That adapter reads `DCL_PAYER_PRIVATE_KEY`, or `X402_PRIVATE_KEY` as its only alias. A general `PRIVATE_KEY` is ignored, even when it is set for another wallet. If neither accepted variable is set, the adapter raises before any network call or signature and names the missing variable. It will not pay more than `DCL_MAX_PAYMENT_USDC` (default `0.01`). The guard never sees the key and never signs a payment. The target POST stays unpaid.

Do not commit a private key or a seed phrase. Use a dedicated wallet for automated x402 payments, keep only a small operational balance, and do not point this adapter at a treasury or personal wallet. Rotate a credential that has been exposed.

See [Protect an HTTP side effect with DCL](docs/PROTECT_HTTP_SIDE_EFFECT.md) and [examples/README.md](examples/README.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE).
