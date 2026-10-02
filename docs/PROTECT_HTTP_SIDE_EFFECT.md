# Protect an HTTP side effect with DCL

DCLGuard controls whether an HTTP side effect is allowed to execute. It does not implement the side effect's business logic and does not manage payment credentials.

DCL decides first. The real HTTP call runs only after COMMIT.

```
application → DCLGuard → DCL Trust Oracle → COMMIT / NO_COMMIT → only COMMIT executes the HTTP side effect
```

## What DCLGuard protects

It protects the decision to perform an HTTP side effect, such as posting an order or sending an email through an API. `DCLGuard.check` asks an existing DCL Trust Oracle and returns a decision. `DCLGuard.post` sends that POST only when the decision is COMMIT and the returned `request_digest` matches the request.

A COMMIT verdict means the call may run. It does not mean the payload is a valid order, a correct email, or a successful payment.

## The flow

1. Your code chooses an action, a target, and a payload.
2. `DCLGuard` POSTs that description to `{oracle_url}/evaluate/{tier}` (`fast` by default). The Oracle receives the action, the target, and the JSON body in the `response` field, not only the digest, because checks such as jailbreak evaluate that text. On the production Oracle that text is sent to `https://webhook.fronesislabs.com`, which is the same disclosure as publishing the decision on the public audit board.
3. The Oracle answers with a verdict.
4. The only permission is HTTP 200, `verdict` exactly `COMMIT`, a string `reason`, and a `request_digest` that matches the request the guard is about to send.
5. `guard.post` then makes a separate HTTP POST to the target. That call does not go through the Oracle transport.

## COMMIT

`decision.allowed` is true only when `decision.verdict` is `COMMIT`. Those two cannot disagree.

`guard.post` hashes the HTTP method, the canonical URL, and the canonical JSON body with SHA-256 and sends that value as `request_digest`. Headers are not part of the digest: they are transport data, and an x402 payment header must not become part of the authorized target request or be forwarded to it. The digest is not the Oracle audit-chain `input_hash`.

The target is called only when the Oracle returns `COMMIT` and the same `request_digest`. If the digest is missing or different, `guard.post` does not open a connection to the target and the reason is `request digest missing` or `request digest mismatch`. `result.executed` is true only after that request returns a non-redirect response. `result.request_sent` is true when the POST to the digested URL was sent.

The hosted Oracle echoes `request_digest` on `EvaluateResponse`. The production proof observed a live `COMMIT` whose returned digest matched the guard's digest, and only then called the target. Clients that omit the field still receive `request_digest: null`; this guard always sends it. An empty string is treated as absent.

`verdict` is an exact match. `COMMITTED`, `commit`, `COMMIT ` with a trailing space, and any other value are denials. `allowed` is true only when `verdict == "COMMIT"`.

### Digest preimage

`request_digest(method, url, body)` in `dcl/guard.py` (and `requestDigest` in `packages/dcl/src/guard.ts`) hashes UTF-8 of:

```text
METHOD
canonical URL
canonical JSON body
```

`canonical_json()` / `canonicalJson()` sort object keys, use compact separators, and keep Unicode (`ensure_ascii=False` in Python). This is not RFC 8785 JCS. `canonical_url()` / `canonicalUrl()` strip whitespace, lowercase the scheme and host, drop the fragment, omit ports 80 and 443, keep other ports, sort query pairs, preserve the path, and use `/` when the path is empty.

A missing body is an empty string, not JSON `null`. `post()` takes `json=` only. Headers, `Authorization`, `Content-Type`, cookies, x402 headers, user-agent, TLS, and connection data are outside the digest. A header that changes the meaning of the request is not cryptographically bound to the Oracle decision.

The checked vector is method `POST`, URL `https://API.Example.com:443/orders?b=2&a=1#fragment`, body `{"z":1,"a":"é"}`, preimage:

```text
POST
https://api.example.com/orders?a=1&b=2
{"a":"é","z":1}
```

SHA-256 `102854ec6909e5be3774fffbfc7bee1922341a2dede88277f7e30f12bc3a8123`. The test hashes that string with SHA-256 directly.

`decision.reason` is the Oracle's reason string. `decision.trace_id` (`traceId` in TypeScript) is set only when the Oracle JSON includes a `trace_id` string. `decision.tx_hash` (`txHash`) is passed through when the Oracle included `tx_hash`. The guard does not copy `tx_hash` into `trace_id`. `verify_url` / `verifyUrl` is passed through the same way.

## NO_COMMIT

A `NO_COMMIT` verdict means the side effect must not run. `allowed` is false. `guard.post` does not open a connection to the target. If you branch yourself, send the HTTP call only inside `if decision.allowed`.

## Timeout, errors, and HTTP 402

The Oracle call has one timeout and is not retried. The guard denies the side effect, and does not call the target, when:

- the Oracle times out
- the connection fails
- the Oracle returns HTTP 402, including when the body says `COMMIT`
- the Oracle returns any other non-200 status, including HTTP 500
- the Oracle redirects. The default client does not follow them. A custom `transport` is responsible for its own requests; the guard still will not call the target unless that transport returns exact `COMMIT` and the same digest
- the target responds with a redirect. The client does not open `Location`. Known case: `request_sent` is true and `executed` is false. The digested URL may already have received that first POST. `executed: false` does not mean the request never left this process
- the body is not a well-formed verdict: not JSON, `{}`, an unknown verdict, a missing or non-string `reason`, or any shape other than `COMMIT` or `NO_COMMIT` plus a string `reason` on HTTP 200

HTTP 200 by itself is not permission. Confidence, the wording of `reason`, and any `allowed` flag in the body are not permission.

## Trust boundary

Request-digest binding, Oracle transport authentication, and audit-chain verification are separate.

The guard compares two strings: the digest it computed and `request_digest` in the Oracle JSON. It does not verify a signature over that JSON. Oracle responses are not cryptographically signed. `DCLGuard` trusts HTTPS/TLS to the configured Oracle URL. The guard protocol has no nonce, expiry, or replay counter. Adding those would change the protocol; this library does not.

`oracle.tx_hash` on a live response is the chain identifier from the Oracle. `ChainState.append` defines it as `0x` plus SHA-256 of the canonical audit record. It is not a Base transaction hash. `dcl_core.verify_chain()` needs the full record (`index`, `prev_hash`, `input_hash`, `policy_hash`, `confidence`, `timestamp`, `drift_context`, and the other canonical fields). The production proof JSON does not include that record, so it is not an offline chain proof.

Enforcement is inside the process that calls `DCLGuard.post()`. Another HTTP client in the same application is outside that boundary.

## Pass a payment-capable transport

A hosted Oracle may require payment before it returns a verdict. Chain, token, and signing stay inside an HTTP client you already have. Pass that client as `transport`. The guard calls it with the Oracle evaluate URL only, never with the side-effect target.

```python
from dcl import DCLGuard
from dcl.guard import OracleHttpResponse

def payment_transport(url, body, timeout):
    response = existing_payment_client.post(url, json=body, timeout=timeout)
    return OracleHttpResponse(status=response.status_code, body=response.content)

guard = DCLGuard(
    oracle_url="https://webhook.fronesislabs.com",
    transport=payment_transport,
)
```

```typescript
const guard = new DCLGuard({
  oracleUrl: "https://webhook.fronesislabs.com",
  transport: async (url, body, timeoutMs) => {
    const response = await existingPaymentFetch(url, {
      method: "POST",
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
    return { status: response.status, body: await response.text() };
  },
});
```

If that transport is missing, raises, or still returns HTTP 402, `check` returns `allowed: false` and `post` does not call the target. You do not parse a 402 response yourself.

`examples/production_web2_proof.py` is outside the guard. It pays only the Oracle evaluate URL and refuses any other URL. The payer key is `DCL_PAYER_PRIVATE_KEY`. `X402_PRIVATE_KEY` is the only alias. A general `PRIVATE_KEY` is ignored. If neither accepted variable is set, the adapter raises before any network call or signature and names the missing variable. `DCL_MAX_PAYMENT_USDC` defaults to `0.01`. The guard does not read those variables and does not sign the payment. The target POST remains the guard's unpaid client and runs only after exact `COMMIT`, a matching `request_digest`, and a non-redirect response.

The recorded runs were taken at commit `79390fc93f9ecf0baebe96e750d25e133ff1ef3e`:

- `examples/production_web2_proof.json` at `2026-10-02T06:45:16Z`. Digest `841bae2cf5392e1c55c4be5bae4187722df1af40166b1f8fc5c485d515b70019`. Oracle chain id `0xaa13b48b6089eb31c9050719b61705d2a33dce911e0299b32c5244cb8821db83`. Payment transaction `0x33f8af305b255b1a5d15b891f036b5940a47afa90fe9742201ea35af28ce2ad1`.
- `examples/production_web2_negative_proof.json` at `2026-10-02T06:46:17Z`. Digest `bc6bc2e1d5e9101a177d0d07469670d81699305e41e23b6fe6ff46d70b8b806e`. Oracle chain id `0xa244dccca0682a89441f99bc982ec1f260a2493f667e80c72bd1c4a22d846689`. `target.called` is false because this client did not call the target. httpbin does not contribute an independent counter.

These two JSON files are the current evidence. This repository does not contain an earlier proof note. A write-up that cites commit `8b620d0` or different hashes is a previous run, not a second canonical proof. The identifier that note called an Oracle transaction reference is the audit-chain hash (`oracle.tx_hash`), not a Base transaction.

Do not commit a private key or a seed phrase. Use a dedicated wallet with a small balance, not a treasury or personal wallet.

See `examples/README.md`. The guard itself still has no wallet.

## What DCLGuard does not do

- It does not implement the side effect's business logic.
- It does not manage payment credentials, wallets, or private keys.
- It does not send x402 payments, hold USDC, or talk to a chain on your behalf.
- It does not retry a timed-out Oracle call.
- It does not provide universal HTTP security. It does not judge the target's response, and it does not offer `GET`, `PUT`, `PATCH`, or `DELETE` helpers.
- It does not replace the DCL Trust Oracle, change Audit Event v1.0, or score policy.
- `LocalSandbox` is a loopback stub for tests and local development. It is not production DCL and it is not a second policy engine. `block_if_contains` is only a switch you set. `tx_hash` values it returns are sandbox correlation ids, not audit proofs, and it does not invent a `trace_id`.

## Install

From a checkout of this repository:

```bash
pip install -e .
```

The TypeScript package is `packages/dcl` (`@fronesis/dcl`). It has no install-time dependencies. Tests run with Node's type stripper:

```bash
node --experimental-strip-types --test packages/dcl/test/guard.test.ts
```

## Initialize the guard

`oracle_url` is the origin of an existing DCL Trust Oracle. The guard calls `POST /evaluate/fast` on that origin.

```python
from dcl import DCLGuard

guard = DCLGuard(oracle_url="https://webhook.fronesislabs.com")
```

## Check the action

```python
decision = guard.check(
    action="POST",
    target="https://api.example.com/orders",
    payload={"amount": 42},
)
```

`decision.allowed` is true only when the verdict is `COMMIT`.

## Execute the HTTP request only after COMMIT

```python
import requests

if decision.allowed:
    requests.post("https://api.example.com/orders", json={"amount": 42})
```

The same gate is available as one call. The POST is sent only after `COMMIT` and a matching `request_digest`:

```python
result = guard.post("https://api.example.com/orders", json={"amount": 42})
if result.executed:
    print(result.status_code, result.text)
```

On `NO_COMMIT`, a missing or different `request_digest`, timeout, HTTP 402, HTTP 500, a network error, or a malformed reply, `result.executed` and `result.request_sent` are both false and the target receives no request. A refused target redirect is the known exception: `request_sent` is true and `executed` is false.

## TypeScript

```typescript
import { DCLGuard } from "@fronesis/dcl";

const guard = new DCLGuard({ oracleUrl: "https://webhook.fronesislabs.com" });
const payload = { amount: 42 };
const decision = await guard.check({
  action: "POST",
  target: "https://api.example.com/orders",
  payload,
});
if (decision.allowed) {
  await fetch("https://api.example.com/orders", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}
```

Or let the guard send the POST:

```typescript
const result = await guard.post("https://api.example.com/orders", { json: payload });
```

`decision.traceId` is the Oracle `trace_id` when that field was returned. It is not `tx_hash`.

## Local sandbox

This repository does not include the DCL Trust Oracle. `LocalSandbox` is a loopback stand-in for the verdict HTTP contract so you can exercise both branches before using a production URL. It does not apply production policy.

```python
from dcl import DCLGuard, LocalSandbox

with LocalSandbox(block_if_contains=["jailbreak"]) as sandbox:
    guard = DCLGuard(oracle_url=sandbox.url)

    allowed = guard.check(
        action="POST",
        target="https://api.example.com/orders",
        payload={"amount": 42},
    )
    assert allowed.verdict == "COMMIT"

    blocked = guard.check(
        action="POST",
        target="https://api.example.com/orders",
        payload={"note": "jailbreak"},
    )
    assert blocked.verdict == "NO_COMMIT"
```

```typescript
import { DCLGuard, LocalSandbox } from "@fronesis/dcl";

const sandbox = new LocalSandbox({ blockIfContains: ["jailbreak"] });
await sandbox.start();
const guard = new DCLGuard({ oracleUrl: sandbox.url });
const decision = await guard.check({
  action: "POST",
  target: "https://api.example.com/orders",
  payload: { amount: 42 },
});
await sandbox.close();
```

When you are done with the stand-in, pass the production Oracle origin as `oracle_url` / `oracleUrl`.

Optional `tier` selects an existing Oracle route: `fast` (default), `strict`, `jailbreak`, `safety`, or `quality`. Optional `agent_id` is a label sent with the check. The guard does not change those routes or the Oracle's response schema.
