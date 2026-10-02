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
2. `DCLGuard` POSTs that description to `{oracle_url}/evaluate/{tier}` (`fast` by default).
3. The Oracle answers with a verdict.
4. The only permission is HTTP 200, `verdict` exactly `COMMIT`, a string `reason`, and a `request_digest` that matches the request the guard is about to send.
5. `guard.post` then makes a separate HTTP POST to the target. That call does not go through the Oracle transport.

## COMMIT

`decision.allowed` is true only when `decision.verdict` is `COMMIT`. Those two cannot disagree.

`guard.post` hashes the HTTP method, the canonical URL, and the canonical JSON body with SHA-256 and sends that value as `request_digest`. Headers are not part of the digest: they are transport data, and an x402 payment header must not become part of the authorized target request or be forwarded to it. The digest is not the Oracle audit-chain `input_hash`.

The target is called only when the Oracle returns `COMMIT` and the same `request_digest`. If the digest is missing or different, `guard.post` does not open a connection to the target and the reason is `request digest missing` or `request digest mismatch`. `result.executed` is true only after that request is sent.

The hosted Oracle echoes `request_digest` on `EvaluateResponse`. The production proof observed a live `COMMIT` whose returned digest matched the guard's digest, and only then called the target. Clients that omit the field still receive `request_digest: null`; this guard always sends it.

`decision.reason` is the Oracle's reason string. `decision.trace_id` (`traceId` in TypeScript) is set only when the Oracle JSON includes a `trace_id` string. `decision.tx_hash` (`txHash`) is passed through when the Oracle included `tx_hash`. The guard does not copy `tx_hash` into `trace_id`. `verify_url` / `verifyUrl` is passed through the same way.

## NO_COMMIT

A `NO_COMMIT` verdict means the side effect must not run. `allowed` is false. `guard.post` does not open a connection to the target. If you branch yourself, send the HTTP call only inside `if decision.allowed`.

## Timeout, errors, and HTTP 402

The Oracle call has one timeout and is not retried. The guard denies the side effect, and does not call the target, when:

- the Oracle times out
- the connection fails
- the Oracle returns HTTP 402, including when the body says `COMMIT`
- the Oracle returns any other non-200 status, including HTTP 500
- the Oracle redirects. The default client does not follow them, because `Location` could be the target. A custom `transport` is responsible for its own requests; the guard still will not call the target unless that transport returns a COMMIT verdict
- the body is not a well-formed verdict: not JSON, `{}`, an unknown verdict, a missing or non-string `reason`, or any shape other than `COMMIT` or `NO_COMMIT` plus a string `reason` on HTTP 200

HTTP 200 by itself is not permission. Confidence, the wording of `reason`, and any `allowed` flag in the body are not permission.

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

`examples/production_web2_proof.py` pays only the Oracle evaluate URL and refuses any other URL. The target POST remains the guard's unpaid client and runs only after `COMMIT` and a matching `request_digest`. The recorded runs are `examples/production_web2_proof.json` and `examples/production_web2_negative_proof.json`. See `examples/README.md`. The guard itself still has no wallet.

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

On `NO_COMMIT`, a missing or different `request_digest`, timeout, HTTP 402, HTTP 500, a network error, or a malformed reply, `result.executed` is false and the target receives no request.

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
