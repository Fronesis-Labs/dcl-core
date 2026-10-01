# Web2 integration design note

## Phase 1 — audit

This workspace (`DariRinch/dcl-core`) is a LangGraph research repo. It does not contain the DCL Trust Oracle.

| Search | In this repo | What it actually is |
| --- | --- | --- |
| `DCLClient` / `DclClient` | Not present | The public TypeScript client is `DclClient` in [Fronesis-Labs/dcl-sdk](https://github.com/Fronesis-Labs/dcl-sdk) `src/client.ts`. It POSTs `EvaluateRequest` to `/evaluate/{tier}` and throws on any non-OK response. Payment is an injected `fetchImpl`. |
| `DCLGuard` | Not present | No guard, decorator, or side-effect wrapper exists here or in that SDK. |
| `DCLAuditTool` | Not present | Audit decode is a paid Oracle route (`GET /audit/{tx_hash}`), not a client in this repo. |
| Python SDK | Not present | `agent.py` is a LangGraph graph: keyword `APPROVE` / `REJECT`, then append `data/agent_logs.json`. `eval_agent.py` scores those logs offline. PyPI `dcl-core` (Fronesis-Labs) verifies hash chains offline. It does not call the Oracle. |
| TypeScript client | Not present | No `package.json` in this repo. |
| HTTP evaluation helpers | Not present | Production contract, documented by `dcl-sdk` `PROTOCOL.md` §5 and `dcl-webhook`: `POST /evaluate/fast`, `/evaluate/strict`, `/evaluate/jailbreak`, `/evaluate/safety`, `/evaluate/quality`. |
| Policy / enforcement wrappers | Only `agent.py` `decide()` | Local keyword match. It is not the Oracle and was left unchanged. |
| Local Sandbox | Not present | `dcl-webhook` can run on `localhost:8080`, and that process is still x402-gated. No payment-free sandbox was found. |

Closest existing object: `DclClient.evaluate("fast", { response, agent_id, task_type })` against `POST /evaluate/fast`.

What blocks using it as the Web2 layer:

1. The caller must already know the evaluation body (`response` text, tier names). There is no action / target / payload shape for an HTTP side effect.
2. Non-OK responses throw. A `try/except` that still performs the side effect would fail open. HTTP 402 is the caller's problem.
3. Nothing withholds the downstream HTTP call. The SDK returns data; it does not gate a POST.
4. Production settlement (x402, Base, USDC) sits outside the client, so a Web2 caller is pushed into payment parsing.

Parameters that are actually required to approve a side effect: the action and the target. The Oracle's required field is `response` (string). Payload, tier, agent id, and timeout can be optional. Payment credentials are not required for the call shape; they are required only when the deployed Oracle answers 402.

Where Web3 shows up today: `DclClient` documents an x402-aware `fetchImpl`, and both the hosted API and the local webhook server refuse unpaid calls. Chain id, token, and signing are not part of `EvaluateRequest`, but the caller still has to handle them to get a verdict.

Decision: add a thin facade in this repo. It calls the existing `/evaluate/{tier}` route and maps the existing `verdict` field. It does not add a policy engine, a hash implementation, a payment signer, or a second Oracle.

## Facade

`DCLGuard.check` writes the action, target, and JSON payload into `EvaluateRequest.response`, with `task_type` `http_side_effect`. `allowed` is true only for HTTP 200 and `verdict == "COMMIT"`. Timeout, malformed JSON, any other verdict, HTTP 500, HTTP 402, and transport errors become `NO_COMMIT` and do not raise into the caller's side effect.

`DCLGuard.post` is the same check plus the POST. The POST function is reached only after `decision.allowed` is true.

An optional `transport` can wrap an existing payment-capable HTTP client. This package does not construct an x402 payment. If that transport is absent or still returns 402, the guard denies.

## Local Sandbox gap

There is no DCL Local Sandbox to integrate. The minimal bridge is `LocalSandbox`: a loopback server with the public verdict JSON and a caller-supplied substring switch. `tx_hash` values are `sandbox-N` correlation ids, not audit-chain proofs. Production policy still lives only on the Oracle. Point `oracle_url` at a real Oracle when leaving the sandbox.
