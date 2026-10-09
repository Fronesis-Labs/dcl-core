# Production Web2 proof

One ordinary POST, gated by the existing `DCLGuard` API. x402 settlement is performed by `examples/oracle_x402_transport.py`, which is not part of `DCLGuard`. The protected target stays a normal unpaid HTTPS request.

The recorded evidence was produced from commit `79390fc93f9ecf0baebe96e750d25e133ff1ef3e` on 2026-10-02. Do not start a new paid run unless you intend to spend USDC. The positive file is [production_web2_proof.json](production_web2_proof.json) (`2026-10-02T06:45:16Z`, digest `841bae2cf5392e1c55c4be5bae4187722df1af40166b1f8fc5c485d515b70019`). The negative file is [production_web2_negative_proof.json](production_web2_negative_proof.json) (`2026-10-02T06:46:17Z`, digest `bc6bc2e1d5e9101a177d0d07469670d81699305e41e23b6fe6ff46d70b8b806e`).

`oracle.tx_hash` is the DCL audit-chain identifier returned by the Oracle (`0x` plus SHA-256 of the canonical chain record). It is not the Base payment transaction. `payment.tx_hash` in the positive file is that payment transaction: `0x33f8af305b255b1a5d15b891f036b5940a47afa90fe9742201ea35af28ce2ad1`. The JSON does not include the fields `verify_chain()` requires, so it is not an offline chain proof and it does not authenticate the Oracle response. The README line "Don't trust the agent. Trust the proof." is that chain check. These JSON files only confirm the sequence this client observed.

These two JSON files are the current evidence. This repository does not contain an earlier proof note. A write-up that cites commit `8b620d0` or different hashes is a previous run, not a second canonical proof. The identifier that note called an Oracle transaction reference is the audit-chain hash (`oracle.tx_hash`), not a Base transaction.

The first full Bazaar live run is [bazaar_live_e2e_proof.json](bazaar_live_e2e_proof.json) (`2026-10-09T09:57:54Z`). `DCLGuard.post` paid one `$0.01` `exact` transfer on `eip155:8453` to `https://bazaar.fronesislabs.com/evaluate/fast`, received HTTP 200 and `COMMIT` with digest `841bae2cf5392e1c55c4be5bae4187722df1af40166b1f8fc5c485d515b70019`, then `POST https://httpbin.org/post` returned HTTP 200 and echoed that JSON body. The payment transaction is `0xc7077fcb8c2f254e2f27aa4a81331cdf99cff8b47036198d82b1e33dbb0810f8`. The audit-chain id `0xb3ed861a91cfdaf839aee4719e34b0d95a2a518f5c5d93f66ee27e32475796fa` is not that payment. The observed sequence contains one `payment` and one `target`. httpbin echoed `{"action":"post_json","note":"harmless DCL Web2 production proof"}`.

The Oracle receives the action, the target, and the JSON body in the `response` field, not only the digest, because checks such as jailbreak evaluate that text. On the production Oracle that text is sent to `https://webhook.fronesislabs.com`, which is the same disclosure as publishing the decision on the public audit board.

`target.called: false` on the negative proof means this process did not execute the target POST. httpbin does not supply a separate counter. Another client could still have called httpbin.

```
production_web2_proof
  → DCLGuard.post
  → Oracle /evaluate/fast
  → HTTP 402
  → x402 payment, Oracle URL only
  → Oracle COMMIT + matching request_digest
  → DCLGuard unpaid POST
  → https://httpbin.org/post
  → HTTP 200
```

The target is called only from inside `DCLGuard.post`, and only when the verdict is `COMMIT` and the returned `request_digest` matches. The payment transport is `examples/oracle_x402_transport.py`. It is not part of `DCLGuard`. If that transport is invoked with any URL other than the Oracle evaluate URL, it refuses before signing and before opening a connection.

`DCLGuard(...)` with no transport still works and still fails closed. This example is the only place that supplies a wallet.

## What this proves

A normal Web2 HTTP side effect can sit behind DCL authorization and runs only after the live Oracle returns `COMMIT` with the same `request_digest` the guard computed for that POST.

## What this does not prove

It does not prove that the target's business action was correct, that the target authenticated or authorized the caller, or that the target action settled financially. It does not prove that DCL replaces application authorization. It proves the enforcement boundary: the HTTP call is withheld until the Oracle commits.

## Prerequisites

- Python 3.10 or newer.
- This repository on the import path. From the repo root, `pip install -e .` does that. The script also inserts the repo root on `sys.path`.
- The x402 client used by the proof adapter, not by the guard:

```bash
pip install -r examples/requirements.txt
```

That installs `x402[requests,evm]>=2.25.0`, the same payment client family the DCL webhook uses. An equivalent extra is `pip install -e '.[proof]'`.
- Outbound HTTPS to the Oracle origin and, after `COMMIT`, to `https://httpbin.org/post`.
- A payer key in `DCL_PAYER_PRIVATE_KEY`. `X402_PRIVATE_KEY` is the only alias. A general `PRIVATE_KEY` is ignored, even when it is set for another wallet. If neither accepted variable is set, the script exits before any network call or signature.

The script never prints that value. Do not commit it. Do not commit a seed phrase. Use a dedicated wallet for this payment, keep only a small operational balance, and do not use a treasury or personal wallet. Rotate a credential that has been exposed.

No API key is required. The Oracle call is the x402 payment above. The target call is unpaid.

## Payment cap

`DCL_MAX_PAYMENT_USDC` is the most USDC this process will authorize for the Oracle request. The default is `0.01`, which is the live `maxAmountRequired` of `10000` atomic units on Base USDC (6 decimals).

The cap is applied by the x402 client's spend control before a payment header is created. If the 402 price is higher, the transport does not sign, does not submit a payment, and `DCLGuard` does not call the target. The JSON `stage` is `payment cap`. Do not raise the cap just to obtain a success.

There is one payment attempt for the Oracle request. A rejected or insufficient payment is not retried. The transport does not pay the target.

## Run

```bash
export DCL_ORACLE_URL="https://webhook.fronesislabs.com"
export DCL_PAYER_PRIVATE_KEY="..."
export DCL_MAX_PAYMENT_USDC="0.01"
python examples/production_web2_proof.py
```

`DCL_ORACLE_URL` is optional. When it is unset, the script uses `https://webhook.fronesislabs.com` and `POST /evaluate/fast`.

If neither accepted payer variable is set, the process prints this line and does not call the Oracle or the target:

```text
production proof unavailable: DCL_PAYER_PRIVATE_KEY is not set. The only accepted alias is X402_PRIVATE_KEY. PRIVATE_KEY is ignored.
```

It then prints JSON with `complete: false`, that same sentence as `stage`, verdict `NO_COMMIT`, and no target HTTP status, and exits 1.

## What the script does

1. Builds a two-field JSON body whose `action` is `post_json`.
2. Builds an Oracle-only x402 transport and passes it as `DCLGuard(..., transport=...)`.
3. Calls `guard.post("https://httpbin.org/post", json=payload)` once.
4. The guard asks the Oracle. The transport records the initial HTTP status. On 402 it asks the x402 client for one payment header, using the network, scheme, and asset in that 402 `accepts` entry, then sends that header only to the same Oracle URL.
5. The guard sends the httpbin POST with its own unpaid client only after HTTP 200, `verdict == COMMIT`, and a returned `request_digest` that matches the digest computed for that POST.
6. Prints one JSON object. Exit code 0 means `complete` is true. Any other outcome exits 1.

`complete` is true only when that single execution observed HTTP 402, one payment attempt, a final Oracle HTTP 200 with `COMMIT` and the matching `request_digest`, and a target HTTP 200 from `guard.post`.

## Expected success

A completed proof looks like this, with values taken from the live responses. Fields the Oracle or the payment client did not return are omitted.

- `oracle.initial_status` is 402 and `oracle.payment_required` is true.
- `oracle.final_status` is 200 and `oracle.verdict` is `COMMIT`.
- `oracle.trace_id` is present only when the Oracle JSON included `trace_id`. It is never copied from `tx_hash` or from the payment transaction.
- `oracle.tx_hash` is the DCL audit-chain hash the Oracle included (`ChainState.append` returns `0x` plus SHA-256 of the canonical record). It is not a Base transaction hash. `payment.tx_hash` is present only when the x402 client returned a settlement transaction. They are different fields.
- `oracle.event_id` is present only when the Oracle JSON included `event_id`.
- `target.http_status` is the status of the POST the guard sent, and only when the verdict was `COMMIT`.
- `enforcement.sequence` records `oracle_402`, then `payment`, then `oracle_final`, then `target` only if the guard executed the POST.
- `complete` is true and the process exits 0.

## What counts as valid proof

All of the following, from one execution of this script:

- The Oracle URL is the live Trust Oracle (the documented origin, or `DCL_ORACLE_URL` set to that origin).
- The initial 402, the payment, and the final verdict were observed by the transport in that order.
- The verdict, reason, and any trace id, event id, or Oracle tx hash are copied from that response.
- The httpbin status is the status `DCLGuard.post` observed after `COMMIT`.
- The script output is the process's own JSON, unmodified.

A local sandbox, a mocked Oracle, a handwritten `COMMIT`, or a POST issued outside `DCLGuard` is not this proof.

## Safety limits

- One JSON POST of a few dozen bytes. No credentials are sent to httpbin.
- The external target is `https://httpbin.org/post`, a public request echo. It is not localhost, not the DCL Oracle, and not a Fronesis host.
- The script does not retry a rejected payment, follow an Oracle redirect, or attach a payment header to the target.
- Missing payer credentials, a price above `DCL_MAX_PAYMENT_USDC`, a rejected payment, a non-200 Oracle response, and a malformed Oracle body all leave the target uncalled.
- `DCLGuard.post` withholds the target unless the Oracle returns the same `request_digest` the guard computed for that POST. Headers are not in the digest. The recorded live run did that: Oracle HTTP 200, `COMMIT`, the same digest, then target HTTP 200. See [production_web2_proof.json](production_web2_proof.json).

## Negative path

`examples/production_web2_negative_proof.py` calls the live Oracle through `DCLGuard.post`. The body contains the published default-policy forbidden token `jailbreak`. The target stays `https://httpbin.org/post`.

```bash
python3 examples/production_web2_negative_proof.py
```

`complete` is true only when the Oracle HTTP status is 200, the verdict is a real `NO_COMMIT`, and `target.called` is false. HTTP 402 is recorded as a payment challenge and is not treated as that verdict. The script does not write a local `NO_COMMIT` in place of the Oracle response.

The completed live negative run is [production_web2_negative_proof.json](production_web2_negative_proof.json): Oracle 402, x402 payment, `NO_COMMIT`, `target.called` false. That flag is this client's observation that `DCLGuard` did not call the target. It is not an independent httpbin audit.
