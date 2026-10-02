#!/usr/bin/env python3
"""Live negative proof: a real Oracle non-COMMIT must not call the target.

This script does not invent a verdict. It sends one evaluate request through
``DCLGuard.post``. The payload includes the published default-policy token
``jailbreak``, which that policy lists as forbidden. The target is the public
httpbin echo and is reached only if the guard executes the POST.

A complete negative proof is an Oracle HTTP 200 whose verdict is NO_COMMIT,
with the target uncalled. HTTP 402 is a payment challenge, not that verdict.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, TextIO

_ROOT = Path(__file__).resolve().parents[1]
_EXAMPLES = Path(__file__).resolve().parent
for _path in (_ROOT, _EXAMPLES):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from dcl import DCLGuard, SideEffectResult, request_digest
from dcl.guard import OracleHttpResponse
from oracle_x402_transport import (
    InvalidPaymentCap,
    OracleTransportObservation,
    build_oracle_only_transport,
    payment_credentials_configured,
)
from production_web2_proof import resolve_oracle_url

TARGET_URL = "https://httpbin.org/post"
# The hosted default policy lists this token as forbidden. It is not a secret.
PAYLOAD = {
    "action": "post_json",
    "note": "dcl negative proof contains the published forbidden token jailbreak",
}
_SYNTHETIC_REASONS = frozenset(
    {
        "payment required and could not be completed",
        "payment credentials not configured",
        "request digest missing",
        "request digest mismatch",
        "oracle timeout",
        "oracle unavailable",
        "malformed oracle response",
        "action payload is not JSON-serializable",
    }
)


class _ObservedTransport:
    """Unpaid Oracle call that records the HTTP status and never calls the target."""

    def __init__(self, evaluate_url: str, observation: OracleTransportObservation) -> None:
        self._evaluate_url = evaluate_url
        self.observation = observation

    def __call__(self, url: str, body: Mapping[str, object], timeout: float) -> OracleHttpResponse:
        if url != self._evaluate_url:
            self.observation.stage = "transport refused non-oracle url"
            raise RuntimeError("transport refused non-oracle url")
        self.observation.urls.append(url)
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "dcl-guard",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read()
                status = response.status
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            status = exc.code
        self.observation.initial_status = status
        self.observation.final_status = status
        self.observation.sequence.append("oracle_final")
        if status == 402:
            self.observation.payment_required = True
            self.observation.stage = "oracle returned HTTP 402 before a verdict"
        return OracleHttpResponse(status=status, body=raw)


def build_negative_record(
    *,
    oracle_url: str,
    target_url: str,
    result: SideEffectResult,
    timestamp: str,
    observation: OracleTransportObservation,
    sent_digest: str,
) -> dict[str, object]:
    """Record a live negative attempt without filling in missing Oracle fields."""
    decision = result.decision
    http_status = observation.final_status
    policy_verdict = (
        http_status == 200
        and decision.verdict == "NO_COMMIT"
        and decision.reason not in _SYNTHETIC_REASONS
        and not decision.reason.startswith("oracle error")
    )
    target_called = bool(result.executed)
    complete = bool(policy_verdict and not target_called)

    oracle: dict[str, object] = {"url": oracle_url}
    if http_status is not None:
        oracle["http_status"] = http_status
        oracle["final_status"] = http_status
    if observation.initial_status is not None:
        oracle["initial_status"] = observation.initial_status
    if policy_verdict:
        oracle["verdict"] = decision.verdict
        oracle["reason"] = decision.reason
    else:
        oracle["guard_reason"] = decision.reason
    if decision.trace_id:
        oracle["trace_id"] = decision.trace_id
    if decision.event_id:
        oracle["event_id"] = decision.event_id
    if decision.tx_hash:
        oracle["tx_hash"] = decision.tx_hash
    if decision.request_digest:
        oracle["request_digest"] = decision.request_digest

    record: dict[str, object] = {
        "proof": "dcl-web2-production-negative",
        "complete": complete,
        "oracle": oracle,
        "request_digest": sent_digest,
        "target": {
            "url": target_url,
            "method": "POST",
            "called": target_called,
        },
        "enforcement": {
            "dcl_checked_before_target": not target_called or decision.verdict == "COMMIT",
            "target_called_after_commit": target_called and decision.verdict == "COMMIT",
        },
        "timestamp": timestamp,
    }
    if not complete:
        if observation.stage:
            record["stage"] = observation.stage
        elif http_status == 402:
            record["stage"] = "oracle returned HTTP 402 before a verdict"
        elif not policy_verdict:
            record["stage"] = "oracle did not return a policy NO_COMMIT"
        else:
            record["stage"] = "target was called"
    return record


def run(environ: Mapping[str, str] | None = None, *, stdout: TextIO | None = None) -> int:
    env = os.environ if environ is None else environ
    out = stdout or sys.stdout
    oracle_url = resolve_oracle_url(env)
    evaluate_url = f"{oracle_url.rstrip('/')}/evaluate/fast"
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    sent = request_digest("POST", TARGET_URL, PAYLOAD)
    observation = OracleTransportObservation()
    if payment_credentials_configured(env):
        try:
            transport = build_oracle_only_transport(evaluate_url, env, observation)
        except InvalidPaymentCap:
            observation.stage = "payment cap"
            record = {
                "proof": "dcl-web2-production-negative",
                "complete": False,
                "stage": "payment cap",
                "oracle": {"url": oracle_url, "guard_reason": "payment cap is not usable"},
                "request_digest": sent,
                "target": {"url": TARGET_URL, "method": "POST", "called": False},
                "timestamp": timestamp,
            }
            json.dump(record, out, indent=2)
            out.write("\n")
            return 1
    else:
        transport = _ObservedTransport(evaluate_url, observation)
    guard = DCLGuard(oracle_url=oracle_url, transport=transport)
    result = guard.post(TARGET_URL, json=PAYLOAD)
    record = build_negative_record(
        oracle_url=oracle_url,
        target_url=TARGET_URL,
        result=result,
        timestamp=timestamp,
        observation=observation,
        sent_digest=sent,
    )
    json.dump(record, out, indent=2)
    out.write("\n")
    return 0 if record["complete"] else 1


def main() -> int:
    return run(os.environ)


if __name__ == "__main__":
    sys.exit(main())
