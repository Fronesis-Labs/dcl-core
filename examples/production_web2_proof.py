#!/usr/bin/env python3
"""Ask the live DCL Trust Oracle before a harmless external POST.

The target request is sent only by ``DCLGuard.post``, and only after that
call's verdict is COMMIT. When payer credentials are configured, the Oracle
call goes through an x402 transport that pays only the Oracle evaluate URL.
This script prints the decision and the transport's own observations. It
does not invent a verdict, trace id, event id, or transaction hash.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, TextIO

_ROOT = Path(__file__).resolve().parents[1]
_EXAMPLES = Path(__file__).resolve().parent
for _path in (_ROOT, _EXAMPLES):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from dcl import DCLGuard, SideEffectResult
from oracle_x402_transport import (
    InvalidPaymentCap,
    MISSING_PAYER_KEY_MESSAGE,
    OracleTransportObservation,
    build_oracle_only_transport,
    payment_credentials_configured,
)

# Documented production origin. ``DCL_ORACLE_URL`` overrides it.
DOCUMENTED_ORACLE_URL = "https://webhook.fronesislabs.com"
# Public echo service. Not the Oracle, and not a Fronesis host.
TARGET_URL = "https://httpbin.org/post"
PAYLOAD = {
    "action": "post_json",
    "note": "harmless DCL Web2 production proof",
}
_CREDENTIALS_MESSAGE = "production proof unavailable: " + MISSING_PAYER_KEY_MESSAGE


def resolve_oracle_url(environ: Mapping[str, str]) -> str:
    """Use ``DCL_ORACLE_URL`` when it is non-empty, otherwise the documented origin."""
    configured = environ.get("DCL_ORACLE_URL", "").strip()
    return configured or DOCUMENTED_ORACLE_URL


def build_proof_record(
    *,
    oracle_url: str,
    target_url: str,
    result: SideEffectResult,
    timestamp: str,
    observation: OracleTransportObservation | None = None,
) -> dict[str, object]:
    """Shape one proof object from a ``DCLGuard.post`` result.

    ``executed`` is set by the guard only after COMMIT, so
    ``target_called_after_commit`` follows that flag. A denial keeps the
    target status out of the record. ``complete`` additionally requires the
    observed chain HTTP 402, one payment, Oracle HTTP 200, and target HTTP 200
    when a transport observation is present.
    """
    decision = result.decision
    committed = decision.verdict == "COMMIT" and decision.allowed and result.executed
    chain_ok = _payment_chain_ok(observation)
    target_ok = result.status_code == 200
    complete = bool(committed and target_ok and chain_ok)

    oracle: dict[str, object] = {
        "url": oracle_url,
        "verdict": decision.verdict,
        "reason": decision.reason,
    }
    if observation is not None and observation.initial_status is not None:
        oracle["initial_status"] = observation.initial_status
        oracle["payment_required"] = observation.initial_status == 402
    if observation is not None and observation.final_status is not None:
        oracle["final_status"] = observation.final_status
    # Copy only the fields the Oracle actually returned on the decision.
    if decision.trace_id:
        oracle["trace_id"] = decision.trace_id
    if decision.tx_hash:
        oracle["tx_hash"] = decision.tx_hash
    if decision.event_id:
        oracle["event_id"] = decision.event_id
    elif observation is not None and observation.event_id:
        oracle["event_id"] = observation.event_id
    if decision.request_digest:
        oracle["request_digest"] = decision.request_digest

    target: dict[str, object] = {
        "url": target_url,
        "method": "POST",
    }
    if committed and result.status_code is not None:
        target["http_status"] = result.status_code

    enforcement: dict[str, object] = {
        # post() always evaluates before it can set executed. If executed
        # is set without COMMIT, the control flow was not the guard's.
        "dcl_checked_before_target": (not result.executed) or committed,
        "target_called_after_commit": committed,
    }
    if observation is not None:
        sequence = list(observation.sequence)
        if result.executed:
            sequence.append("target")
        enforcement["sequence"] = sequence

    record: dict[str, object] = {
        "proof": "dcl-web2-production",
        "complete": complete,
        "oracle": oracle,
        "target": target,
        "enforcement": enforcement,
        "timestamp": timestamp,
    }
    if not complete:
        record["stage"] = _incomplete_stage(result, observation)
    payment = _payment_fields(observation)
    if payment:
        record["payment"] = payment
    return record


def credentials_missing_record(
    *,
    oracle_url: str,
    target_url: str,
    timestamp: str,
) -> dict[str, object]:
    """Incomplete proof used when no payer key is configured."""
    return {
        "proof": "dcl-web2-production",
        "complete": False,
        "stage": MISSING_PAYER_KEY_MESSAGE,
        "oracle": {
            "url": oracle_url,
            "verdict": "NO_COMMIT",
            "reason": MISSING_PAYER_KEY_MESSAGE,
        },
        "target": {
            "url": target_url,
            "method": "POST",
        },
        "enforcement": {
            "dcl_checked_before_target": True,
            "target_called_after_commit": False,
        },
        "timestamp": timestamp,
    }


def run(environ: Mapping[str, str] | None = None, *, stdout: TextIO | None = None) -> int:
    """Run one proof. Returns 0 only when that run's chain completed."""
    env = os.environ if environ is None else environ
    out = stdout or sys.stdout
    oracle_url = resolve_oracle_url(env)
    timestamp = _timestamp()
    if not payment_credentials_configured(env):
        out.write(_CREDENTIALS_MESSAGE + "\n")
        record = credentials_missing_record(
            oracle_url=oracle_url,
            target_url=TARGET_URL,
            timestamp=timestamp,
        )
        json.dump(record, out, indent=2)
        out.write("\n")
        return 1

    observation = OracleTransportObservation()
    try:
        transport = build_oracle_only_transport(
            f"{oracle_url.rstrip('/')}/evaluate/fast",
            env,
            observation,
        )
    except InvalidPaymentCap:
        record = credentials_missing_record(
            oracle_url=oracle_url,
            target_url=TARGET_URL,
            timestamp=timestamp,
        )
        record["stage"] = "payment cap"
        record["oracle"] = {
            "url": oracle_url,
            "verdict": "NO_COMMIT",
            "reason": "payment cap is not usable",
        }
        json.dump(record, out, indent=2)
        out.write("\n")
        return 1

    guard = DCLGuard(oracle_url=oracle_url, transport=transport)
    result = guard.post(TARGET_URL, json=PAYLOAD)
    record = build_proof_record(
        oracle_url=oracle_url,
        target_url=TARGET_URL,
        result=result,
        timestamp=timestamp,
        observation=observation,
    )
    json.dump(record, out, indent=2)
    out.write("\n")
    return 0 if record["complete"] else 1


def main() -> int:
    return run(os.environ)


def _timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _payment_chain_ok(observation: OracleTransportObservation | None) -> bool:
    if observation is None:
        return True
    return (
        observation.initial_status == 402
        and observation.payment_required
        and observation.payment_attempted
        and not observation.over_cap
        and observation.final_status == 200
        and observation.sequence[:3] == ["oracle_402", "payment", "oracle_final"]
    )


def _incomplete_stage(
    result: SideEffectResult,
    observation: OracleTransportObservation | None,
) -> str:
    if observation is not None and observation.stage:
        return observation.stage
    if observation is not None and observation.over_cap:
        return "payment cap"
    if result.decision.verdict != "COMMIT":
        if (
            observation is not None
            and observation.payment_attempted
            and observation.final_status == 402
        ):
            return "payment rejected"
        return "oracle denied"
    if result.status_code != 200:
        return "target http status"
    if observation is not None and observation.initial_status != 402:
        return "oracle did not require payment"
    return "incomplete"


def _payment_fields(
    observation: OracleTransportObservation | None,
) -> dict[str, object] | None:
    if observation is None:
        return None
    if not observation.payment_attempted and not observation.payment_tx_hash:
        return None
    payment: dict[str, object] = {"attempted": observation.payment_attempted}
    if observation.payment_network:
        payment["network"] = observation.payment_network
    if observation.payment_asset:
        payment["asset"] = observation.payment_asset
    if observation.payment_amount_atomic:
        payment["amount_atomic"] = observation.payment_amount_atomic
    if observation.settled is not None:
        payment["settled"] = observation.settled
    if observation.payment_tx_hash:
        payment["tx_hash"] = observation.payment_tx_hash
    return payment


if __name__ == "__main__":
    sys.exit(main())
