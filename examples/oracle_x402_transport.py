"""Oracle-only x402 transport for the production Web2 proof.

DCLGuard stays unpaid and fail-closed. This adapter is the only place that
talks to the x402 client. It pays a single Oracle evaluate request when that
request returns HTTP 402, and it refuses every other URL before any network
call and before any signature.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Mapping

from dcl.guard import OracleHttpResponse

# Matches the live Oracle 402: maxAmountRequired "10000" is 0.01 USDC (6 decimals).
DEFAULT_MAX_PAYMENT_USDC = "0.01"

# Existing payer-key names. The first non-empty value wins. Values are never logged.
_PAYER_KEY_ENV_VARS = (
    "DCL_PAYER_PRIVATE_KEY",
    "X402_PRIVATE_KEY",
    "PRIVATE_KEY",
)

_CAP_ENV_VAR = "DCL_MAX_PAYMENT_USDC"

Send = Callable[
    [str, Mapping[str, Any], float, Mapping[str, str] | None],
    tuple[int, bytes, Mapping[str, str]],
]


class OracleUrlRefused(Exception):
    """The transport was asked to call something other than the Oracle."""


class InvalidPaymentCap(Exception):
    """``DCL_MAX_PAYMENT_USDC`` is missing a usable positive amount."""


@dataclass
class OracleTransportObservation:
    """What this process actually saw while the guard was calling the transport.

    Timestamps are monotonic seconds. ``sequence`` is the order of those
    observations. The target request is not in this object; the guard sends
    it later, with a different client, only after COMMIT.
    """

    initial_status: int | None = None
    payment_required: bool = False
    payment_attempted: bool = False
    over_cap: bool = False
    final_status: int | None = None
    payment_network: str | None = None
    payment_asset: str | None = None
    payment_amount_atomic: str | None = None
    payment_tx_hash: str | None = None
    settled: bool | None = None
    event_id: str | None = None
    stage: str | None = None
    sequence: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)


def payment_credentials_configured(environ: Mapping[str, str]) -> bool:
    """True when a payer key env var is set to a non-empty string."""
    return _payer_key(environ) is not None


def parse_max_payment_usdc(environ: Mapping[str, str]) -> Decimal:
    """Read the USDC cap. Default is ``0.01``, the live Oracle price."""
    raw = environ.get(_CAP_ENV_VAR, DEFAULT_MAX_PAYMENT_USDC).strip()
    if raw.startswith("$"):
        raw = raw[1:].strip()
    try:
        amount = Decimal(raw)
    except InvalidOperation as exc:
        raise InvalidPaymentCap(_CAP_ENV_VAR) from exc
    if not amount.is_finite() or amount <= 0:
        raise InvalidPaymentCap(_CAP_ENV_VAR)
    return amount


def build_oracle_only_transport(
    evaluate_url: str,
    environ: Mapping[str, str],
    observation: OracleTransportObservation | None = None,
    *,
    send: Send | None = None,
) -> OracleOnlyX402Transport:
    """Build a transport that can pay only ``evaluate_url``."""
    key = _payer_key(environ)
    if key is None:
        raise OracleUrlRefused("payment credentials not configured")
    observed = observation if observation is not None else OracleTransportObservation()
    return OracleOnlyX402Transport(
        evaluate_url,
        payer_key=key,
        max_payment_usdc=parse_max_payment_usdc(environ),
        observation=observed,
        send=send or _requests_send,
    )


class OracleOnlyX402Transport:
    """Callable ``Transport`` that pays one Oracle 402 and nothing else."""

    def __init__(
        self,
        evaluate_url: str,
        *,
        payer_key: str,
        max_payment_usdc: Decimal,
        observation: OracleTransportObservation,
        send: Send,
    ) -> None:
        if not isinstance(evaluate_url, str) or not evaluate_url.strip():
            raise ValueError("evaluate_url is required")
        self._evaluate_url = evaluate_url.strip()
        self._payer_key = payer_key
        self._max_payment_usdc = max_payment_usdc
        self.observation = observation
        self._send = send

    def __call__(
        self,
        url: str,
        body: Mapping[str, Any],
        timeout: float,
    ) -> OracleHttpResponse:
        if url != self._evaluate_url:
            self.observation.stage = "transport refused non-oracle url"
            self.observation.sequence.append("refused_non_oracle_url")
            raise OracleUrlRefused("transport refused non-oracle url")

        self.observation.urls.append(url)
        status, raw, headers = self._send(url, body, timeout, None)
        self.observation.initial_status = status
        if status != 402:
            self.observation.final_status = status
            self.observation.sequence.append("oracle_final")
            self.observation.event_id = _event_id(raw)
            return OracleHttpResponse(status=status, body=raw)

        self.observation.payment_required = True
        self.observation.sequence.append("oracle_402")
        try:
            payment_headers = self._payment_headers(raw, headers)
        except _CapExceeded:
            self.observation.over_cap = True
            self.observation.stage = "payment cap"
            self.observation.final_status = 402
            return OracleHttpResponse(status=402, body=raw)
        except Exception:
            self.observation.stage = "payment failed"
            self.observation.final_status = 402
            return OracleHttpResponse(status=402, body=raw)

        self.observation.payment_attempted = True
        self.observation.sequence.append("payment")
        self.observation.urls.append(url)
        try:
            final_status, final_raw, final_headers = self._send(
                url, body, timeout, payment_headers
            )
        except Exception:
            self.observation.stage = "payment failed"
            raise

        self.observation.sequence.append("oracle_final")
        self.observation.final_status = final_status
        self.observation.event_id = _event_id(final_raw)
        self._capture_settlement(final_headers)
        if final_status == 402 and not self.observation.stage:
            self.observation.stage = "payment rejected"
        elif final_status != 200 and not self.observation.stage:
            self.observation.stage = "oracle error"
        return OracleHttpResponse(status=final_status, body=final_raw)

    def _payment_headers(
        self,
        raw: bytes,
        response_headers: Mapping[str, str],
    ) -> dict[str, str]:
        """Create one x402 payment header for the 402 the Oracle just returned."""
        from x402 import NoMatchingRequirementsError, x402ClientSync
        from x402.http.x402_http_client import x402HTTPClientSync
        from x402.mechanisms.evm.exact.v1 import ExactEvmSchemeV1
        from eth_account import Account

        client = x402ClientSync()
        http = x402HTTPClientSync(client)
        required = http.get_payment_required_response(_header_lookup(response_headers), raw)
        account = Account.from_key(self._payer_key)
        scheme = ExactEvmSchemeV1(account)
        registered = False
        for requirement in required.accepts:
            if getattr(requirement, "scheme", None) != "exact":
                continue
            client.register_v1(requirement.network, scheme)
            registered = True
        if not registered:
            raise NoMatchingRequirementsError("no exact payment requirement")

        # The x402 client's own spend control. "$0.01" rejects maxAmountRequired above 10000.
        client.set_spend_controls(
            {"max_amount_per_payment": f"${format(self._max_payment_usdc, 'f')}"}
        )

        def _remember(ctx: Any) -> None:
            selected = ctx.selected_requirements
            self.observation.payment_network = str(selected.network)
            self.observation.payment_asset = str(selected.asset)
            self.observation.payment_amount_atomic = str(selected.get_amount())

        client.on_after_payment_creation(_remember)
        try:
            payload = client.create_payment_payload(required)
        except NoMatchingRequirementsError as exc:
            if "max_amount_per_payment" in str(exc):
                raise _CapExceeded from exc
            raise
        return http.encode_payment_signature_header(payload)

    def _capture_settlement(self, response_headers: Mapping[str, str]) -> None:
        from x402 import x402ClientSync
        from x402.http.x402_http_client import x402HTTPClientSync

        http = x402HTTPClientSync(x402ClientSync())
        try:
            settled = http.get_payment_settle_response(_header_lookup(response_headers))
        except Exception:
            return
        transaction = getattr(settled, "transaction", None)
        if isinstance(transaction, str) and transaction:
            self.observation.payment_tx_hash = transaction
        success = getattr(settled, "success", None)
        if isinstance(success, bool):
            self.observation.settled = success
        amount = getattr(settled, "amount", None)
        if isinstance(amount, str) and amount and self.observation.settled:
            self.observation.payment_amount_atomic = amount


class _CapExceeded(Exception):
    """The 402 price is above the configured USDC cap. Nothing was signed."""


def _payer_key(environ: Mapping[str, str]) -> str | None:
    for name in _PAYER_KEY_ENV_VARS:
        value = environ.get(name, "").strip()
        if value:
            return value
    return None


def _header_lookup(headers: Mapping[str, str]):
    folded = {str(key).lower(): value for key, value in headers.items()}

    def get(name: str) -> str | None:
        value = folded.get(name.lower())
        return value if isinstance(value, str) and value else None

    return get


def _event_id(body: bytes | str) -> str | None:
    """Read ``event_id`` from an Oracle body. Never substitute ``tx_hash``."""
    import json

    if isinstance(body, bytes):
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            return None
    else:
        text = body
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    event_id = data.get("event_id")
    if isinstance(event_id, str) and event_id:
        return event_id
    return None


def _requests_send(
    url: str,
    body: Mapping[str, Any],
    timeout: float,
    headers: Mapping[str, str] | None,
) -> tuple[int, bytes, Mapping[str, str]]:
    """POST JSON once. Redirects are not followed."""
    import json

    import requests

    outbound = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "dcl-guard",
    }
    if headers:
        outbound.update({str(key): str(value) for key, value in headers.items()})
    response = requests.post(
        url,
        data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
        headers=outbound,
        timeout=timeout,
        allow_redirects=False,
    )
    return response.status_code, response.content, dict(response.headers)
