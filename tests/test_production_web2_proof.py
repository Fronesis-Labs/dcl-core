"""Static and local checks for the production example.

These tests do not call the live Oracle and they are not production evidence.
The live script is examples/production_web2_proof.py. Payment tests use a
local Oracle and a local target. The x402 client signs locally; nothing is
broadcast.
"""

from __future__ import annotations

import importlib.util
import io
import json
import re
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from dcl import DCLGuard
from dcl.guard import Decision, SideEffectResult

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "production_web2_proof.py"
ADAPTER = ROOT / "examples" / "oracle_x402_transport.py"

_FORBIDDEN_CALLS = (
    "requests.post",
    "requests.request",
    "urllib",
    "urlopen",
    "http.client",
    "httpx",
    "aiohttp",
    "subprocess",
    "os.system",
)

_SECRET_PATTERNS = (
    re.compile(r"api[_-]?key", re.IGNORECASE),
    re.compile(r"private[_-]?key", re.IGNORECASE),
    re.compile(r"BEGIN [A-Z ]*PRIVATE KEY"),
    re.compile(r"sk_live_"),
    re.compile(r"sk_test_"),
    re.compile(r"xox[baprs]-"),
    re.compile(r"ghp_"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"bearer\s+", re.IGNORECASE),
    re.compile(r"X-PAYMENT", re.IGNORECASE),
    re.compile(r"mnemonic", re.IGNORECASE),
    re.compile(r"seed phrase", re.IGNORECASE),
    re.compile(r"0x[a-fA-F0-9]{64}"),
    re.compile(r"Authorization\s*:", re.IGNORECASE),
)


def _load_example():
    spec = importlib.util.spec_from_file_location("production_web2_proof", EXAMPLE)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load production example")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ExampleSourceTests(unittest.TestCase):
    def test_example_source_has_no_direct_target_call_or_secret(self) -> None:
        source = EXAMPLE.read_text(encoding="utf-8")
        for token in _FORBIDDEN_CALLS:
            self.assertNotIn(token, source)
        for pattern in _SECRET_PATTERNS:
            self.assertIsNone(pattern.search(source), pattern.pattern)
        self.assertNotIn("localhost", source)
        self.assertNotIn("127.0.0.1", source)
        self.assertNotIn('"verdict": "COMMIT"', source)
        self.assertNotIn('"verdict":"COMMIT"', source)
        self.assertIn("DCLGuard", source)
        self.assertIn("guard.post(", source)
        self.assertNotIn("guard.check(", source)
        self.assertIn("DCL_ORACLE_URL", source)
        self.assertIn("guard.post(", source)
        adapter = ADAPTER.read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"BEGIN [A-Z ]*PRIVATE KEY", adapter))
        self.assertIsNone(re.search(r"0x[a-fA-F0-9]{64}", adapter))
        self.assertNotIn("sk_live_", adapter)
        self.assertNotIn("sk_test_", adapter)


class ExampleRecordTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_example()

    def test_constants_name_the_documented_oracle_and_a_third_party_target(self) -> None:
        self.assertEqual(self.mod.DOCUMENTED_ORACLE_URL, "https://webhook.fronesislabs.com")
        self.assertEqual(self.mod.TARGET_URL, "https://httpbin.org/post")
        self.assertNotIn("fronesislabs", self.mod.TARGET_URL)
        self.assertTrue(self.mod.TARGET_URL.startswith("https://"))

    def test_oracle_url_defaults_and_can_be_overridden(self) -> None:
        self.assertEqual(self.mod.resolve_oracle_url({}), self.mod.DOCUMENTED_ORACLE_URL)
        self.assertEqual(self.mod.resolve_oracle_url({"DCL_ORACLE_URL": "  "}), self.mod.DOCUMENTED_ORACLE_URL)
        self.assertEqual(
            self.mod.resolve_oracle_url({"DCL_ORACLE_URL": "https://oracle.example/root"}),
            "https://oracle.example/root",
        )

    def test_denial_does_not_claim_the_target_ran(self) -> None:
        decision = Decision(False, "NO_COMMIT", "payment required and could not be completed")
        result = SideEffectResult(decision=decision, executed=False)
        record = self.mod.build_proof_record(
            oracle_url=self.mod.DOCUMENTED_ORACLE_URL,
            target_url=self.mod.TARGET_URL,
            result=result,
            timestamp="2026-10-01T00:00:00Z",
        )
        self.assertFalse(record["complete"])
        self.assertEqual(record["oracle"]["verdict"], "NO_COMMIT")
        self.assertNotIn("trace_id", record["oracle"])
        self.assertNotIn("tx_hash", record["oracle"])
        self.assertNotIn("event_id", record["oracle"])
        self.assertNotIn("http_status", record["target"])
        self.assertTrue(record["enforcement"]["dcl_checked_before_target"])
        self.assertFalse(record["enforcement"]["target_called_after_commit"])

    def test_trace_id_stays_separate_from_tx_hash(self) -> None:
        decision = Decision(True, "COMMIT", "ok", trace_id=None, tx_hash="0xabc")
        result = SideEffectResult(decision=decision, executed=True, status_code=200, text="{}")
        record = self.mod.build_proof_record(
            oracle_url=self.mod.DOCUMENTED_ORACLE_URL,
            target_url=self.mod.TARGET_URL,
            result=result,
            timestamp="2026-10-01T00:00:00Z",
        )
        self.assertTrue(record["complete"])
        self.assertNotIn("trace_id", record["oracle"])
        self.assertEqual(record["oracle"]["tx_hash"], "0xabc")
        self.assertEqual(record["target"]["http_status"], 200)
        self.assertTrue(record["enforcement"]["target_called_after_commit"])

        both = Decision(True, "COMMIT", "ok", trace_id="trace-9", tx_hash="0xabc")
        both_result = SideEffectResult(decision=both, executed=True, status_code=200, text="{}")
        both_record = self.mod.build_proof_record(
            oracle_url=self.mod.DOCUMENTED_ORACLE_URL,
            target_url=self.mod.TARGET_URL,
            result=both_result,
            timestamp="2026-10-01T00:00:00Z",
        )
        self.assertEqual(both_record["oracle"]["trace_id"], "trace-9")
        self.assertEqual(both_record["oracle"]["tx_hash"], "0xabc")
        self.assertNotEqual(both_record["oracle"]["trace_id"], both_record["oracle"]["tx_hash"])

    def test_executed_without_commit_is_not_reported_as_enforced(self) -> None:
        decision = Decision(False, "NO_COMMIT", "denied")
        result = SideEffectResult(decision=decision, executed=True, status_code=200, text="{}")
        record = self.mod.build_proof_record(
            oracle_url=self.mod.DOCUMENTED_ORACLE_URL,
            target_url=self.mod.TARGET_URL,
            result=result,
            timestamp="2026-10-01T00:00:00Z",
        )
        self.assertFalse(record["complete"])
        self.assertFalse(record["enforcement"]["dcl_checked_before_target"])
        self.assertFalse(record["enforcement"]["target_called_after_commit"])
        self.assertNotIn("http_status", record["target"])


class ExampleCredentialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_example()

    def test_missing_credentials_are_incomplete_and_do_not_call_the_target(self) -> None:
        self.assertFalse(self.mod.payment_credentials_configured({}))
        self.assertFalse(self.mod.payment_credentials_configured({"DCL_PAYER_PRIVATE_KEY": "  "}))
        self.assertFalse(self.mod.payment_credentials_configured({"PRIVATE_KEY": ""}))
        self.assertFalse(self.mod.payment_credentials_configured({"PRIVATE_KEY": "other-wallet"}))
        self.assertTrue(self.mod.payment_credentials_configured({"DCL_PAYER_PRIVATE_KEY": "configured"}))
        self.assertTrue(self.mod.payment_credentials_configured({"X402_PRIVATE_KEY": "configured"}))
        with self.assertRaises(Exception) as caught:
            self.mod.build_oracle_only_transport(
                "https://webhook.fronesislabs.com/evaluate/fast",
                {"PRIVATE_KEY": "other-wallet"},
            )
        self.assertIn("DCL_PAYER_PRIVATE_KEY is not set", str(caught.exception))
        self.assertIn("PRIVATE_KEY is ignored", str(caught.exception))

        stdout = io.StringIO()
        code = self.mod.run({}, stdout=stdout)
        text = stdout.getvalue()
        self.assertEqual(code, 1)
        message, payload = text.split("\n", 1)
        self.assertEqual(message, "production proof unavailable: " + self.mod.MISSING_PAYER_KEY_MESSAGE)
        record = json.loads(payload)
        self.assertFalse(record["complete"])
        self.assertEqual(record["stage"], self.mod.MISSING_PAYER_KEY_MESSAGE)
        self.assertEqual(record["oracle"]["verdict"], "NO_COMMIT")
        self.assertNotIn("http_status", record["target"])
        self.assertNotIn("trace_id", record["oracle"])
        self.assertNotIn("tx_hash", record["oracle"])
        self.assertFalse(record["enforcement"]["target_called_after_commit"])

    def test_unusable_cap_does_not_call_the_target(self) -> None:
        stdout = io.StringIO()
        code = self.mod.run(
            {"DCL_PAYER_PRIVATE_KEY": "configured", "DCL_MAX_PAYMENT_USDC": "0"},
            stdout=stdout,
        )
        self.assertEqual(code, 1)
        record = json.loads(stdout.getvalue())
        self.assertEqual(record["stage"], "payment cap")
        self.assertFalse(record["complete"])
        self.assertEqual(record["oracle"]["verdict"], "NO_COMMIT")
        self.assertNotIn("http_status", record["target"])


_BASE_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
_BASE_PAY_TO = "0xb790ed3796194E5511C44411CF045F67E069cdC0"


def _v2_challenge(
    accepts: list[dict[str, object]],
) -> tuple[bytes, dict[str, str]]:
    """Build an unpaid v2 402. The body is empty; the challenge is the header."""
    from x402.http.utils import encode_payment_required_header
    from x402.schemas import PaymentRequired, PaymentRequirements, ResourceInfo

    required = PaymentRequired(
        x402_version=2,
        resource=ResourceInfo(
            url="https://bazaar.example/evaluate/fast",
            description="fast",
            mime_type="application/json",
        ),
        accepts=[PaymentRequirements.model_validate(item) for item in accepts],
    )
    return b"", {
        "Content-Type": "application/json",
        "PAYMENT-REQUIRED": encode_payment_required_header(required),
    }


def _exact_base_accept(amount: str, **overrides: object) -> dict[str, object]:
    accept: dict[str, object] = {
        "scheme": "exact",
        "network": "eip155:8453",
        "amount": amount,
        "payTo": _BASE_PAY_TO,
        "maxTimeoutSeconds": 300,
        "asset": _BASE_USDC,
        "extra": {"name": "USD Coin", "version": "2"},
    }
    accept.update(overrides)
    return accept


def _challenge(amount: str) -> bytes:
    return json.dumps(
        {
            "x402Version": 1,
            "error": "X-PAYMENT header is required",
            "accepts": [
                {
                    "scheme": "exact",
                    "network": "base",
                    "maxAmountRequired": amount,
                    "resource": "http://oracle.example/evaluate/fast",
                    "description": "",
                    "mimeType": "",
                    "payTo": "0xb790ed3796194E5511C44411CF045F67E069cdC0",
                    "maxTimeoutSeconds": 300,
                    "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                    "extra": {"name": "USD Coin", "version": "2"},
                }
            ],
        }
    ).encode("utf-8")


class _ThreadingServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class _HitServer:
    def __init__(self, respond) -> None:
        self.hits: list[dict[str, object]] = []
        parent = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args: object) -> None:
                return

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                signature = self.headers.get("PAYMENT-SIGNATURE")
                legacy = self.headers.get("X-PAYMENT")
                if signature:
                    payment_header = "PAYMENT-SIGNATURE"
                elif legacy:
                    payment_header = "X-PAYMENT"
                else:
                    payment_header = None
                parent.hits.append(
                    {
                        "path": self.path,
                        "body": raw,
                        "paid": payment_header is not None,
                        "payment_header": payment_header,
                    }
                )
                status, payload, extra = respond(self.path, raw, self.headers)
                self.send_response(status)
                for key, value in extra.items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self._server = _ThreadingServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        host, port = self._server.server_address[:2]
        self.url = f"http://{host}:{port}"

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


class OracleTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_example()
        cls.adapter = importlib.import_module("oracle_x402_transport")
        from eth_account import Account

        cls.payer = Account.create().key.hex()

    def _guard(self, oracle: _HitServer, observation):
        transport = self.adapter.OracleOnlyX402Transport(
            f"{oracle.url}/evaluate/fast",
            payer_key=self.payer,
            max_payment_usdc=self.adapter.parse_max_payment_usdc({}),
            observation=observation,
            send=self.adapter._requests_send,
        )
        guard = DCLGuard(oracle_url=oracle.url, transport=transport, timeout=5)
        return guard, transport

    def test_transport_refuses_a_non_oracle_url_before_any_send(self) -> None:
        calls: list[str] = []

        def send(url, body, timeout, headers):  # type: ignore[no-untyped-def]
            calls.append(url)
            raise AssertionError("send must not run")

        observation = self.adapter.OracleTransportObservation()
        transport = self.adapter.OracleOnlyX402Transport(
            "https://webhook.fronesislabs.com/evaluate/fast",
            payer_key=self.payer,
            max_payment_usdc=self.adapter.parse_max_payment_usdc({}),
            observation=observation,
            send=send,
        )
        with self.assertRaises(self.adapter.OracleUrlRefused):
            transport("https://httpbin.org/post", {"action": "post_json"}, 1.0)
        self.assertEqual(calls, [])
        self.assertEqual(observation.sequence, ["refused_non_oracle_url"])
        self.assertFalse(observation.payment_attempted)

    def test_price_over_cap_does_not_pay_or_call_the_target(self) -> None:
        oracle = _HitServer(lambda path, raw, headers: (402, _challenge("20000"), {"Content-Type": "application/json"}))
        target = _HitServer(lambda path, raw, headers: (200, b"{}", {"Content-Type": "application/json"}))
        observation = self.adapter.OracleTransportObservation()
        try:
            guard, _transport = self._guard(oracle, observation)
            result = guard.post(target.url + "/post", json={"action": "post_json"})
        finally:
            oracle.close()
            target.close()
        self.assertEqual(len(oracle.hits), 1)
        self.assertFalse(oracle.hits[0]["paid"])
        self.assertEqual(target.hits, [])
        self.assertFalse(result.executed)
        self.assertEqual(result.decision.verdict, "NO_COMMIT")
        self.assertEqual(observation.sequence, ["oracle_402"])
        self.assertTrue(observation.over_cap)
        self.assertFalse(observation.payment_attempted)
        record = self.mod.build_proof_record(
            oracle_url=oracle.url,
            target_url=target.url + "/post",
            result=result,
            timestamp="2026-10-01T00:00:00Z",
            observation=observation,
        )
        self.assertFalse(record["complete"])
        self.assertEqual(record["stage"], "payment cap")
        self.assertNotIn("http_status", record["target"])

    def test_payment_rejected_does_not_retry_or_call_the_target(self) -> None:
        def respond(path, raw, headers):  # type: ignore[no-untyped-def]
            if headers.get("X-PAYMENT"):
                return 402, b'{"error":"insufficient_funds"}', {"Content-Type": "application/json"}
            return 402, _challenge("10000"), {"Content-Type": "application/json"}

        oracle = _HitServer(respond)
        target = _HitServer(lambda path, raw, headers: (200, b"{}", {}))
        observation = self.adapter.OracleTransportObservation()
        try:
            guard, _transport = self._guard(oracle, observation)
            result = guard.post(target.url + "/post", json={"action": "post_json"})
        finally:
            oracle.close()
            target.close()
        self.assertEqual(len(oracle.hits), 2)
        self.assertFalse(oracle.hits[0]["paid"])
        self.assertTrue(oracle.hits[1]["paid"])
        self.assertEqual(target.hits, [])
        self.assertFalse(result.executed)
        self.assertEqual(observation.sequence, ["oracle_402", "payment", "oracle_final"])
        self.assertEqual(observation.final_status, 402)
        record = self.mod.build_proof_record(
            oracle_url=oracle.url,
            target_url=target.url + "/post",
            result=result,
            timestamp="2026-10-01T00:00:00Z",
            observation=observation,
        )
        self.assertEqual(record["stage"], "payment rejected")
        self.assertNotIn("http_status", record["target"])
        self.assertFalse(record["complete"])

    def test_oracle_non_200_after_payment_does_not_call_the_target(self) -> None:
        def respond(path, raw, headers):  # type: ignore[no-untyped-def]
            if headers.get("X-PAYMENT"):
                return 500, b'{"error":"boom"}', {"Content-Type": "application/json"}
            return 402, _challenge("10000"), {"Content-Type": "application/json"}

        oracle = _HitServer(respond)
        target = _HitServer(lambda path, raw, headers: (200, b"{}", {}))
        observation = self.adapter.OracleTransportObservation()
        try:
            guard, _transport = self._guard(oracle, observation)
            result = guard.post(target.url + "/post", json={"action": "post_json"})
        finally:
            oracle.close()
            target.close()
        self.assertEqual(len(oracle.hits), 2)
        self.assertEqual(target.hits, [])
        self.assertFalse(result.executed)
        self.assertEqual(observation.final_status, 500)
        record = self.mod.build_proof_record(
            oracle_url=oracle.url,
            target_url=target.url + "/post",
            result=result,
            timestamp="2026-10-01T00:00:00Z",
            observation=observation,
        )
        self.assertEqual(record["stage"], "oracle error")
        self.assertNotIn("http_status", record["target"])

    def test_malformed_oracle_body_after_payment_does_not_call_the_target(self) -> None:
        def respond(path, raw, headers):  # type: ignore[no-untyped-def]
            if headers.get("X-PAYMENT"):
                return 200, b"not-json", {"Content-Type": "text/plain"}
            return 402, _challenge("10000"), {"Content-Type": "application/json"}

        oracle = _HitServer(respond)
        target = _HitServer(lambda path, raw, headers: (200, b"{}", {}))
        observation = self.adapter.OracleTransportObservation()
        try:
            guard, _transport = self._guard(oracle, observation)
            result = guard.post(target.url + "/post", json={"action": "post_json"})
        finally:
            oracle.close()
            target.close()
        self.assertEqual(target.hits, [])
        self.assertFalse(result.executed)
        self.assertEqual(result.decision.reason, "malformed oracle response")
        self.assertIsNone(result.decision.trace_id)
        record = self.mod.build_proof_record(
            oracle_url=oracle.url,
            target_url=target.url + "/post",
            result=result,
            timestamp="2026-10-01T00:00:00Z",
            observation=observation,
        )
        self.assertNotIn("http_status", record["target"])
        self.assertNotIn("trace_id", record["oracle"])
        self.assertFalse(record["complete"])

    def test_commit_calls_the_target_once_and_only_pays_the_oracle(self) -> None:
        from x402.schemas.responses import SettleResponse
        from x402.http.utils import encode_payment_response_header

        payment_tx = "0x" + "cd" * 32
        audit_tx = "0x" + "ab" * 32
        settle = encode_payment_response_header(
            SettleResponse(success=True, transaction=payment_tx, network="base", amount="10000")
        )

        def respond(path, raw, headers):  # type: ignore[no-untyped-def]
            if headers.get("X-PAYMENT"):
                echoed = None
                try:
                    incoming = json.loads(raw.decode("utf-8"))
                    if isinstance(incoming, dict) and isinstance(incoming.get("request_digest"), str):
                        echoed = incoming["request_digest"]
                except (UnicodeDecodeError, json.JSONDecodeError):
                    echoed = None
                payload = {
                    "verdict": "COMMIT",
                    "reason": "ok",
                    "trace_id": "trace-live",
                    "tx_hash": audit_tx,
                    "event_id": "event-live",
                }
                if echoed:
                    payload["request_digest"] = echoed
                body = json.dumps(payload).encode("utf-8")
                return 200, body, {"Content-Type": "application/json", "X-PAYMENT-RESPONSE": settle}
            return 402, _challenge("10000"), {"Content-Type": "application/json"}

        oracle = _HitServer(respond)
        target = _HitServer(lambda path, raw, headers: (200, b'{"echo":true}', {"Content-Type": "application/json"}))
        observation = self.adapter.OracleTransportObservation()
        target_url = target.url + "/post"
        try:
            guard, transport = self._guard(oracle, observation)
            result = guard.post(target_url, json={"action": "post_json", "note": "local"})
        finally:
            oracle.close()
            target.close()

        self.assertEqual([hit["paid"] for hit in oracle.hits], [False, True])
        self.assertEqual(len(target.hits), 1)
        self.assertEqual(observation.urls, [f"{oracle.url}/evaluate/fast", f"{oracle.url}/evaluate/fast"])
        self.assertNotIn(target_url, observation.urls)
        self.assertEqual(observation.sequence, ["oracle_402", "payment", "oracle_final"])
        self.assertEqual(observation.initial_status, 402)
        self.assertEqual(observation.final_status, 200)
        self.assertEqual(observation.payment_network, "base")
        self.assertEqual(observation.payment_asset.lower(), "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913")
        self.assertEqual(observation.payment_amount_atomic, "10000")
        self.assertEqual(observation.payment_tx_hash, payment_tx)
        self.assertTrue(result.executed)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.decision.trace_id, "trace-live")
        self.assertEqual(result.decision.tx_hash, audit_tx)
        self.assertNotEqual(result.decision.trace_id, result.decision.tx_hash)
        self.assertNotEqual(result.decision.trace_id, payment_tx)
        record = self.mod.build_proof_record(
            oracle_url=oracle.url,
            target_url=target_url,
            result=result,
            timestamp="2026-10-01T00:00:00Z",
            observation=observation,
        )
        self.assertTrue(record["complete"])
        self.assertEqual(record["oracle"]["initial_status"], 402)
        self.assertEqual(record["oracle"]["final_status"], 200)
        self.assertEqual(record["oracle"]["verdict"], "COMMIT")
        self.assertEqual(record["oracle"]["trace_id"], "trace-live")
        self.assertEqual(record["oracle"]["event_id"], "event-live")
        self.assertEqual(record["oracle"]["tx_hash"], audit_tx)
        self.assertEqual(record["payment"]["tx_hash"], payment_tx)
        self.assertNotEqual(record["oracle"]["trace_id"], record["payment"]["tx_hash"])
        self.assertEqual(record["target"]["http_status"], 200)
        self.assertEqual(
            record["enforcement"]["sequence"],
            ["oracle_402", "payment", "oracle_final", "target"],
        )
        self.assertTrue(record["enforcement"]["target_called_after_commit"])
        self.assertIs(transport.observation, observation)

    def test_v2_payment_required_calls_the_target_only_after_commit(self) -> None:
        from x402.http.utils import decode_payment_signature_header, encode_payment_response_header
        from x402.schemas.responses import SettleResponse

        payment_tx = "0x" + "ef" * 32
        audit_tx = "0x" + "11" * 32
        settle = encode_payment_response_header(
            SettleResponse(success=True, transaction=payment_tx, network="eip155:8453", amount="10000")
        )
        other = {
            "scheme": "upto",
            "network": "eip155:84532",
            "amount": "1",
            "payTo": "0x1111111111111111111111111111111111111111",
            "maxTimeoutSeconds": 300,
            "asset": "0x2222222222222222222222222222222222222222",
            "extra": {"name": "Other", "version": "2"},
        }
        body, challenge_headers = _v2_challenge([other, _exact_base_accept("10000")])
        signatures: list[str] = []

        def respond(path, raw, headers):  # type: ignore[no-untyped-def]
            signature = headers.get("PAYMENT-SIGNATURE")
            if signature:
                signatures.append(signature)
                echoed = None
                try:
                    incoming = json.loads(raw.decode("utf-8"))
                    if isinstance(incoming, dict) and isinstance(incoming.get("request_digest"), str):
                        echoed = incoming["request_digest"]
                except (UnicodeDecodeError, json.JSONDecodeError):
                    echoed = None
                reply = {
                    "verdict": "COMMIT",
                    "reason": "ok",
                    "trace_id": "trace-v2",
                    "tx_hash": audit_tx,
                    "event_id": "event-v2",
                }
                if echoed:
                    reply["request_digest"] = echoed
                return 200, json.dumps(reply).encode("utf-8"), {
                    "Content-Type": "application/json",
                    "PAYMENT-RESPONSE": settle,
                }
            return 402, body, challenge_headers

        oracle = _HitServer(respond)
        target = _HitServer(lambda path, raw, headers: (200, b'{"echo":true}', {"Content-Type": "application/json"}))
        observation = self.adapter.OracleTransportObservation()
        try:
            guard, _transport = self._guard(oracle, observation)
            result = guard.post(target.url + "/post", json={"action": "post_json", "note": "v2"})
        finally:
            oracle.close()
            target.close()

        self.assertEqual([hit["payment_header"] for hit in oracle.hits], [None, "PAYMENT-SIGNATURE"])
        self.assertEqual(len(signatures), 1)
        payload = decode_payment_signature_header(signatures[0])
        accepted = payload.accepted
        self.assertEqual(payload.x402_version, 2)
        self.assertEqual(accepted.scheme, "exact")
        self.assertEqual(accepted.network, "eip155:8453")
        self.assertEqual(accepted.get_amount(), "10000")
        self.assertEqual(accepted.asset.lower(), _BASE_USDC.lower())
        self.assertEqual(accepted.pay_to.lower(), _BASE_PAY_TO.lower())
        self.assertEqual(len(target.hits), 1)
        self.assertTrue(result.executed)
        self.assertEqual(result.decision.verdict, "COMMIT")
        self.assertEqual(result.decision.trace_id, "trace-v2")
        self.assertEqual(result.decision.tx_hash, audit_tx)
        self.assertEqual(result.decision.event_id, "event-v2")
        self.assertNotEqual(result.decision.trace_id, result.decision.tx_hash)
        self.assertNotEqual(result.decision.trace_id, payment_tx)
        self.assertEqual(observation.sequence, ["oracle_402", "payment", "oracle_final"])
        self.assertEqual(observation.payment_network, "eip155:8453")
        self.assertEqual(observation.payment_amount_atomic, "10000")
        self.assertEqual(observation.payment_tx_hash, payment_tx)
        self.assertTrue(observation.settled)

    def test_v2_no_commit_does_not_call_the_target(self) -> None:
        body, challenge_headers = _v2_challenge([_exact_base_accept("10000")])

        def respond(path, raw, headers):  # type: ignore[no-untyped-def]
            if headers.get("PAYMENT-SIGNATURE"):
                echoed = json.loads(raw.decode("utf-8")).get("request_digest")
                return 200, json.dumps({
                    "verdict": "NO_COMMIT",
                    "reason": "policy",
                    "request_digest": echoed,
                    "trace_id": "trace-deny",
                    "tx_hash": "0x" + "22" * 32,
                }).encode("utf-8"), {"Content-Type": "application/json"}
            return 402, body, challenge_headers

        oracle = _HitServer(respond)
        target = _HitServer(lambda path, raw, headers: (200, b"{}", {}))
        observation = self.adapter.OracleTransportObservation()
        try:
            guard, _transport = self._guard(oracle, observation)
            result = guard.post(target.url + "/post", json={"action": "post_json"})
        finally:
            oracle.close()
            target.close()
        self.assertEqual([hit["payment_header"] for hit in oracle.hits], [None, "PAYMENT-SIGNATURE"])
        self.assertEqual(target.hits, [])
        self.assertFalse(result.executed)
        self.assertEqual(result.decision.verdict, "NO_COMMIT")
        self.assertEqual(result.decision.trace_id, "trace-deny")
        self.assertNotEqual(result.decision.trace_id, result.decision.tx_hash)

    def test_v2_digest_mismatch_does_not_call_the_target(self) -> None:
        body, challenge_headers = _v2_challenge([_exact_base_accept("10000")])

        def respond(path, raw, headers):  # type: ignore[no-untyped-def]
            if headers.get("PAYMENT-SIGNATURE"):
                return 200, json.dumps({
                    "verdict": "COMMIT",
                    "reason": "ok",
                    "request_digest": "ab" * 32,
                    "tx_hash": "0x" + "33" * 32,
                }).encode("utf-8"), {"Content-Type": "application/json"}
            return 402, body, challenge_headers

        oracle = _HitServer(respond)
        target = _HitServer(lambda path, raw, headers: (200, b"{}", {}))
        observation = self.adapter.OracleTransportObservation()
        try:
            guard, _transport = self._guard(oracle, observation)
            result = guard.post(target.url + "/post", json={"action": "post_json"})
        finally:
            oracle.close()
            target.close()
        self.assertEqual(len(target.hits), 0)
        self.assertFalse(result.executed)
        self.assertEqual(result.decision.verdict, "NO_COMMIT")
        self.assertEqual(result.decision.reason, "request digest mismatch")
        self.assertIsNone(result.decision.trace_id)
        self.assertEqual(result.decision.tx_hash, "0x" + "33" * 32)

    def test_v2_oracle_http_error_does_not_call_the_target(self) -> None:
        body, challenge_headers = _v2_challenge([_exact_base_accept("10000")])

        def respond(path, raw, headers):  # type: ignore[no-untyped-def]
            if headers.get("PAYMENT-SIGNATURE"):
                return 500, b"oracle down", {"Content-Type": "text/plain"}
            return 402, body, challenge_headers

        oracle = _HitServer(respond)
        target = _HitServer(lambda path, raw, headers: (200, b"{}", {}))
        observation = self.adapter.OracleTransportObservation()
        try:
            guard, _transport = self._guard(oracle, observation)
            result = guard.post(target.url + "/post", json={"action": "post_json"})
        finally:
            oracle.close()
            target.close()
        self.assertEqual(target.hits, [])
        self.assertFalse(result.executed)
        self.assertEqual(result.decision.verdict, "NO_COMMIT")
        self.assertEqual(observation.final_status, 500)
        self.assertEqual(observation.stage, "oracle error")

    def test_v2_amount_above_the_cap_does_not_sign(self) -> None:
        body, challenge_headers = _v2_challenge([_exact_base_accept("20000")])
        oracle = _HitServer(lambda path, raw, headers: (402, body, challenge_headers))
        target = _HitServer(lambda path, raw, headers: (200, b"{}", {}))
        observation = self.adapter.OracleTransportObservation()
        try:
            guard, _transport = self._guard(oracle, observation)
            result = guard.post(target.url + "/post", json={"action": "post_json"})
        finally:
            oracle.close()
            target.close()
        self.assertEqual(len(oracle.hits), 1)
        self.assertIsNone(oracle.hits[0]["payment_header"])
        self.assertEqual(target.hits, [])
        self.assertFalse(result.executed)
        self.assertTrue(observation.over_cap)
        self.assertFalse(observation.payment_attempted)

    def test_v2_non_exact_scheme_is_not_registered(self) -> None:
        body, challenge_headers = _v2_challenge([_exact_base_accept("10000", scheme="upto")])
        oracle = _HitServer(lambda path, raw, headers: (402, body, challenge_headers))
        target = _HitServer(lambda path, raw, headers: (200, b"{}", {}))
        observation = self.adapter.OracleTransportObservation()
        try:
            guard, _transport = self._guard(oracle, observation)
            result = guard.post(target.url + "/post", json={"action": "post_json"})
        finally:
            oracle.close()
            target.close()
        self.assertEqual(len(oracle.hits), 1)
        self.assertIsNone(oracle.hits[0]["payment_header"])
        self.assertEqual(target.hits, [])
        self.assertFalse(result.executed)
        self.assertFalse(observation.payment_attempted)
        self.assertEqual(observation.stage, "payment failed")

    def test_negative_record_requires_a_live_policy_denial(self) -> None:
        import importlib

        negative = importlib.import_module("production_web2_negative_proof")
        denied = Decision(False, "NO_COMMIT", "forbidden: 'jailbreak'")
        result = SideEffectResult(decision=denied, executed=False)
        observation = self.adapter.OracleTransportObservation()
        observation.final_status = 200
        observation.initial_status = 200
        record = negative.build_negative_record(
            oracle_url="https://webhook.fronesislabs.com",
            target_url="https://httpbin.org/post",
            result=result,
            timestamp="2026-10-02T00:00:00Z",
            observation=observation,
            sent_digest="abc",
        )
        self.assertTrue(record["complete"])
        self.assertEqual(record["oracle"]["verdict"], "NO_COMMIT")
        self.assertFalse(record["target"]["called"])

        challenge = Decision(False, "NO_COMMIT", "payment required and could not be completed")
        observation.final_status = 402
        record = negative.build_negative_record(
            oracle_url="https://webhook.fronesislabs.com",
            target_url="https://httpbin.org/post",
            result=SideEffectResult(decision=challenge, executed=False),
            timestamp="2026-10-02T00:00:00Z",
            observation=observation,
            sent_digest="abc",
        )
        self.assertFalse(record["complete"])
        self.assertNotIn("verdict", record["oracle"])
        self.assertEqual(record["oracle"]["http_status"], 402)
        self.assertFalse(record["target"]["called"])


if __name__ == "__main__":
    unittest.main()
