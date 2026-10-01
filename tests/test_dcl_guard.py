"""DCLGuard must not perform the HTTP side effect unless the Oracle says COMMIT.

The side-effect call below is a real POST to a local server, the same
observation point as requests.post. Counts come from that server, not from
the boolean alone.
"""

from __future__ import annotations

import json
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from dcl import DCLGuard, LocalSandbox
from dcl.guard import Decision, OracleHttpResponse


class _ThreadingServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class ScriptedOracle:
    def __init__(
        self,
        mode: str,
        *,
        sleep_s: float = 2.0,
        body: bytes | None = None,
        status: int = 200,
        location: str = "",
    ) -> None:
        self.mode = mode
        self.sleep_s = sleep_s
        self.body = body
        self.status = status
        self.location = location
        self.hits: list[dict[str, object]] = []
        oracle = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args: object) -> None:
                return

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                oracle.hits.append({"path": self.path, "body": raw})
                if oracle.mode == "timeout":
                    time.sleep(oracle.sleep_s)
                    return
                if oracle.mode == "redirect":
                    self.send_response(307)
                    self.send_header("Location", oracle.location or "http://127.0.0.1/")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if oracle.mode == "commit":
                    status, payload = 200, oracle.body or _commit_body()
                elif oracle.mode == "block":
                    status, payload = 200, _block_body()
                elif oracle.mode == "malformed":
                    status, payload = 200, b"not-json"
                elif oracle.mode == "bad-verdict":
                    status, payload = 200, b'{"verdict":"MAYBE","reason":"no"}'
                elif oracle.mode == "server-error":
                    status, payload = 500, b'{"error":"boom"}'
                elif oracle.mode == "payment":
                    # A challenge body must not be honored even if it says COMMIT.
                    status, payload = 402, b'{"verdict":"COMMIT","reason":"paid","accepts":[]}'
                elif oracle.mode == "raw":
                    status = oracle.status
                    payload = oracle.body if oracle.body is not None else b""
                else:
                    status, payload = 500, b"{}"
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
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


class EffectServer:
    def __init__(self) -> None:
        self.hits: list[dict[str, object]] = []
        effect = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args: object) -> None:
                return

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                effect.hits.append({"path": self.path, "body": raw})
                payload = b'{"ok":true}'
                self.send_response(201)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self._server = _ThreadingServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        host, port = self._server.server_address[:2]
        self.url = f"http://{host}:{port}/orders"

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def _commit_body() -> bytes:
    return json.dumps(
        {
            "verdict": "COMMIT",
            "confidence": 0.95,
            "reason": "All policy checks passed",
            "tx_hash": "0xabc",
            "verify_url": "https://example.test/verify/abc",
            "chain_index": 1,
            "input_hash": "0xdef",
            "policy_version": "1.0.0",
            "timestamp": 1,
            "pipeline_id": "",
            "drift_mode": "NORMAL",
            "drift_score": 0,
        }
    ).encode()


def _block_body() -> bytes:
    return json.dumps(
        {
            "verdict": "NO_COMMIT",
            "reason": "forbidden phrase",
            "tx_hash": "0xblocked",
        }
    ).encode()


def developer_post(url: str, payload: dict) -> None:
    """The side effect a caller would make with requests.post after COMMIT."""
    data = json.dumps(payload).encode()
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            response.read()
    except urllib.error.HTTPError:
        return


class GuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.effect = EffectServer()

    def tearDown(self) -> None:
        self.effect.close()

    def _guard(self, oracle: ScriptedOracle, **kwargs: object) -> DCLGuard:
        return DCLGuard(oracle.url, timeout=0.3, **kwargs)  # type: ignore[arg-type]

    def test_commit_executes_side_effect(self) -> None:
        oracle = ScriptedOracle("commit")
        try:
            guard = self._guard(oracle)
            payload = {"amount": 42}
            decision = guard.check("POST", self.effect.url, payload)
            if decision.allowed:
                developer_post(self.effect.url, payload)
            self.assertTrue(decision.allowed)
            self.assertEqual(decision.verdict, "COMMIT")
            self.assertEqual(decision.reason, "All policy checks passed")
            self.assertIsNone(decision.trace_id)
            self.assertEqual(decision.tx_hash, "0xabc")
            self.assertEqual(decision.allowed, decision.verdict == "COMMIT")
            self.assertEqual(decision.verify_url, "https://example.test/verify/abc")
            self.assertEqual(len(self.effect.hits), 1)
            self.assertEqual(json.loads(self.effect.hits[0]["body"]), payload)  # type: ignore[arg-type]

            result = guard.post(self.effect.url, json=payload)
            self.assertTrue(result.executed)
            self.assertEqual(result.status_code, 201)
            self.assertEqual(len(self.effect.hits), 2)

            sent = json.loads(oracle.hits[0]["body"])  # type: ignore[arg-type]
            self.assertEqual(set(sent), {"response", "agent_id", "task_type"})
            self.assertIn("action: POST", sent["response"])
            self.assertIn(self.effect.url, sent["response"])
            self.assertIn('"amount":42', sent["response"])
            self.assertTrue(oracle.hits[0]["path"].endswith("/evaluate/fast"))  # type: ignore[union-attr]
            self.assertEqual(len(oracle.hits), 2)
        finally:
            oracle.close()

    def test_no_commit_does_not_execute_side_effect(self) -> None:
        oracle = ScriptedOracle("block")
        try:
            self._assert_blocked(oracle, reason_contains="forbidden phrase")
        finally:
            oracle.close()

    def test_timeout_does_not_execute_side_effect(self) -> None:
        oracle = ScriptedOracle("timeout", sleep_s=2.0)
        try:
            self._assert_blocked(oracle, reason_contains="timeout")
        finally:
            oracle.close()

    def test_malformed_response_does_not_execute_side_effect(self) -> None:
        oracle = ScriptedOracle("malformed")
        try:
            self._assert_blocked(oracle, reason_contains="malformed")
        finally:
            oracle.close()

    def test_invalid_verdict_does_not_execute_side_effect(self) -> None:
        oracle = ScriptedOracle("bad-verdict")
        try:
            self._assert_blocked(oracle, reason_contains="malformed")
        finally:
            oracle.close()

    def test_http_500_does_not_execute_side_effect(self) -> None:
        oracle = ScriptedOracle("server-error")
        try:
            self._assert_blocked(oracle, reason_contains="HTTP 500")
        finally:
            oracle.close()

    def test_payment_required_fails_closed_without_manual_402(self) -> None:
        oracle = ScriptedOracle("payment")
        try:
            guard = self._guard(oracle)
            payload = {"amount": 42}
            decision = guard.check("POST", self.effect.url, payload)
            if decision.allowed:
                developer_post(self.effect.url, payload)
            result = guard.post(self.effect.url, json=payload)
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.verdict, "NO_COMMIT")
            self.assertIn("payment required", decision.reason)
            self.assertIsNone(decision.trace_id)
            self.assertIsNone(decision.tx_hash)
            self.assertEqual(decision.allowed, decision.verdict == "COMMIT")
            self.assertFalse(result.executed)
            self.assertEqual(self.effect.hits, [])
            self.assertEqual(len(oracle.hits), 2)
            self.assertNotIn("402", decision.reason)
        finally:
            oracle.close()

    def test_transport_failure_fails_closed(self) -> None:
        def boom(url: str, body: dict, timeout: float) -> OracleHttpResponse:
            raise RuntimeError("wallet unavailable")

        guard = DCLGuard("http://127.0.0.1:9", transport=boom)
        decision = guard.check("POST", self.effect.url, {"amount": 1})
        if decision.allowed:
            developer_post(self.effect.url, {"amount": 1})
        result = guard.post(self.effect.url, json={"amount": 1})
        self.assertFalse(decision.allowed)
        self.assertFalse(result.executed)
        self.assertEqual(self.effect.hits, [])

    def test_trace_id_is_not_aliased_from_tx_hash(self) -> None:
        samples = [
            (
                {"verdict": "COMMIT", "reason": "ok", "tx_hash": "0xabc"},
                None,
                "0xabc",
                True,
            ),
            (
                {"verdict": "NO_COMMIT", "reason": "no", "tx_hash": "0xblocked"},
                None,
                "0xblocked",
                False,
            ),
            (
                {"verdict": "COMMIT", "reason": "ok", "tx_hash": "0xabc", "trace_id": ""},
                None,
                "0xabc",
                True,
            ),
            (
                {"verdict": "COMMIT", "reason": "ok", "tx_hash": "0xabc", "trace_id": 12},
                None,
                "0xabc",
                True,
            ),
            (
                {
                    "verdict": "COMMIT",
                    "reason": "ok",
                    "tx_hash": "0xabc",
                    "trace_id": "trace-9",
                    "verify_url": "https://example.test/verify/abc",
                },
                "trace-9",
                "0xabc",
                True,
            ),
            (
                {
                    "verdict": "NO_COMMIT",
                    "reason": "no",
                    "tx_hash": "0xabc",
                    "trace_id": "trace-9",
                },
                "trace-9",
                "0xabc",
                False,
            ),
        ]
        for body, trace_id, tx_hash, allowed in samples:
            with self.subTest(body=body):
                oracle = ScriptedOracle("raw", body=json.dumps(body).encode())
                try:
                    result = self._guard(oracle).post(self.effect.url, json={"amount": 1})
                    self.assertEqual(result.decision.trace_id, trace_id)
                    self.assertEqual(result.decision.tx_hash, tx_hash)
                    self.assertEqual(result.decision.allowed, allowed)
                    self.assertEqual(result.decision.verdict, "COMMIT" if allowed else "NO_COMMIT")
                    self.assertEqual(result.decision.allowed, result.decision.verdict == "COMMIT")
                    self.assertEqual(result.executed, allowed)
                    self.assertEqual(len(oracle.hits), 1)
                    self.assertEqual(len(self.effect.hits), 1 if allowed else 0)
                finally:
                    oracle.close()
                    self.effect.hits.clear()

    def test_single_post_counts_oracle_and_target(self) -> None:
        cases = [
            ("commit", 1, True),
            ("block", 0, False),
            ("payment", 0, False),
            ("server-error", 0, False),
            ("malformed", 0, False),
            ("bad-verdict", 0, False),
            ("timeout", 0, False),
        ]
        for mode, target_hits, executed in cases:
            with self.subTest(mode=mode):
                oracle = ScriptedOracle(mode, sleep_s=2.0)
                try:
                    started = time.monotonic()
                    result = self._guard(oracle).post(self.effect.url, json={"amount": 42})
                    elapsed = time.monotonic() - started
                    self.assertEqual(len(oracle.hits), 1)
                    self.assertEqual(len(self.effect.hits), target_hits)
                    self.assertEqual(result.executed, executed)
                    self.assertEqual(result.decision.allowed, executed)
                    self.assertEqual(result.decision.allowed, result.decision.verdict == "COMMIT")
                    if executed:
                        self.assertEqual(result.decision.verdict, "COMMIT")
                        self.assertEqual(json.loads(self.effect.hits[0]["body"]), {"amount": 42})  # type: ignore[arg-type]
                    else:
                        self.assertEqual(result.decision.verdict, "NO_COMMIT")
                    if mode == "timeout":
                        self.assertLess(elapsed, 1.5)
                        self.assertIn("timeout", result.decision.reason)
                finally:
                    oracle.close()
                    self.effect.hits.clear()

    def test_malformed_bodies_fail_closed(self) -> None:
        bodies = [
            b"{}",
            b'{"verdict":"UNKNOWN"}',
            b'{"verdict":"UNKNOWN","reason":"no"}',
            b"not json",
            b'{"verdict":"COMMIT"}',
            b'{"verdict":"COMMIT","reason":1}',
            b'{"verdict":"commit","reason":"ok"}',
            b'{"confidence":0.99,"reason":"All policy checks passed"}',
            b'{"reason":"COMMIT"}',
            b"[]",
            b"null",
        ]
        for body in bodies:
            with self.subTest(body=body):
                oracle = ScriptedOracle("raw", body=body)
                try:
                    result = self._guard(oracle).post(self.effect.url, json={"amount": 1})
                    self.assertEqual(len(oracle.hits), 1)
                    self.assertEqual(self.effect.hits, [])
                    self.assertFalse(result.executed)
                    self.assertFalse(result.decision.allowed)
                    self.assertEqual(result.decision.verdict, "NO_COMMIT")
                    self.assertIn("malformed", result.decision.reason)
                    self.assertIsNone(result.decision.trace_id)
                finally:
                    oracle.close()
                    self.effect.hits.clear()

    def test_reason_text_does_not_grant_commit(self) -> None:
        body = json.dumps(
            {
                "verdict": "NO_COMMIT",
                "reason": "COMMIT",
                "allowed": True,
                "confidence": 1,
            }
        ).encode()
        oracle = ScriptedOracle("raw", body=body)
        try:
            result = self._guard(oracle).post(self.effect.url, json={"amount": 1})
            self.assertEqual(result.decision.reason, "COMMIT")
            self.assertEqual(result.decision.verdict, "NO_COMMIT")
            self.assertFalse(result.decision.allowed)
            self.assertFalse(result.executed)
            self.assertEqual(len(oracle.hits), 1)
            self.assertEqual(self.effect.hits, [])
        finally:
            oracle.close()

    def test_allowed_flag_cannot_disagree_with_verdict(self) -> None:
        body = json.dumps(
            {"verdict": "COMMIT", "reason": "yes", "allowed": False, "confidence": 0}
        ).encode()
        oracle = ScriptedOracle("raw", body=body)
        try:
            result = self._guard(oracle).post(self.effect.url, json={"amount": 3})
            self.assertTrue(result.decision.allowed)
            self.assertEqual(result.decision.verdict, "COMMIT")
            self.assertTrue(result.executed)
            self.assertEqual(len(oracle.hits), 1)
            self.assertEqual(len(self.effect.hits), 1)
        finally:
            oracle.close()

    def test_network_error_does_not_call_target(self) -> None:
        guard = DCLGuard("http://127.0.0.1:9", timeout=1)
        result = guard.post(self.effect.url, json={"amount": 1})
        self.assertFalse(result.executed)
        self.assertEqual(self.effect.hits, [])
        self.assertFalse(result.decision.allowed)
        self.assertEqual(result.decision.verdict, "NO_COMMIT")
        self.assertIn("unavailable", result.decision.reason)

    def test_redirect_does_not_reach_target(self) -> None:
        oracle = ScriptedOracle("redirect", location=self.effect.url)
        try:
            result = self._guard(oracle).post(self.effect.url, json={"amount": 1})
            self.assertEqual(len(oracle.hits), 1)
            self.assertEqual(self.effect.hits, [])
            self.assertFalse(result.executed)
            self.assertFalse(result.decision.allowed)
            self.assertEqual(result.decision.verdict, "NO_COMMIT")
            self.assertIn("HTTP 307", result.decision.reason)
        finally:
            oracle.close()

    def test_transport_cannot_reach_target_without_commit(self) -> None:
        calls: list[str] = []

        def malicious(url: str, body: dict, timeout: float) -> OracleHttpResponse:
            calls.append(url)
            if url == self.effect.url or url.startswith(self.effect.url):
                developer_post(self.effect.url, {"via": "transport"})
            return OracleHttpResponse(
                status=200,
                body=json.dumps(
                    {"verdict": "NO_COMMIT", "reason": "denied", "tx_hash": "0xnot-a-trace"}
                ),
            )

        guard = DCLGuard("http://oracle.test", timeout=1, transport=malicious)
        result = guard.post(self.effect.url, json={"amount": 1})
        self.assertEqual(calls, ["http://oracle.test/evaluate/fast"])
        self.assertEqual(self.effect.hits, [])
        self.assertFalse(result.executed)
        self.assertFalse(result.decision.allowed)
        self.assertEqual(result.decision.verdict, "NO_COMMIT")
        self.assertIsNone(result.decision.trace_id)
        self.assertEqual(result.decision.tx_hash, "0xnot-a-trace")

    def test_commit_post_uses_separate_http_call(self) -> None:
        calls: list[str] = []

        def transport(url: str, body: dict, timeout: float) -> OracleHttpResponse:
            calls.append(url)
            if self.effect.url in url:
                developer_post(self.effect.url, {"via": "transport"})
            return OracleHttpResponse(status=200, body=_commit_body())

        guard = DCLGuard("http://oracle.test", timeout=2, transport=transport)
        result = guard.post(self.effect.url, json={"amount": 7})
        self.assertEqual(calls, ["http://oracle.test/evaluate/fast"])
        self.assertTrue(result.executed)
        self.assertEqual(result.decision.verdict, "COMMIT")
        self.assertTrue(result.decision.allowed)
        self.assertIsNone(result.decision.trace_id)
        self.assertEqual(result.decision.tx_hash, "0xabc")
        self.assertEqual(len(self.effect.hits), 1)
        self.assertEqual(json.loads(self.effect.hits[0]["body"]), {"amount": 7})  # type: ignore[arg-type]

    def _assert_blocked(self, oracle: ScriptedOracle, *, reason_contains: str) -> None:
        guard = self._guard(oracle)
        payload = {"amount": 42}
        decision = guard.check("POST", self.effect.url, payload)
        if decision.allowed:
            developer_post(self.effect.url, payload)
        result = guard.post(self.effect.url, json=payload)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.verdict, "NO_COMMIT")
        self.assertIn(reason_contains, decision.reason)
        self.assertFalse(result.executed)
        self.assertEqual(result.status_code, None)
        self.assertEqual(result.decision.allowed, result.decision.verdict == "COMMIT")
        self.assertEqual(self.effect.hits, [])
        self.assertEqual(len(oracle.hits), 2)


class SandboxTests(unittest.TestCase):
    def test_sandbox_commit_and_block(self) -> None:
        effect = EffectServer()
        try:
            with LocalSandbox(block_if_contains=["jailbreak"]) as sandbox:
                guard = DCLGuard(oracle_url=sandbox.url)
                allowed = guard.post(effect.url, json={"amount": 42})
                blocked = guard.post(effect.url, json={"note": "jailbreak the order"})
            self.assertTrue(allowed.decision.allowed)
            self.assertEqual(allowed.decision.verdict, "COMMIT")
            self.assertTrue(allowed.executed)
            self.assertIsNone(allowed.decision.trace_id)
            self.assertEqual(allowed.decision.tx_hash, "sandbox-1")
            self.assertIsNone(blocked.decision.trace_id)
            self.assertEqual(blocked.decision.tx_hash, "sandbox-2")
            self.assertFalse(blocked.decision.allowed)
            self.assertEqual(blocked.decision.verdict, "NO_COMMIT")
            self.assertFalse(blocked.executed)
            self.assertEqual(len(effect.hits), 1)
            self.assertEqual(json.loads(effect.hits[0]["body"]), {"amount": 42})  # type: ignore[arg-type]
        finally:
            effect.close()


class DecisionInvariantTests(unittest.TestCase):
    def test_allowed_must_match_verdict(self) -> None:
        with self.assertRaises(ValueError):
            Decision(True, "NO_COMMIT", "x")
        with self.assertRaises(ValueError):
            Decision(False, "COMMIT", "x")
        commit = Decision(True, "COMMIT", "ok", trace_id=None, tx_hash="0xabc")
        self.assertIsNone(commit.trace_id)
        self.assertEqual(commit.tx_hash, "0xabc")
        self.assertTrue(commit.allowed)


if __name__ == "__main__":
    unittest.main()
