"""Local HTTP stand-in for the DCL evaluation contract.

This is not the Trust Oracle and it does not run DCL policy, x402, or the
audit chain. It only answers ``POST /evaluate/{tier}`` with the public
verdict JSON so a developer can exercise COMMIT / NO_COMMIT without paying.

Substring blocking is a test switch the caller configures. It is not a
second policy engine.
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_TIERS = frozenset({"fast", "strict", "jailbreak", "safety", "quality"})


class _SandboxServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class LocalSandbox:
    """Bind a loopback server that speaks the evaluation response shape.

    ``block_if_contains`` lists substrings. If one appears in the action
    text sent to the Oracle (``response``), the sandbox returns NO_COMMIT.
    Otherwise it returns COMMIT.
    """

    def __init__(
        self,
        block_if_contains: list[str] | None = None,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        self.block_if_contains = [item for item in (block_if_contains or []) if item]
        self.host = host
        self.port = port
        self._server: _SandboxServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._counter = 0
        self.requests: list[dict[str, object]] = []

    @property
    def url(self) -> str:
        if self._server is None:
            raise RuntimeError("LocalSandbox is not started")
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> str:
        if self._server is not None:
            return self.url
        sandbox = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args: object) -> None:
                return

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                sandbox.requests.append({"path": self.path, "body": raw})
                tier = self.path.removeprefix("/evaluate/").split("?", 1)[0]
                if not self.path.startswith("/evaluate/") or tier not in _TIERS:
                    payload = b'{"verdict":"NO_COMMIT","reason":"sandbox unknown route"}'
                    status = 404
                else:
                    status = 200
                    payload = json.dumps(sandbox._decide(raw)).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("X-DCL-Sandbox", "1")
                self.end_headers()
                self.wfile.write(payload)

        self._server = _SandboxServer((self.host, self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.url

    def close(self) -> None:
        server = self._server
        self._server = None
        if server is not None:
            server.shutdown()
            server.server_close()

    def __enter__(self) -> "LocalSandbox":
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _decide(self, raw: bytes) -> dict[str, object]:
        try:
            incoming = json.loads(raw.decode("utf-8"))
            response_text = incoming.get("response", "") if isinstance(incoming, dict) else ""
            if not isinstance(response_text, str):
                response_text = str(response_text)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            response_text = ""

        matched = next((item for item in self.block_if_contains if item in response_text), None)
        if matched is not None:
            verdict = "NO_COMMIT"
            reason = f"sandbox blocked because the action contained {matched!r}"
            confidence = 0.0
        else:
            verdict = "COMMIT"
            reason = "sandbox allowed this action"
            confidence = 1.0

        with self._lock:
            self._counter += 1
            index = self._counter

        return {
            "verdict": verdict,
            "confidence": confidence,
            "reason": reason,
            "tx_hash": f"sandbox-{index}",
            "chain_index": index,
            "input_hash": "sandbox",
            "policy_version": "sandbox",
            "timestamp": time.time(),
            "pipeline_id": "",
            "drift_mode": "NORMAL",
            "drift_score": 0.0,
            "seal_text": "",
            "verify_url": "",
        }
