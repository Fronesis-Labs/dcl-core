"""Fail-closed check against the existing DCL Trust Oracle REST API.

This module does not score policy, hash audit records, or settle x402
payments. It POSTs the intended action to ``/evaluate/{tier}`` and turns
anything other than a well-formed COMMIT into a denial.
"""

from __future__ import annotations

import hashlib
import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from dcl.signed_envelope import (
    OracleTrustConfig,
    decision_from_signed_wrapper,
    looks_like_signed_wrapper,
)

_TIERS = frozenset({"fast", "strict", "jailbreak", "safety", "quality"})
_ORACLE_USER_AGENT = "dcl-guard"


@dataclass(frozen=True)
class Decision:
    """Whether the side effect may run.

    ``allowed`` is true only when ``verdict`` is ``COMMIT``.
    ``trace_id`` is set only from the Oracle ``trace_id`` field. It is
    never copied from ``tx_hash``. ``tx_hash`` and ``verify_url`` are
    passed through when the Oracle sent those fields.
    """

    allowed: bool
    verdict: str
    reason: str
    trace_id: str | None = None
    tx_hash: str | None = None
    verify_url: str | None = None
    event_id: str | None = None
    request_digest: str | None = None

    def __post_init__(self) -> None:
        if self.verdict not in ("COMMIT", "NO_COMMIT"):
            raise ValueError("verdict must be COMMIT or NO_COMMIT")
        if self.allowed != (self.verdict == "COMMIT"):
            raise ValueError("allowed must equal verdict == COMMIT")


@dataclass(frozen=True)
class SideEffectResult:
    """Outcome of a guarded HTTP POST.

    ``request_sent`` is true when the POST to the digested URL was sent,
    including when that response was a redirect the guard refused to follow.
    ``executed`` is true only when that POST returned a non-redirect response
    after exact ``COMMIT`` and a matching digest. A denial before the target
    call leaves both false. ``executed`` false with ``request_sent`` true
    means the digested host may already have seen the request.
    """

    decision: Decision
    executed: bool
    status_code: int | None = None
    text: str | None = None
    request_sent: bool = False


@dataclass(frozen=True)
class OracleHttpResponse:
    """What an optional payment-capable transport returns to the guard."""

    status: int
    body: bytes | str


Transport = Callable[[str, Mapping[str, Any], float], OracleHttpResponse]


def _deny(reason: str) -> Decision:
    return Decision(allowed=False, verdict="NO_COMMIT", reason=reason)


def _optional_str(value: Any) -> str | None:
    if isinstance(value, str) and value:
        return value
    return None


def canonical_json(value: Any) -> str:
    """This package's deterministic JSON encoding, not RFC 8785 JCS.

    Object keys are sorted. Separators are compact. Unicode is preserved
    (``ensure_ascii=False``). Arrays keep their order. ``None`` is not valid
    here. Callers that have no body use an empty string instead, so a
    missing body does not hash as JSON ``null``.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_url(url: str) -> str:
    """Normalize a URL for the request digest.

    Scheme and host are lowercased, the fragment is dropped, and the
    default port for the scheme is omitted. Query pairs are sorted.
    Headers are not part of the URL.
    """
    parts = urllib.parse.urlsplit(url.strip())
    if not parts.scheme or not parts.hostname:
        return url.strip()
    host = parts.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    port = parts.port
    if port and not (
        (parts.scheme.lower() == "http" and port == 80)
        or (parts.scheme.lower() == "https" and port == 443)
    ):
        host = f"{host}:{port}"
    if parts.username is not None:
        auth = parts.username
        if parts.password is not None:
            auth = f"{auth}:{parts.password}"
        host = f"{auth}@{host}"
    path = parts.path or "/"
    query_pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    query_pairs.sort()
    query = urllib.parse.urlencode(query_pairs)
    return urllib.parse.urlunsplit((parts.scheme.lower(), host, path, query, ""))


def request_digest(method: str, url: str, body: Any = None) -> str:
    """SHA-256 of the protected HTTP intent.

    The preimage is ``METHOD\\ncanonical URL\\ncanonical JSON``. A missing
    body is an empty line, not JSON ``null``. HTTP headers are omitted:
    they carry transport and payment material, including x402 headers that
    must never become part of the authorized target request. This digest
    is not the Oracle audit-chain ``input_hash``.
    """
    if not isinstance(method, str) or not method.strip():
        raise ValueError("method is required")
    if not isinstance(url, str) or not url.strip():
        raise ValueError("url is required")
    canonical_body = "" if body is None else canonical_json(body)
    material = f"{method.strip().upper()}\n{canonical_url(url)}\n{canonical_body}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _describe_action(action: str, target: str, payload: Any) -> str:
    lines = [f"action: {action.strip().upper()}", f"target: {target.strip()}"]
    if payload is not None:
        lines.append(
            "payload: "
            + json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
        )
    return "\n".join(lines)


class _DenyRedirects(urllib.request.HTTPRedirectHandler):
    """Refuse 3xx instead of following Location.

    A redirect could point at a URL that was not covered by the request
    digest. Following it would perform that call.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)


class TargetRedirectRefused(Exception):
    """The digested target URL answered with a redirect. Location was not opened."""

    def __init__(self, status: int) -> None:
        self.status = status
        super().__init__(f"target redirect refused (HTTP {status})")


def _urllib_transport(url: str, body: Mapping[str, Any], timeout: float) -> OracleHttpResponse:
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": _ORACLE_USER_AGENT,
        },
        method="POST",
    )
    opener = urllib.request.build_opener(_DenyRedirects)
    try:
        with opener.open(request, timeout=timeout) as response:
            return OracleHttpResponse(status=response.status, body=response.read())
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        return OracleHttpResponse(status=exc.code, body=raw)
    except (TimeoutError, socket.timeout) as exc:
        raise TimeoutError("oracle timeout") from exc
    except urllib.error.URLError as exc:
        reason = exc.reason
        if isinstance(reason, (TimeoutError, socket.timeout)):
            raise TimeoutError("oracle timeout") from exc
        raise ConnectionError("oracle unavailable") from exc


def _decision_from_http(
    status: int,
    body: bytes | str,
    *,
    expected_digest: str | None,
    trust: OracleTrustConfig | None = None,
) -> Decision:
    # A payment challenge must never be parsed as an allow, even if the
    # body contains a COMMIT verdict.
    if status == 402:
        return _deny("payment required and could not be completed")
    if status != 200:
        return _deny(f"oracle error (HTTP {status})")

    if isinstance(body, bytes):
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            return _deny("malformed oracle response")
    else:
        text = body

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        return _deny("malformed oracle response")
    if not isinstance(data, dict):
        return _deny("malformed oracle response")

    if looks_like_signed_wrapper(data):
        signed = decision_from_signed_wrapper(
            data,
            expected_digest=expected_digest,
            trust=trust,
        )
        return Decision(
            signed.allowed,
            signed.verdict,
            signed.reason,
            trace_id=signed.trace_id,
            request_digest=signed.request_digest,
        )

    verdict = data.get("verdict")
    reason = data.get("reason")
    if verdict not in ("COMMIT", "NO_COMMIT") or not isinstance(reason, str):
        return _deny("malformed oracle response")

    # trace_id and tx_hash are different fields. Do not copy one into the other.
    # request_digest is the HTTP intent digest, not input_hash.
    trace_id = _optional_str(data.get("trace_id"))
    tx_hash = _optional_str(data.get("tx_hash"))
    verify_url = _optional_str(data.get("verify_url"))
    event_id = _optional_str(data.get("event_id"))
    returned_digest = _optional_str(data.get("request_digest"))
    if verdict == "COMMIT" and expected_digest is not None and returned_digest != expected_digest:
        reason = "request digest missing" if returned_digest is None else "request digest mismatch"
        return Decision(
            allowed=False,
            verdict="NO_COMMIT",
            reason=reason,
            trace_id=trace_id,
            tx_hash=tx_hash,
            verify_url=verify_url,
            event_id=event_id,
            request_digest=returned_digest,
        )
    return Decision(
        allowed=verdict == "COMMIT",
        verdict=verdict,
        reason=reason,
        trace_id=trace_id,
        tx_hash=tx_hash,
        verify_url=verify_url,
        event_id=event_id,
        request_digest=returned_digest,
    )


def _execute_post(
    url: str,
    payload: Any,
    headers: Mapping[str, str] | None,
    timeout: float,
) -> tuple[int, str]:
    data = None
    hdrs = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    if headers:
        hdrs.update({str(key): str(value) for key, value in headers.items()})
    request = urllib.request.Request(url, data=data, headers=hdrs, method="POST")
    opener = urllib.request.build_opener(_DenyRedirects)
    try:
        with opener.open(request, timeout=timeout) as response:
            if 300 <= response.status < 400:
                raise TargetRedirectRefused(response.status)
            raw = response.read()
            return response.status, raw.decode("utf-8", errors="replace")
    except TargetRedirectRefused:
        raise
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            raise TargetRedirectRefused(exc.code) from exc
        raw = exc.read()
        return exc.code, raw.decode("utf-8", errors="replace")


class DCLGuard:
    """Ask DCL before an HTTP side effect.

    Parameters
    ----------
    oracle_url:
        Origin of an existing DCL Trust Oracle REST API, for example
        ``https://webhook.fronesislabs.com`` or a :class:`LocalSandbox` URL.
        The guard calls ``POST {oracle_url}/evaluate/{tier}``.
    timeout:
        Seconds to wait for the Oracle. Exceeding it denies the action.
    tier:
        Existing evaluation route. Defaults to ``fast``. One of
        ``fast``, ``strict``, ``jailbreak``, ``safety``, ``quality``.
    agent_id:
        Optional label stored by the Oracle with the check.
    transport:
        Optional replacement for the Oracle HTTP call. Use this only to
        plug in an existing payment-capable client. The guard invokes it
        with the Oracle evaluate URL and never uses it to call the
        side-effect target. Returning HTTP 402, or raising, denies the
        action. This guard does not sign payments or follow Oracle redirects.
    trust:
        Optional public-key mapping for a signed decision envelope. ``None``
        keeps the unsigned Oracle JSON path. A signed wrapper is never
        treated as trusted unless this mapping is supplied. Nonces are not
        stored.
    """

    def __init__(
        self,
        oracle_url: str,
        *,
        timeout: float = 10.0,
        tier: str = "fast",
        agent_id: str = "dcl-guard",
        transport: Transport | None = None,
        trust: OracleTrustConfig | None = None,
    ) -> None:
        if not isinstance(oracle_url, str) or not oracle_url.strip():
            raise ValueError("oracle_url is required")
        if tier not in _TIERS:
            raise ValueError(f"unknown evaluation tier: {tier}")
        if trust is not None and not isinstance(trust, OracleTrustConfig):
            raise TypeError("trust must be OracleTrustConfig or None")
        self.oracle_url = oracle_url.strip().rstrip("/")
        self.timeout = float(timeout)
        self.tier = tier
        self.agent_id = agent_id
        self.trust = trust
        self._transport = transport or _urllib_transport

    def check(
        self,
        action: str,
        target: str,
        payload: Any = None,
        *,
        tier: str | None = None,
        agent_id: str | None = None,
        timeout: float | None = None,
    ) -> Decision:
        """Return whether ``action`` against ``target`` is allowed.

        The side effect is not performed here. ``allowed`` is true only
        when the Oracle returns a JSON body whose ``verdict`` is exactly
        ``COMMIT``.
        """
        if not isinstance(action, str) or not action.strip():
            return _deny("action is required")
        if not isinstance(target, str) or not target.strip():
            return _deny("target is required")

        selected = tier or self.tier
        if selected not in _TIERS:
            return _deny("unknown evaluation tier")

        try:
            described = _describe_action(action, target, payload)
            digest = request_digest(action, target, payload)
        except (TypeError, ValueError):
            return _deny("action payload is not JSON-serializable")

        request_body = {
            "response": described,
            "agent_id": agent_id or self.agent_id,
            "task_type": "http_side_effect",
            "request_digest": digest,
        }
        wait = self.timeout if timeout is None else float(timeout)
        url = f"{self.oracle_url}/evaluate/{selected}"
        try:
            result = self._transport(url, request_body, wait)
        except TimeoutError:
            return _deny("oracle timeout")
        except Exception:
            return _deny("oracle unavailable")

        status = getattr(result, "status", None)
        body = getattr(result, "body", b"")
        if not isinstance(status, int):
            return _deny("malformed oracle response")
        if not isinstance(body, (bytes, str)):
            return _deny("malformed oracle response")
        return _decision_from_http(status, body, expected_digest=digest, trust=self.trust)

    def post(
        self,
        url: str,
        json: Any = None,
        *,
        headers: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> SideEffectResult:
        """POST ``json`` to ``url`` only after DCL returns COMMIT for this request.

        The guard hashes the method, canonical URL, and canonical JSON body.
        Headers are not hashed. ``json`` is the only body parameter; there
        is no ``data`` or ``files`` argument. A missing body hashes as an
        empty string, not JSON ``null``.

        The target is opened only when the verdict is exactly ``COMMIT`` and
        the returned digest is identical. A redirect from that URL is not
        followed: ``Location`` is not requested, and ``executed`` is false.
        ``request_sent`` is still true, because the digested host may already
        have received that first POST.
        """
        try:
            expected = request_digest("POST", url, json)
        except (TypeError, ValueError):
            return SideEffectResult(
                decision=_deny("action payload is not JSON-serializable"),
                executed=False,
            )
        decision = self.check(
            action="POST",
            target=url,
            payload=json,
            timeout=timeout,
        )
        if (
            decision.verdict != "COMMIT"
            or not decision.allowed
            or decision.request_digest != expected
        ):
            if decision.verdict == "COMMIT" and decision.request_digest != expected:
                decision = Decision(
                    allowed=False,
                    verdict="NO_COMMIT",
                    reason=(
                        "request digest missing"
                        if decision.request_digest is None
                        else "request digest mismatch"
                    ),
                    trace_id=decision.trace_id,
                    tx_hash=decision.tx_hash,
                    verify_url=decision.verify_url,
                    event_id=decision.event_id,
                    request_digest=decision.request_digest,
                )
            return SideEffectResult(decision=decision, executed=False)

        wait = self.timeout if timeout is None else float(timeout)
        try:
            status_code, text = _execute_post(url, json, headers, wait)
        except TargetRedirectRefused:
            return SideEffectResult(
                decision=Decision(
                    allowed=False,
                    verdict="NO_COMMIT",
                    reason="target redirect refused",
                    trace_id=decision.trace_id,
                    tx_hash=decision.tx_hash,
                    verify_url=decision.verify_url,
                    event_id=decision.event_id,
                    request_digest=decision.request_digest,
                ),
                executed=False,
                request_sent=True,
            )
        return SideEffectResult(
            decision=decision,
            executed=True,
            status_code=status_code,
            text=text,
            request_sent=True,
        )
