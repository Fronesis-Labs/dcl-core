/**
 * Fail-closed check against the existing DCL Trust Oracle REST API.
 *
 * This module does not score policy, hash audit records, or settle x402
 * payments. It POSTs the intended action to `/evaluate/{tier}` and turns
 * anything other than a well-formed COMMIT into a denial.
 */

const TIERS = new Set(["fast", "strict", "jailbreak", "safety", "quality"]);

export interface Decision {
  /** True only when verdict is COMMIT. */
  allowed: boolean;
  verdict: "COMMIT" | "NO_COMMIT";
  reason: string;
  /** Set only from the Oracle `trace_id` field. Never copied from `tx_hash`. */
  traceId: string | null;
  /** Passed through from Oracle `tx_hash` when that field is a non-empty string. */
  txHash: string | null;
  verifyUrl: string | null;
  /** Passed through from Oracle `event_id`. Never copied from `tx_hash`. */
  eventId: string | null;
  /**
   * HTTP intent digest returned by the Oracle.
   * This is not the audit-chain `input_hash`.
   */
  requestDigest: string | null;
}

export interface SideEffectResult {
  decision: Decision;
  /**
   * True only when the POST returned a non-redirect response after exact
   * COMMIT and a matching digest. False with `requestSent` true means the
   * digested host may already have seen the request.
   */
  executed: boolean;
  /**
   * True when the POST to the digested URL was sent, including a redirect
   * the guard refused to follow.
   */
  requestSent: boolean;
  statusCode: number | null;
  text: string | null;
}

export interface OracleHttpResponse {
  status: number;
  body: string;
}

export type OracleTransport = (
  url: string,
  body: Record<string, unknown>,
  timeoutMs: number,
) => Promise<OracleHttpResponse>;

export interface DCLGuardOptions {
  oracleUrl: string;
  timeoutMs?: number;
  tier?: string;
  agentId?: string;
  /** Oracle HTTP call only. Never used to perform the side effect. */
  transport?: OracleTransport;
}

export interface CheckInput {
  action: string;
  target: string;
  payload?: unknown;
  tier?: string;
  agentId?: string;
  timeoutMs?: number;
}

export interface PostOptions {
  json?: unknown;
  headers?: Record<string, string>;
  timeoutMs?: number;
}

function decision(fields: Decision): Decision {
  if (fields.allowed !== (fields.verdict === "COMMIT")) {
    throw new Error("allowed must equal verdict === COMMIT");
  }
  return fields;
}

function deny(reason: string): Decision {
  return decision({
    allowed: false,
    verdict: "NO_COMMIT",
    reason,
    traceId: null,
    txHash: null,
    verifyUrl: null,
    eventId: null,
    requestDigest: null,
  });
}

function optionalString(value: unknown): string | null {
  return typeof value === "string" && value ? value : null;
}

export function describeAction(action: string, target: string, payload: unknown): string {
  const lines = [`action: ${action.trim().toUpperCase()}`, `target: ${target.trim()}`];
  if (payload !== undefined) {
    lines.push(`payload: ${canonicalJson(payload)}`);
  }
  return lines.join("\n");
}

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  return `{${keys
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(",")}}`;
}

export function canonicalUrl(url: string): string {
  const trimmed = url.trim();
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return trimmed;
  }
  const scheme = parsed.protocol.replace(/:$/, "").toLowerCase();
  let host = parsed.hostname.toLowerCase();
  if (host.includes(":")) {
    host = `[${host}]`;
  }
  const port = parsed.port;
  const defaultPort = (scheme === "http" && port === "80") || (scheme === "https" && port === "443");
  if (port && !defaultPort) {
    host = `${host}:${port}`;
  }
  if (parsed.username) {
    const auth = parsed.password ? `${parsed.username}:${parsed.password}` : parsed.username;
    host = `${auth}@${host}`;
  }
  const path = parsed.pathname || "/";
  const pairs: [string, string][] = [];
  parsed.searchParams.forEach((value, key) => {
    pairs.push([key, value]);
  });
  pairs.sort((left, right) => {
    if (left[0] < right[0]) return -1;
    if (left[0] > right[0]) return 1;
    if (left[1] < right[1]) return -1;
    if (left[1] > right[1]) return 1;
    return 0;
  });
  const query = pairs
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
    .join("&");
  return query ? `${scheme}://${host}${path}?${query}` : `${scheme}://${host}${path}`;
}

export async function requestDigest(method: string, url: string, body?: unknown): Promise<string> {
  if (!method || !method.trim()) {
    throw new Error("method is required");
  }
  if (!url || !url.trim()) {
    throw new Error("url is required");
  }
  const canonicalBody = body === undefined ? "" : canonicalJson(body);
  const material = `${method.trim().toUpperCase()}\n${canonicalUrl(url)}\n${canonicalBody}`;
  const bytes = new TextEncoder().encode(material);
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(hash)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function isTimeout(error: unknown): boolean {
  if (!error || typeof error !== "object" || !("name" in error)) {
    return false;
  }
  const name = (error as { name?: string }).name;
  return name === "TimeoutError" || name === "AbortError";
}

async function fetchTransport(
  url: string,
  body: Record<string, unknown>,
  timeoutMs: number,
): Promise<OracleHttpResponse> {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      "User-Agent": "dcl-guard",
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(timeoutMs),
    // A 3xx Location could be the side-effect target. Do not follow it.
    redirect: "manual",
  });
  return { status: response.status, body: await response.text() };
}

function decisionFromHttp(status: number, body: string, expectedDigest: string | null): Decision {
  if (status === 402) {
    return deny("payment required and could not be completed");
  }
  if (status !== 200) {
    return deny(`oracle error (HTTP ${status})`);
  }
  let data: unknown;
  try {
    data = JSON.parse(body);
  } catch {
    return deny("malformed oracle response");
  }
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    return deny("malformed oracle response");
  }
  const record = data as Record<string, unknown>;
  const verdict = record.verdict;
  const reason = record.reason;
  if ((verdict !== "COMMIT" && verdict !== "NO_COMMIT") || typeof reason !== "string") {
    return deny("malformed oracle response");
  }
  const parsedVerdict = verdict === "COMMIT" ? "COMMIT" : "NO_COMMIT";
  // trace_id and tx_hash are different fields. Do not copy one into the other.
  // request_digest is the HTTP intent digest, not input_hash.
  const traceId = optionalString(record.trace_id);
  const txHash = optionalString(record.tx_hash);
  const verifyUrl = optionalString(record.verify_url);
  const eventId = optionalString(record.event_id);
  const returnedDigest = optionalString(record.request_digest);
  if (parsedVerdict === "COMMIT" && expectedDigest !== null && returnedDigest !== expectedDigest) {
    return decision({
      allowed: false,
      verdict: "NO_COMMIT",
      reason: returnedDigest === null ? "request digest missing" : "request digest mismatch",
      traceId,
      txHash,
      verifyUrl,
      eventId,
      requestDigest: returnedDigest,
    });
  }
  return decision({
    allowed: parsedVerdict === "COMMIT",
    verdict: parsedVerdict,
    reason,
    traceId,
    txHash,
    verifyUrl,
    eventId,
    requestDigest: returnedDigest,
  });
}

export class DCLGuard {
  readonly oracleUrl: string;
  readonly timeoutMs: number;
  readonly tier: string;
  readonly agentId: string;
  private readonly transport: OracleTransport;

  constructor(options: DCLGuardOptions) {
    if (!options.oracleUrl || !options.oracleUrl.trim()) {
      throw new Error("oracleUrl is required");
    }
    const tier = options.tier ?? "fast";
    if (!TIERS.has(tier)) {
      throw new Error(`unknown evaluation tier: ${tier}`);
    }
    this.oracleUrl = options.oracleUrl.trim().replace(/\/$/, "");
    this.timeoutMs = options.timeoutMs ?? 10_000;
    this.tier = tier;
    this.agentId = options.agentId ?? "dcl-guard";
    this.transport = options.transport ?? fetchTransport;
  }

  async check(input: CheckInput): Promise<Decision> {
    if (!input.action || !input.action.trim()) {
      return deny("action is required");
    }
    if (!input.target || !input.target.trim()) {
      return deny("target is required");
    }
    const tier = input.tier ?? this.tier;
    if (!TIERS.has(tier)) {
      return deny("unknown evaluation tier");
    }

    let described: string;
    let digest: string;
    try {
      described = describeAction(input.action, input.target, input.payload);
      digest = await requestDigest(input.action, input.target, input.payload);
    } catch {
      return deny("action payload is not JSON-serializable");
    }

    const requestBody = {
      response: described,
      agent_id: input.agentId ?? this.agentId,
      task_type: "http_side_effect",
      request_digest: digest,
    };
    const timeoutMs = input.timeoutMs ?? this.timeoutMs;
    const url = `${this.oracleUrl}/evaluate/${tier}`;
    let result: OracleHttpResponse;
    try {
      result = await this.transport(url, requestBody, timeoutMs);
    } catch (error) {
      if (isTimeout(error)) {
        return deny("oracle timeout");
      }
      return deny("oracle unavailable");
    }
    if (!result || typeof result.status !== "number" || typeof result.body !== "string") {
      return deny("malformed oracle response");
    }
    return decisionFromHttp(result.status, result.body, digest);
  }

  /**
   * POST `json` to `url` only after DCL returns COMMIT.
   * A denial before that POST leaves `requestSent` false.
   * A target redirect sets `requestSent` true and `executed` false.
   */
  async post(url: string, options: PostOptions = {}): Promise<SideEffectResult> {
    let expected: string;
    try {
      expected = await requestDigest("POST", url, options.json);
    } catch {
      return {
        decision: deny("action payload is not JSON-serializable"),
        executed: false,
        requestSent: false,
        statusCode: null,
        text: null,
      };
    }
    let verdict = await this.check({
      action: "POST",
      target: url,
      payload: options.json,
      timeoutMs: options.timeoutMs,
    });
    if (verdict.verdict !== "COMMIT" || !verdict.allowed || verdict.requestDigest !== expected) {
      if (verdict.verdict === "COMMIT" && verdict.requestDigest !== expected) {
        verdict = decision({
          allowed: false,
          verdict: "NO_COMMIT",
          reason: verdict.requestDigest === null ? "request digest missing" : "request digest mismatch",
          traceId: verdict.traceId,
          txHash: verdict.txHash,
          verifyUrl: verdict.verifyUrl,
          eventId: verdict.eventId,
          requestDigest: verdict.requestDigest,
        });
      }
      return {
        decision: verdict,
        executed: false,
        requestSent: false,
        statusCode: null,
        text: null,
      };
    }

    const headers: Record<string, string> = { Accept: "application/json" };
    const init: RequestInit = { method: "POST", headers };
    if (options.json !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(options.json);
    }
    if (options.headers) {
      Object.assign(headers, options.headers);
    }
    const timeoutMs = options.timeoutMs ?? this.timeoutMs;
    init.signal = AbortSignal.timeout(timeoutMs);
    // Do not follow a target redirect. Location is outside the digest.
    init.redirect = "manual";
    const response = await fetch(url, init);
    const redirected =
      response.type === "opaqueredirect" || (response.status >= 300 && response.status < 400);
    if (redirected) {
      return {
        decision: decision({
          allowed: false,
          verdict: "NO_COMMIT",
          reason: "target redirect refused",
          traceId: verdict.traceId,
          txHash: verdict.txHash,
          verifyUrl: verdict.verifyUrl,
          eventId: verdict.eventId,
          requestDigest: verdict.requestDigest,
        }),
        executed: false,
        requestSent: true,
        statusCode: null,
        text: null,
      };
    }
    const text = await response.text();
    return {
      decision: verdict,
      executed: true,
      requestSent: true,
      statusCode: response.status,
      text,
    };
  }
}
