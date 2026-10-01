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
}

export interface SideEffectResult {
  decision: Decision;
  /** True only after COMMIT and the side-effect request was sent. */
  executed: boolean;
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

function canonicalJson(value: unknown): string {
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

function decisionFromHttp(status: number, body: string): Decision {
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
  return decision({
    allowed: parsedVerdict === "COMMIT",
    verdict: parsedVerdict,
    reason,
    traceId: optionalString(record.trace_id),
    txHash: optionalString(record.tx_hash),
    verifyUrl: optionalString(record.verify_url),
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
    try {
      described = describeAction(input.action, input.target, input.payload);
    } catch {
      return deny("action payload is not JSON-serializable");
    }

    const requestBody = {
      response: described,
      agent_id: input.agentId ?? this.agentId,
      task_type: "http_side_effect",
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
    return decisionFromHttp(result.status, result.body);
  }

  /**
   * POST `json` to `url` only after DCL returns COMMIT.
   * On any denial the target receives no request.
   */
  async post(url: string, options: PostOptions = {}): Promise<SideEffectResult> {
    const decision = await this.check({
      action: "POST",
      target: url,
      payload: options.json,
      timeoutMs: options.timeoutMs,
    });
    if (decision.verdict !== "COMMIT" || !decision.allowed) {
      return { decision, executed: false, statusCode: null, text: null };
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
    const response = await fetch(url, init);
    const text = await response.text();
    return {
      decision,
      executed: true,
      statusCode: response.status,
      text,
    };
  }
}
