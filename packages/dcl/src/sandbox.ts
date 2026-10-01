/**
 * Loopback stand-in for the DCL evaluation HTTP contract.
 *
 * Not the Trust Oracle. It does not run DCL policy, x402, or the audit
 * chain. `blockIfContains` is a caller-supplied test switch.
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";

const TIERS = new Set(["fast", "strict", "jailbreak", "safety", "quality"]);

export interface LocalSandboxOptions {
  blockIfContains?: string[];
  host?: string;
}

export class LocalSandbox {
  readonly blockIfContains: string[];
  readonly host: string;
  url: string | null = null;
  readonly requests: { path: string; body: string }[] = [];
  private server: ReturnType<typeof createServer> | null = null;
  private counter = 0;

  constructor(options: LocalSandboxOptions = {}) {
    this.blockIfContains = (options.blockIfContains ?? []).filter((item) => item);
    this.host = options.host ?? "127.0.0.1";
  }

  start(): Promise<string> {
    if (this.url && this.server) {
      return Promise.resolve(this.url);
    }
    const server = createServer((req, res) => {
      this.handle(req, res);
    });
    this.server = server;
    return new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, this.host, () => {
        const address = server.address();
        if (!address || typeof address === "string") {
          reject(new Error("sandbox failed to bind"));
          return;
        }
        this.url = `http://${this.host}:${address.port}`;
        resolve(this.url);
      });
    });
  }

  close(): Promise<void> {
    const server = this.server;
    this.server = null;
    this.url = null;
    if (!server) {
      return Promise.resolve();
    }
    return new Promise((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  }

  private handle(req: IncomingMessage, res: ServerResponse): void {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      const path = req.url ?? "/";
      this.requests.push({ path, body: raw });
      const tier = path.replace(/^\/evaluate\//, "").split("?")[0];
      if (req.method !== "POST" || !path.startsWith("/evaluate/") || !TIERS.has(tier)) {
        this.send(res, 404, {
          verdict: "NO_COMMIT",
          reason: "sandbox unknown route",
        });
        return;
      }
      this.send(res, 200, this.decide(raw));
    });
  }

  private decide(raw: string): Record<string, unknown> {
    let responseText = "";
    try {
      const incoming = JSON.parse(raw) as { response?: unknown };
      responseText = typeof incoming.response === "string" ? incoming.response : "";
    } catch {
      responseText = "";
    }
    const matched = this.blockIfContains.find((item) => responseText.includes(item));
    const verdict = matched ? "NO_COMMIT" : "COMMIT";
    const reason = matched
      ? `sandbox blocked because the action contained ${JSON.stringify(matched)}`
      : "sandbox allowed this action";
    this.counter += 1;
    return {
      verdict,
      confidence: matched ? 0 : 1,
      reason,
      tx_hash: `sandbox-${this.counter}`,
      chain_index: this.counter,
      input_hash: "sandbox",
      policy_version: "sandbox",
      timestamp: Date.now() / 1000,
      pipeline_id: "",
      drift_mode: "NORMAL",
      drift_score: 0,
      seal_text: "",
      verify_url: "",
    };
  }

  private send(res: ServerResponse, status: number, body: Record<string, unknown>): void {
    const payload = JSON.stringify(body);
    res.writeHead(status, {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(payload),
      "X-DCL-Sandbox": "1",
    });
    res.end(payload);
  }
}
