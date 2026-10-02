/**
 * The side-effect fetch below hits a local server. Denials are asserted by
 * that server's request count, not only by decision.allowed.
 */

import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { describe, it, afterEach } from "node:test";

import { DCLGuard, LocalSandbox, requestDigest } from "../src/index.ts";

interface Hit {
  path: string;
  body: string;
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function listen(handler: (req: IncomingMessage, res: ServerResponse) => void): Promise<{
  url: string;
  close: () => Promise<void>;
}> {
  const server = createServer(handler);
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        reject(new Error("failed to bind"));
        return;
      }
      resolve({
        url: `http://127.0.0.1:${address.port}`,
        close: () =>
          new Promise((done, fail) => {
            server.close((error) => (error ? fail(error) : done()));
          }),
      });
    });
  });
}

async function startOracle(
  mode: string,
  extra: { body?: string; status?: number; location?: string; sleepMs?: number } = {},
): Promise<{ url: string; hits: Hit[]; close: () => Promise<void> }> {
  const hits: Hit[] = [];
  const server = await listen(async (req, res) => {
    const body = await readBody(req);
    hits.push({ path: req.url ?? "/", body });
    if (mode === "timeout") {
      await new Promise((resolve) => setTimeout(resolve, extra.sleepMs ?? 2000));
      return;
    }
    if (mode === "redirect") {
      res.writeHead(307, {
        Location: extra.location ?? "http://127.0.0.1/",
        "Content-Length": "0",
      });
      res.end();
      return;
    }
    let status = 200;
    let payload = "";
    if (mode === "commit" || mode === "commit-omit-digest" || mode === "commit-bad-digest") {
      const commit: Record<string, unknown> = {
        verdict: "COMMIT",
        reason: "All policy checks passed",
        tx_hash: "0xabc",
        verify_url: "https://example.test/verify/abc",
      };
      if (mode === "commit") {
        try {
          const incoming = JSON.parse(body) as { request_digest?: unknown };
          if (typeof incoming.request_digest === "string" && incoming.request_digest) {
            commit.request_digest = incoming.request_digest;
          }
        } catch {
          // Leave the digest off. The guard must then fail closed.
        }
      } else if (mode === "commit-bad-digest") {
        commit.request_digest = "0".repeat(64);
      }
      payload = JSON.stringify(commit);
    } else if (mode === "block") {
      payload = JSON.stringify({
        verdict: "NO_COMMIT",
        reason: "forbidden phrase",
        tx_hash: "0xblocked",
      });
    } else if (mode === "malformed") {
      payload = "not-json";
    } else if (mode === "bad-verdict") {
      payload = JSON.stringify({ verdict: "MAYBE", reason: "no" });
    } else if (mode === "server-error") {
      status = 500;
      payload = JSON.stringify({ error: "boom" });
    } else if (mode === "payment") {
      status = 402;
      payload = JSON.stringify({ verdict: "COMMIT", reason: "paid", accepts: [] });
    } else if (mode === "raw") {
      status = extra.status ?? 200;
      payload = extra.body ?? "";
    }
    res.writeHead(status, {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(payload),
    });
    res.end(payload);
  });
  return { url: server.url, hits, close: server.close };
}

async function startEffect(): Promise<{ url: string; hits: Hit[]; close: () => Promise<void> }> {
  const hits: Hit[] = [];
  const server = await listen(async (req, res) => {
    const body = await readBody(req);
    hits.push({ path: req.url ?? "/", body });
    const payload = JSON.stringify({ ok: true });
    res.writeHead(201, {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(payload),
    });
    res.end(payload);
  });
  return { url: `${server.url}/orders`, hits, close: server.close };
}

async function developerFetch(url: string, payload: unknown): Promise<void> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  await response.text();
}

describe("DCLGuard side effects", () => {
  const closers: Array<() => Promise<void>> = [];

  afterEach(async () => {
    while (closers.length) {
      const close = closers.pop();
      if (close) {
        await close();
      }
    }
  });

  async function blocked(mode: string, reasonIncludes: string): Promise<void> {
    const oracle = await startOracle(mode);
    const effect = await startEffect();
    closers.push(oracle.close, effect.close);
    const guard = new DCLGuard({
      oracleUrl: oracle.url,
      timeoutMs: mode === "timeout" ? 200 : 1000,
    });
    const payload = { amount: 42 };
    const decision = await guard.check({
      action: "POST",
      target: effect.url,
      payload,
    });
    if (decision.allowed) {
      await developerFetch(effect.url, payload);
    }
    const result = await guard.post(effect.url, { json: payload });
    assert.equal(decision.allowed, false);
    assert.equal(decision.verdict, "NO_COMMIT");
    assert.match(decision.reason, new RegExp(reasonIncludes));
    assert.equal(result.executed, false);
    assert.equal(effect.hits.length, 0);
    assert.equal(decision.allowed, decision.verdict === "COMMIT");
    assert.equal(oracle.hits.length, 2);
  }

  it("COMMIT executes the side effect", async () => {
    const oracle = await startOracle("commit");
    const effect = await startEffect();
    closers.push(oracle.close, effect.close);
    const guard = new DCLGuard({ oracleUrl: oracle.url });
    const payload = { amount: 42 };
    const decision = await guard.check({
      action: "POST",
      target: effect.url,
      payload,
    });
    if (decision.allowed) {
      await developerFetch(effect.url, payload);
    }
    assert.equal(decision.allowed, true);
    assert.equal(decision.verdict, "COMMIT");
    assert.equal(decision.reason, "All policy checks passed");
    assert.equal(decision.traceId, null);
    assert.equal(decision.txHash, "0xabc");
    assert.equal(decision.allowed, decision.verdict === "COMMIT");
    assert.equal(decision.verifyUrl, "https://example.test/verify/abc");
    assert.equal(effect.hits.length, 1);
    assert.deepEqual(JSON.parse(effect.hits[0].body), payload);

    const result = await guard.post(effect.url, { json: payload });
    assert.equal(result.executed, true);
    assert.equal(result.statusCode, 201);
    assert.equal(effect.hits.length, 2);

    const sent = JSON.parse(oracle.hits[0].body) as Record<string, string>;
    assert.deepEqual(Object.keys(sent).sort(), ["agent_id", "request_digest", "response", "task_type"]);
    assert.equal(sent.request_digest, await requestDigest("POST", effect.url, payload));
    assert.match(sent.response, /action: POST/);
    assert.match(sent.response, /"amount":42/);
    assert.equal(oracle.hits[0].path, "/evaluate/fast");
    assert.equal(oracle.hits.length, 2);
  });

  it("NO_COMMIT does not execute the side effect", async () => {
    await blocked("block", "forbidden phrase");
  });

  it("timeout does not execute the side effect", async () => {
    await blocked("timeout", "timeout");
  });

  it("malformed response does not execute the side effect", async () => {
    await blocked("malformed", "malformed");
  });

  it("invalid verdict does not execute the side effect", async () => {
    await blocked("bad-verdict", "malformed");
  });

  it("HTTP 500 does not execute the side effect", async () => {
    await blocked("server-error", "HTTP 500");
  });

  it("payment required fails closed without a manual 402", async () => {
    const oracle = await startOracle("payment");
    const effect = await startEffect();
    closers.push(oracle.close, effect.close);
    const guard = new DCLGuard({ oracleUrl: oracle.url });
    const payload = { amount: 42 };
    const decision = await guard.check({
      action: "POST",
      target: effect.url,
      payload,
    });
    if (decision.allowed) {
      await developerFetch(effect.url, payload);
    }
    const result = await guard.post(effect.url, { json: payload });
    assert.equal(decision.allowed, false);
    assert.equal(decision.verdict, "NO_COMMIT");
    assert.match(decision.reason, /payment required/);
    assert.equal(decision.traceId, null);
    assert.equal(decision.txHash, null);
    assert.equal(decision.allowed, decision.verdict === "COMMIT");
    assert.equal(result.executed, false);
    assert.equal(effect.hits.length, 0);
    assert.equal(oracle.hits.length, 2);
    assert.equal(decision.reason.includes("402"), false);
  });

  it("transport failure fails closed", async () => {
    const effect = await startEffect();
    closers.push(effect.close);
    const guard = new DCLGuard({
      oracleUrl: "http://127.0.0.1:9",
      transport: async () => {
        throw new Error("wallet unavailable");
      },
    });
    const decision = await guard.check({
      action: "POST",
      target: effect.url,
      payload: { amount: 1 },
    });
    if (decision.allowed) {
      await developerFetch(effect.url, { amount: 1 });
    }
    const result = await guard.post(effect.url, { json: { amount: 1 } });
    assert.equal(decision.allowed, false);
    assert.equal(result.executed, false);
    assert.equal(effect.hits.length, 0);
  });

  it("trace_id is not aliased from tx_hash", async () => {
    const samples: Array<{
      body: Record<string, unknown>;
      traceId: string | null;
      txHash: string | null;
      allowed: boolean;
    }> = [
      {
        body: { verdict: "COMMIT", reason: "ok", tx_hash: "0xabc" },
        traceId: null,
        txHash: "0xabc",
        allowed: true,
      },
      {
        body: { verdict: "NO_COMMIT", reason: "no", tx_hash: "0xblocked" },
        traceId: null,
        txHash: "0xblocked",
        allowed: false,
      },
      {
        body: { verdict: "COMMIT", reason: "ok", tx_hash: "0xabc", trace_id: "" },
        traceId: null,
        txHash: "0xabc",
        allowed: true,
      },
      {
        body: { verdict: "COMMIT", reason: "ok", tx_hash: "0xabc", trace_id: 12 },
        traceId: null,
        txHash: "0xabc",
        allowed: true,
      },
      {
        body: {
          verdict: "COMMIT",
          reason: "ok",
          tx_hash: "0xabc",
          trace_id: "trace-9",
          verify_url: "https://example.test/verify/abc",
        },
        traceId: "trace-9",
        txHash: "0xabc",
        allowed: true,
      },
      {
        body: {
          verdict: "NO_COMMIT",
          reason: "no",
          tx_hash: "0xabc",
          trace_id: "trace-9",
        },
        traceId: "trace-9",
        txHash: "0xabc",
        allowed: false,
      },
    ];
    for (const sample of samples) {
      const effect = await startEffect();
      const body = { ...sample.body };
      if (sample.allowed) {
        body.request_digest = await requestDigest("POST", effect.url, { amount: 1 });
      }
      const oracle = await startOracle("raw", { body: JSON.stringify(body) });
      closers.push(oracle.close, effect.close);
      const guard = new DCLGuard({ oracleUrl: oracle.url });
      const result = await guard.post(effect.url, { json: { amount: 1 } });
      assert.equal(result.decision.traceId, sample.traceId);
      assert.equal(result.decision.txHash, sample.txHash);
      assert.equal(result.decision.allowed, sample.allowed);
      assert.equal(result.decision.verdict, sample.allowed ? "COMMIT" : "NO_COMMIT");
      assert.equal(result.decision.allowed, result.decision.verdict === "COMMIT");
      assert.equal(result.executed, sample.allowed);
      assert.equal(oracle.hits.length, 1);
      assert.equal(effect.hits.length, sample.allowed ? 1 : 0);
    }
  });

  it("a single post counts oracle and target requests", async () => {
    const cases: Array<{ mode: string; targetHits: number; executed: boolean }> = [
      { mode: "commit", targetHits: 1, executed: true },
      { mode: "block", targetHits: 0, executed: false },
      { mode: "payment", targetHits: 0, executed: false },
      { mode: "server-error", targetHits: 0, executed: false },
      { mode: "malformed", targetHits: 0, executed: false },
      { mode: "bad-verdict", targetHits: 0, executed: false },
      { mode: "timeout", targetHits: 0, executed: false },
    ];
    for (const sample of cases) {
      const oracle = await startOracle(sample.mode, { sleepMs: 2000 });
      const effect = await startEffect();
      closers.push(oracle.close, effect.close);
      const guard = new DCLGuard({
        oracleUrl: oracle.url,
        timeoutMs: sample.mode === "timeout" ? 200 : 1000,
      });
      const started = Date.now();
      const result = await guard.post(effect.url, { json: { amount: 42 } });
      const elapsed = Date.now() - started;
      assert.equal(oracle.hits.length, 1, sample.mode);
      assert.equal(effect.hits.length, sample.targetHits, sample.mode);
      assert.equal(result.executed, sample.executed, sample.mode);
      assert.equal(result.decision.allowed, sample.executed, sample.mode);
      assert.equal(result.decision.allowed, result.decision.verdict === "COMMIT");
      if (sample.executed) {
        assert.equal(result.decision.verdict, "COMMIT");
        assert.deepEqual(JSON.parse(effect.hits[0].body), { amount: 42 });
      } else {
        assert.equal(result.decision.verdict, "NO_COMMIT");
      }
      if (sample.mode === "timeout") {
        assert.ok(elapsed < 1500, `timeout took ${elapsed}ms`);
        assert.match(result.decision.reason, /timeout/);
      }
    }
  });

  it("malformed bodies fail closed", async () => {
    const bodies = [
      "{}",
      '{"verdict":"UNKNOWN"}',
      '{"verdict":"UNKNOWN","reason":"no"}',
      "not json",
      '{"verdict":"COMMIT"}',
      '{"verdict":"COMMIT","reason":1}',
      '{"verdict":"commit","reason":"ok"}',
      '{"confidence":0.99,"reason":"All policy checks passed"}',
      '{"reason":"COMMIT"}',
      "[]",
      "null",
    ];
    for (const body of bodies) {
      const oracle = await startOracle("raw", { body });
      const effect = await startEffect();
      closers.push(oracle.close, effect.close);
      const guard = new DCLGuard({ oracleUrl: oracle.url });
      const result = await guard.post(effect.url, { json: { amount: 1 } });
      assert.equal(oracle.hits.length, 1, body);
      assert.equal(effect.hits.length, 0, body);
      assert.equal(result.executed, false, body);
      assert.equal(result.decision.allowed, false, body);
      assert.equal(result.decision.verdict, "NO_COMMIT", body);
      assert.match(result.decision.reason, /malformed/);
      assert.equal(result.decision.traceId, null);
    }
  });

  it("reason text does not grant COMMIT", async () => {
    const oracle = await startOracle("raw", {
      body: JSON.stringify({
        verdict: "NO_COMMIT",
        reason: "COMMIT",
        allowed: true,
        confidence: 1,
      }),
    });
    const effect = await startEffect();
    closers.push(oracle.close, effect.close);
    const guard = new DCLGuard({ oracleUrl: oracle.url });
    const result = await guard.post(effect.url, { json: { amount: 1 } });
    assert.equal(result.decision.reason, "COMMIT");
    assert.equal(result.decision.verdict, "NO_COMMIT");
    assert.equal(result.decision.allowed, false);
    assert.equal(result.executed, false);
    assert.equal(oracle.hits.length, 1);
    assert.equal(effect.hits.length, 0);
  });

  it("an allowed flag cannot disagree with verdict", async () => {
    const effect = await startEffect();
    const oracle = await startOracle("raw", {
      body: JSON.stringify({
        verdict: "COMMIT",
        reason: "yes",
        allowed: false,
        confidence: 0,
        request_digest: await requestDigest("POST", effect.url, { amount: 3 }),
      }),
    });
    closers.push(oracle.close, effect.close);
    const guard = new DCLGuard({ oracleUrl: oracle.url });
    const result = await guard.post(effect.url, { json: { amount: 3 } });
    assert.equal(result.decision.allowed, true);
    assert.equal(result.decision.verdict, "COMMIT");
    assert.equal(result.executed, true);
    assert.equal(oracle.hits.length, 1);
    assert.equal(effect.hits.length, 1);
  });

  it("network error does not call the target", async () => {
    const effect = await startEffect();
    closers.push(effect.close);
    const guard = new DCLGuard({ oracleUrl: "http://127.0.0.1:9", timeoutMs: 1000 });
    const result = await guard.post(effect.url, { json: { amount: 1 } });
    assert.equal(result.executed, false);
    assert.equal(effect.hits.length, 0);
    assert.equal(result.decision.allowed, false);
    assert.equal(result.decision.verdict, "NO_COMMIT");
    assert.match(result.decision.reason, /unavailable/);
  });

  it("redirect does not reach the target", async () => {
    const effect = await startEffect();
    const oracle = await startOracle("redirect", { location: effect.url });
    closers.push(effect.close, oracle.close);
    const guard = new DCLGuard({ oracleUrl: oracle.url });
    const result = await guard.post(effect.url, { json: { amount: 1 } });
    assert.equal(oracle.hits.length, 1);
    assert.equal(effect.hits.length, 0);
    assert.equal(result.executed, false);
    assert.equal(result.decision.allowed, false);
    assert.equal(result.decision.verdict, "NO_COMMIT");
    assert.match(result.decision.reason, /HTTP 307/);
  });

  it("transport cannot reach the target without COMMIT", async () => {
    const effect = await startEffect();
    closers.push(effect.close);
    const calls: string[] = [];
    const guard = new DCLGuard({
      oracleUrl: "http://oracle.test",
      transport: async (url) => {
        calls.push(url);
        if (url === effect.url || url.startsWith(effect.url)) {
          await developerFetch(effect.url, { via: "transport" });
        }
        return {
          status: 200,
          body: JSON.stringify({
            verdict: "NO_COMMIT",
            reason: "denied",
            tx_hash: "0xnot-a-trace",
          }),
        };
      },
    });
    const result = await guard.post(effect.url, { json: { amount: 1 } });
    assert.deepEqual(calls, ["http://oracle.test/evaluate/fast"]);
    assert.equal(effect.hits.length, 0);
    assert.equal(result.executed, false);
    assert.equal(result.decision.allowed, false);
    assert.equal(result.decision.verdict, "NO_COMMIT");
    assert.equal(result.decision.traceId, null);
    assert.equal(result.decision.txHash, "0xnot-a-trace");
  });

  it("COMMIT post uses a separate HTTP call", async () => {
    const effect = await startEffect();
    closers.push(effect.close);
    const calls: string[] = [];
    const guard = new DCLGuard({
      oracleUrl: "http://oracle.test",
      transport: async (url, body) => {
        calls.push(url);
        if (url.includes(effect.url)) {
          await developerFetch(effect.url, { via: "transport" });
        }
        const digest = typeof body.request_digest === "string" ? body.request_digest : undefined;
        return {
          status: 200,
          body: JSON.stringify({
            verdict: "COMMIT",
            reason: "All policy checks passed",
            tx_hash: "0xabc",
            verify_url: "https://example.test/verify/abc",
            ...(digest ? { request_digest: digest } : {}),
          }),
        };
      },
    });
    const result = await guard.post(effect.url, { json: { amount: 7 } });
    assert.deepEqual(calls, ["http://oracle.test/evaluate/fast"]);
    assert.equal(result.executed, true);
    assert.equal(result.decision.verdict, "COMMIT");
    assert.equal(result.decision.allowed, true);
    assert.equal(result.decision.traceId, null);
    assert.equal(result.decision.txHash, "0xabc");
    assert.equal(effect.hits.length, 1);
    assert.deepEqual(JSON.parse(effect.hits[0].body), { amount: 7 });
  });

  it("local sandbox commits and blocks without a paid oracle", async () => {
    const effect = await startEffect();
    closers.push(effect.close);
    const sandbox = new LocalSandbox({ blockIfContains: ["jailbreak"] });
    const url = await sandbox.start();
    closers.push(() => sandbox.close());
    const guard = new DCLGuard({ oracleUrl: url });
    const allowed = await guard.post(effect.url, { json: { amount: 42 } });
    const blocked = await guard.post(effect.url, { json: { note: "jailbreak the order" } });
    assert.equal(allowed.decision.allowed, true);
    assert.equal(allowed.decision.verdict, "COMMIT");
    assert.equal(allowed.executed, true);
    assert.equal(allowed.decision.traceId, null);
    assert.equal(allowed.decision.txHash, "sandbox-1");
    assert.equal(blocked.decision.traceId, null);
    assert.equal(blocked.decision.txHash, "sandbox-2");
    assert.equal(blocked.decision.allowed, false);
    assert.equal(blocked.executed, false);
    assert.equal(effect.hits.length, 1);
    assert.deepEqual(JSON.parse(effect.hits[0].body), { amount: 42 });
  });

  it("digest is stable across JSON key order", async () => {
    const url = "https://API.Example.com:443/orders?b=2&a=1#fragment";
    const left = await requestDigest("post", url, { z: 1, a: "é" });
    const right = await requestDigest("POST", url, { a: "é", z: 1 });
    assert.equal(left, right);
    assert.equal(left.length, 64);
    assert.notEqual(left, await requestDigest("PUT", url, { a: "é", z: 1 }));
    assert.notEqual(left, await requestDigest("POST", "https://api.example.com/orders?a=1&b=3", { a: "é", z: 1 }));
    assert.notEqual(left, await requestDigest("POST", url, { a: "é", z: 2 }));
    assert.notEqual(left, await requestDigest("POST", url));
  });

  it("COMMIT with a different request digest does not call the target", async () => {
    const oracle = await startOracle("commit-bad-digest");
    const effect = await startEffect();
    closers.push(oracle.close, effect.close);
    const guard = new DCLGuard({ oracleUrl: oracle.url });
    const result = await guard.post(effect.url, { json: { amount: 42 } });
    assert.equal(oracle.hits.length, 1);
    assert.equal(effect.hits.length, 0);
    assert.equal(result.executed, false);
    assert.equal(result.decision.verdict, "NO_COMMIT");
    assert.equal(result.decision.reason, "request digest mismatch");
    assert.equal(result.decision.requestDigest, "0".repeat(64));
  });

  it("COMMIT without a request digest does not call the target", async () => {
    const oracle = await startOracle("commit-omit-digest");
    const effect = await startEffect();
    closers.push(oracle.close, effect.close);
    const guard = new DCLGuard({ oracleUrl: oracle.url });
    const result = await guard.post(effect.url, { json: { amount: 42 } });
    assert.equal(oracle.hits.length, 1);
    assert.equal(effect.hits.length, 0);
    assert.equal(result.executed, false);
    assert.equal(result.decision.reason, "request digest missing");
    assert.equal(result.decision.requestDigest, null);
  });

  it("known digest vector matches sha256 of the canonical preimage", async () => {
    const preimage = 'POST\nhttps://api.example.com/orders?a=1&b=2\n{"a":"é","z":1}';
    const expected = "102854ec6909e5be3774fffbfc7bee1922341a2dede88277f7e30f12bc3a8123";
    const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(preimage));
    const actual = [...new Uint8Array(hash)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
    assert.equal(actual, expected);
    const url = "https://API.Example.com:443/orders?b=2&a=1#fragment";
    assert.equal(await requestDigest("post", url, { z: 1, a: "é" }), expected);
    assert.equal(await requestDigest(" post ", url, { a: "é", z: 1 }), expected);
  });

  it("only the exact verdict COMMIT is allowed", async () => {
    const effect = await startEffect();
    closers.push(effect.close);
    const samples: Array<[string | null, boolean]> = [
      ["COMMIT", true],
      ["NO_COMMIT", false],
      ["COMMITTED", false],
      ["COMMIT ", false],
      ["commit", false],
      [null, false],
      ["YES", false],
    ];
    for (const [verdict, allowed] of samples) {
      const body: Record<string, unknown> = { reason: "ok" };
      if (verdict !== null) {
        body.verdict = verdict;
      }
      if (allowed) {
        body.request_digest = await requestDigest("POST", effect.url, { n: 1 });
      }
      const oracle = await startOracle("raw", { body: JSON.stringify(body) });
      closers.push(oracle.close);
      const result = await new DCLGuard({ oracleUrl: oracle.url, timeoutMs: 1000 }).post(effect.url, {
        json: { n: 1 },
      });
      assert.equal(result.decision.allowed, allowed, String(verdict));
      assert.equal(result.executed, allowed, String(verdict));
      assert.equal(result.decision.verdict, allowed ? "COMMIT" : "NO_COMMIT");
      effect.hits.length = 0;
    }
  });

  it("target redirect is not followed", async () => {
    const sinkHits: string[] = [];
    const sink = await listen(async (req, res) => {
      sinkHits.push(await readBody(req));
      res.writeHead(200, { "Content-Length": "0" });
      res.end();
    });
    closers.push(sink.close);
    const originHits: string[] = [];
    const origin = await listen(async (req, res) => {
      originHits.push(await readBody(req));
      res.writeHead(302, { Location: `${sink.url}/elsewhere`, "Content-Length": "0" });
      res.end();
    });
    closers.push(origin.close);
    const target = `${origin.url}/orders`;
    const oracle = await startOracle("raw", {
      body: JSON.stringify({
        verdict: "COMMIT",
        reason: "ok",
        request_digest: await requestDigest("POST", target, { n: 1 }),
      }),
    });
    closers.push(oracle.close);
    const result = await new DCLGuard({ oracleUrl: oracle.url, timeoutMs: 1000 }).post(target, {
      json: { n: 1 },
    });
    assert.deepEqual(originHits, [JSON.stringify({ n: 1 })]);
    assert.deepEqual(sinkHits, []);
    assert.equal(result.executed, false);
    assert.equal(result.decision.verdict, "NO_COMMIT");
    assert.equal(result.decision.reason, "target redirect refused");
  });
});
