/**
 * Rebuild and verify the signed-envelope v1 vector with Node's Ed25519.
 * This file does not import the guard and does not change production behavior.
 */
import assert from "node:assert/strict";
import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";

const fixturePath = new URL("../../../tests/fixtures/signed_oracle_decision_envelope_v1.json", import.meta.url);
const fixture = JSON.parse(readFileSync(fixturePath, "utf8")) as {
  canonical_payload: string;
  canonical_sha256: string;
  public_key_hex: string;
  signature_base64: string;
  verification_result: boolean;
  envelope: Record<string, string>;
  signature: { algorithm: string; key_id: string; value: string };
};

const FIELD_ORDER = [
  "expires_at",
  "issued_at",
  "key_id",
  "nonce",
  "policy_id",
  "policy_version",
  "request_digest",
  "schema_version",
  "trace_id",
  "verdict",
] as const;

function jsonString(value: string): string {
  // Match the spec: escape only quotes, backslashes, and C0 controls.
  // JSON.stringify also escapes U+2028 and U+2029; those are not C0 controls.
  return JSON.stringify(value).replace(/\\u2028/g, "\u2028").replace(/\\u2029/g, "\u2029");
}

function canonicalPayload(envelope: Record<string, string>): string {
  const keys = Object.keys(envelope);
  if (keys.length !== FIELD_ORDER.length || FIELD_ORDER.some((name) => !Object.hasOwn(envelope, name))) {
    throw new Error("envelope fields must be exactly the v1 allowlist");
  }
  return `{${FIELD_ORDER.map((name) => `${jsonString(name)}:${jsonString(envelope[name])}`).join(",")}}`;
}

function publicKey() {
  const raw = Buffer.from(fixture.public_key_hex, "hex");
  return createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: raw.toString("base64url") },
    format: "jwk",
  });
}

test("signed envelope vector canonical bytes and Ed25519 verification", () => {
  const payload = canonicalPayload(fixture.envelope);
  assert.equal(payload, fixture.canonical_payload);
  const raw = Buffer.from(payload, "utf8");
  assert.equal(raw.length, 339);
  assert.equal(createHash("sha256").update(raw).digest("hex"), fixture.canonical_sha256);
  assert.equal(fixture.signature.algorithm, "Ed25519");
  assert.equal(fixture.signature.key_id, fixture.envelope.key_id);
  assert.equal(fixture.verification_result, true);

  const key = publicKey();
  const signature = Buffer.from(fixture.signature_base64, "base64");
  assert.equal(signature.length, 64);
  assert.equal(verify(null, raw, key, signature), true);

  const mutated = Buffer.from(raw);
  mutated[mutated.length - 1] ^= 0x01;
  assert.equal(verify(null, mutated, key, signature), false);

  const withSpace = Buffer.concat([raw, Buffer.from(" ")]);
  assert.equal(verify(null, withSpace, key, signature), false);
});

test("an extra envelope field is outside the signed payload", () => {
  assert.throws(() => canonicalPayload({ ...fixture.envelope, note: "not signed" }));
  assert.equal(fixture.canonical_payload.includes("note"), false);
  assert.equal(jsonString("é"), '"é"');
  assert.equal(Buffer.from(jsonString("é"), "utf8").toString("hex"), "22c3a922");
});
