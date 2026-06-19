import assert from "node:assert/strict";
import test from "node:test";
import {
  normalizeClientId,
  normalizeClientVersion,
  readClientMetadata,
} from "../clientMetadata.mjs";

test("client metadata accepts bounded product identifiers without collecting device identity", () => {
  assert.equal(normalizeClientId(" com.ktbatterham.CertWatch "), "com.ktbatterham.certwatch");
  assert.equal(normalizeClientId("securl-ios"), "securl-ios");
  assert.equal(normalizeClientId("device id 123"), null);
  assert.equal(normalizeClientId("550e8400-e29b-41d4-a716-446655440000"), null);
  assert.equal(normalizeClientId("abcdef0123456789abcdef0123456789"), null);
  assert.equal(normalizeClientId("a".repeat(65)), null);
  assert.equal(normalizeClientVersion("1.4.0+42"), "1.4.0+42");
  assert.equal(normalizeClientVersion("version with spaces"), null);
  assert.equal(normalizeClientVersion("550e8400-e29b-41d4-a716-446655440000"), null);
});

test("client metadata is optional, ignores malformed headers, and supports app id fallback", () => {
  assert.deepEqual(readClientMetadata({ headers: {} }), { client: null, version: null });
  assert.deepEqual(readClientMetadata({
    headers: {
      "x-securl-client": "securl-ios",
      "x-securl-client-version": "1.2.0+19",
    },
  }), {
    client: "securl-ios",
    version: "1.2.0+19",
  });
  assert.deepEqual(readClientMetadata({
    headers: {
      "x-securl-client": "invalid client",
      "x-securl-client-version": "1.2.0",
    },
  }, { fallbackClient: "com.ktbatterham.securl" }), {
    client: "com.ktbatterham.securl",
    version: "1.2.0",
  });
});
