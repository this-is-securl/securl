import assert from "node:assert/strict";
import test from "node:test";
import {
  normalizeClientId,
  normalizeClientChannel,
  normalizeClientVersion,
  inferAppIdFromClient,
  inferClientChannel,
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
  assert.equal(normalizeClientChannel("App_Store"), "app-store");
  assert.equal(normalizeClientChannel("tf"), "testflight");
  assert.equal(normalizeClientChannel("debug"), "development");
  assert.equal(normalizeClientChannel("ci"), "automation");
  assert.equal(normalizeClientChannel("random"), null);
  assert.equal(inferAppIdFromClient("securl-ios"), "com.ktbatterham.securl");
  assert.equal(inferAppIdFromClient("header-watch-ios"), "com.ktbatterham.headerwatch");
  assert.equal(inferAppIdFromClient("cert-watch-ios"), "com.ktbatterham.certwatch");
  assert.equal(inferClientChannel({ client: "securl-api-smoke", version: "1.0.0" }), "automation");
});

test("client metadata is optional, ignores malformed headers, and supports app id fallback", () => {
  assert.deepEqual(readClientMetadata({ headers: {} }), {
    client: null,
    version: null,
    channel: null,
    appId: null,
  });
  assert.deepEqual(readClientMetadata({
    headers: {
      "x-securl-client": "securl-ios",
      "x-securl-client-version": "1.2.0+19",
      "x-securl-client-channel": "app-store",
    },
  }), {
    client: "securl-ios",
    version: "1.2.0+19",
    channel: "app-store",
    appId: "com.ktbatterham.securl",
  });
  assert.deepEqual(readClientMetadata({
    headers: {
      "x-securl-client": "invalid client",
      "x-securl-client-version": "1.2.0",
    },
  }, { fallbackClient: "com.ktbatterham.securl" }), {
    client: "com.ktbatterham.securl",
    version: "1.2.0",
    channel: null,
    appId: "com.ktbatterham.securl",
  });
});
