import assert from "node:assert/strict";
import test from "node:test";
import {
  LINK_SHARE_SCHEMA,
  LINK_SHARE_TTL_MS,
  buildLinkSharePreview,
  classifyLinkShare,
  createLinkShareRecord,
  createInspectionProof,
  hashRevokeToken,
  verifyInspectionProof,
} from "../linkShareContract.mjs";

function inspection() {
  return {
    schema: "securl.link-inspection.v1",
    submittedUrl: "https://person:secret@example.com/reset/abcdefghijklmnopqrstuvwxyz012345?token=raw#private",
    normalizedUrl: "https://person:secret@example.com/reset/abcdefghijklmnopqrstuvwxyz012345?token=raw#private",
    destinationUrl: "https://destination.example/doc/550e8400-e29b-41d4-a716-446655440000?key=raw#private",
    verdict: { level: "review", title: "attacker text", summary: "query=raw" },
    redirects: [{
      url: "https://redirect.example/path?recipient=person@example.com#raw",
      hostname: "redirect.example",
      statusCode: 302,
      location: "https://destination.example/?token=raw",
      originChanged: true,
      downgradedToHttp: false,
    }],
    response: { statusCode: 200, contentType: "text/html\r\nInjected: yes", contentLength: "123", contentDisposition: null, elapsedMs: 9 },
    signals: [
      { id: "nested_destination", level: "info", title: "attacker text", detail: "person@example.com?token=raw" },
      { id: "origin_change_0", level: "info", title: "host", detail: "secret" },
    ],
    limitations: ["attacker text"],
  };
}

test("link-share preview is a strict server-authored redaction", () => {
  const preview = buildLinkSharePreview(inspection());
  assert.equal(preview.schema, LINK_SHARE_SCHEMA);
  assert.deepEqual(preview.source, {
    scheme: "https",
    hostname: "example.com",
    path: "/reset/:redacted",
    displayUrl: "https://example.com/reset/:redacted",
  });
  assert.equal(preview.destination.displayUrl, "https://destination.example/doc/:redacted");
  assert.deepEqual(preview.redirects, [{
    position: 1,
    hostname: "redirect.example",
    statusCode: 302,
    originChanged: true,
    downgradedToHttp: false,
  }]);
  assert.equal(preview.verdict.title, "Review before opening");
  assert.deepEqual(preview.signals, [{ id: "nested_destination", level: "attention", title: "The URL contained another destination" }]);
  assert.equal(preview.response.contentType, "text/htmlInjected: yes");
  const serialized = JSON.stringify(preview);
  for (const secret of ["person", "secret", "token=raw", "#private", "550e8400", "attacker text", "person@example.com"]) {
    assert.equal(serialized.includes(secret), false, `preview leaked ${secret}`);
  }
});

test("link shares use independent high-entropy ids and tokens and expire after 30 days", () => {
  const now = new Date("2026-09-23T08:00:00.000Z");
  const first = createLinkShareRecord({ inspection: inspection(), now });
  const second = createLinkShareRecord({ inspection: inspection(), now });
  assert.match(first.publicId, /^[A-Za-z0-9_-]{32}$/);
  assert.match(first.revokeToken, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(first.publicId, second.publicId);
  assert.notEqual(first.revokeToken, second.revokeToken);
  assert.equal(Date.parse(first.expiresAt) - Date.parse(first.createdAt), LINK_SHARE_TTL_MS);
  assert.equal(classifyLinkShare(first, now), "active");
  assert.equal(classifyLinkShare(first, new Date(Date.parse(first.expiresAt))), "expired");
  assert.equal(classifyLinkShare({ ...first, revokedAt: now.toISOString() }, now), "revoked");
  assert.equal(classifyLinkShare(null, now), "not_found");
});

test("revocation tokens are stored only as salted hashes", () => {
  assert.equal(hashRevokeToken("token", "salt"), hashRevokeToken("token", "salt"));
  assert.notEqual(hashRevokeToken("token", "salt"), hashRevokeToken("token", "other"));
  assert.equal(hashRevokeToken("token", "salt").includes("token"), false);
});

test("inspection proofs bind every byte of backend evidence", () => {
  const value = inspection();
  const proof = createInspectionProof(value, "proof-salt");
  assert.equal(verifyInspectionProof(value, proof, "proof-salt"), true);
  assert.equal(verifyInspectionProof({ ...value, destinationUrl: "https://attacker.example/" }, proof, "proof-salt"), false);
  assert.equal(verifyInspectionProof(value, proof, "other-salt"), false);
  assert.equal(verifyInspectionProof(value, "malformed", "proof-salt"), false);
});
