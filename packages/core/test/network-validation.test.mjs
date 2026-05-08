import assert from "node:assert/strict";
import test from "node:test";
import dns from "node:dns/promises";

import { assertPublicRedirectTarget, isPrivateIpv6 } from "../dist/network-validation.js";

test("isPrivateIpv6 recognizes mapped and tunneled private ranges", () => {
  assert.equal(isPrivateIpv6("::ffff:127.0.0.1"), true);
  assert.equal(isPrivateIpv6("2002:7f00:0001::"), true);
  assert.equal(isPrivateIpv6("2002:0a00:0001::"), true);
  assert.equal(isPrivateIpv6("2002:c0a8:0001::"), true);
});

test("assertPublicRedirectTarget rethrows dns lookup failures", async (t) => {
  const originalLookup = dns.lookup;
  dns.lookup = async () => {
    throw new Error("getaddrinfo ENOTFOUND missing.example");
  };

  t.after(() => {
    dns.lookup = originalLookup;
  });

  await assert.rejects(
    () => assertPublicRedirectTarget(new URL("https://missing.example")),
    /ENOTFOUND/,
  );
});
