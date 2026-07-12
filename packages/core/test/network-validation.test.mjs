import assert from "node:assert/strict";
import test from "node:test";
import dns from "node:dns/promises";

import {
  assertPublicRedirectTarget,
  assertPublicRequestTarget,
  createPinnedLookup,
  isPrivateAddress,
  isPrivateIpv6,
} from "../dist/network-validation.js";
import { scanLiveCertificate, scanTls } from "../dist/certificate.js";

test("isPrivateIpv6 recognizes mapped and tunneled private ranges", () => {
  assert.equal(isPrivateIpv6("::ffff:127.0.0.1"), true);
  assert.equal(isPrivateIpv6("[::ffff:7f00:1]"), true);
  assert.equal(isPrivateIpv6("2002:7f00:0001::"), true);
  assert.equal(isPrivateIpv6("2002:0a00:0001::"), true);
  assert.equal(isPrivateIpv6("2002:c0a8:0001::"), true);
});

test("isPrivateIpv6 covers ULA, full link-local range and NAT64 private targets", () => {
  assert.equal(isPrivateIpv6("fd12:3456::1"), true); // ULA fc00::/7
  assert.equal(isPrivateIpv6("febf::1"), true); // top of link-local fe80::/10
  assert.equal(isPrivateIpv6("fea0::1"), true); // mid link-local
  assert.equal(isPrivateIpv6("64:ff9b::10.0.0.1"), true); // NAT64 wrapping private v4
  assert.equal(isPrivateIpv6("2002:0808:0808::"), false); // 6to4 wrapping public 8.8.8.8
  assert.equal(isPrivateIpv6("2606:4700:4700::1111"), false); // public (Cloudflare)
});

test("createPinnedLookup only yields pre-validated addresses", () => {
  const pinned = createPinnedLookup([{ address: "93.184.216.34", family: 4 }]);

  // all: false form -> (err, address, family)
  pinned("attacker-controlled.example", { family: 4 }, (err, address, family) => {
    assert.equal(err, null);
    assert.equal(address, "93.184.216.34");
    assert.equal(family, 4);
  });

  // all: true form -> (err, [{address, family}])
  pinned("attacker-controlled.example", { all: true }, (err, addresses) => {
    assert.equal(err, null);
    assert.deepEqual(addresses, [{ address: "93.184.216.34", family: 4 }]);
  });

  // legacy (hostname, callback) form
  pinned("attacker-controlled.example", (err, address) => {
    assert.equal(err, null);
    assert.equal(address, "93.184.216.34");
  });
});

test("assertPublicRequestTarget returns the validated addresses for pinning", async (t) => {
  const originalLookup = dns.lookup;
  dns.lookup = async () => [{ address: "93.184.216.34", family: 4 }];
  t.after(() => {
    dns.lookup = originalLookup;
  });

  const addresses = await assertPublicRequestTarget(new URL("https://example.com/"));
  assert.deepEqual(addresses, [{ address: "93.184.216.34", family: 4 }]);
});

test("assertPublicRequestTarget blocks DNS-rebinding when any resolved address is private", async (t) => {
  const originalLookup = dns.lookup;
  // Simulate a rebinding payload: one public, one private address returned together.
  dns.lookup = async () => [
    { address: "93.184.216.34", family: 4 },
    { address: "169.254.169.254", family: 4 },
  ];
  t.after(() => {
    dns.lookup = originalLookup;
  });

  await assert.rejects(
    () => assertPublicRequestTarget(new URL("https://rebind.example/")),
    /did not resolve exclusively to public IP addresses/,
  );
});

test("assertPublicRequestTarget blocks normalized private IP literal forms", async () => {
  await assert.rejects(
    () => assertPublicRequestTarget(new URL("https://2130706433/")),
    /not public and was blocked/,
  );
  await assert.rejects(
    () => assertPublicRequestTarget(new URL("https://0x7f.0.0.1/")),
    /not public and was blocked/,
  );
  await assert.rejects(
    () => assertPublicRequestTarget(new URL("https://[::ffff:127.0.0.1]/")),
    /not public and was blocked/,
  );
  assert.equal(isPrivateAddress("[::ffff:7f00:1]"), true);
});

test("assertPublicRedirectTarget blocks private redirect IP literals before DNS", async () => {
  await assert.rejects(
    () => assertPublicRedirectTarget(new URL("https://[::ffff:127.0.0.1]/")),
    /not public and was blocked/,
  );
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

test("certificate probes reject private and encoded local targets before connecting", async () => {
  for (const target of [
    "https://127.0.0.1/",
    "https://2130706433/",
    "https://169.254.169.254/",
    "https://[::1]/",
    "https://[::ffff:127.0.0.1]/",
  ]) {
    await assert.rejects(() => scanTls(new URL(target)), /not public and was blocked/);
    await assert.rejects(() => scanLiveCertificate(new URL(target)), /not public and was blocked/);
  }
});

test("certificate probes reject mixed public/private DNS answers", async (t) => {
  const originalLookup = dns.lookup;
  dns.lookup = async () => [
    { address: "93.184.216.34", family: 4 },
    { address: "10.0.0.1", family: 4 },
  ];
  t.after(() => { dns.lookup = originalLookup; });

  await assert.rejects(
    () => scanLiveCertificate(new URL("https://rebind.example/")),
    /did not resolve exclusively to public IP addresses/,
  );
});
