import assert from "node:assert/strict";
import dns from "node:dns/promises";
import test from "node:test";
import { analyzeDomainSecurity, evaluateDmarcPolicy, evaluateSpfPolicy } from "../dist/domain-security.js";

test("evaluateSpfPolicy classifies hardfail, softfail, and permissive SPF records", () => {
  assert.deepEqual(evaluateSpfPolicy(null), {
    status: "missing",
    allMechanism: null,
    dnsLookupMechanisms: 0,
    summary: "No SPF record was detected at the zone apex.",
  });

  const hardfail = evaluateSpfPolicy("v=spf1 include:_spf.example.com ip4:192.0.2.0/24 -all");
  assert.equal(hardfail.status, "strong");
  assert.equal(hardfail.allMechanism, "-all");
  assert.equal(hardfail.dnsLookupMechanisms, 1);

  const softfail = evaluateSpfPolicy("v=spf1 include:_spf.example.com ~all");
  assert.equal(softfail.status, "watch");
  assert.equal(softfail.allMechanism, "~all");

  const permissive = evaluateSpfPolicy("v=spf1 +all");
  assert.equal(permissive.status, "weak");
  assert.equal(permissive.allMechanism, "+all");
});

test("evaluateDmarcPolicy classifies enforcing, partial rollout, and monitor-only records", () => {
  assert.deepEqual(evaluateDmarcPolicy(null), {
    status: "missing",
    policy: null,
    subdomainPolicy: null,
    pct: null,
    reporting: false,
    summary: "No DMARC record was detected.",
  });

  const enforcing = evaluateDmarcPolicy("v=DMARC1; p=reject; sp=quarantine; rua=mailto:dmarc@example.com");
  assert.equal(enforcing.status, "strong");
  assert.equal(enforcing.policy, "reject");
  assert.equal(enforcing.subdomainPolicy, "quarantine");
  assert.equal(enforcing.reporting, true);

  const partial = evaluateDmarcPolicy("v=DMARC1; p=quarantine; pct=50");
  assert.equal(partial.status, "watch");
  assert.equal(partial.pct, 50);

  const monitorOnly = evaluateDmarcPolicy("v=DMARC1; p=none; rua=mailto:dmarc@example.com");
  assert.equal(monitorOnly.status, "weak");
  assert.equal(monitorOnly.policy, "none");
});

test("analyzeDomainSecurity includes passive SMTP reporting and BIMI trust signals", async (t) => {
  const original = {
    resolveMx: dns.resolveMx,
    resolveNs: dns.resolveNs,
    resolveTxt: dns.resolveTxt,
    resolveCaa: dns.resolveCaa,
    resolve: dns.resolve,
  };

  t.after(() => {
    dns.resolveMx = original.resolveMx;
    dns.resolveNs = original.resolveNs;
    dns.resolveTxt = original.resolveTxt;
    dns.resolveCaa = original.resolveCaa;
    dns.resolve = original.resolve;
  });

  dns.resolveMx = async () => [{ priority: 10, exchange: "mail.example.com" }];
  dns.resolveNs = async () => ["ns1.example.com"];
  dns.resolveCaa = async () => [{ issue: "letsencrypt.org" }];
  dns.resolve = async (_host, type) => {
    if (type === "DS") {
      return [{ keyTag: 12345, algorithm: 13, digestType: 2, digest: "abcdef" }];
    }
    return [];
  };
  dns.resolveTxt = async (host) => {
    if (host === "example.com") {
      return [["v=spf1 include:_spf.example.com -all"]];
    }
    if (host === "_dmarc.example.com") {
      return [["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]];
    }
    if (host === "_mta-sts.example.com") {
      return [["v=STSv1; id=20260519"]];
    }
    if (host === "_smtp._tls.example.com") {
      return [["v=TLSRPTv1; rua=mailto:tlsrpt@example.com"]];
    }
    if (host === "default._bimi.example.com") {
      return [["v=BIMI1; l=https://example.com/bimi.svg"]];
    }
    return [];
  };

  const result = await analyzeDomainSecurity("example.com", async () => ({
    statusCode: 200,
    headers: {},
    body: "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400",
    url: "https://mta-sts.example.com/.well-known/mta-sts.txt",
  }));

  assert.equal(result.tlsRpt.reporting, true);
  assert.match(result.tlsRpt.dns, /^v=TLSRPTv1/);
  assert.equal(result.bimi.status, "present");
  assert.match(result.bimi.dns, /^v=BIMI1/);
  assert.equal(
    result.issues.includes("MTA-STS is present, but no TLS-RPT reporting record was detected."),
    false,
  );
  assert.equal(
    result.strengths.includes("TLS-RPT reporting is published for SMTP transport issues."),
    true,
  );
  assert.equal(
    result.strengths.includes("BIMI is published, which can support brand trust when paired with enforcing DMARC."),
    true,
  );
});

test("analyzeDomainSecurity flags missing TLS-RPT only when MTA-STS is present", async (t) => {
  const original = {
    resolveMx: dns.resolveMx,
    resolveNs: dns.resolveNs,
    resolveTxt: dns.resolveTxt,
    resolveCaa: dns.resolveCaa,
    resolve: dns.resolve,
  };

  t.after(() => {
    dns.resolveMx = original.resolveMx;
    dns.resolveNs = original.resolveNs;
    dns.resolveTxt = original.resolveTxt;
    dns.resolveCaa = original.resolveCaa;
    dns.resolve = original.resolve;
  });

  dns.resolveMx = async () => [{ priority: 10, exchange: "mail.example.com" }];
  dns.resolveNs = async () => ["ns1.example.com"];
  dns.resolveCaa = async () => [{ issue: "letsencrypt.org" }];
  dns.resolve = async () => [{ keyTag: 12345, algorithm: 13, digestType: 2, digest: "abcdef" }];
  dns.resolveTxt = async (host) => {
    if (host === "example.com") {
      return [["v=spf1 include:_spf.example.com -all"]];
    }
    if (host === "_dmarc.example.com") {
      return [["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]];
    }
    if (host === "_mta-sts.example.com") {
      return [["v=STSv1; id=20260519"]];
    }
    return [];
  };

  const result = await analyzeDomainSecurity("example.com", async () => {
    throw new Error("not fetched");
  });

  assert.equal(result.tlsRpt.reporting, false);
  assert.equal(
    result.issues.includes("MTA-STS is present, but no TLS-RPT reporting record was detected."),
    true,
  );
});
