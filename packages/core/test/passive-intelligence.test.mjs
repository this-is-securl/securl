import assert from "node:assert/strict";
import test from "node:test";
import { buildPassiveIntelligence, emptyPassiveIntelligence } from "../dist/passive-intelligence.js";

const baseInput = {
  technologies: [],
  infrastructure: {
    host: "example.com",
    addresses: [],
    cnameTargets: [],
    reverseDns: [],
    providers: [],
    issues: [],
    strengths: [],
    summary: "",
  },
  thirdPartyTrust: {
    totalProviders: 0,
    highRiskProviders: 0,
    providers: [],
    issues: [],
    strengths: [],
    summary: "",
  },
  htmlSecurity: {
    fetched: true,
    pageUrl: "https://example.com/",
    pageTitle: "Example",
    metaGenerator: null,
    forms: [],
    sameSiteHosts: [],
    externalScriptDomains: [],
    externalStylesheetDomains: [],
    insecureResourceUrls: [],
    inlineScriptCount: 0,
    inlineStyleCount: 0,
    missingSriScriptUrls: [],
    firstPartyPaths: [],
    passiveLeakSignals: [],
    clientExposureSignals: [],
    libraryFingerprints: [],
    libraryRiskSignals: [],
    detectedTechnologies: [],
    aiSurface: {
      detected: false,
      assistantVisible: false,
      aiPageSignals: [],
      vendors: [],
      discoveredPaths: [],
      disclosures: [],
      privacySignals: [],
      governanceSignals: [],
      issues: [],
      strengths: [],
    },
    issues: [],
    strengths: [],
  },
  aiSurface: {
    detected: false,
    assistantVisible: false,
    aiPageSignals: [],
    vendors: [],
    discoveredPaths: [],
    disclosures: [],
    privacySignals: [],
    governanceSignals: [],
    issues: [],
    strengths: [],
  },
  domainSecurity: {
    host: "example.com",
    mxRecords: [],
    nsRecords: [],
    caaRecords: [],
    dnssec: { enabled: false, dsRecords: [], status: "not_signed" },
    spf: null,
    dmarc: null,
    emailPolicy: {
      spf: { status: "missing", allMechanism: null, dnsLookupMechanisms: 0, summary: "" },
      dmarc: { status: "missing", policy: null, subdomainPolicy: null, pct: null, reporting: false, summary: "" },
    },
    mtaSts: { dns: null, policyUrl: null, policy: null },
    issues: ["No SPF record was detected."],
    strengths: [],
  },
  securityTxt: {
    status: "missing",
    url: null,
    contact: [],
    expires: null,
    policy: [],
    acknowledgments: [],
    encryption: [],
    hiring: [],
    preferredLanguages: [],
    canonical: [],
    raw: null,
    issues: [],
  },
  publicSignals: {
    hstsPreload: {
      status: "not_preloaded",
      summary: "",
      sourceUrl: "https://hstspreload.org/api/v2/status?domain=example.com",
    },
    issues: [],
    strengths: [],
  },
  identityProvider: {
    detected: false,
    provider: null,
    protocol: null,
    redirectOrigins: [],
    authHostCandidates: [],
    loginPaths: [],
    openIdConfigurationUrl: null,
    wellKnownEndpoints: [],
    issuer: null,
    authorizationEndpoint: null,
    tokenEndpoint: null,
    endSessionEndpoint: null,
    redirectUriSignals: [],
    tenantBrand: null,
    tenantRegion: null,
    tenantSignals: [],
    issues: [],
    strengths: [],
  },
  wafFingerprint: {
    detected: false,
    providers: [],
    edgeSignals: [],
    issues: [],
    strengths: [],
    summary: "",
  },
  apiSurface: {
    probes: [],
    issues: [],
    strengths: [],
  },
  assessmentLimitation: {
    limited: false,
    title: null,
  },
};

test("buildPassiveIntelligence summarizes stack, telemetry, trust, and exposure without active probing language", () => {
  const result = buildPassiveIntelligence({
    ...baseInput,
    technologies: [
      {
        name: "Cloudflare",
        category: "network",
        evidence: "Observed in Cloudflare response headers",
        version: null,
        confidence: "high",
        detection: "observed",
      },
      {
        name: "Next.js",
        category: "frontend",
        evidence: "Detected from Next.js page assets",
        version: null,
        confidence: "medium",
        detection: "inferred",
      },
    ],
    infrastructure: {
      ...baseInput.infrastructure,
      providers: [
        {
          provider: "Cloudflare",
          category: "edge",
          confidence: "high",
          source: "headers",
          evidence: "cf-ray",
        },
      ],
    },
    thirdPartyTrust: {
      ...baseInput.thirdPartyTrust,
      totalProviders: 2,
      providers: [
        {
          domain: "www.googletagmanager.com",
          name: "Google Tag Manager",
          category: "analytics",
          risk: "medium",
          evidence: "script",
        },
        {
          domain: "static.hotjar.com",
          name: "Hotjar",
          category: "session_replay",
          risk: "high",
          evidence: "script",
        },
      ],
    },
    htmlSecurity: {
      ...baseInput.htmlSecurity,
      passiveLeakSignals: [
        {
          category: "source_map",
          severity: "warning",
          title: "Source map references visible",
          detail: "Production page markup exposes source map references.",
          evidence: ["https://example.com/app.js.map"],
        },
      ],
    },
  });

  assert.match(result.collectionBoundary, /No port scanning/);
  assert.ok(result.signals.some((signal) => signal.title === "Visible technology stack"));
  assert.ok(result.signals.some((signal) => signal.category === "telemetry" && signal.risk === "watch"));
  assert.ok(result.signals.some((signal) => signal.category === "exposure" && signal.risk === "attention"));
  assert.ok(result.issues.length >= 2);
});

test("emptyPassiveIntelligence preserves the passive boundary", () => {
  const result = emptyPassiveIntelligence("Not collected.");

  assert.equal(result.postureRead, "Not collected.");
  assert.deepEqual(result.signals, []);
  assert.match(result.collectionBoundary, /Passive read only/);
});
