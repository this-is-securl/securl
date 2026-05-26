import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { analyzeHtmlDocument } from "../dist/index.js";
import { detectAssessmentLimitation } from "../dist/html-page-analysis.js";
import { AI_VENDOR_MATCHERS, THIRD_PARTY_PROVIDER_MATCHERS, analyzeThirdPartyTrust } from "../dist/htmlInsights.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const fixturesDir = path.join(__dirname, "fixtures");

const readFixture = (name) => fs.readFileSync(path.join(fixturesDir, name), "utf8");

test("ignores api-like asset paths in client exposure detection", () => {
  const htmlSecurity = analyzeHtmlDocument("https://apple.com/", readFixture("apple-api-asset.html"));
  assert.equal(htmlSecurity.clientExposureSignals.length, 0);
});

test("does not treat max-image-preview robots metadata as an environment leak", () => {
  const htmlSecurity = analyzeHtmlDocument("https://www.bbc.co.uk/", readFixture("max-image-preview.html"));
  assert.equal(
    htmlSecurity.clientExposureSignals.some((signal) => signal.category === "environment"),
    false,
  );
});

test("does not treat generic crisp css class names as AI/support automation", () => {
  const htmlSecurity = analyzeHtmlDocument("https://sentrustsouthend.co.uk/", readFixture("crisp-wordpress-class.html"));
  assert.equal(htmlSecurity.aiSurface.detected, false);
  assert.equal(htmlSecurity.aiSurface.vendors.length, 0);
});

test("keeps passive vendor signature registries visible to tests", () => {
  assert.equal(AI_VENDOR_MATCHERS.some((matcher) => matcher.name === "OpenAI"), true);
  assert.equal(AI_VENDOR_MATCHERS.some((matcher) => matcher.name === "Crisp"), true);
  assert.equal(THIRD_PARTY_PROVIDER_MATCHERS.some((matcher) => matcher.name === "Session Replay / Experience Analytics"), true);
});

test("detects explicit AI vendor assets without relying on generic copy", () => {
  const htmlSecurity = analyzeHtmlDocument(
    "https://example.com/",
    `<!doctype html><html><head>
      <script src="https://cdn.openai.com/widgets/assistant.js"></script>
    </head><body><button>Chat with AI</button></body></html>`,
  );

  assert.equal(htmlSecurity.aiSurface.detected, true);
  assert.equal(htmlSecurity.aiSurface.vendors.some((vendor) => vendor.name === "OpenAI"), true);
  assert.equal(htmlSecurity.aiSurface.issues.some((issue) => /disclosure/i.test(issue)), true);
});

test("does not treat generic product copy as Microsoft Copilot exposure", () => {
  const htmlSecurity = analyzeHtmlDocument(
    "https://example.com/",
    `<!doctype html><html><body>
      <p>Our onboarding co-pilot helps teams learn the workflow.</p>
      <p>This is a guide for copiloting a rollout with a human reviewer.</p>
    </body></html>`,
  );

  assert.equal(htmlSecurity.aiSurface.vendors.some((vendor) => vendor.name === "Microsoft Copilot"), false);
});

test("classifies third-party trust from the exported provider registry", () => {
  const htmlSecurity = analyzeHtmlDocument(
    "https://example.com/",
    `<!doctype html><html><head>
      <script src="https://cdn.segment.com/analytics.js"></script>
      <script src="https://static.hotjar.com/c/hotjar.js"></script>
    </head><body></body></html>`,
  );
  const trust = analyzeThirdPartyTrust(new URL("https://example.com/"), htmlSecurity, htmlSecurity.aiSurface);

  assert.equal(trust.totalProviders, 2);
  assert.equal(trust.providers.some((provider) => provider.category === "session_replay" && provider.risk === "high"), true);
  assert.equal(trust.issues.some((issue) => /Session replay/i.test(issue)), true);
});

test("preserves positive client exposure and auth signals when they are explicit", () => {
  const htmlSecurity = analyzeHtmlDocument("https://example.com/", readFixture("client-config-positive.html"));
  assert.equal(
    htmlSecurity.clientExposureSignals.some((signal) => signal.category === "config"),
    true,
  );
  assert.equal(
    htmlSecurity.clientExposureSignals.some(
      (signal) => signal.category === "config" && signal.evidence.includes("environment"),
    ),
    true,
  );
  assert.equal(htmlSecurity.forms.some((form) => form.hasPasswordField), true);
  assert.equal(htmlSecurity.firstPartyPaths.includes("/login"), true);
});

test("extracts explicit versioned client library fingerprints from script URLs", () => {
  const htmlSecurity = analyzeHtmlDocument(
    "https://example.com/",
    `<!doctype html><html><head>
      <script src="https://cdn.example.com/assets/jquery-3.4.0.min.js"></script>
      <script src="https://cdn.example.com/assets/bootstrap.bundle-5.3.3.min.js"></script>
    </head><body></body></html>`,
  );

  assert.deepEqual(
    htmlSecurity.libraryFingerprints.map((item) => `${item.packageName}@${item.version}`),
    ["jquery@3.4.0", "bootstrap@5.3.3"],
  );
  assert.equal(htmlSecurity.libraryRiskSignals.length, 0);
});

test("scores SRI coverage for external resources", () => {
  const htmlSecurity = analyzeHtmlDocument(
    "https://example.com/",
    `<!doctype html><html><head>
      <script src="https://cdn.example.net/a.js"></script>
      <script src="https://cdn.example.net/b.js"></script>
      <script src="/local.js"></script>
      <link rel="stylesheet" href="https://fonts.example.net/font.css">
    </head><body></body></html>`,
  );

  assert.equal(htmlSecurity.sriCoverage.externalScripts, 2);
  assert.equal(htmlSecurity.sriCoverage.externalStylesheets, 1);
  assert.equal(htmlSecurity.sriCoverage.coveragePercent, 0);
  assert.equal(
    htmlSecurity.sriCoverage.issues.includes("External scripts or stylesheets are loaded without Subresource Integrity coverage."),
    true,
  );
});

test("recognises full SRI coverage on external resources", () => {
  const htmlSecurity = analyzeHtmlDocument(
    "https://example.com/",
    `<!doctype html><html><head>
      <script src="https://cdn.example.net/a.js" integrity="sha384-abc123"></script>
      <script src="https://cdn.example.net/b.js" integrity="sha512-def456"></script>
    </head><body></body></html>`,
  );

  assert.equal(htmlSecurity.sriCoverage.coveragePercent, 100);
  assert.equal(htmlSecurity.sriCoverage.scriptsWithSri, 2);
  assert.equal(htmlSecurity.sriCoverage.strengths.length, 1);
});

test("detects framework and version leakage from fetched HTML only", () => {
  const htmlSecurity = analyzeHtmlDocument(
    "https://example.com/",
    `<!doctype html><html><head>
      <script id="__NEXT_DATA__" type="application/json">{"buildId":"abc"}</script>
      <script>/* jQuery v3.6.0 */</script>
      <link rel="stylesheet" href="https://cdn.example.net/wp-content/themes/site/style.css">
    </head><body></body></html>`,
  );

  const leaks = htmlSecurity.frameworkVersionLeaks;
  assert.equal(leaks.some((item) => item.framework === "Next.js"), true);
  assert.equal(leaks.some((item) => item.framework === "WordPress"), true);
  assert.equal(leaks.some((item) => item.framework === "jQuery" && item.versionHint === "3.6.0"), true);
});

test("keeps clean HTML free of framework version leaks", () => {
  const htmlSecurity = analyzeHtmlDocument(
    "https://example.com/",
    "<!doctype html><html><head></head><body><main>Hello</main></body></html>",
  );

  assert.deepEqual(htmlSecurity.frameworkVersionLeaks, []);
  assert.equal(htmlSecurity.sriCoverage.issues.length, 0);
});

test("extracts sibling same-site hosts from page content without treating third parties as internal", () => {
  const htmlSecurity = analyzeHtmlDocument(
    "https://www.bbc.co.uk/",
    `<!doctype html><html><body>
      <a href="https://account.bbc.co.uk/signin">Sign in</a>
      <script src="https://static.bbc.co.uk/orbit.js"></script>
      <a href="https://www.example-cdn.com/asset">CDN</a>
    </body></html>`,
  );

  assert.deepEqual(htmlSecurity.sameSiteHosts, ["account.bbc.co.uk", "static.bbc.co.uk"]);
});

test("detectAssessmentLimitation treats server errors as unavailable posture reads", () => {
  const limitation = detectAssessmentLimitation(503, {}, "<html><body>Service Unavailable</body></html>");

  assert.equal(limitation.limited, true);
  assert.equal(limitation.kind, "service_unavailable");
  assert.match(limitation.detail, /HTTP 503/);
});

test("flags explicit vulnerable training or challenge page markers from title and paths", () => {
  const htmlSecurity = analyzeHtmlDocument(
    "https://public-firing-range.appspot.com/",
    `<!doctype html><html><head><title>Firing Range</title></head><body>
      <a href="/xss/index.html">XSS</a>
      <a href="/clickjacking/index.html">Clickjacking</a>
    </body></html>`,
  );

  assert.equal(
    htmlSecurity.issues.includes("Page content suggests an intentionally vulnerable training or challenge surface."),
    true,
  );
  assert.equal(htmlSecurity.strengths.some((item) => item.includes("Challenge-style page markers were visible")), false);
});

test("detects common client telemetry and session analytics vendors", () => {
  const htmlSecurity = analyzeHtmlDocument(
    "https://example.com/",
    `<!doctype html><html><head>
      <script src="https://cdn.segment.com/analytics.js/v1/write-key/analytics.min.js"></script>
      <script src="https://www.clarity.ms/tag/example"></script>
      <script src="https://www.datadoghq-browser-agent.com/us1/v5/datadog-rum.js"></script>
    </head><body></body></html>`,
  );

  const names = htmlSecurity.detectedTechnologies.map((item) => item.name);
  assert.ok(names.includes("Segment"));
  assert.ok(names.includes("Microsoft Clarity"));
  assert.ok(names.includes("Datadog RUM"));
});

// Regression test for adcb3de — extractVersionNear must find versions in CDN URLs
// e.g. https://cdn.jsdelivr.net/@angular/core@17.3.0/bundles/core.umd.js
test("extracts framework versions from CDN URL paths (regression: adcb3de)", () => {
  const htmlSecurity = analyzeHtmlDocument(
    "https://example.com/",
    `<!doctype html><html><head>
      <script src="https://cdn.jsdelivr.net/npm/@angular/core@17.3.0/bundles/core.umd.js"></script>
      <script src="https://cdn.jsdelivr.net/npm/vue@3.4.21/dist/vue.global.js"></script>
    </head><body></body></html>`,
  );

  const leaks = htmlSecurity.frameworkVersionLeaks;
  const angular = leaks.find((item) => item.framework === "Angular");
  const vue = leaks.find((item) => item.framework === "Vue");

  assert.ok(angular, "Angular should be detected from CDN URL");
  assert.equal(angular?.versionHint, "17.3.0", "Angular version should be extracted from CDN URL");

  assert.ok(vue, "Vue should be detected from CDN URL");
  assert.equal(vue?.versionHint, "3.4.21", "Vue version should be extracted from CDN URL");
});
