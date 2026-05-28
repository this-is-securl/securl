import assert from "node:assert/strict";
import test from "node:test";
import { analyzeHtmlDocument, buildCompromiseSignals } from "../dist/index.js";

const baseCtDiscovery = {
  queriedDomain: "example.com",
  sourceUrl: "https://crt.sh/?q=%25.example.com&output=json",
  subdomains: [],
  wildcardEntries: [],
  prioritizedHosts: [],
  sampledHosts: [],
  coverageSummary: "No sampled hosts.",
  issues: [],
  strengths: [],
};

const baseExposure = {
  probes: [],
  issues: [],
  strengths: [],
};

test("compromise signals flag off-origin password forms and suspicious inline scripts", () => {
  const htmlSecurity = analyzeHtmlDocument(
    "https://example.com/",
    `<!doctype html><html><head>
      <script>eval(atob("YWxlcnQoMSk="));</script>
    </head><body>
      <form method="POST" action="https://login.example-idp.test/session">
        <input type="password" name="password">
      </form>
    </body></html>`,
  );

  const result = buildCompromiseSignals({
    finalUrl: new URL("https://example.com/"),
    htmlSecurity,
    ctDiscovery: baseCtDiscovery,
    exposure: baseExposure,
  });

  assert.equal(result.posture, "suspicious");
  assert.ok(result.indicators.some((indicator) => indicator.title === "Password form posts off-origin"));
  assert.ok(result.indicators.some((indicator) => indicator.title === "Obfuscated inline script markers visible"));
  assert.ok(result.issues.includes("Password form posts off-origin"));
});

test("compromise signals include CT takeover and exposure indicators", () => {
  const htmlSecurity = analyzeHtmlDocument(
    "https://example.com/",
    "<!doctype html><html><body><main>Clean</main></body></html>",
  );

  const result = buildCompromiseSignals({
    finalUrl: new URL("https://example.com/"),
    htmlSecurity,
    ctDiscovery: {
      ...baseCtDiscovery,
      sampledHosts: [
        {
          host: "stale.example.com",
          category: "app",
          priority: "high",
          reachable: true,
          finalUrl: "https://stale.example.com/",
          statusCode: 404,
          responseKind: "html",
          identityProvider: null,
          edgeProvider: null,
          cnameTargets: ["missing.herokuapp.com"],
          suspectedTakeover: {
            provider: "Heroku",
            confidence: "medium",
            evidence: "CNAME points at Heroku and the response matches a missing-app pattern.",
          },
          note: "Possible takeover signal.",
        },
      ],
    },
    exposure: {
      ...baseExposure,
      probes: [
        {
          label: "Environment file",
          path: "/.env",
          statusCode: 200,
          finalUrl: "https://example.com/.env",
          finding: "exposed",
          detail: "Environment file returned a successful response.",
        },
      ],
    },
  });

  assert.equal(result.posture, "suspicious");
  assert.ok(result.indicators.some((indicator) => indicator.title === "Possible subdomain takeover signal"));
  assert.ok(result.indicators.some((indicator) => indicator.title === "Sensitive public path appears exposed"));
});
