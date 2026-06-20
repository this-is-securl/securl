#!/usr/bin/env node

const DEFAULT_BASE_URL = "https://securl-app-production.up.railway.app";
const DEFAULT_TARGET = "https://securl.online";
const DEFAULT_MODE = "quiet";
const DEFAULT_TIMEOUT_MS = 90_000;
const POLL_INTERVAL_MS = 1_500;

function getArg(name, fallback) {
  const prefix = `--${name}=`;
  const match = process.argv.find((arg) => arg.startsWith(prefix));
  if (!match) return fallback;
  return match.slice(prefix.length);
}

function buildBaseUrl() {
  return String(getArg("base-url", process.env.SMOKE_API_BASE_URL || DEFAULT_BASE_URL)).replace(/\/+$/, "");
}

function buildOwnerToken() {
  return `smoke-${Date.now()}-${crypto.randomUUID()}`;
}

async function fetchText(url, options = {}) {
  const response = await fetch(url, {
    headers: {
      Accept: "application/json",
      ...(options.headers || {}),
    },
    ...options,
  });
  const text = await response.text();
  return { response, text };
}

function parseJson(text, label) {
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${label} did not return JSON: ${text.slice(0, 160)}`);
  }
}

async function expectJson({ url, label, options = {}, okStatuses = [200] }) {
  const { response, text } = await fetchText(url, options);
  if (!okStatuses.includes(response.status)) {
    throw new Error(`${label} failed with HTTP ${response.status}: ${text.slice(0, 240)}`);
  }
  return parseJson(text, label);
}

async function pollScan({ baseUrl, scanId, headers, timeoutMs }) {
  const deadline = Date.now() + timeoutMs;
  let lastPayload = null;

  while (Date.now() < deadline) {
    const payload = await expectJson({
      url: `${baseUrl}/api/scans/${encodeURIComponent(scanId)}`,
      label: "scan detail",
      options: { headers },
    });
    lastPayload = payload;
    const status = payload.scan?.status;
    if (status === "completed" || status === "failed") {
      return payload;
    }
    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
  }

  throw new Error(`Scan ${scanId} did not finish within ${timeoutMs}ms. Last status: ${lastPayload?.scan?.status || "unknown"}`);
}

function assertCapabilities(payload) {
  const resources = payload.scans?.resources || [];
  const features = payload.scans?.features || [];
  const serviceResources = payload.service?.resources || [];

  for (const resource of [
    "POST /api/scans",
    "GET /api/scans/:id",
    "GET /api/scans/:id/summary",
    "GET /api/scans/:id/findings",
    "GET /api/scans/:id/digest",
    "GET /api/scans/:id/brief",
    "GET /api/scans/:id/vendors",
    "GET /api/scans/:id/action-plan",
    "GET /api/scans/:id/events",
    "GET /api/scans/:id/evidence",
    "GET /api/scans/:id/history",
    "GET /api/scans/:id/comparison",
    "GET /api/scans/:id/drift",
    "GET /api/scans/:id/export?format=json|markdown|sarif|ci-json",
    "GET /api/scans/:id/share",
  ]) {
    if (!resources.includes(resource)) {
      throw new Error(`Capabilities missing scan resource: ${resource}`);
    }
  }

  for (const resource of ["GET /api/certificates/live?url=:url"]) {
    if (!serviceResources.includes(resource)) {
      throw new Error(`Capabilities missing service resource: ${resource}`);
    }
  }

  for (const feature of ["evidence-summary", "posture-digest", "posture-drift", "exposure-brief", "vendor-exposure", "action-plan", "scan-events", "scan-resource-links"]) {
    if (!features.includes(feature)) {
      throw new Error(`Capabilities missing scan feature: ${feature}`);
    }
  }

  if (!payload.certificates?.features?.includes("live-certificate")) {
    throw new Error("Capabilities missing live-certificate feature.");
  }
  if (!payload.notifications?.features?.includes("device-registration")) {
    throw new Error("Capabilities missing notification device-registration feature.");
  }
  for (const feature of ["test-notification", "bounded-delivery-retry", "durable-notification-outbox"]) {
    if (!payload.notifications?.features?.includes(feature)) {
      throw new Error(`Capabilities missing notification feature: ${feature}`);
    }
  }
  if (!payload.notifications?.resources?.includes("POST /api/notification-devices/:id/test")) {
    throw new Error("Capabilities missing notification test resource.");
  }
}

function assertScanResourceLinks(payload, scanId) {
  const resources = payload.resources || {};
  const expected = {
    detail: `/api/scans/${scanId}`,
    summary: `/api/scans/${scanId}/summary`,
    findings: `/api/scans/${scanId}/findings`,
    digest: `/api/scans/${scanId}/digest`,
    events: `/api/scans/${scanId}/events`,
    evidence: `/api/scans/${scanId}/evidence`,
    history: `/api/scans/${scanId}/history`,
    comparison: `/api/scans/${scanId}/comparison`,
    drift: `/api/scans/${scanId}/drift`,
    share: `/api/scans/${scanId}/share`,
  };

  for (const [name, path] of Object.entries(expected)) {
    if (resources[name] !== path) {
      throw new Error(`Scan create response missing resources.${name}: expected ${path}, got ${resources[name] || "missing"}`);
    }
  }
}

async function main() {
  const baseUrl = buildBaseUrl();
  const target = getArg("target", process.env.SMOKE_TARGET_URL || DEFAULT_TARGET);
  const mode = getArg("mode", process.env.SMOKE_SCAN_MODE || DEFAULT_MODE);
  const timeoutMs = Number(getArg("timeout-ms", process.env.SMOKE_TIMEOUT_MS || DEFAULT_TIMEOUT_MS));
  const ownerToken = buildOwnerToken();
  const ownerHeaders = {
    "X-Scan-Owner": ownerToken,
    "X-SecURL-Client": "securl-api-smoke",
    "X-SecURL-Client-Version": "1.0.0",
  };
  const jsonOwnerHeaders = { ...ownerHeaders, "Content-Type": "application/json" };

  console.log(`SecURL API smoke`);
  console.log(`Base URL: ${baseUrl}`);
  console.log(`Target: ${target}`);
  console.log(`Mode: ${mode}`);
  console.log("");

  const health = await expectJson({ url: `${baseUrl}/api/health`, label: "health" });
  console.log(`health: ${health.ok ? "ok" : "unexpected"}`);

  const readiness = await expectJson({ url: `${baseUrl}/api/ready`, label: "readiness" });
  if (!readiness.storage?.available) {
    throw new Error(`Readiness storage unavailable: ${JSON.stringify(readiness.storage || {})}`);
  }
  console.log(`ready: ${readiness.storage.backend} storage available`);

  const capabilities = await expectJson({ url: `${baseUrl}/api/capabilities`, label: "capabilities" });
  assertCapabilities(capabilities);
  console.log(`capabilities: ${capabilities.service?.corePackage}@${capabilities.service?.coreVersion}`);

  const createPayload = await expectJson({
    url: `${baseUrl}/api/scans`,
    label: "scan create",
    okStatuses: [202],
    options: {
      method: "POST",
      headers: jsonOwnerHeaders,
      body: JSON.stringify({ url: target, mode }),
    },
  });

  const scanId = createPayload.scan?.id;
  if (!scanId) {
    throw new Error("Scan create response did not include scan.id");
  }
  assertScanResourceLinks(createPayload, scanId);
  console.log(`scan: ${scanId}${createPayload.fromCache ? " (cache hit)" : ""}`);

  const detailPayload = createPayload.scan?.status === "completed"
    ? await expectJson({
        url: `${baseUrl}/api/scans/${encodeURIComponent(scanId)}`,
        label: "scan detail",
        options: { headers: ownerHeaders },
      })
    : await pollScan({ baseUrl, scanId, headers: ownerHeaders, timeoutMs });

  if (detailPayload.scan?.status !== "completed") {
    throw new Error(`Scan finished with status ${detailPayload.scan?.status || "unknown"}`);
  }

  const result = detailPayload.scan.result;
  if (!result) {
    throw new Error("Completed scan did not include result payload");
  }
  console.log(`result: ${result.grade} / ${result.score}`);

  const endpointChecks = [
    ["summary", `/api/scans/${encodeURIComponent(scanId)}/summary`, ownerHeaders],
    ["findings", `/api/scans/${encodeURIComponent(scanId)}/findings`, ownerHeaders],
    ["digest", `/api/scans/${encodeURIComponent(scanId)}/digest`, ownerHeaders],
    ["brief", `/api/scans/${encodeURIComponent(scanId)}/brief`, ownerHeaders],
    ["vendors", `/api/scans/${encodeURIComponent(scanId)}/vendors`, ownerHeaders],
    ["action-plan", `/api/scans/${encodeURIComponent(scanId)}/action-plan`, ownerHeaders],
    ["evidence", `/api/scans/${encodeURIComponent(scanId)}/evidence`, ownerHeaders],
    ["history", `/api/scans/${encodeURIComponent(scanId)}/history`, ownerHeaders],
    ["comparison", `/api/scans/${encodeURIComponent(scanId)}/comparison`, ownerHeaders],
    ["drift", `/api/scans/${encodeURIComponent(scanId)}/drift`, ownerHeaders],
    ["share", `/api/scans/${encodeURIComponent(scanId)}/share`, {}],
  ];

  for (const [label, path, headers] of endpointChecks) {
    const payload = await expectJson({
      url: `${baseUrl}${path}`,
      label,
      options: { headers },
    });
    console.log(`${label}: ok`);
    if (label === "digest" && !payload.digest) {
      throw new Error("Digest endpoint returned an empty digest");
    }
    if (label === "brief" && !payload.brief) {
      throw new Error("Brief endpoint returned an empty exposure brief");
    }
    if (label === "vendors" && !payload.vendors) {
      throw new Error("Vendors endpoint returned an empty vendor exposure brief");
    }
    if (label === "action-plan" && !payload.actionPlan) {
      throw new Error("Action plan endpoint returned an empty action plan");
    }
    if (label === "evidence" && !payload.evidence) {
      throw new Error("Evidence endpoint returned an empty evidence payload");
    }
    if (label === "share" && !payload.scan?.result) {
      throw new Error("Share endpoint returned an empty scan result");
    }
  }

  const eventsResponse = await fetch(`${baseUrl}/api/scans/${encodeURIComponent(scanId)}/events`, {
    headers: ownerHeaders,
  });
  const eventsText = await eventsResponse.text();
  if (eventsResponse.status !== 200 || !/event: scan_terminal/.test(eventsText)) {
    throw new Error(`Scan events stream did not reach terminal state: HTTP ${eventsResponse.status}`);
  }
  console.log("events: ok");

  const certificate = await expectJson({
    url: `${baseUrl}/api/certificates/live?url=${encodeURIComponent(target)}`,
    label: "live certificate",
    options: { headers: ownerHeaders },
  });
  if (!certificate.certificate || certificate.certificate.available !== true) {
    throw new Error("Live certificate endpoint did not return certificate data.");
  }
  console.log(`live-certificate: ${certificate.certificate.daysRemaining ?? "unknown"} days`);

  const exportChecks = [
    ["json export", "json", "application/json"],
    ["markdown export", "markdown", "text/markdown"],
    ["sarif export", "sarif", "application/sarif+json"],
    ["ci-json export", "ci-json", "application/json"],
  ];

  for (const [label, format, expectedContentType] of exportChecks) {
    const { response, text } = await fetchText(`${baseUrl}/api/scans/${encodeURIComponent(scanId)}/export?format=${format}`, {
      headers: ownerHeaders,
    });
    if (response.status !== 200) {
      throw new Error(`${label} failed with HTTP ${response.status}: ${text.slice(0, 240)}`);
    }
    const contentType = response.headers.get("content-type") || "";
    if (!contentType.includes(expectedContentType)) {
      throw new Error(`${label} returned unexpected content-type: ${contentType || "missing"}`);
    }
    if (!text.trim()) {
      throw new Error(`${label} returned an empty body`);
    }
    console.log(`${label}: ok`);
  }

  console.log("");
  console.log("Smoke passed.");
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
