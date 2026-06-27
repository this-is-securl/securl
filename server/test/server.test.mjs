import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import http from "node:http";
import net from "node:net";
import test from "node:test";
import { once } from "node:events";

const SERVER_ENTRY = new URL("../index.mjs", import.meta.url);
const SCAN_OWNER_ONE = "test-scan-owner-token-one";
const SCAN_OWNER_TWO = "test-scan-owner-token-two";

const scanOwnerHeaders = (owner = SCAN_OWNER_ONE) => ({
  "X-Scan-Owner": owner,
});

const scanOwnerJsonHeaders = (owner = SCAN_OWNER_ONE) => ({
  "Content-Type": "application/json",
  ...scanOwnerHeaders(owner),
});

const bearerHeaders = (token) => ({
  Authorization: `Bearer ${token}`,
});

const bearerJsonHeaders = (token) => ({
  "Content-Type": "application/json",
  ...bearerHeaders(token),
});

const postScan = (baseUrl, url, options = {}) =>
  fetch(`${baseUrl}/api/scans`, {
    method: "POST",
    headers: scanOwnerJsonHeaders(options.owner),
    body: JSON.stringify({
      url,
      ...(options.mode ? { mode: options.mode } : {}),
    }),
    ...("headers" in options
      ? {
          headers: {
            ...scanOwnerJsonHeaders(options.owner),
            ...options.headers,
          },
        }
      : {}),
  });

const postMonitoringTarget = (baseUrl, url, options = {}) =>
  fetch(`${baseUrl}/api/monitoring-targets`, {
    method: "POST",
    headers: scanOwnerJsonHeaders(options.owner),
    body: JSON.stringify({
      url,
      ...(options.cadence ? { cadence: options.cadence } : {}),
      ...(options.label ? { label: options.label } : {}),
      ...(options.appId ? { appId: options.appId } : {}),
      ...(options.policy ? { policy: options.policy } : {}),
    }),
    ...("headers" in options
      ? {
          headers: {
            ...scanOwnerJsonHeaders(options.owner),
            ...options.headers,
          },
        }
      : {}),
  });

const runMonitoringTarget = (baseUrl, targetId, options = {}) =>
  fetch(`${baseUrl}/api/monitoring-targets/${targetId}/run`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...scanOwnerHeaders(options.owner),
    },
    body: JSON.stringify({
      ...(options.mode ? { mode: options.mode } : {}),
    }),
  });

const getMonitoringTarget = (baseUrl, targetId, options = {}) =>
  fetch(`${baseUrl}/api/monitoring-targets/${targetId}`, {
    headers: options.token ? bearerHeaders(options.token) : scanOwnerHeaders(options.owner),
  });

const getMonitoringSummary = (baseUrl, options = {}) =>
  fetch(`${baseUrl}/api/monitoring-summary`, {
    headers: options.token ? bearerHeaders(options.token) : scanOwnerHeaders(options.owner),
  });

const registerUser = (baseUrl, { email, password, displayName }) =>
  fetch(`${baseUrl}/api/auth/register`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      email,
      password,
      ...(displayName ? { displayName } : {}),
    }),
  });

const loginUser = (baseUrl, { email, password }) =>
  fetch(`${baseUrl}/api/auth/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      email,
      password,
    }),
  });

const getFreePort = () =>
  new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        reject(new Error("Could not allocate a test port."));
        return;
      }
      const { port } = address;
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(port);
      });
    });
    server.on("error", reject);
  });

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitForScanTerminal(baseUrl, scanId, { owner = SCAN_OWNER_ONE, attempts = 80 } = {}) {
  let payload = null;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const response = await fetch(`${baseUrl}/api/scans/${scanId}`, {
      headers: scanOwnerHeaders(owner),
    });
    payload = await response.json();
    if (payload.scan?.status === "completed" || payload.scan?.status === "failed") {
      return {
        response,
        payload,
      };
    }
    await wait(100);
  }
  assert.fail(`Timed out waiting for scan ${scanId}.`);
}

const requestRawPath = (baseUrl, requestPath) =>
  new Promise((resolve, reject) => {
    const url = new URL(baseUrl);
    const request = http.request(
      {
        hostname: url.hostname,
        port: url.port,
        path: requestPath,
        method: "GET",
      },
      (response) => {
        let body = "";
        response.setEncoding("utf8");
        response.on("data", (chunk) => {
          body += chunk;
        });
        response.on("end", () => {
          resolve({ statusCode: response.statusCode || 0, body });
        });
      },
    );
    request.on("error", reject);
    request.end();
  });

function createServerProcess(envOverrides = {}) {
  const child = spawn(process.execPath, [SERVER_ENTRY.pathname], {
    cwd: new URL("../../", import.meta.url).pathname,
    env: {
      ...process.env,
      NODE_ENV: "test",
      ...envOverrides,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });

  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    stdout += chunk;
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });

  return {
    child,
    getStdout: () => stdout,
    getStderr: () => stderr,
  };
}

async function startServer(envOverrides = {}) {
  const port = await getFreePort();
  const serverProcess = createServerProcess({
    PORT: String(port),
    ...envOverrides,
  });

  const started = await Promise.race([
    once(serverProcess.child.stdout, "data"),
    once(serverProcess.child, "exit").then(([code]) => {
      throw new Error(`Server exited before startup with code ${code}.\n${serverProcess.getStdout()}\n${serverProcess.getStderr()}`);
    }),
    wait(5000).then(() => {
      throw new Error(`Timed out waiting for server startup.\n${serverProcess.getStdout()}\n${serverProcess.getStderr()}`);
    }),
  ]);

  const firstChunk = String(started[0] || "");
  if (!firstChunk.includes("server_started")) {
    await wait(100);
  }

  return {
    ...serverProcess,
    port,
    baseUrl: `http://127.0.0.1:${port}`,
    async stop() {
      if (serverProcess.child.exitCode !== null) {
        return;
      }
      serverProcess.child.kill("SIGTERM");
      await once(serverProcess.child, "exit");
    },
  };
}

test("server blocks production startup without explicit auth or opt-in", async () => {
  const { child, getStderr } = createServerProcess({
    NODE_ENV: "production",
    PORT: "0",
    API_KEY: "",
    ALLOW_UNAUTHENTICATED: "false",
  });

  const [code] = await once(child, "exit");
  assert.equal(code, 1);
  assert.match(getStderr(), /server_start_blocked/);
});

test("server blocks production startup in multi-instance mode without upstash backend", async () => {
  const { child, getStderr } = createServerProcess({
    NODE_ENV: "production",
    PORT: "0",
    API_KEY: "test-secret",
    DEPLOYMENT_MODE: "multi-instance",
    RATE_LIMIT_BACKEND: "in-memory",
  });

  const [code] = await once(child, "exit");
  assert.equal(code, 1);
  assert.match(getStderr(), /RATE_LIMIT_BACKEND=upstash/i);
});

test("server blocks startup when upstash backend is missing credentials", async () => {
  const { child, getStderr } = createServerProcess({
    NODE_ENV: "production",
    PORT: "0",
    API_KEY: "test-secret",
    RATE_LIMIT_BACKEND: "upstash",
    UPSTASH_REDIS_REST_URL: "",
    UPSTASH_REDIS_REST_TOKEN: "",
  });

  const [code] = await once(child, "exit");
  assert.equal(code, 1);
  assert.match(getStderr(), /UPSTASH_REDIS_REST_URL/i);
});

test("server blocks startup when postgres scan repository is missing DATABASE_URL", async () => {
  const { child, getStderr } = createServerProcess({
    NODE_ENV: "production",
    PORT: "0",
    API_KEY: "test-secret",
    SCAN_REPOSITORY_BACKEND: "postgres",
    DATABASE_URL: "",
  });

  const [code] = await once(child, "exit");
  assert.equal(code, 1);
  assert.match(getStderr(), /DATABASE_URL/i);
});

test("server blocks startup when postgres scan repository is unreachable", async () => {
  const { child, getStderr } = createServerProcess({
    NODE_ENV: "production",
    PORT: "0",
    API_KEY: "test-secret",
    SCAN_REPOSITORY_BACKEND: "postgres",
    DATABASE_URL: "postgres://127.0.0.1:1/secure_header_insight",
    PGSSLMODE: "disable",
  });

  const [code] = await once(child, "exit");
  assert.equal(code, 1);
  assert.match(getStderr(), /scan repository is unavailable|connect/i);
});

test("scan resources require API key when configured", async () => {
  const server = await startServer({
    API_KEY: "test-secret",
  });

  try {
    const response = await fetch(`${server.baseUrl}/api/scans`);
    const payload = await response.json();

    assert.equal(response.status, 401);
    assert.match(payload.error, /API key/i);
  } finally {
    await server.stop();
  }
});

test("static frontend responses include the hardened browser headers", async () => {
  const server = await startServer();

  try {
    const response = await fetch(`${server.baseUrl}/`);

    assert.equal(response.status, 200);
    assert.equal(response.headers.get("strict-transport-security"), "max-age=31536000; includeSubDomains; preload");
    assert.equal(response.headers.get("permissions-policy"), "camera=(), microphone=(), geolocation=(), browsing-topics=()");
    assert.equal(response.headers.get("cross-origin-opener-policy"), "same-origin");
    assert.equal(response.headers.get("cross-origin-resource-policy"), "same-origin");
  } finally {
    await server.stop();
  }
});

test("production defaults to API-only serving unless frontend serving is enabled", async () => {
  const server = await startServer({
    NODE_ENV: "production",
    ALLOW_UNAUTHENTICATED: "true",
    AUTH_TOKEN_FINGERPRINT_SALT: "test-auth-token-salt",
    API_KEY_FINGERPRINT_SALT: "test-api-key-salt",
    SERVE_FRONTEND: "false",
  });

  try {
    const response = await fetch(`${server.baseUrl}/`);
    const payload = await response.json();

    assert.equal(response.status, 404);
    assert.match(payload.error, /frontend is served separately/i);
  } finally {
    await server.stop();
  }
});

test("security.txt is served as a real file instead of the SPA shell", async () => {
  const server = await startServer();

  try {
    const response = await fetch(`${server.baseUrl}/.well-known/security.txt`);
    const body = await response.text();

    assert.equal(response.status, 200);
    assert.match(response.headers.get("content-type") || "", /application\/octet-stream|text\/plain/i);
    assert.match(body, /Contact:\s+mailto:ktbatterham@me\.com/i);
    assert.match(body, /Expires:\s+2027-05-05T00:00:00\.000Z/i);
    assert.doesNotMatch(body, /<html/i);
  } finally {
    await server.stop();
  }
});

test("health endpoint includes deployment and rate-limit metadata", async () => {
  const server = await startServer({
    DEPLOYMENT_MODE: "single-instance",
  });

  try {
    const response = await fetch(`${server.baseUrl}/api/health`);
    const payload = await response.json();
    assert.equal(response.status, 200);
    assert.equal(payload.ok, true);
    assert.equal(payload.deploymentMode, "single-instance");
    assert.equal(payload.rateLimit.backend, "in-memory");
    assert.equal(payload.rateLimit.distributed, false);
    assert.equal(payload.rateLimit.requester.maxRequests, 30);
    assert.equal(payload.rateLimit.target.maxRequests, 10);
    assert.equal(payload.abuseAlerting.threshold, 25);
    assert.equal(payload.scanTimeoutMs, 45000);
    assert.equal(payload.deepPassiveScanTimeoutMs, 75000);
    assert.equal(payload.scanScheduler.concurrency, 2);
    assert.equal(payload.scanScheduler.staleRunningScanMs, 120000);
  } finally {
    await server.stop();
  }
});

test("health endpoint returns minimal readiness data in production mode", async () => {
  const server = await startServer({
    NODE_ENV: "production",
    API_KEY: "test-secret",
    DEPLOYMENT_MODE: "single-instance",
  });

  try {
    const response = await fetch(`${server.baseUrl}/api/health`);
    const payload = await response.json();
    assert.equal(response.status, 200);
    assert.equal(payload.ok, true);
    assert.ok(payload.now);
    assert.equal("deploymentMode" in payload, false);
    assert.equal("rateLimit" in payload, false);
    assert.equal("abuseAlerting" in payload, false);
  } finally {
    await server.stop();
  }
});

test("health endpoint rejects unsupported methods", async () => {
  const server = await startServer();

  try {
    const response = await fetch(`${server.baseUrl}/api/health`, {
      method: "POST",
    });
    const payload = await response.json();
    assert.equal(response.status, 405);
    assert.equal(response.headers.get("allow"), "GET, OPTIONS");
    assert.match(payload.error, /Method not allowed/i);
  } finally {
    await server.stop();
  }
});

test("readiness endpoint reports storage availability", async () => {
  const server = await startServer();

  try {
    const response = await fetch(`${server.baseUrl}/api/ready`);
    const payload = await response.json();
    assert.equal(response.status, 200);
    assert.equal(payload.ok, true);
    assert.ok(payload.now);
    assert.equal(payload.storage.backend, "memory");
    assert.equal(payload.storage.available, true);
  } finally {
    await server.stop();
  }
});

test("capabilities endpoint exposes additive client feature metadata", async () => {
  const server = await startServer({
    MONITORING_SCHEDULER_ENABLED: "true",
    MONITORING_SWEEP_INTERVAL_MS: "60000",
  });

  try {
    const response = await fetch(`${server.baseUrl}/api/capabilities`);
    const payload = await response.json();
    assert.equal(response.status, 200);
    assert.equal(payload.apiVersion, "2026-05-14");
    assert.equal(payload.service.name, "SecURL API");
    assert.equal(payload.service.corePackage, "securl");
    assert.match(payload.service.coreVersion, /^\d+\.\d+\.\d+/);
    assert.ok(payload.service.resources.includes("GET /api/ready"));
    assert.ok(payload.service.resources.includes("GET /api/certificates/live?url=:url"));
    assert.deepEqual(payload.service.clientTelemetry.headers, {
      client: "X-SecURL-Client",
      version: "X-SecURL-Client-Version",
    });
    assert.equal(payload.service.clientTelemetry.optional, true);
    assert.equal(payload.service.clientTelemetry.privacySafe, true);
    assert.deepEqual(payload.scans.modes, ["standard", "quiet", "deep-passive"]);
    assert.ok(payload.scans.features.includes("finding-evidence"));
    assert.ok(payload.scans.features.includes("evidence-summary"));
    assert.ok(payload.scans.features.includes("remediation-plan"));
    assert.ok(payload.scans.features.includes("posture-insights"));
    assert.ok(payload.scans.features.includes("mobile-scan-summary"));
    assert.ok(payload.scans.features.includes("exposure-brief"));
    assert.ok(payload.scans.features.includes("vendor-exposure"));
    assert.ok(payload.scans.features.includes("action-plan"));
    assert.ok(payload.scans.features.includes("scan-events"));
    assert.ok(payload.scans.features.includes("scan-resource-links"));
    assert.ok(payload.scans.features.includes("durable-scan-jobs"));
    assert.ok(payload.scans.features.includes("observation-ledger-v1"));
    assert.ok(payload.scans.features.includes("observation-drift-v1"));
    assert.ok(payload.scans.features.includes("observation-policy-v1"));
    assert.equal(payload.scans.scoring.model, "weighted-passive-posture");
    assert.equal(payload.scans.scoring.version, "2026-06-14");
    assert.deepEqual(payload.scans.scoring.scoreRange, { min: 0, max: 100 });
    assert.equal(payload.scans.maxDurationMs.standard, 45000);
    assert.equal(payload.scans.maxDurationMs.deepPassive, 75000);
    assert.equal(payload.scans.policy.defaultId, "securl-baseline-v1");
    assert.equal(payload.scans.policy.maxRules, 25);
    assert.ok(payload.auth.resources.includes("GET /api/auth/api-keys"));
    assert.ok(payload.auth.resources.includes("DELETE /api/auth/api-keys/:id"));
    assert.ok(payload.scans.resources.includes("GET /api/scans/:id/digest"));
    assert.ok(payload.scans.resources.includes("GET /api/scans/:id/insights"));
    assert.ok(payload.scans.resources.includes("GET /api/scans/:id/mobile-summary"));
    assert.ok(payload.scans.resources.includes("GET /api/scans/:id/brief"));
    assert.ok(payload.scans.resources.includes("GET /api/scans/:id/vendors"));
    assert.ok(payload.scans.resources.includes("GET /api/scans/:id/action-plan"));
    assert.ok(payload.scans.resources.includes("GET /api/scans/:id/observations"));
    assert.ok(payload.scans.resources.includes("GET /api/scans/:id/observation-drift"));
    assert.ok(payload.scans.resources.includes("GET /api/scans/:id/policy-evaluation"));
    assert.ok(payload.scans.resources.includes("GET /api/scans/:id/events"));
    assert.ok(payload.scans.resources.includes("GET /api/scans/:id/comparison"));
    assert.ok(payload.scans.resources.includes("GET /api/scans/:id/drift"));
    assert.ok(payload.scans.resources.includes("GET /api/scans/:id/export?format=json|markdown|sarif|ci-json"));
    assert.equal(payload.monitoring.enabled, true);
    assert.equal(payload.monitoring.scheduler.enabled, true);
    assert.equal(payload.monitoring.scheduler.mode, "quiet");
    assert.equal(payload.monitoring.scheduler.intervalMs, 60000);
    assert.equal(typeof payload.monitoring.scheduler.lastSweep.checked, "number");
    assert.equal(typeof payload.monitoring.scheduler.lastSweep.failed, "number");
    assert.ok(payload.monitoring.features.includes("mobile-posture-drift-summary"));
    assert.ok(payload.monitoring.features.includes("mobile-digest-preview"));
    assert.ok(payload.monitoring.features.includes("cert-attention-state"));
    assert.ok(payload.monitoring.features.includes("target-observation-policy"));
    assert.ok(payload.monitoring.resources.includes("GET /api/monitoring-summary"));
    assert.ok(payload.monitoring.resources.includes("GET /api/monitoring-mobile-summary"));
    assert.ok(payload.monitoring.resources.includes("POST /api/monitoring-targets/:id/run"));
    assert.ok(payload.certificates.resources.includes("GET /api/certificates/live?url=:url"));
    assert.ok(payload.certificates.features.includes("live-certificate"));
    assert.ok(payload.certificates.features.includes("cert-attention-state"));
    assert.ok(payload.notifications.features.includes("device-health"));
    assert.ok(payload.notifications.features.includes("delivery-audit"));
    assert.ok(payload.notifications.features.includes("test-notification"));
    assert.ok(payload.notifications.features.includes("bounded-delivery-retry"));
    assert.ok(payload.notifications.features.includes("durable-notification-outbox"));
    assert.ok(payload.notifications.resources.includes("GET /api/notification-devices/health"));
    assert.ok(payload.notifications.resources.includes("POST /api/notification-devices"));
    assert.ok(payload.notifications.resources.includes("POST /api/notification-devices/:id/test"));
    assert.equal(payload.alerts.enabled, true);
    assert.ok(payload.alerts.features.includes("policy-violation-alerts"));
    assert.ok(payload.alerts.features.includes("policy-alert-brief-v1"));
    assert.ok(payload.alerts.features.includes("policy-alert-actions-v1"));
    assert.ok(payload.alerts.features.includes("durable-alert-outbox"));
    assert.ok(payload.alerts.features.includes("signed-webhooks"));
    assert.ok(payload.alerts.resources.includes("POST /api/alert-destinations/:id/test"));
    assert.equal(payload.alerts.channels.webhook, true);
    assert.equal(payload.alerts.channels.email, false);
    assert.equal(payload.notifications.delivery.timeoutMs, 10000);
    assert.equal(payload.notifications.delivery.maxAttempts, 3);
    assert.ok(payload.notifications.delivery.invalidTokenReasons.includes("BadDeviceToken"));
    assert.ok(payload.notifications.delivery.retries.includes("apns_5xx"));
    assert.equal(payload.notifications.outbox.enabled, true);
    assert.equal(payload.notifications.enabled, false);
    assert.equal(payload.safety.passiveFirst, true);
  } finally {
    await server.stop();
  }
});

test("live certificate endpoint validates HTTPS targets before doing a cheap TLS read", async () => {
  const server = await startServer();

  try {
    const missingOwnerResponse = await fetch(`${server.baseUrl}/api/certificates/live?url=https://example.com`);
    const missingOwnerPayload = await missingOwnerResponse.json();
    assert.equal(missingOwnerResponse.status, 401);
    assert.match(missingOwnerPayload.error, /scan owner token/i);

    const httpResponse = await fetch(`${server.baseUrl}/api/certificates/live?url=http://example.com`, {
      headers: scanOwnerHeaders(),
    });
    const httpPayload = await httpResponse.json();
    assert.equal(httpResponse.status, 400);
    assert.match(httpPayload.error, /HTTPS URL/i);
  } finally {
    await server.stop();
  }
});

test("capabilities endpoint is public in production mode", async () => {
  const server = await startServer({
    NODE_ENV: "production",
    API_KEY: "test-secret",
    DEPLOYMENT_MODE: "single-instance",
  });

  try {
    const response = await fetch(`${server.baseUrl}/api/capabilities`);
    const payload = await response.json();
    assert.equal(response.status, 200);
    assert.equal(payload.apiVersion, "2026-05-14");
    assert.equal(payload.auth.methods.includes("api-key"), true);
    assert.equal(payload.auth.anonymousScanOwner, false);
  } finally {
    await server.stop();
  }
});

test("telemetry endpoint returns aggregate page-load and failure counters", async () => {
  const server = await startServer();

  try {
    const pageResponse = await fetch(server.baseUrl, {
      headers: {
        "User-Agent": "TelemetryTest/1.0",
      },
    });
    assert.equal(pageResponse.status, 200);
    const secondPageResponse = await fetch(server.baseUrl, {
      headers: {
        "User-Agent": "TelemetryTest/1.0",
      },
    });
    assert.equal(secondPageResponse.status, 200);

    const badScan = await postScan(server.baseUrl, "https://user:pass@example.com");
    assert.equal(badScan.status, 400);

    const telemetryResponse = await fetch(`${server.baseUrl}/api/telemetry`);
    const payload = await telemetryResponse.json();

    assert.equal(telemetryResponse.status, 200);
    assert.equal(payload.persistence, "memory");
    assert.equal(payload.pageLoads, 2);
    assert.equal(payload.visitors.unique, 1);
    assert.equal(payload.visitors.totalPageLoads, 2);
    assert.equal(payload.visitors.today.pageLoads >= 2, true);
    assert.equal(payload.visitors.today.uniqueVisitors >= 1, true);
    assert.equal(payload.trafficSources.pageLoads.direct, 2);
    assert.equal(payload.scans.requested, 0);
    assert.equal(payload.scans.completed, 0);
    assert.equal(payload.failures.classes.invalid_target_credentials, 1);
  } finally {
    await server.stop();
  }
});

test("telemetry endpoint separates scan engagement from raw scan volume", async () => {
  const server = await startServer();

  try {
    const scanResponse = await postScan(server.baseUrl, "https://example.com", {
      headers: {
        Referer: "https://securl.online/",
        "User-Agent": "TelemetryScanTest/1.0",
      },
    });
    const scanPayload = await scanResponse.json();
    assert.equal(scanResponse.status, 202);
    await waitForScanTerminal(server.baseUrl, scanPayload.scan.id);

    const telemetryResponse = await fetch(`${server.baseUrl}/api/telemetry`);
    const payload = await telemetryResponse.json();

    assert.equal(telemetryResponse.status, 200);
    assert.equal(payload.scans.requested, 1);
    assert.equal(payload.scans.completed, 1);
    assert.equal(payload.scans.engagement.uniqueRequesters, 1);
    assert.equal(payload.scans.engagement.uniqueClients, 1);
    assert.equal(payload.scans.engagement.uniqueTargets, 1);
    assert.equal(Object.values(payload.scans.engagement.sources).reduce((sum, count) => sum + count, 0), 1);
    assert.equal(payload.scans.engagement.channels.browser_owner, 1);
    assert.equal(payload.scans.engagement.repeatTargets[0].target, "https://example.com");
    assert.equal(payload.scans.engagement.recent[0].target, "https://example.com");
    assert.equal(payload.scans.engagement.recent[0].channel, "browser_owner");
  } finally {
    await server.stop();
  }
});

test("telemetry endpoint rejects unsupported methods", async () => {
  const server = await startServer();

  try {
    const response = await fetch(`${server.baseUrl}/api/telemetry`, {
      method: "POST",
    });
    const payload = await response.json();
    assert.equal(response.status, 405);
    assert.equal(response.headers.get("allow"), "GET, OPTIONS");
    assert.match(payload.error, /Method not allowed/i);
  } finally {
    await server.stop();
  }
});

test("telemetry page-load tracking works when trusted proxy mode is enabled", async () => {
  const server = await startServer({
    TRUST_PROXY: "true",
  });

  try {
    const pageResponse = await fetch(server.baseUrl, {
      headers: {
        "User-Agent": "TelemetryProxyTest/1.0",
        "X-Forwarded-For": "203.0.113.10",
      },
    });
    assert.equal(pageResponse.status, 200);

    const telemetryResponse = await fetch(`${server.baseUrl}/api/telemetry`);
    const payload = await telemetryResponse.json();

    assert.equal(telemetryResponse.status, 200);
    assert.equal(payload.visitors.totalPageLoads, 1);
    assert.equal(payload.visitors.unique, 1);
  } finally {
    await server.stop();
  }
});

test("telemetry page-load beacon records Hostinger frontend visits", async () => {
  const server = await startServer({
    TRUST_PROXY: "true",
  });

  try {
    const beaconResponse = await fetch(`${server.baseUrl}/api/telemetry/page-load`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Origin: "https://app.securl.online",
        "User-Agent": "TelemetryBeaconTest/1.0",
        "X-Forwarded-For": "203.0.113.20",
      },
      body: JSON.stringify({
        referrer: "https://news.ycombinator.com/item?id=123",
        currentUrl: "https://app.securl.online/",
      }),
    });
    assert.equal(beaconResponse.status, 202);
    assert.equal(beaconResponse.headers.get("access-control-allow-origin"), "https://app.securl.online");

    const telemetryResponse = await fetch(`${server.baseUrl}/api/telemetry`);
    const payload = await telemetryResponse.json();

    assert.equal(payload.visitors.totalPageLoads, 1);
    assert.equal(payload.visitors.unique, 1);
    assert.equal(payload.trafficSources.pageLoads.hacker_news, 1);
  } finally {
    await server.stop();
  }
});

test("telemetry event beacon records funnel events", async () => {
  const server = await startServer({
    TRUST_PROXY: "true",
  });

  try {
    const eventResponse = await fetch(`${server.baseUrl}/api/telemetry/event`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Origin: "https://app.securl.online",
        "User-Agent": "TelemetryEventTest/1.0",
        "X-Forwarded-For": "203.0.113.21",
      },
      body: JSON.stringify({
        event: "share_link_copied",
        referrer: "https://github.com/ktbatterham/external-posture-insight",
        currentUrl: "https://app.securl.online/?utm_source=launch",
        target: "https://example.com/",
        scanId: "scan-one",
      }),
    });
    assert.equal(eventResponse.status, 202);
    assert.equal(eventResponse.headers.get("access-control-allow-origin"), "https://app.securl.online");

    const telemetryResponse = await fetch(`${server.baseUrl}/api/telemetry`);
    const payload = await telemetryResponse.json();

    assert.equal(payload.funnel.events.share_link_copied, 1);
    assert.equal(payload.funnel.bySource["utm:launch"].share_link_copied, 1);
    assert.equal(payload.funnel.recent[0].scanId, "scan-one");

    const handoffResponse = await fetch(`${server.baseUrl}/api/telemetry/event`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Origin: "https://app.securl.online",
      },
      body: JSON.stringify({
        event: "handoff_started",
        currentUrl: "https://securl.online/?utm_source=landing",
        target: "https://example.com/",
      }),
    });
    assert.equal(handoffResponse.status, 202);

    const updatedTelemetryResponse = await fetch(`${server.baseUrl}/api/telemetry`);
    const updatedPayload = await updatedTelemetryResponse.json();
    assert.equal(updatedPayload.funnel.events.handoff_started, 1);
    assert.equal(updatedPayload.funnel.bySource["utm:landing"].handoff_started, 1);

    const invalidResponse = await fetch(`${server.baseUrl}/api/telemetry/event`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Origin: "https://app.securl.online",
      },
      body: JSON.stringify({
        event: "unexpected_event",
      }),
    });
    assert.equal(invalidResponse.status, 400);
  } finally {
    await server.stop();
  }
});

test("telemetry endpoint is hidden by default in production", async () => {
  const server = await startServer({
    NODE_ENV: "production",
    API_KEY: "test-secret",
  });

  try {
    const telemetryResponse = await fetch(`${server.baseUrl}/api/telemetry`);
    const payload = await telemetryResponse.json();

    assert.equal(telemetryResponse.status, 404);
    assert.match(payload.error, /not available/i);
  } finally {
    await server.stop();
  }
});

test("telemetry endpoint requires an admin token when exposed in production", async () => {
  const server = await startServer({
    NODE_ENV: "production",
    API_KEY: "test-secret",
    EXPOSE_TELEMETRY: "true",
    TELEMETRY_TOKEN: "telemetry-secret",
  });

  try {
    const unauthenticatedResponse = await fetch(`${server.baseUrl}/api/telemetry`);
    const unauthenticatedPayload = await unauthenticatedResponse.json();
    assert.equal(unauthenticatedResponse.status, 404);
    assert.match(unauthenticatedPayload.error, /not available/i);

    const authenticatedResponse = await fetch(`${server.baseUrl}/api/telemetry`, {
      headers: {
        Authorization: "Bearer telemetry-secret",
      },
    });
    const authenticatedPayload = await authenticatedResponse.json();
    assert.equal(authenticatedResponse.status, 200);
    assert.equal(authenticatedPayload.persistence, "memory");
    assert.ok(authenticatedPayload.visitors);
  } finally {
    await server.stop();
  }
});

test("api preflight allows the Hostinger frontend origins", async () => {
  const server = await startServer();

  try {
    for (const origin of ["https://app.securl.online", "https://securl.online"]) {
      const response = await fetch(`${server.baseUrl}/api/scans`, {
        method: "OPTIONS",
        headers: {
          Origin: origin,
          "Access-Control-Request-Method": "POST",
          "Access-Control-Request-Headers": "content-type,x-scan-owner,authorization",
        },
      });

      assert.equal(response.status, 204);
      assert.equal(response.headers.get("access-control-allow-origin"), origin);
      assert.match(response.headers.get("access-control-allow-methods") || "", /POST/);
      assert.match(response.headers.get("access-control-allow-methods") || "", /DELETE/);
      assert.match(response.headers.get("access-control-allow-headers") || "", /X-Scan-Owner/i);
      assert.match(response.headers.get("access-control-allow-headers") || "", /X-SecURL-Client/i);
      assert.match(response.headers.get("access-control-allow-headers") || "", /X-SecURL-Client-Version/i);
      assert.match(response.headers.get("access-control-allow-headers") || "", /Authorization/i);
    }
  } finally {
    await server.stop();
  }
});

test("auth register, session, login, and logout flow works", async () => {
  const server = await startServer();

  try {
    const registerResponse = await registerUser(server.baseUrl, {
      email: "keith@example.com",
      password: "correct horse battery staple",
      displayName: "Keith",
    });
    const registerPayload = await registerResponse.json();
    assert.equal(registerResponse.status, 201);
    assert.equal(registerPayload.user.email, "keith@example.com");
    assert.ok(registerPayload.session.token);

    const sessionResponse = await fetch(`${server.baseUrl}/api/auth/session`, {
      headers: bearerHeaders(registerPayload.session.token),
    });
    const sessionPayload = await sessionResponse.json();
    assert.equal(sessionResponse.status, 200);
    assert.equal(sessionPayload.authenticated, true);
    assert.equal(sessionPayload.user.email, "keith@example.com");

    const logoutResponse = await fetch(`${server.baseUrl}/api/auth/logout`, {
      method: "POST",
      headers: bearerHeaders(registerPayload.session.token),
    });
    const logoutPayload = await logoutResponse.json();
    assert.equal(logoutResponse.status, 200);
    assert.equal(logoutPayload.ok, true);

    const loggedOutSession = await fetch(`${server.baseUrl}/api/auth/session`, {
      headers: bearerHeaders(registerPayload.session.token),
    });
    const loggedOutPayload = await loggedOutSession.json();
    assert.equal(loggedOutSession.status, 401);
    assert.match(loggedOutPayload.error, /invalid or expired/i);

    const loginResponse = await loginUser(server.baseUrl, {
      email: "keith@example.com",
      password: "correct horse battery staple",
    });
    const loginPayload = await loginResponse.json();
    assert.equal(loginResponse.status, 200);
    assert.ok(loginPayload.session.token);
  } finally {
    await server.stop();
  }
});

test("auth registration does not reveal whether an email already exists", async () => {
  const server = await startServer();

  try {
    const firstResponse = await registerUser(server.baseUrl, {
      email: "repeat@example.com",
      password: "correct horse battery staple",
    });
    assert.equal(firstResponse.status, 201);

    const secondResponse = await registerUser(server.baseUrl, {
      email: "repeat@example.com",
      password: "correct horse battery staple",
    });
    const secondPayload = await secondResponse.json();
    assert.equal(secondResponse.status, 400);
    assert.equal(secondPayload.error, "Unable to create an account with those credentials.");
  } finally {
    await server.stop();
  }
});

test("auth attempts are rate limited", async () => {
  const server = await startServer({
    AUTH_RATE_LIMIT_MAX_REQUESTS: "1",
    AUTH_RATE_LIMIT_WINDOW_MS: "60000",
  });

  try {
    const firstResponse = await loginUser(server.baseUrl, {
      email: "nobody@example.com",
      password: "correct horse battery staple",
    });
    const firstPayload = await firstResponse.json();
    assert.equal(firstResponse.status, 401);
    assert.match(firstPayload.error, /incorrect/i);

    const secondResponse = await loginUser(server.baseUrl, {
      email: "nobody@example.com",
      password: "correct horse battery staple",
    });
    const secondPayload = await secondResponse.json();
    assert.equal(secondResponse.status, 429);
    assert.match(secondPayload.error, /too many authentication attempts/i);
  } finally {
    await server.stop();
  }
});

test("authenticated sessions can own scan and monitoring resources without scan-owner headers", async () => {
  const server = await startServer();

  try {
    const registerResponse = await registerUser(server.baseUrl, {
      email: "owner@example.com",
      password: "very strong password",
    });
    const registerPayload = await registerResponse.json();
    const token = registerPayload.session.token;

    const scanResponse = await fetch(`${server.baseUrl}/api/scans`, {
      method: "POST",
      headers: bearerJsonHeaders(token),
      body: JSON.stringify({
        url: "https://example.com",
      }),
    });
    const scanPayload = await scanResponse.json();
    assert.equal(scanResponse.status, 202);
    assert.match(scanPayload.scan.id, /[a-f0-9-]{36}/i);
    assert.equal(scanPayload.resources.events, `/api/scans/${scanPayload.scan.id}/events`);
    assert.equal(scanPayload.resources.digest, `/api/scans/${scanPayload.scan.id}/digest`);
    assert.equal(scanPayload.resources.insights, `/api/scans/${scanPayload.scan.id}/insights`);
    assert.equal(scanPayload.resources.mobileSummary, `/api/scans/${scanPayload.scan.id}/mobile-summary`);

    const listResponse = await fetch(`${server.baseUrl}/api/scans`, {
      headers: bearerHeaders(token),
    });
    const listPayload = await listResponse.json();
    assert.equal(listResponse.status, 200);
    assert.equal(listPayload.scans.length, 1);

    const monitoringResponse = await fetch(`${server.baseUrl}/api/monitoring-targets`, {
      method: "POST",
      headers: bearerJsonHeaders(token),
      body: JSON.stringify({
        url: "https://example.com",
        cadence: "daily",
      }),
    });
    const monitoringPayload = await monitoringResponse.json();
    assert.equal(monitoringResponse.status, 201);
    assert.equal(monitoringPayload.apiVersion, "2026-05-14");
    assert.equal(monitoringPayload.target.ownerId, undefined);
    assert.equal(monitoringPayload.target.requesterScope, undefined);
  } finally {
    await server.stop();
  }
});

test("authenticated users can create, use, list, and revoke API keys", async () => {
  const server = await startServer();

  try {
    const registerResponse = await registerUser(server.baseUrl, {
      email: "apikey@example.com",
      password: "very strong password",
    });
    const registerPayload = await registerResponse.json();
    const sessionToken = registerPayload.session.token;

    const createKeyResponse = await fetch(`${server.baseUrl}/api/auth/api-keys`, {
      method: "POST",
      headers: bearerJsonHeaders(sessionToken),
      body: JSON.stringify({ name: "Local CLI" }),
    });
    const createKeyPayload = await createKeyResponse.json();
    assert.equal(createKeyResponse.status, 201);
    assert.equal(createKeyPayload.apiKey.name, "Local CLI");
    assert.match(createKeyPayload.token, /^securl_/);
    assert.ok(!createKeyPayload.apiKey.tokenHash);
    assert.deepEqual(createKeyPayload.apiKey.usage, {
      scansRequested: 0,
      scansCompleted: 0,
      scansFailed: 0,
      scansQueued: 0,
      scansRunning: 0,
      fullReads: 0,
      limitedReads: 0,
      latestScanAt: null,
      latestScanId: null,
      latestTarget: null,
    });

    const listKeysResponse = await fetch(`${server.baseUrl}/api/auth/api-keys`, {
      headers: bearerHeaders(sessionToken),
    });
    const listKeysPayload = await listKeysResponse.json();
    assert.equal(listKeysResponse.status, 200);
    assert.equal(listKeysPayload.apiKeys.length, 1);
    assert.equal(listKeysPayload.apiKeys[0].id, createKeyPayload.apiKey.id);
    assert.ok(!("token" in listKeysPayload.apiKeys[0]));
    assert.equal(listKeysPayload.apiKeys[0].usage.scansRequested, 0);

    const scanResponse = await fetch(`${server.baseUrl}/api/scans`, {
      method: "POST",
      headers: bearerJsonHeaders(createKeyPayload.token),
      body: JSON.stringify({
        url: "https://example.com",
      }),
    });
    const scanPayload = await scanResponse.json();
    assert.equal(scanResponse.status, 202);
    assert.match(scanPayload.scan.id, /[a-f0-9-]{36}/i);

    const listScansResponse = await fetch(`${server.baseUrl}/api/scans`, {
      headers: bearerHeaders(createKeyPayload.token),
    });
    const listScansPayload = await listScansResponse.json();
    assert.equal(listScansResponse.status, 200);
    assert.equal(listScansPayload.scans.length, 1);
    assert.equal(listScansPayload.scans[0].id, scanPayload.scan.id);

    const usedKeysResponse = await fetch(`${server.baseUrl}/api/auth/api-keys`, {
      headers: bearerHeaders(sessionToken),
    });
    const usedKeysPayload = await usedKeysResponse.json();
    assert.equal(usedKeysResponse.status, 200);
    const usage = usedKeysPayload.apiKeys[0].usage;
    assert.equal(usage.scansRequested, 1);
    assert.equal(
      usage.scansQueued + usage.scansRunning + usage.scansCompleted + usage.scansFailed,
      1,
    );
    assert.equal(usage.latestScanId, scanPayload.scan.id);
    assert.equal(usage.latestTarget, "https://example.com/");

    const revokeResponse = await fetch(`${server.baseUrl}/api/auth/api-keys/${createKeyPayload.apiKey.id}`, {
      method: "DELETE",
      headers: bearerHeaders(sessionToken),
    });
    const revokePayload = await revokeResponse.json();
    assert.equal(revokeResponse.status, 200);
    assert.equal(revokePayload.ok, true);

    const revokedListResponse = await fetch(`${server.baseUrl}/api/scans`, {
      headers: bearerHeaders(createKeyPayload.token),
    });
    const revokedListPayload = await revokedListResponse.json();
    assert.equal(revokedListResponse.status, 401);
    assert.match(revokedListPayload.error, /valid/i);
  } finally {
    await server.stop();
  }
});

test("api responses include cors headers for the Hostinger frontend origin", async () => {
  const server = await startServer();

  try {
    const response = await fetch(`${server.baseUrl}/api/scans`, {
      headers: {
        Origin: "https://app.securl.online",
      },
    });
    const payload = await response.json();

    assert.equal(response.status, 401);
    assert.equal(response.headers.get("access-control-allow-origin"), "https://app.securl.online");
    assert.match(payload.error, /owner token/i);
  } finally {
    await server.stop();
  }
});

test("development API accepts the configured Vite origin", async () => {
  const server = await startServer();

  try {
    const response = await fetch(`${server.baseUrl}/api/scans`, {
      headers: {
        Origin: "http://localhost:8080",
      },
    });
    const payload = await response.json();

    assert.equal(response.status, 401);
    assert.equal(response.headers.get("access-control-allow-origin"), "http://localhost:8080");
    assert.match(payload.error, /owner token/i);
  } finally {
    await server.stop();
  }
});

test("api rejects unexpected origins", async () => {
  const server = await startServer();

  try {
    const response = await fetch(`${server.baseUrl}/api/scans`, {
      headers: {
        Origin: "https://evil.example",
      },
    });
    const payload = await response.json();

    assert.equal(response.status, 403);
    assert.equal(response.headers.get("access-control-allow-origin"), null);
    assert.match(payload.error, /Origin is not allowed/i);
  } finally {
    await server.stop();
  }
});

test("scan resources start empty and return 404 for unknown ids", async () => {
  const server = await startServer();

  try {
    const listResponse = await fetch(`${server.baseUrl}/api/scans`, {
      headers: scanOwnerHeaders(),
    });
    const listPayload = await listResponse.json();

    assert.equal(listResponse.status, 200);
    assert.deepEqual(listPayload.scans, []);

    const missingResponse = await fetch(`${server.baseUrl}/api/scans/not-a-real-scan`, {
      headers: scanOwnerHeaders(),
    });
    const missingPayload = await missingResponse.json();

    assert.equal(missingResponse.status, 404);
    assert.match(missingPayload.error, /Scan not found/i);
  } finally {
    await server.stop();
  }
});

test("notification devices can be registered, listed, and disabled without echoing raw APNs tokens", async () => {
  const server = await startServer();
  const apnsToken = "a".repeat(64);

  try {
    const invalidResponse = await fetch(`${server.baseUrl}/api/notification-devices`, {
      method: "POST",
      headers: scanOwnerJsonHeaders(),
      body: JSON.stringify({ apnsToken: "not-a-token" }),
    });
    const invalidPayload = await invalidResponse.json();
    assert.equal(invalidResponse.status, 400);
    assert.match(invalidPayload.error, /APNs device token/i);

    const createResponse = await fetch(`${server.baseUrl}/api/notification-devices`, {
      method: "POST",
      headers: {
        ...scanOwnerJsonHeaders(),
        "X-SecURL-Client": "securl-ios",
        "X-SecURL-Client-Version": "1.2.0+19",
      },
      body: JSON.stringify({
        apnsToken,
        platform: "ios",
        environment: "sandbox",
        appId: "online.securl.app",
      }),
    });
    const createPayload = await createResponse.json();
    assert.equal(createResponse.status, 201);
    assert.equal(createPayload.apiVersion, "2026-05-14");
    assert.equal(createPayload.device.token, undefined);
    assert.equal(createPayload.device.tokenPrefix, "aaaaaaaa...");
    assert.equal(createPayload.device.environment, "sandbox");

    const testResponse = await fetch(`${server.baseUrl}/api/notification-devices/${createPayload.device.id}/test`, {
      method: "POST",
      headers: {
        ...scanOwnerJsonHeaders(),
        "X-SecURL-Client": "securl-ios",
        "X-SecURL-Client-Version": "1.2.0+19",
      },
    });
    const testPayload = await testResponse.json();
    assert.equal(testResponse.status, 503);
    assert.equal(testPayload.delivered, false);
    assert.equal(testPayload.delivery.skipped, "apns_not_configured");

    const wrongOwnerTestResponse = await fetch(`${server.baseUrl}/api/notification-devices/${createPayload.device.id}/test`, {
      method: "POST",
      headers: scanOwnerJsonHeaders(SCAN_OWNER_TWO),
    });
    assert.equal(wrongOwnerTestResponse.status, 404);

    const listResponse = await fetch(`${server.baseUrl}/api/notification-devices`, {
      headers: scanOwnerHeaders(),
    });
    const listPayload = await listResponse.json();
    assert.equal(listResponse.status, 200);
    assert.equal(listPayload.devices.length, 1);
    assert.equal(listPayload.devices[0].token, undefined);
    assert.equal(listPayload.devices[0].lastPushStatus, null);

    const healthResponse = await fetch(`${server.baseUrl}/api/notification-devices/health`, {
      headers: {
        ...scanOwnerHeaders(),
        "X-SecURL-Client": "securl-ios",
        "X-SecURL-Client-Version": "1.2.0+19",
      },
    });
    const healthPayload = await healthResponse.json();
    assert.equal(healthResponse.status, 200);
    assert.equal(healthPayload.health.registeredDevices, 1);
    assert.equal(healthPayload.health.activeDevices, 1);
    assert.equal(healthPayload.health.readyDevices, 1);
    assert.equal(healthPayload.health.staleDevices, 0);
    assert.equal(healthPayload.health.devicesNeedingRegistration, 0);
    assert.equal(healthPayload.health.byStatus.ready, 1);
    assert.equal(healthPayload.health.staleAfterDays, 30);
    assert.equal(healthPayload.health.byAppId["online.securl.app"], 1);
    assert.equal(healthPayload.devices[0].status, "ready");
    assert.equal(healthPayload.devices[0].stale, false);
    assert.equal(healthPayload.devices[0].needsRegistration, false);
    assert.equal(healthPayload.devices[0].lastPushStatus, null);

    const telemetryResponse = await fetch(`${server.baseUrl}/api/telemetry`);
    const telemetryPayload = await telemetryResponse.json();
    assert.equal(telemetryPayload.funnel.events.notification_device_registered, 1);
    assert.equal(telemetryPayload.funnel.events.notification_device_health_read, 1);
    assert.equal(telemetryPayload.funnel.events.notification_test_requested, 1);
    assert.equal(telemetryPayload.funnel.byClient["securl-ios"].notification_device_registered, 1);
    assert.equal(telemetryPayload.funnel.byClient["securl-ios"].notification_device_health_read, 1);
    assert.equal(
      telemetryPayload.clients.identity.backendEventsByClientVersion["securl-ios@1.2.0+19"].notification_device_registered,
      1,
    );
    assert.equal(telemetryPayload.notifications.delivery.batches, 1);
    assert.equal(telemetryPayload.notifications.delivery.skipped.apns_not_configured, 1);
    assert.equal(telemetryPayload.notifications.delivery.byChannel.device_test.batches, 1);

    const deleteResponse = await fetch(`${server.baseUrl}/api/notification-devices/${createPayload.device.id}`, {
      method: "DELETE",
      headers: scanOwnerHeaders(),
    });
    const deletePayload = await deleteResponse.json();
    assert.equal(deleteResponse.status, 200);
    assert.equal(deletePayload.deleted, true);
  } finally {
    await server.stop();
  }
});

test("alert destinations can be registered, tested, listed, and disabled without exposing secrets", async () => {
  const server = await startServer();
  try {
    const anonymousResponse = await fetch(`${server.baseUrl}/api/alert-destinations`, {
      headers: scanOwnerHeaders(SCAN_OWNER_ONE),
    });
    assert.equal(anonymousResponse.status, 403);
    const registration = await registerUser(server.baseUrl, {
      email: "alerts@example.com",
      password: "correct horse battery staple",
    });
    const token = (await registration.json()).session.token;
    const createResponse = await fetch(`${server.baseUrl}/api/alert-destinations`, {
      method: "POST",
      headers: { ...bearerHeaders(token), "Content-Type": "application/json" },
      body: JSON.stringify({ type: "email", label: "Security inbox", email: "security@example.com" }),
    });
    const created = await createResponse.json();
    assert.equal(createResponse.status, 201);
    assert.equal(created.destination.type, "email");
    assert.equal(created.destination.emailHint, "s***@example.com");
    assert.equal(created.destination.email, undefined);
    assert.equal(created.destination.signingSecret, undefined);

    const listResponse = await fetch(`${server.baseUrl}/api/alert-destinations`, {
      headers: bearerHeaders(token),
    });
    const listed = await listResponse.json();
    assert.equal(listResponse.status, 200);
    assert.equal(listed.destinations.length, 1);
    assert.equal(listed.destinations[0].emailHint, "s***@example.com");

    const testResponse = await fetch(`${server.baseUrl}/api/alert-destinations/${created.destination.id}/test`, {
      method: "POST",
      headers: bearerHeaders(token),
    });
    const tested = await testResponse.json();
    assert.equal(testResponse.status, 202);
    assert.equal(tested.result.queued, 1);

    const deleteResponse = await fetch(`${server.baseUrl}/api/alert-destinations/${created.destination.id}`, {
      method: "DELETE",
      headers: bearerHeaders(token),
    });
    assert.equal(deleteResponse.status, 200);
    const afterDelete = await fetch(`${server.baseUrl}/api/alert-destinations`, {
      headers: bearerHeaders(token),
    });
    assert.equal((await afterDelete.json()).destinations.length, 0);
  } finally {
    await server.stop();
  }
});

test("alert webhook destinations reject private and credential-bearing URLs", async () => {
  const server = await startServer();
  try {
    const registration = await registerUser(server.baseUrl, {
      email: "webhooks@example.com",
      password: "correct horse battery staple",
    });
    const token = (await registration.json()).session.token;
    for (const url of ["https://127.0.0.1/hook", "https://user:pass@example.com/hook"]) {
      const response = await fetch(`${server.baseUrl}/api/alert-destinations`, {
        method: "POST",
        headers: { ...bearerHeaders(token), "Content-Type": "application/json" },
        body: JSON.stringify({ type: "webhook", url }),
      });
      assert.equal(response.status, 400);
    }
  } finally {
    await server.stop();
  }
});

test("monitoring targets require the same browser owner token as scan resources", async () => {
  const server = await startServer();

  try {
    const missingOwnerResponse = await fetch(`${server.baseUrl}/api/monitoring-targets`);
    const missingOwnerPayload = await missingOwnerResponse.json();
    assert.equal(missingOwnerResponse.status, 401);
    assert.match(missingOwnerPayload.error, /scan owner token/i);

    const createResponse = await postMonitoringTarget(server.baseUrl, "https://example.com", {
      owner: SCAN_OWNER_ONE,
      cadence: "weekly",
    });
    assert.equal(createResponse.status, 201);
    const created = await createResponse.json();
    assert.equal(created.apiVersion, "2026-05-14");
    assert.equal(created.target.cadence, "weekly");

    const wrongOwnerListResponse = await fetch(`${server.baseUrl}/api/monitoring-targets`, {
      headers: scanOwnerHeaders(SCAN_OWNER_TWO),
    });
    const wrongOwnerListPayload = await wrongOwnerListResponse.json();
    assert.equal(wrongOwnerListResponse.status, 200);
    assert.equal(wrongOwnerListPayload.targets.length, 0);
  } finally {
    await server.stop();
  }
});

test("monitoring targets can be created, listed, and deleted", async () => {
  const server = await startServer();

  try {
    const policy = {
      id: "header-baseline",
      name: "Header baseline",
      version: "1",
      rules: [{
        id: "hsts",
        title: "HSTS required",
        severity: "critical",
        scope: "observation",
        selector: { kind: "http.header.strict-transport-security" },
        assertion: { field: "status", operator: "eq", value: "observed" },
        requireMatch: true,
      }],
    };
    const createResponse = await postMonitoringTarget(server.baseUrl, "https://example.com", {
      owner: SCAN_OWNER_ONE,
      cadence: "daily",
      label: "Example target",
      appId: "com.ktbatterham.headerwatch",
      policy,
      headers: {
        "X-SecURL-Client": "header-watch-ios",
        "X-SecURL-Client-Version": "1.1.0+7",
      },
    });
    const createPayload = await createResponse.json();
    assert.equal(createResponse.status, 201);
    assert.equal(createPayload.apiVersion, "2026-05-14");
    assert.equal(createPayload.target.url, "https://example.com/");
    assert.equal(createPayload.target.label, "Example target");
    assert.equal(createPayload.target.due, false);
    assert.equal(createPayload.target.latestScan, null);
    assert.equal(createPayload.target.ownerId, undefined);
    assert.equal(createPayload.target.requesterScope, undefined);
    assert.equal(createPayload.target.observationPolicy.id, policy.id);
    assert.equal(createPayload.target.observationPolicy.rules[0].id, "hsts");
    assert.equal(createPayload.target.observationPolicy.rules[0].enabled, true);

    const targetId = createPayload.target.id;
    const listResponse = await fetch(`${server.baseUrl}/api/monitoring-targets`, {
      headers: scanOwnerHeaders(SCAN_OWNER_ONE),
    });
    const listPayload = await listResponse.json();
    assert.equal(listResponse.status, 200);
    assert.equal(listPayload.targets.length, 1);
    assert.equal(listPayload.targets[0].id, targetId);
    assert.equal(listPayload.targets[0].ownerId, undefined);
    assert.equal(listPayload.targets[0].requesterScope, undefined);
    assert.equal(listPayload.targets[0].observationPolicy.id, "header-baseline");

    const mobileSummaryResponse = await fetch(`${server.baseUrl}/api/monitoring-mobile-summary`, {
      headers: {
        ...scanOwnerHeaders(SCAN_OWNER_ONE),
        "X-SecURL-Client": "header-watch-ios",
        "X-SecURL-Client-Version": "1.1.0+7",
      },
    });
    const mobileSummaryPayload = await mobileSummaryResponse.json();
    assert.equal(mobileSummaryResponse.status, 200);
    assert.equal(mobileSummaryPayload.summary.totalTargets, 1);
    assert.equal(mobileSummaryPayload.summary.postureTargets, 1);
    assert.equal(mobileSummaryPayload.targets[0].id, targetId);
    assert.equal(mobileSummaryPayload.targets[0].latestScan, null);

    const telemetryResponse = await fetch(`${server.baseUrl}/api/telemetry`);
    const telemetryPayload = await telemetryResponse.json();
    assert.equal(telemetryPayload.funnel.events.monitoring_mobile_summary_read, 1);
    assert.equal(telemetryPayload.funnel.events.monitoring_target_registered, 1);
    assert.equal(telemetryPayload.funnel.byClient["header-watch-ios"].monitoring_target_registered, 1);
    assert.equal(telemetryPayload.funnel.byClient["header-watch-ios"].monitoring_mobile_summary_read, 1);

    const deleteResponse = await fetch(`${server.baseUrl}/api/monitoring-targets/${targetId}`, {
      method: "DELETE",
      headers: scanOwnerHeaders(SCAN_OWNER_ONE),
    });
    const deletePayload = await deleteResponse.json();
    assert.equal(deleteResponse.status, 200);
    assert.equal(deletePayload.apiVersion, "2026-05-14");
    assert.equal(deletePayload.ok, true);

    const emptyListResponse = await fetch(`${server.baseUrl}/api/monitoring-targets`, {
      headers: scanOwnerHeaders(SCAN_OWNER_ONE),
    });
    const emptyListPayload = await emptyListResponse.json();
    assert.equal(emptyListPayload.targets.length, 0);
  } finally {
    await server.stop();
  }
});

test("monitoring targets reject malformed observation policies", async () => {
  const server = await startServer();
  try {
    const response = await postMonitoringTarget(server.baseUrl, "https://example.com", {
      owner: SCAN_OWNER_ONE,
      policy: { id: "broken", name: "Broken", version: "1", rules: [] },
    });
    const payload = await response.json();
    assert.equal(response.status, 400);
    assert.match(payload.error, /policy/i);
  } finally {
    await server.stop();
  }
});

test("monitoring target run action queues a new scan for the saved target", async () => {
  const server = await startServer();

  try {
    const createTargetResponse = await postMonitoringTarget(server.baseUrl, "https://example.com", {
      owner: SCAN_OWNER_ONE,
      cadence: "daily",
      label: "Example target",
    });
    const createTargetPayload = await createTargetResponse.json();
    assert.equal(createTargetResponse.status, 201);

    const runResponse = await runMonitoringTarget(server.baseUrl, createTargetPayload.target.id, {
      owner: SCAN_OWNER_ONE,
      mode: "quiet",
    });
    const runPayload = await runResponse.json();
    assert.equal(runResponse.status, 202);
    assert.equal(runPayload.apiVersion, "2026-05-14");
    assert.equal(runPayload.target.id, createTargetPayload.target.id);
    assert.equal(runPayload.scan.url, "https://example.com/");
    assert.equal(runPayload.scan.mode, "quiet");
    assert.equal(runPayload.scan.status, "queued");
  } finally {
    await server.stop();
  }
});

test("monitoring target run action is scoped to the same browser owner token", async () => {
  const server = await startServer();

  try {
    const createTargetResponse = await postMonitoringTarget(server.baseUrl, "https://example.com", {
      owner: SCAN_OWNER_ONE,
      cadence: "daily",
    });
    const createTargetPayload = await createTargetResponse.json();

    const wrongOwnerResponse = await runMonitoringTarget(server.baseUrl, createTargetPayload.target.id, {
      owner: SCAN_OWNER_TWO,
    });
    const wrongOwnerPayload = await wrongOwnerResponse.json();
    assert.equal(wrongOwnerResponse.status, 404);
    assert.match(wrongOwnerPayload.error, /monitoring target not found/i);
  } finally {
    await server.stop();
  }
});

test("monitoring target detail returns recent scans, comparison, and lifecycle events", async () => {
  const server = await startServer();

  try {
    const createTargetResponse = await postMonitoringTarget(server.baseUrl, "https://example.com", {
      owner: SCAN_OWNER_ONE,
      cadence: "daily",
      label: "Example target",
    });
    const createTargetPayload = await createTargetResponse.json();
    assert.equal(createTargetResponse.status, 201);

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const runResponse = await runMonitoringTarget(server.baseUrl, createTargetPayload.target.id, {
        owner: SCAN_OWNER_ONE,
      });
      assert.equal(runResponse.status, 202);
    }

    for (let attempt = 0; attempt < 120; attempt += 1) {
      const detailResponse = await getMonitoringTarget(server.baseUrl, createTargetPayload.target.id, {
        owner: SCAN_OWNER_ONE,
      });
      const detailPayload = await detailResponse.json();
      const completedScans = detailPayload.scans.filter((scan) => scan.status === "completed" || scan.status === "failed");

      if (completedScans.length >= 2) {
        assert.equal(detailResponse.status, 200);
        assert.equal(detailPayload.target.id, createTargetPayload.target.id);
        assert.equal(detailPayload.target.url, "https://example.com/");
        assert.equal(detailPayload.target.ownerId, undefined);
        assert.equal(detailPayload.target.requesterScope, undefined);
        assert.ok(Array.isArray(detailPayload.scans));
        assert.ok(detailPayload.scans.length >= 2);
        assert.ok(detailPayload.comparison);
        assert.equal(detailPayload.comparison.currentScanId, detailPayload.scans[0].id);
        assert.equal(detailPayload.comparison.previousScanId, detailPayload.scans[1].id);
        assert.ok(Array.isArray(detailPayload.comparison.riskEvents));
        assert.ok(detailPayload.comparison.drift);
        assert.equal(typeof detailPayload.comparison.drift.direction, "string");
        assert.ok(Array.isArray(detailPayload.events));
        assert.ok(detailPayload.events.some((event) => event.eventType === "queued"));
        assert.ok(detailPayload.events.some((event) => event.eventType === "completed"));
        return;
      }

      await wait(100);
    }

    assert.fail("Timed out waiting for monitoring target detail.");
  } finally {
    await server.stop();
  }
});

test("monitoring summary rolls up scoped targets and latest risk events", async () => {
  const server = await startServer();

  try {
    const createTargetResponse = await postMonitoringTarget(server.baseUrl, "https://example.com", {
      owner: SCAN_OWNER_ONE,
      cadence: "daily",
      label: "Example portfolio target",
    });
    const createTargetPayload = await createTargetResponse.json();
    assert.equal(createTargetResponse.status, 201);

    const otherOwnerResponse = await postMonitoringTarget(server.baseUrl, "https://example.org", {
      owner: SCAN_OWNER_TWO,
      cadence: "weekly",
      label: "Other owner target",
    });
    assert.equal(otherOwnerResponse.status, 201);

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const runResponse = await runMonitoringTarget(server.baseUrl, createTargetPayload.target.id, {
        owner: SCAN_OWNER_ONE,
      });
      assert.equal(runResponse.status, 202);
    }

    for (let attempt = 0; attempt < 120; attempt += 1) {
      const summaryResponse = await getMonitoringSummary(server.baseUrl, {
        owner: SCAN_OWNER_ONE,
      });
      const summaryPayload = await summaryResponse.json();
      const target = summaryPayload.targets?.find((item) => item.id === createTargetPayload.target.id);

      if (target?.latestScan && target?.previousScan) {
        assert.equal(summaryResponse.status, 200);
        assert.equal(summaryPayload.apiVersion, "2026-05-14");
        assert.equal(summaryPayload.summary.totalTargets, 1);
        assert.equal(summaryPayload.summary.targetsWithCompletedScans, 1);
        assert.equal(typeof summaryPayload.summary.dueTargets, "number");
        assert.equal(typeof summaryPayload.summary.gradeDistribution[target.latestScan.grade], "number");
        assert.equal(typeof summaryPayload.summary.riskEventCounts.info, "number");
        assert.equal(typeof summaryPayload.summary.riskEventCounts.warning, "number");
        assert.equal(typeof summaryPayload.summary.riskEventCounts.critical, "number");
        assert.ok(Array.isArray(summaryPayload.summary.topRiskEvents));
        assert.ok(Array.isArray(target.latestRiskEvents));
        assert.equal(target.ownerId, undefined);
        assert.equal(target.requesterScope, undefined);
        return;
      }

      await wait(100);
    }

    assert.fail("Timed out waiting for monitoring summary.");
  } finally {
    await server.stop();
  }
});

test("monitoring target detail is scoped to the same browser owner token", async () => {
  const server = await startServer();

  try {
    const createTargetResponse = await postMonitoringTarget(server.baseUrl, "https://example.com", {
      owner: SCAN_OWNER_ONE,
      cadence: "daily",
    });
    const createTargetPayload = await createTargetResponse.json();

    const wrongOwnerResponse = await getMonitoringTarget(server.baseUrl, createTargetPayload.target.id, {
      owner: SCAN_OWNER_TWO,
    });
    const wrongOwnerPayload = await wrongOwnerResponse.json();
    assert.equal(wrongOwnerResponse.status, 404);
    assert.match(wrongOwnerPayload.error, /monitoring target not found/i);
  } finally {
    await server.stop();
  }
});

test("scan collection can return target-scoped history for the same url", async () => {
  const server = await startServer();

  try {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const createResponse = await fetch(`${server.baseUrl}/api/scans`, {
        method: "POST",
        headers: scanOwnerJsonHeaders(),
        body: JSON.stringify({
          url: "https://example.com",
        }),
      });
      assert.equal(createResponse.status, 202);
    }

    let completed = 0;
    for (let attempt = 0; attempt < 120 && completed < 2; attempt += 1) {
      const historyResponse = await fetch(
        `${server.baseUrl}/api/scans?url=${encodeURIComponent("https://example.com")}`,
        {
          headers: scanOwnerHeaders(),
        },
      );
      const historyPayload = await historyResponse.json();
      completed = historyPayload.scans.filter((scan) => scan.status === "completed" || scan.status === "failed").length;
      if (completed >= 2) {
        assert.equal(historyResponse.status, 200);
        assert.equal(historyPayload.target.url, "https://example.com/");
        assert.equal(historyPayload.scans.length, 2);
        assert.ok(historyPayload.scans.every((scan) => scan.url === "https://example.com/"));
        assert.ok(historyPayload.comparison);
        assert.equal(historyPayload.comparison.currentScanId, historyPayload.scans[0].id);
        assert.equal(historyPayload.comparison.previousScanId, historyPayload.scans[1].id);
        assert.equal(typeof historyPayload.comparison.diff.scoreDelta, "number");
        assert.ok(Array.isArray(historyPayload.comparison.diff.summary));
        return;
      }
      await wait(100);
    }

    assert.fail("Timed out waiting for target-scoped scan history.");
  } finally {
    await server.stop();
  }
});

test("scan comparison returns direct drift against the previous completed scan", async () => {
  const server = await startServer();

  try {
    const firstResponse = await postScan(server.baseUrl, "https://example.com");
    const firstPayload = await firstResponse.json();
    assert.equal(firstResponse.status, 202);
    const firstScanId = firstPayload.scan.id;
    await waitForScanTerminal(server.baseUrl, firstScanId);

    const secondResponse = await postScan(server.baseUrl, "https://example.com");
    const secondPayload = await secondResponse.json();
    assert.equal(secondResponse.status, 202);
    const secondScanId = secondPayload.scan.id;
    await waitForScanTerminal(server.baseUrl, secondScanId);

    const comparisonResponse = await fetch(`${server.baseUrl}/api/scans/${secondScanId}/comparison`, {
      headers: scanOwnerHeaders(),
    });
    const comparisonPayload = await comparisonResponse.json();

    assert.equal(comparisonResponse.status, 200);
    assert.equal(comparisonPayload.apiVersion, "2026-05-14");
    assert.equal(comparisonPayload.scan.id, secondScanId);
    assert.deepEqual(comparisonPayload.scans.map((scan) => scan.id), [secondScanId, firstScanId]);
    assert.equal(comparisonPayload.comparison.currentScanId, secondScanId);
    assert.equal(comparisonPayload.comparison.previousScanId, firstScanId);
    assert.equal(typeof comparisonPayload.comparison.diff.scoreDelta, "number");
    assert.ok(Array.isArray(comparisonPayload.comparison.diff.summary));
    assert.ok(Array.isArray(comparisonPayload.comparison.riskEvents));
    assert.ok(comparisonPayload.comparison.drift);
    assert.equal(typeof comparisonPayload.comparison.drift.direction, "string");

    const driftResponse = await fetch(`${server.baseUrl}/api/scans/${secondScanId}/drift`, {
      headers: scanOwnerHeaders(),
    });
    const driftPayload = await driftResponse.json();

    assert.equal(driftResponse.status, 200);
    assert.equal(driftPayload.apiVersion, "2026-05-14");
    assert.equal(driftPayload.scan.id, secondScanId);
    assert.equal(driftPayload.drift.currentScanId, secondScanId);
    assert.equal(driftPayload.drift.previousScanId, firstScanId);
    assert.equal(typeof driftPayload.drift.summary.direction, "string");
    assert.ok(Array.isArray(driftPayload.drift.riskEvents));

    const wrongOwnerResponse = await fetch(`${server.baseUrl}/api/scans/${secondScanId}/comparison`, {
      headers: scanOwnerHeaders(SCAN_OWNER_TWO),
    });
    const wrongOwnerPayload = await wrongOwnerResponse.json();

    assert.equal(wrongOwnerResponse.status, 404);
    assert.match(wrongOwnerPayload.error, /scan not found/i);
  } finally {
    await server.stop();
  }
});

test("scan resources require the same requester scope that created the scan", async () => {
  const server = await startServer({
    API_KEY: "test-secret",
  });

  try {
    const createResponse = await fetch(`${server.baseUrl}/api/scans`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": "test-secret",
      },
      body: JSON.stringify({
        url: "https://example.com",
      }),
    });
    const createdPayload = await createResponse.json();
    assert.equal(createResponse.status, 202);

    const scanId = createdPayload.scan.id;
    const unauthenticatedList = await fetch(`${server.baseUrl}/api/scans`);
    const unauthenticatedListPayload = await unauthenticatedList.json();
    assert.equal(unauthenticatedList.status, 401);
    assert.match(unauthenticatedListPayload.error, /API key/i);

    const wrongScopeResponse = await fetch(`${server.baseUrl}/api/scans/${scanId}`, {
      headers: {
        "X-API-Key": "wrong-secret",
      },
    });
    const wrongScopePayload = await wrongScopeResponse.json();
    assert.equal(wrongScopeResponse.status, 401);
    assert.match(wrongScopePayload.error, /API key/i);

    const scopedListResponse = await fetch(`${server.baseUrl}/api/scans`, {
      headers: {
        "X-API-Key": "test-secret",
      },
    });
    const scopedListPayload = await scopedListResponse.json();
    assert.equal(scopedListResponse.status, 200);
    assert.deepEqual(scopedListPayload.scans.map((scan) => scan.id), [scanId]);

    const scopedDetailResponse = await fetch(`${server.baseUrl}/api/scans/${scanId}`, {
      headers: {
        "X-API-Key": "test-secret",
      },
    });
    const scopedDetailPayload = await scopedDetailResponse.json();
    assert.equal(scopedDetailResponse.status, 200);
    assert.equal(scopedDetailPayload.scan.id, scanId);
  } finally {
    await server.stop();
  }
});

test("scan resources accept deep-passive mode for bounded recon", async () => {
  const server = await startServer();

  try {
    const standardResponse = await postScan(server.baseUrl, "https://example.com", {
      mode: "standard",
    });
    const standardPayload = await standardResponse.json();
    assert.equal(standardResponse.status, 202);

    for (let attempt = 0; attempt < 60; attempt += 1) {
      const response = await fetch(`${server.baseUrl}/api/scans/${standardPayload.scan.id}`, {
        headers: scanOwnerHeaders(),
      });
      const payload = await response.json();
      if (payload.scan.status === "completed" || payload.scan.status === "failed") {
        break;
      }
      await wait(100);
    }

    const createResponse = await postScan(server.baseUrl, "https://example.com", {
      mode: "deep-passive",
    });
    const payload = await createResponse.json();

    assert.equal(createResponse.status, 202);
    assert.equal(payload.fromCache, undefined);
    assert.equal(payload.scan.mode, "deep-passive");
    assert.equal(["queued", "running", "completed"].includes(payload.scan.status), true);

    for (let attempt = 0; attempt < 20 && !server.getStdout().includes('"maxScanDurationMs":75000'); attempt += 1) {
      await wait(100);
    }
    assert.match(server.getStdout(), /"mode":"deep-passive".*"maxScanDurationMs":75000/);
  } finally {
    await server.stop();
  }
});

test("unauthenticated scan resources are scoped by browser owner token, not shared IP", async () => {
  const server = await startServer();

  try {
    const createResponse = await fetch(`${server.baseUrl}/api/scans`, {
      method: "POST",
      headers: scanOwnerJsonHeaders(SCAN_OWNER_ONE),
      body: JSON.stringify({
        url: "https://example.com",
      }),
    });
    const createdPayload = await createResponse.json();
    assert.equal(createResponse.status, 202);

    const scanId = createdPayload.scan.id;
    const wrongOwnerResponse = await fetch(`${server.baseUrl}/api/scans/${scanId}`, {
      headers: scanOwnerHeaders(SCAN_OWNER_TWO),
    });
    const wrongOwnerPayload = await wrongOwnerResponse.json();
    assert.equal(wrongOwnerResponse.status, 404);
    assert.match(wrongOwnerPayload.error, /Scan not found/i);

    const wrongOwnerListResponse = await fetch(`${server.baseUrl}/api/scans`, {
      headers: scanOwnerHeaders(SCAN_OWNER_TWO),
    });
    const wrongOwnerListPayload = await wrongOwnerListResponse.json();
    assert.equal(wrongOwnerListResponse.status, 200);
    assert.deepEqual(wrongOwnerListPayload.scans, []);

    const missingOwnerResponse = await fetch(`${server.baseUrl}/api/scans/${scanId}`);
    const missingOwnerPayload = await missingOwnerResponse.json();
    assert.equal(missingOwnerResponse.status, 401);
    assert.match(missingOwnerPayload.error, /owner token/i);
  } finally {
    await server.stop();
  }
});

test("scan resources reject invalid json bodies", async () => {
  const server = await startServer();

  try {
    const response = await fetch(`${server.baseUrl}/api/scans`, {
      method: "POST",
      headers: scanOwnerJsonHeaders(),
      body: "{broken",
    });
    const payload = await response.json();

    assert.equal(response.status, 400);
    assert.match(payload.error, /valid json/i);
  } finally {
    await server.stop();
  }
});

test("scan resources return a sanitized error for invalid targets", async () => {
  const server = await startServer();

  try {
    const response = await fetch(`${server.baseUrl}/api/scans`, {
      method: "POST",
      headers: scanOwnerJsonHeaders(),
      body: JSON.stringify({
        url: "https://user:pass@example.com",
      }),
    });
    const payload = await response.json();

    assert.equal(response.status, 400);
    assert.match(payload.error, /embedded credentials/i);
  } finally {
    await server.stop();
  }
});

test("scan detail endpoints return summary, findings, evidence, and history payloads", async () => {
  const server = await startServer();

  try {
    const createResponse = await fetch(`${server.baseUrl}/api/scans`, {
      method: "POST",
      headers: scanOwnerJsonHeaders(),
      body: JSON.stringify({
        url: "https://example.com",
      }),
    });
    const createdPayload = await createResponse.json();
    assert.equal(createResponse.status, 202);

    const scanId = createdPayload.scan.id;

    let scanPayload = null;
    for (let attempt = 0; attempt < 60; attempt += 1) {
      const response = await fetch(`${server.baseUrl}/api/scans/${scanId}`, {
        headers: scanOwnerHeaders(),
      });
      scanPayload = await response.json();
      if (scanPayload.scan.status === "completed" || scanPayload.scan.status === "failed") {
        break;
      }
      await wait(100);
    }

    assert.equal(scanPayload.scan.status, "completed");
    assert.ok(scanPayload.scan.result);
    assert.equal(scanPayload.scan.id, scanId);
    assert.equal(scanPayload.scan.ownerId, undefined);
    assert.equal(scanPayload.scan.requesterScope, undefined);
    assert.equal(scanPayload.scan.clientIp, undefined);
    assert.equal(scanPayload.scan.summary, undefined);

    const summaryResponse = await fetch(`${server.baseUrl}/api/scans/${scanId}/summary`, {
      headers: scanOwnerHeaders(),
    });
    const findingsResponse = await fetch(`${server.baseUrl}/api/scans/${scanId}/findings`, {
      headers: scanOwnerHeaders(),
    });
    const digestResponse = await fetch(`${server.baseUrl}/api/scans/${scanId}/digest`, {
      headers: scanOwnerHeaders(),
    });
    const insightsResponse = await fetch(`${server.baseUrl}/api/scans/${scanId}/insights`, {
      headers: scanOwnerHeaders(),
    });
    const mobileSummaryResponse = await fetch(`${server.baseUrl}/api/scans/${scanId}/mobile-summary`, {
      headers: scanOwnerHeaders(),
    });
    const briefResponse = await fetch(`${server.baseUrl}/api/scans/${scanId}/brief`, {
      headers: scanOwnerHeaders(),
    });
    const vendorsResponse = await fetch(`${server.baseUrl}/api/scans/${scanId}/vendors`, {
      headers: scanOwnerHeaders(),
    });
    const actionPlanResponse = await fetch(`${server.baseUrl}/api/scans/${scanId}/action-plan`, {
      headers: scanOwnerHeaders(),
    });
    const evidenceResponse = await fetch(`${server.baseUrl}/api/scans/${scanId}/evidence`, {
      headers: scanOwnerHeaders(),
    });
    const observationsResponse = await fetch(`${server.baseUrl}/api/scans/${scanId}/observations`, {
      headers: scanOwnerHeaders(),
    });
    const policyEvaluationResponse = await fetch(`${server.baseUrl}/api/scans/${scanId}/policy-evaluation`, {
      headers: scanOwnerHeaders(),
    });
    const historyResponse = await fetch(`${server.baseUrl}/api/scans/${scanId}/history`, {
      headers: scanOwnerHeaders(),
    });
    const eventsResponse = await fetch(`${server.baseUrl}/api/scans/${scanId}/events`, {
      headers: scanOwnerHeaders(),
    });
    const markdownExportResponse = await fetch(`${server.baseUrl}/api/scans/${scanId}/export?format=markdown`, {
      headers: scanOwnerHeaders(),
    });
    const sarifExportResponse = await fetch(`${server.baseUrl}/api/scans/${scanId}/export?format=sarif`, {
      headers: scanOwnerHeaders(),
    });
    const ciJsonExportResponse = await fetch(`${server.baseUrl}/api/scans/${scanId}/export?format=ci-json`, {
      headers: scanOwnerHeaders(),
    });
    const invalidExportResponse = await fetch(`${server.baseUrl}/api/scans/${scanId}/export?format=pdf`, {
      headers: scanOwnerHeaders(),
    });

    const summaryPayload = await summaryResponse.json();
    const findingsPayload = await findingsResponse.json();
    const digestPayload = await digestResponse.json();
    const insightsPayload = await insightsResponse.json();
    const mobileSummaryPayload = await mobileSummaryResponse.json();
    const briefPayload = await briefResponse.json();
    const vendorsPayload = await vendorsResponse.json();
    const actionPlanPayload = await actionPlanResponse.json();
    const evidencePayload = await evidenceResponse.json();
    const observationsPayload = await observationsResponse.json();
    const policyEvaluationPayload = await policyEvaluationResponse.json();
    const historyPayload = await historyResponse.json();
    const eventsText = await eventsResponse.text();
    const markdownExport = await markdownExportResponse.text();
    const sarifExport = await sarifExportResponse.json();
    const ciJsonExport = await ciJsonExportResponse.json();
    const invalidExportPayload = await invalidExportResponse.json();

    assert.equal(summaryResponse.status, 200);
    assert.equal(summaryPayload.apiVersion, "2026-05-14");
    assert.equal(summaryPayload.summary.id, scanId);
    assert.equal(findingsResponse.status, 200);
    assert.equal(findingsPayload.apiVersion, "2026-05-14");
    assert.ok(Array.isArray(findingsPayload.findings));
    assert.ok(Array.isArray(findingsPayload.strengths));
    assert.ok(Array.isArray(findingsPayload.priorityActions));
    assert.ok(findingsPayload.remediationPlan);
    assert.ok(Array.isArray(findingsPayload.remediationPlan.items));
    assert.ok(findingsPayload.evidenceSummary);
    assert.equal(typeof findingsPayload.evidenceSummary.totalEvidenceReferences, "number");
    assert.ok(
      findingsPayload.findings.every((finding) => Array.isArray(finding.evidence)),
    );
    assert.equal(digestResponse.status, 200);
    assert.equal(digestPayload.apiVersion, "2026-05-14");
    assert.equal(digestPayload.scan.id, scanId);
    assert.equal(digestPayload.digest.target.host, "example.com");
    assert.equal(typeof digestPayload.digest.posture.score, "number");
    assert.ok(Array.isArray(digestPayload.digest.findings.top));
    assert.ok(digestPayload.digest.remediationPlan);
    assert.ok(Array.isArray(digestPayload.digest.remediationPlan.topActions));
    assert.ok(digestPayload.digest.evidence);
    assert.equal(typeof digestPayload.digest.evidence.totalEvidenceReferences, "number");
    assert.ok(Array.isArray(digestPayload.digest.posture.scoreDrivers));
    assert.ok(Array.isArray(digestPayload.digest.intelligence.riskIndicators));
    assert.equal(insightsResponse.status, 200);
    assert.equal(insightsPayload.apiVersion, "2026-05-14");
    assert.equal(insightsPayload.scan.id, scanId);
    assert.ok(insightsPayload.insights);
    assert.equal(typeof insightsPayload.insights.summary, "string");
    assert.ok(Array.isArray(insightsPayload.insights.themes));
    assert.ok(Array.isArray(insightsPayload.insights.topInsights));
    assert.ok(Array.isArray(insightsPayload.insights.nextBestActions));
    assert.equal(mobileSummaryResponse.status, 200);
    assert.equal(mobileSummaryPayload.apiVersion, "2026-05-14");
    assert.equal(mobileSummaryPayload.scan.id, scanId);
    assert.equal(mobileSummaryPayload.ready, true);
    assert.equal(mobileSummaryPayload.digest.target.host, "example.com");
    assert.equal(typeof mobileSummaryPayload.insights.summary, "string");
    assert.equal(mobileSummaryPayload.resources.mobileSummary, `/api/scans/${scanId}/mobile-summary`);
    assert.equal(briefResponse.status, 200);
    assert.equal(briefPayload.apiVersion, "2026-05-14");
    assert.equal(briefPayload.scan.id, scanId);
    assert.ok(briefPayload.brief);
    assert.equal(typeof briefPayload.brief.summary, "string");
    assert.ok(Array.isArray(briefPayload.brief.topRisks));
    assert.ok(Array.isArray(briefPayload.brief.nextActions));
    assert.equal(vendorsResponse.status, 200);
    assert.equal(vendorsPayload.apiVersion, "2026-05-14");
    assert.equal(vendorsPayload.scan.id, scanId);
    assert.ok(vendorsPayload.vendors);
    assert.equal(typeof vendorsPayload.vendors.summary, "string");
    assert.ok(Array.isArray(vendorsPayload.vendors.providers));
    assert.ok(Array.isArray(vendorsPayload.vendors.nextActions));
    assert.equal(actionPlanResponse.status, 200);
    assert.equal(actionPlanPayload.apiVersion, "2026-05-14");
    assert.equal(actionPlanPayload.scan.id, scanId);
    assert.ok(actionPlanPayload.actionPlan);
    assert.equal(typeof actionPlanPayload.actionPlan.summary, "string");
    assert.ok(Array.isArray(actionPlanPayload.actionPlan.items));
    assert.equal(typeof actionPlanPayload.actionPlan.highImpactActions, "number");
    assert.equal(evidenceResponse.status, 200);
    assert.equal(evidencePayload.apiVersion, "2026-05-14");
    assert.ok(Array.isArray(evidencePayload.evidence.headers));
    assert.ok(Array.isArray(evidencePayload.evidence.cookies));
    assert.ok(Array.isArray(evidencePayload.evidence.redirects));
    assert.ok(evidencePayload.evidence.evidenceSummary);
    assert.equal(observationsResponse.status, 200);
    assert.equal(observationsPayload.observationLedger.version, "1.0");
    assert.equal(observationsPayload.observationLedger.target, "https://example.com/");
    assert.ok(observationsPayload.observationLedger.observations.length > 0);
    assert.equal(
      observationsPayload.observationLedger.summary.total,
      observationsPayload.observationLedger.observations.length,
    );
    assert.equal(policyEvaluationResponse.status, 200);
    assert.equal(policyEvaluationPayload.policySource, "default");
    assert.equal(policyEvaluationPayload.policyEvaluation.version, "1.0");
    assert.equal(typeof policyEvaluationPayload.policyEvaluation.passed, "boolean");
    assert.equal(historyResponse.status, 200);
    assert.equal(historyPayload.apiVersion, "2026-05-14");
    assert.equal(historyPayload.scan.id, scanId);
    assert.ok(Array.isArray(historyPayload.events));
    assert.ok(historyPayload.events.length >= 3);
    assert.equal(historyPayload.events[0].eventType, "completed");
    assert.equal(eventsResponse.status, 200);
    assert.match(eventsResponse.headers.get("content-type") || "", /text\/event-stream/i);
    assert.match(eventsText, /event: completed/);
    assert.match(eventsText, /event: scan_terminal/);
    assert.equal(markdownExportResponse.status, 200);
    assert.match(markdownExportResponse.headers.get("content-type") || "", /text\/markdown/i);
    assert.match(markdownExport, /^# SecURL Scan:/);
    assert.equal(sarifExportResponse.status, 200);
    assert.match(sarifExportResponse.headers.get("content-type") || "", /application\/sarif\+json/i);
    assert.equal(sarifExport.version, "2.1.0");
    assert.ok(Array.isArray(sarifExport.runs[0].results));
    assert.equal(ciJsonExportResponse.status, 200);
    assert.equal(ciJsonExport.apiVersion, "2026-05-14");
    assert.equal(ciJsonExport.scan.id, scanId);
    assert.equal(typeof ciJsonExport.posture.passed, "boolean");
    assert.equal(invalidExportResponse.status, 400);
    assert.match(invalidExportPayload.error, /unsupported export format/i);
  } finally {
    await server.stop();
  }
});

test("scan collection rejects unsupported methods", async () => {
  const server = await startServer();

  try {
    const response = await fetch(`${server.baseUrl}/api/scans`, {
      method: "PUT",
      headers: scanOwnerHeaders(),
    });
    const payload = await response.json();

    assert.equal(response.status, 405);
    assert.equal(response.headers.get("allow"), "GET, POST");
    assert.match(payload.error, /Method not allowed/i);
  } finally {
    await server.stop();
  }
});

test("scan collection rejects HEAD requests without triggering scan work", async () => {
  const server = await startServer();

  try {
    const response = await fetch(`${server.baseUrl}/api/scans`, {
      method: "HEAD",
      headers: scanOwnerHeaders(),
    });

    assert.equal(response.status, 405);
    assert.equal(response.headers.get("allow"), "GET, POST");
    assert.doesNotMatch(server.getStdout(), /analysis_requested/);
  } finally {
    await server.stop();
  }
});

test("rate limiting ignores spoofed forwarded headers unless trust proxy is enabled", async () => {
  const server = await startServer();

  try {
    let limitedResponse = null;
    for (let index = 0; index < 31; index += 1) {
      const response = await postScan(server.baseUrl, `https://localhost-${index}.example.com`, {
        headers: {
          "X-Forwarded-For": `198.51.100.${index}`,
        },
      });
      if (response.status === 429) {
        limitedResponse = response;
        break;
      }
    }

    assert.ok(limitedResponse, "Expected spoofed forwarded headers to be ignored for rate limiting.");
    assert.equal(limitedResponse.status, 429);
    assert.equal(limitedResponse.headers.get("retry-after"), "900");
  } finally {
    await server.stop();
  }
});

test("trusted proxy mode uses forwarded headers for client attribution", async () => {
  const server = await startServer({
    TRUST_PROXY: "true",
  });

  try {
    for (let index = 0; index < 31; index += 1) {
      const response = await postScan(server.baseUrl, `https://localhost-${index}.example.com`, {
        headers: {
          "X-Forwarded-For": `198.51.100.${index}`,
        },
      });
      assert.equal(response.status, 400);
    }
  } finally {
    await server.stop();
  }
});

test("trusted proxy mode uses the last valid forwarded IP for client attribution", async () => {
  const server = await startServer({
    TRUST_PROXY: "true",
  });

  try {
    let limitedResponse = null;
    for (let index = 0; index < 31; index += 1) {
      const response = await postScan(server.baseUrl, `https://localhost-${index}.example.com`, {
        headers: {
          "X-Forwarded-For": `198.51.100.${index}, not-an-ip, 203.0.113.10`,
        },
      });
      if (response.status === 429) {
        limitedResponse = response;
        break;
      }
    }

    assert.ok(limitedResponse, "Expected the appended forwarded IP to be used for rate limiting.");
    assert.equal(limitedResponse.status, 429);
  } finally {
    await server.stop();
  }
});

test("rate limiting supports environment overrides", async () => {
  const server = await startServer({
    RATE_LIMIT_WINDOW_MS: "2000",
    RATE_LIMIT_MAX_REQUESTS: "2",
  });

  try {
    const one = await postScan(server.baseUrl, "https://localhost-1.example.com");
    const two = await postScan(server.baseUrl, "https://localhost-2.example.com");
    const three = await postScan(server.baseUrl, "https://localhost-3.example.com");

    assert.equal(one.status, 400);
    assert.equal(two.status, 400);
    assert.equal(three.status, 429);
    assert.equal(three.headers.get("retry-after"), "2");
  } finally {
    await server.stop();
  }
});

test("upstash limiter falls back to local throttling when backend requests fail", async () => {
  const server = await startServer({
    RATE_LIMIT_BACKEND: "upstash",
    UPSTASH_REDIS_REST_URL: "http://127.0.0.1:9",
    UPSTASH_REDIS_REST_TOKEN: "test-token",
    RATE_LIMIT_WINDOW_MS: "2000",
    RATE_LIMIT_MAX_REQUESTS: "2",
  });

  try {
    const one = await postScan(server.baseUrl, "https://localhost-1.example.com");
    const two = await postScan(server.baseUrl, "https://localhost-2.example.com");
    const three = await postScan(server.baseUrl, "https://localhost-3.example.com");

    assert.equal(one.status, 400);
    assert.equal(two.status, 400);
    assert.equal(three.status, 429);
    assert.match(server.getStderr(), /rate_limit_backend_error/);
  } finally {
    await server.stop();
  }
});

test("target quota limits repeated requests to the same host per requester scope", async () => {
  const server = await startServer({
    TARGET_RATE_LIMIT_WINDOW_MS: "2000",
    TARGET_RATE_LIMIT_MAX_REQUESTS: "2",
  });

  try {
    const one = await postScan(server.baseUrl, "https://repeat-target.example.com");
    const two = await postScan(server.baseUrl, "https://repeat-target.example.com");
    const three = await postScan(server.baseUrl, "https://repeat-target.example.com");

    assert.equal(one.status, 400);
    assert.equal(two.status, 400);
    assert.equal(three.status, 429);
    assert.equal(three.headers.get("retry-after"), "2");
    const payload = await three.json();
    assert.match(payload.error, /for this target/i);
  } finally {
    await server.stop();
  }
});

test("static serving rejects encoded traversal paths", async () => {
  const server = await startServer();

  try {
    const response = await requestRawPath(server.baseUrl, "/%2e%2e/%2e%2e/package.json");
    assert.equal(response.statusCode, 400);
    assert.match(response.body, /invalid request path/i);
  } finally {
    await server.stop();
  }
});

test("scan owner tokens that are too short or low-entropy are rejected", async () => {
  const server = await startServer();

  try {
    // Too short (< 24 chars).
    const shortResponse = await fetch(`${server.baseUrl}/api/scans`, {
      headers: scanOwnerHeaders("short-owner-token"),
    });
    assert.equal(shortResponse.status, 401);
    assert.match((await shortResponse.json()).error, /scan owner token is required/i);

    // Long enough but degenerate (only 1 distinct character).
    const lowEntropyResponse = await fetch(`${server.baseUrl}/api/scans`, {
      headers: scanOwnerHeaders("a".repeat(40)),
    });
    assert.equal(lowEntropyResponse.status, 401);

    // A realistic random token (UUID-shaped) is accepted.
    const okResponse = await fetch(`${server.baseUrl}/api/scans`, {
      headers: scanOwnerHeaders("3f2504e0-4f89-41d3-9a0c-0305e82c3301"),
    });
    assert.equal(okResponse.status, 200);
  } finally {
    await server.stop();
  }
});
