import { createRequire } from "node:module";
import { API_VERSION } from "./scanDtos.mjs";

const require = createRequire(import.meta.url);
const appPackage = require("../package.json");
const corePackage = require("../packages/core/package.json");

export function buildCapabilitiesPayload({
  authenticated,
  allowUnauthenticated,
  scanTimeoutMs,
  deepPassiveScanTimeoutMs,
  scanConcurrency,
  monitoringScheduler,
  serveFrontend,
} = {}) {
  return {
    apiVersion: API_VERSION,
    service: {
      name: "SecURL API",
      appVersion: appPackage.version,
      corePackage: corePackage.name,
      coreVersion: corePackage.version,
      serveFrontend: Boolean(serveFrontend),
    },
    auth: {
      methods: [
        ...(authenticated ? ["api-key"] : []),
        "bearer-session",
        ...(allowUnauthenticated ? ["scan-owner"] : []),
      ],
      anonymousScanOwner: Boolean(allowUnauthenticated),
    },
    scans: {
      modes: ["standard", "quiet", "deep-passive"],
      statuses: ["queued", "running", "completed", "failed"],
      maxDurationMs: {
        standard: scanTimeoutMs,
        quiet: scanTimeoutMs,
        deepPassive: deepPassiveScanTimeoutMs,
      },
      concurrency: scanConcurrency,
      resources: [
        "POST /api/scans",
        "GET /api/scans",
        "GET /api/scans?url=:url",
        "GET /api/scans/:id",
        "GET /api/scans/:id/summary",
        "GET /api/scans/:id/findings",
        "GET /api/scans/:id/evidence",
        "GET /api/scans/:id/history",
        "GET /api/scans/:id/share",
      ],
    },
    monitoring: {
      enabled: true,
      cadences: ["daily", "weekly"],
      scheduler: {
        enabled: Boolean(monitoringScheduler?.enabled),
        mode: monitoringScheduler?.mode ?? "quiet",
        intervalMs: monitoringScheduler?.intervalMs ?? null,
        limit: monitoringScheduler?.limit ?? null,
      },
      resources: [
        "POST /api/monitoring-targets",
        "GET /api/monitoring-targets",
        "GET /api/monitoring-targets/:id",
        "POST /api/monitoring-targets/:id/run",
        "DELETE /api/monitoring-targets/:id",
      ],
    },
    exports: {
      formats: ["json", "markdown", "sarif", "ci-json"],
      shareLinks: true,
    },
    safety: {
      passiveFirst: true,
      publicTargetsOnly: true,
      blocksPrivateNetworkTargets: true,
    },
  };
}
