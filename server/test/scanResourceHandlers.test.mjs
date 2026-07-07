import assert from "node:assert/strict";
import test from "node:test";

import {
  buildScanResourceLinks,
  getDeploymentScopedResultCacheAgeMs,
  RESULT_CACHE_TTL_MS,
} from "../scanResourceHandlers.mjs";

test("deployment-scoped result cache ignores pre-start scans and caps the ttl", () => {
  assert.equal(getDeploymentScopedResultCacheAgeMs(1_000, 2_000), 0);
  assert.equal(getDeploymentScopedResultCacheAgeMs(5_000, 2_000), 3_000);
  assert.equal(
    getDeploymentScopedResultCacheAgeMs(RESULT_CACHE_TTL_MS + 5_000, 0),
    RESULT_CACHE_TTL_MS,
  );
});

test("scan resource links point clients at lightweight follow-up endpoints", () => {
  assert.deepEqual(buildScanResourceLinks("scan-one"), {
    detail: "/api/scans/scan-one",
    summary: "/api/scans/scan-one/summary",
    findings: "/api/scans/scan-one/findings",
    digest: "/api/scans/scan-one/digest",
    insights: "/api/scans/scan-one/insights",
    mobileSummary: "/api/scans/scan-one/mobile-summary",
    brief: "/api/scans/scan-one/brief",
    vendors: "/api/scans/scan-one/vendors",
    actionPlan: "/api/scans/scan-one/action-plan",
    events: "/api/scans/scan-one/events",
    evidence: "/api/scans/scan-one/evidence",
    observations: "/api/scans/scan-one/observations",
    observationDrift: "/api/scans/scan-one/observation-drift",
    policyEvaluation: "/api/scans/scan-one/policy-evaluation",
    history: "/api/scans/scan-one/history",
    comparison: "/api/scans/scan-one/comparison",
    drift: "/api/scans/scan-one/drift",
    share: "/api/scans/scan-one/share",
    shareCard: "/api/scans/scan-one/share-card",
  });
});
