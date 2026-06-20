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
    events: "/api/scans/scan-one/events",
    evidence: "/api/scans/scan-one/evidence",
    observations: "/api/scans/scan-one/observations",
    observationDrift: "/api/scans/scan-one/observation-drift",
    history: "/api/scans/scan-one/history",
    comparison: "/api/scans/scan-one/comparison",
    drift: "/api/scans/scan-one/drift",
    share: "/api/scans/scan-one/share",
  });
});
