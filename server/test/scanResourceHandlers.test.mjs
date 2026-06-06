import assert from "node:assert/strict";
import test from "node:test";

import {
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
