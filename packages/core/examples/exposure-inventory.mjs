import { analyzeUrl } from "securl";
import { buildExternalExposureInventory } from "securl/exposure-inventory";

const target = process.argv[2] ?? "https://example.com";
const result = await analyzeUrl(target);
const exposure = buildExternalExposureInventory(result);

console.log(JSON.stringify({
  target: result.finalUrl,
  schemaVersion: exposure.schemaVersion,
  risk: exposure.risk,
  summary: exposure.summary,
  counts: exposure.inventoryCounts,
  inventory: exposure.inventory,
  nextActions: exposure.nextActions,
}, null, 2));
