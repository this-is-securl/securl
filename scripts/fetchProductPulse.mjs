#!/usr/bin/env node
import { readRailwayVariables } from "./lib/readRailwayVariables.mjs";

const DEFAULT_BASE_URL = "https://securl-app-production.up.railway.app";

const describeBucket = (bucket = {}) => Object.entries(bucket || {})
  .filter(([, count]) => Number(count || 0) > 0)
  .sort(([, left], [, right]) => Number(right || 0) - Number(left || 0))
  .map(([name, count]) => `${name}: ${count}`)
  .join(", ");

const main = async () => {
  const vars = process.env.TELEMETRY_TOKEN ? {} : readRailwayVariables();
  const token = process.env.TELEMETRY_TOKEN || vars.TELEMETRY_TOKEN || vars.ADMIN_TELEMETRY_TOKEN;
  if (!token) {
    const railwayHint = vars.__railwayReadError
      ? ` Railway variable lookup failed: ${vars.__railwayReadError}`
      : "";
    throw new Error(`TELEMETRY_TOKEN was not found in this shell or Railway variables.${railwayHint} Run \`railway login\`, or export TELEMETRY_TOKEN for this command.`);
  }

  const baseUrl = (process.env.TELEMETRY_BASE_URL || vars.PUBLIC_API_BASE_URL || DEFAULT_BASE_URL).replace(/\/+$/, "");
  const response = await fetch(`${baseUrl}/api/product-pulse`, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
  const body = await response.text();
  if (!response.ok) {
    throw new Error(`Product pulse request failed with HTTP ${response.status}: ${body.slice(0, 160)}`);
  }

  const payload = JSON.parse(body);
  const pulse = payload.productPulse || {};
  const today = pulse.today || {};
  console.log("SecURL product pulse");
  console.log(`Generated: ${payload.generatedAt}`);
  console.log(`Date: ${today.date || "unknown"}`);
  console.log(`Backend API events today: ${today.backendApiEvents ?? 0}`);
  console.log("");
  console.log("Apps today");
  const appRows = Object.entries(today.appEvents || {})
    .sort(([, left], [, right]) => Number(right?.total || 0) - Number(left?.total || 0));
  if (!appRows.length) {
    console.log("  - none");
  }
  for (const [appId, summary] of appRows) {
    const activeOwners = today.activeOwnersByApp?.[appId] ?? 0;
    const uniqueTargets = today.uniqueTargetsByApp?.[appId] ?? 0;
    const outcomes = describeBucket(today.monitoringRegistrationOutcomesByApp?.[appId]);
    const kinds = describeBucket(today.monitoringTargetKindsByApp?.[appId]);
    console.log(`  - ${appId}: ${summary.total} events / ${activeOwners} active owners / ${uniqueTargets} targets`);
    if (outcomes) console.log(`    outcomes: ${outcomes}`);
    if (kinds) console.log(`    kinds: ${kinds}`);
  }
  console.log("");
  console.log("Recent monitoring registrations");
  const registrations = today.recentMonitoringRegistrations || [];
  if (!registrations.length) {
    console.log("  - none");
  }
  for (const event of registrations.slice(0, 12)) {
    const app = event.appId || event.client || "unknown-app";
    const kind = event.targetKind ? ` ${event.targetKind}` : "";
    const outcome = event.outcome ? ` ${event.outcome}` : "";
    console.log(`  - ${event.occurredAt} ${app}${kind}${outcome} ${event.target || ""}`.trimEnd());
  }
};

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
