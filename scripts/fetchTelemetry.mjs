#!/usr/bin/env node
import { execFileSync } from "node:child_process";

const DEFAULT_BASE_URL = "https://securl-app-production.up.railway.app";

const readRailwayVariables = () => {
  try {
    const raw = execFileSync("railway", ["variables", "--json"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    return JSON.parse(raw);
  } catch (error) {
    throw new Error("Unable to read Railway variables. Is the Railway CLI installed, logged in, and linked to this project?");
  }
};

const formatMs = (value) => `${Math.round(value || 0).toLocaleString()}ms`;

const main = async () => {
  const vars = readRailwayVariables();
  const token = vars.TELEMETRY_TOKEN || process.env.TELEMETRY_TOKEN;
  if (!token) {
    throw new Error("TELEMETRY_TOKEN was not found in Railway variables or the current shell.");
  }

  const baseUrl = (process.env.TELEMETRY_BASE_URL || vars.PUBLIC_API_BASE_URL || DEFAULT_BASE_URL).replace(/\/+$/, "");
  const response = await fetch(`${baseUrl}/api/telemetry`, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  const body = await response.text();
  if (!response.ok) {
    throw new Error(`Telemetry request failed with HTTP ${response.status}: ${body.slice(0, 160)}`);
  }

  const telemetry = JSON.parse(body);
  const sources = Object.entries(telemetry.trafficSources?.pageLoads || {})
    .sort(([, left], [, right]) => right - left)
    .map(([source, count]) => `  - ${source}: ${count}`)
    .join("\n") || "  - none";

  console.log(`SecURL telemetry\n`);
  console.log(`Started: ${telemetry.startedAt}`);
  console.log(`Storage: ${telemetry.persistence}`);
  console.log("");
  console.log(`Visitors`);
  console.log(`  Page loads: ${telemetry.pageLoads}`);
  console.log(`  Unique visitors: ${telemetry.visitors?.unique ?? 0}`);
  console.log(`  Today: ${telemetry.visitors?.today?.pageLoads ?? 0} page loads / ${telemetry.visitors?.today?.uniqueVisitors ?? 0} unique`);
  console.log("");
  console.log(`Traffic sources`);
  console.log(sources);
  console.log("");
  console.log(`Scans`);
  console.log(`  Requested: ${telemetry.scans?.requested ?? 0}`);
  console.log(`  Completed: ${telemetry.scans?.completed ?? 0}`);
  console.log(`  Unique requesters: ${telemetry.scans?.engagement?.uniqueRequesters ?? 0}`);
  console.log(`  Unique clients: ${telemetry.scans?.engagement?.uniqueClients ?? 0}`);
  console.log(`  Unique targets: ${telemetry.scans?.engagement?.uniqueTargets ?? 0}`);
  console.log(`  Full reads: ${telemetry.scans?.fullReads ?? 0}`);
  console.log(`  Limited reads: ${telemetry.scans?.limitedReads ?? 0}`);
  console.log(`  Timed out: ${telemetry.scans?.timedOut ?? 0}`);
  console.log(`  Average total time: ${formatMs(telemetry.scans?.timing?.total?.averageMs)}`);
  const scanChannels = Object.entries(telemetry.scans?.engagement?.channels || {})
    .sort(([, left], [, right]) => right - left);
  if (scanChannels.length) {
    console.log("  Channels:");
    for (const [channel, count] of scanChannels) {
      console.log(`    - ${channel}: ${count}`);
    }
  }
  const scanSources = Object.entries(telemetry.scans?.engagement?.sources || {})
    .sort(([, left], [, right]) => right - left)
    .slice(0, 8);
  if (scanSources.length) {
    console.log("  Sources:");
    for (const [source, count] of scanSources) {
      console.log(`    - ${source}: ${count}`);
    }
  }
  const repeatTargets = telemetry.scans?.engagement?.repeatTargets || [];
  if (repeatTargets.length) {
    console.log("  Repeat targets:");
    for (const item of repeatTargets.slice(0, 5)) {
      console.log(`    - ${item.target}: ${item.count}`);
    }
  }
  console.log("");
  console.log(`Funnel`);
  const funnelEvents = Object.entries(telemetry.funnel?.events || {})
    .sort(([, left], [, right]) => right - left);
  if (funnelEvents.length) {
    for (const [event, count] of funnelEvents) {
      console.log(`  ${event}: ${count}`);
    }
  } else {
    console.log("  No funnel events recorded yet.");
  }
  const topFunnelSources = Object.entries(telemetry.funnel?.bySource || {})
    .map(([source, events]) => [
      source,
      Object.values(events || {}).reduce((sum, count) => sum + Number(count || 0), 0),
    ])
    .sort(([, left], [, right]) => right - left)
    .slice(0, 5);
  if (topFunnelSources.length) {
    console.log("  Sources:");
    for (const [source, count] of topFunnelSources) {
      console.log(`    - ${source}: ${count}`);
    }
  }
  console.log("");
  console.log(`Failures`);
  console.log(`  Auth rejected: ${telemetry.failures?.authRejected ?? 0}`);
  console.log(`  Requester rate limited: ${telemetry.failures?.requesterRateLimited ?? 0}`);
  console.log(`  Target rate limited: ${telemetry.failures?.targetRateLimited ?? 0}`);

  const failureClasses = Object.entries(telemetry.failures?.classes || {});
  if (failureClasses.length) {
    console.log("  Classes:");
    for (const [failureClass, count] of failureClasses.sort(([, left], [, right]) => right - left)) {
      console.log(`    - ${failureClass}: ${count}`);
    }
  }
};

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
