#!/usr/bin/env node
import { readRailwayVariables } from "./lib/readRailwayVariables.mjs";

const DEFAULT_BASE_URL = "https://securl-app-production.up.railway.app";

const formatMs = (value) => `${Math.round(value || 0).toLocaleString()}ms`;
const sumEventCounts = (events = {}) => Object.values(events || {})
  .reduce((sum, count) => sum + Number(count || 0), 0);
const sortedEventBuckets = (buckets = {}) => Object.entries(buckets || {})
  .map(([name, events]) => [name, events || {}, sumEventCounts(events)])
  .filter(([, , total]) => total > 0)
  .sort(([, , left], [, , right]) => right - left);
const describeEventCounts = (events = {}) => Object.entries(events || {})
  .filter(([, count]) => Number(count || 0) > 0)
  .sort(([, left], [, right]) => Number(right || 0) - Number(left || 0))
  .map(([event, count]) => `${event}: ${count}`)
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
  console.log("Client consumption");
  const clientConsumption = telemetry.clients?.consumption || {};
  console.log(`  Backend API events: ${clientConsumption.backendApiEvents ?? 0}`);
  console.log(`  Today: ${clientConsumption.todayBackendApiEvents ?? 0}`);
  console.log(`  Monitoring target registrations: ${clientConsumption.monitoringTargetRegistrations ?? 0}`);
  console.log(`  Mobile monitoring summary reads: ${clientConsumption.monitoringMobileSummaryReads ?? 0}`);
  console.log(`  Notification device registrations: ${clientConsumption.notificationDeviceRegistrations ?? 0}`);
  console.log(`  Notification device health reads: ${clientConsumption.notificationDeviceHealthReads ?? 0}`);
  console.log(`  Notification test requests: ${clientConsumption.notificationTestRequests ?? 0}`);
  console.log(`  Live certificate reads: ${clientConsumption.liveCertificateReads ?? 0}`);
  console.log(`  Live certificate failures: ${clientConsumption.liveCertificateFailures ?? 0}`);
  const todayConsumption = clientConsumption.today || {};
  const todayConsumptionRows = Object.entries(todayConsumption)
    .filter(([, count]) => Number(count || 0) > 0)
    .sort(([, left], [, right]) => Number(right || 0) - Number(left || 0));
  if (todayConsumptionRows.length) {
    console.log("  Today by event:");
    for (const [event, count] of todayConsumptionRows) {
      console.log(`    - ${event}: ${count}`);
    }
  }
  const activeSignals = Object.entries(clientConsumption.adoptionSignals || {})
    .filter(([, active]) => active)
    .map(([signal]) => signal);
  console.log(`  Active signals: ${activeSignals.length ? activeSignals.join(", ") : "none"}`);
  const todayByClient = sortedEventBuckets(telemetry.funnel?.todayByClient);
  if (todayByClient.length) {
    console.log("  Today by app/client:");
    for (const [client, events, total] of todayByClient.slice(0, 8)) {
      console.log(`    - ${client}: ${total} (${describeEventCounts(events)})`);
    }
  }
  const todayByVersion = sortedEventBuckets(telemetry.funnel?.todayByClientVersion);
  if (todayByVersion.length) {
    console.log("  Today by client version:");
    for (const [version, events, total] of todayByVersion.slice(0, 8)) {
      console.log(`    - ${version}: ${total} (${describeEventCounts(events)})`);
    }
  }
  const todayBySource = sortedEventBuckets(telemetry.funnel?.todayBySource);
  if (todayBySource.length) {
    console.log("  Today by backend source:");
    for (const [source, events, total] of todayBySource.slice(0, 8)) {
      console.log(`    - ${source}: ${total} (${describeEventCounts(events)})`);
    }
  }
  const clientModes = Object.entries(clientConsumption.byMode || {})
    .map(([mode, events]) => [
      mode,
      Object.values(events || {}).reduce((sum, count) => sum + Number(count || 0), 0),
    ])
    .filter(([, count]) => count > 0)
    .sort(([, left], [, right]) => right - left);
  if (clientModes.length) {
    console.log("  Apps / modes:");
    for (const [mode, count] of clientModes) {
      console.log(`    - ${mode}: ${count}`);
    }
  }
  const clientIdentity = telemetry.clients?.identity || {};
  const identifiedClients = new Set([
    ...Object.keys(clientIdentity.scanRequestsByClient || {}),
    ...Object.keys(clientIdentity.backendEventsByClient || {}),
  ]);
  if (identifiedClients.size) {
    console.log("  Identified clients:");
    for (const client of [...identifiedClients].sort()) {
      const scans = clientIdentity.scanRequestsByClient?.[client] || 0;
      const events = Object.values(clientIdentity.backendEventsByClient?.[client] || {})
        .reduce((sum, count) => sum + Number(count || 0), 0);
      console.log(`    - ${client}: ${scans} scans / ${events} service events`);
    }
  }
  const identifiedVersions = new Set([
    ...Object.keys(clientIdentity.scanRequestsByClientVersion || {}),
    ...Object.keys(clientIdentity.backendEventsByClientVersion || {}),
  ]);
  if (identifiedVersions.size) {
    console.log("  Client versions:");
    for (const version of [...identifiedVersions].sort()) {
      const scans = clientIdentity.scanRequestsByClientVersion?.[version] || 0;
      const events = Object.values(clientIdentity.backendEventsByClientVersion?.[version] || {})
        .reduce((sum, count) => sum + Number(count || 0), 0);
      console.log(`    - ${version}: ${scans} scans / ${events} service events`);
    }
  }
  const recentBackendEvents = (telemetry.funnel?.recent || [])
    .filter((event) => event?.source === "backend_api")
    .slice(0, 8);
  if (recentBackendEvents.length) {
    console.log("  Recent backend events:");
    for (const event of recentBackendEvents) {
      const clientLabel = event.client
        ? `${event.client}${event.clientVersion ? `@${event.clientVersion}` : ""}`
        : "unknown-client";
      const targetLabel = event.target ? ` ${event.target}` : "";
      console.log(`    - ${event.occurredAt} ${event.event} ${clientLabel}${targetLabel}`);
    }
  }
  const delivery = telemetry.notifications?.delivery || {};
  console.log("");
  console.log("Notification delivery");
  console.log(`  Batches: ${delivery.batches ?? 0}`);
  console.log(`  Devices attempted: ${delivery.attempted ?? 0}`);
  console.log(`  APNs attempts: ${delivery.attempts ?? 0}`);
  console.log(`  Sent: ${delivery.sent ?? 0}`);
  console.log(`  Failed: ${delivery.failed ?? 0}`);
  console.log(`  Retried: ${delivery.retried ?? 0}`);
  console.log(`  Tokens disabled: ${delivery.disabled ?? 0}`);
  const skippedDeliveries = Object.entries(delivery.skipped || {});
  if (skippedDeliveries.length) {
    console.log("  Skipped:");
    for (const [reason, count] of skippedDeliveries.sort(([, left], [, right]) => right - left)) {
      console.log(`    - ${reason}: ${count}`);
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
