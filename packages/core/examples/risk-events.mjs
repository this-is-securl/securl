import {
  buildHistoryDiffFromSnapshots,
  snapshotFromAnalysis,
} from "securl/history-diff";
import {
  buildPostureRiskEventsFromSnapshots,
} from "securl/risk-events";

const [currentPath, previousPath] = process.argv.slice(2);

if (!currentPath || !previousPath) {
  console.error("Usage: node risk-events.mjs current-report.json previous-report.json");
  process.exit(1);
}

const current = JSON.parse(await import("node:fs/promises").then((fs) => fs.readFile(currentPath, "utf8")));
const previous = JSON.parse(await import("node:fs/promises").then((fs) => fs.readFile(previousPath, "utf8")));

const currentSnapshot = snapshotFromAnalysis(current.analysis ?? current);
const previousSnapshot = snapshotFromAnalysis(previous.analysis ?? previous);
const diff = buildHistoryDiffFromSnapshots(currentSnapshot, previousSnapshot);
const riskEvents = buildPostureRiskEventsFromSnapshots(currentSnapshot, previousSnapshot, diff);

console.log(JSON.stringify({
  diff,
  riskEvents,
}, null, 2));
