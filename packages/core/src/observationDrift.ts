import { createHash } from "node:crypto";
import type {
  ObservationChange,
  ObservationChangeImpact,
  ObservationChangeSeverity,
  ObservationChangeType,
  ObservationDriftReport,
  ObservationLedger,
  ObservationStatus,
  PostureObservation,
} from "./types.js";

const STATUS_RANK: Record<ObservationStatus, number> = {
  unavailable: 0,
  missing: 1,
  inferred: 2,
  observed: 3,
};

const CRITICAL_KINDS = new Set([
  "tls.certificate.valid",
  "email.dmarc",
  "http.header.strict-transport-security",
  "http.header.content-security-policy",
]);

function equalValue(left: PostureObservation["value"], right: PostureObservation["value"]): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function certificateBand(days: number): number {
  if (days < 0) return 0;
  if (days <= 7) return 1;
  if (days <= 14) return 2;
  if (days <= 30) return 3;
  return 4;
}

function impactFor(previous: PostureObservation | null, current: PostureObservation | null): ObservationChangeImpact {
  if (!previous && current) {
    return current.status === "missing" || current.status === "unavailable" ? "regression" : "change";
  }
  if (previous && !current) {
    return previous.status === "missing" || previous.status === "unavailable" ? "improvement" : "regression";
  }
  if (!previous || !current) return "change";
  if (STATUS_RANK[current.status] < STATUS_RANK[previous.status]) return "regression";
  if (STATUS_RANK[current.status] > STATUS_RANK[previous.status]) return "improvement";
  if (current.kind === "tls.certificate.days_remaining"
    && typeof previous.value === "number"
    && typeof current.value === "number") {
    const previousBand = certificateBand(previous.value);
    const currentBand = certificateBand(current.value);
    if (currentBand < previousBand) return "regression";
    if (currentBand > previousBand || current.value > previous.value + 7) return "improvement";
    return "change";
  }
  if (current.kind === "tls.certificate.valid"
    && typeof previous.value === "boolean"
    && typeof current.value === "boolean") {
    return current.value ? "improvement" : "regression";
  }
  return "change";
}

function severityFor(kind: string, impact: ObservationChangeImpact, current: PostureObservation | null): ObservationChangeSeverity {
  if (impact !== "regression") return "info";
  if (kind === "tls.certificate.valid" && current?.value === false) return "critical";
  if (CRITICAL_KINDS.has(kind) && (current?.status === "missing" || current?.status === "unavailable")) return "critical";
  if (kind === "tls.certificate.days_remaining" && typeof current?.value === "number" && current.value <= 14) return "critical";
  return "warning";
}

function changeId(observationId: string, type: ObservationChangeType): string {
  return `chg_${createHash("sha256").update(`${observationId}\u0000${type}`).digest("hex").slice(0, 20)}`;
}

function summaryFor(type: ObservationChangeType, previous: PostureObservation | null, current: PostureObservation | null): string {
  const label = current?.kind ?? previous?.kind ?? "observation";
  if (type === "added") return `${label} was newly detected.`;
  if (type === "removed") return `${label} is no longer detected.`;
  if (type === "status_changed") return `${label} changed from ${previous?.status} to ${current?.status}.`;
  if (type === "confidence_changed") return `${label} confidence changed from ${previous?.confidence} to ${current?.confidence}.`;
  return `${label} changed from ${JSON.stringify(previous?.value)} to ${JSON.stringify(current?.value)}.`;
}

function buildChange(type: ObservationChangeType, previous: PostureObservation | null, current: PostureObservation | null): ObservationChange {
  const observation = current ?? previous;
  if (!observation) throw new Error("Observation change requires a current or previous value.");
  const impact = impactFor(previous, current);
  return {
    id: changeId(observation.id, type),
    observationId: observation.id,
    type,
    impact,
    severity: severityFor(observation.kind, impact, current),
    category: observation.category,
    kind: observation.kind,
    subject: observation.subject,
    previous,
    current,
    summary: summaryFor(type, previous, current),
  };
}

export function diffObservationLedgers(current: ObservationLedger, previous: ObservationLedger): ObservationDriftReport {
  const currentById = new Map(current.observations.map((observation) => [observation.id, observation]));
  const previousById = new Map(previous.observations.map((observation) => [observation.id, observation]));
  const changes: ObservationChange[] = [];

  for (const observation of current.observations) {
    const before = previousById.get(observation.id) ?? null;
    if (!before) {
      changes.push(buildChange("added", null, observation));
      continue;
    }
    if (before.status !== observation.status) changes.push(buildChange("status_changed", before, observation));
    if (!equalValue(before.value, observation.value)) changes.push(buildChange("value_changed", before, observation));
    if (before.confidence !== observation.confidence) changes.push(buildChange("confidence_changed", before, observation));
  }
  for (const observation of previous.observations) {
    if (!currentById.has(observation.id)) changes.push(buildChange("removed", observation, null));
  }

  const severityRank = { critical: 3, warning: 2, info: 1 } as const;
  changes.sort((left, right) => severityRank[right.severity] - severityRank[left.severity] || left.id.localeCompare(right.id));
  const regressions = changes.filter((change) => change.impact === "regression").length;
  const improvements = changes.filter((change) => change.impact === "improvement").length;
  const bySeverity = { info: 0, warning: 0, critical: 0 };
  const byCategory: ObservationDriftReport["summary"]["byCategory"] = {};
  for (const change of changes) {
    bySeverity[change.severity] += 1;
    byCategory[change.category] = (byCategory[change.category] ?? 0) + 1;
  }

  return {
    version: "1.0",
    target: current.target,
    comparedAt: current.generatedAt,
    previousObservedAt: previous.generatedAt,
    currentObservedAt: current.generatedAt,
    changes,
    summary: {
      direction: regressions ? "regressed" : improvements ? "improved" : changes.length ? "changed" : "unchanged",
      total: changes.length,
      regressions,
      improvements,
      neutralChanges: changes.length - regressions - improvements,
      bySeverity,
      byCategory,
    },
  };
}
