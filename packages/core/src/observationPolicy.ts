import { createHash } from "node:crypto";
import type {
  ObservationChange,
  ObservationDriftReport,
  ObservationLedger,
  ObservationPolicy,
  ObservationPolicyEvaluation,
  ObservationPolicyRule,
  ObservationPolicySeverity,
  ObservationPolicyViolation,
  PostureObservation,
} from "./types.js";

const MAX_RULES = 25;
const VALID_OPERATORS = new Set(["eq", "neq", "in", "gte", "lte"]);
const VALID_SEVERITIES = new Set(["info", "warning", "critical"]);
const VALID_SCOPES = new Set(["observation", "change"]);
const VALID_FIELDS = new Set(["status", "value", "confidence", "impact", "severity", "type"]);
const VALID_CATEGORIES = new Set(["transport", "header", "certificate", "dns", "email", "infrastructure", "technology", "trust", "availability"]);

export const DEFAULT_OBSERVATION_POLICY: ObservationPolicy = {
  id: "securl-baseline-v1",
  name: "SecURL baseline",
  version: "1.0",
  rules: [
    {
      id: "certificate-valid",
      title: "Certificate must remain valid",
      severity: "critical",
      scope: "observation",
      selector: { kind: "tls.certificate.valid" },
      assertion: { field: "value", operator: "eq", value: true },
      requireMatch: true,
    },
    {
      id: "certificate-window",
      title: "Certificate must have at least 14 days remaining",
      severity: "critical",
      scope: "observation",
      selector: { kind: "tls.certificate.days_remaining" },
      assertion: { field: "value", operator: "gte", value: 14 },
      requireMatch: true,
    },
    {
      id: "hsts-present",
      title: "HSTS must be present",
      severity: "warning",
      scope: "observation",
      selector: { kind: "http.header.strict-transport-security" },
      assertion: { field: "status", operator: "eq", value: "observed" },
      requireMatch: true,
    },
    {
      id: "csp-present",
      title: "Content Security Policy must be present",
      severity: "warning",
      scope: "observation",
      selector: { kind: "http.header.content-security-policy" },
      assertion: { field: "status", operator: "eq", value: "observed" },
      requireMatch: true,
    },
    {
      id: "dmarc-enforced",
      title: "DMARC should be strong or monitored",
      severity: "warning",
      scope: "observation",
      selector: { kind: "email.dmarc" },
      assertion: { field: "value", operator: "in", value: ["strong", "watch"] },
      requireMatch: true,
    },
    {
      id: "critical-regression",
      title: "Critical observation regressions are not allowed",
      severity: "critical",
      scope: "change",
      selector: {},
      assertion: { field: "severity", operator: "neq", value: "critical" },
      requireMatch: false,
    },
  ],
};

function boundedText(value: unknown, field: string, max: number): string {
  if (typeof value !== "string" || !value.trim() || value.length > max) {
    throw new Error(`Observation policy ${field} must be a non-empty string up to ${max} characters.`);
  }
  return value.trim();
}

export function validateObservationPolicy(value: unknown): ObservationPolicy {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Observation policy must be an object.");
  const input = value as Record<string, unknown>;
  if (!Array.isArray(input.rules) || input.rules.length === 0 || input.rules.length > MAX_RULES) {
    throw new Error(`Observation policy must contain between 1 and ${MAX_RULES} rules.`);
  }
  const seen = new Set<string>();
  const rules = input.rules.map((rawRule) => {
    if (!rawRule || typeof rawRule !== "object" || Array.isArray(rawRule)) throw new Error("Each observation policy rule must be an object.");
    const rule = rawRule as Record<string, unknown>;
    const id = boundedText(rule.id, "rule id", 64);
    if (!/^[a-z0-9][a-z0-9._-]*$/i.test(id) || seen.has(id)) throw new Error(`Observation policy rule id is invalid or duplicated: ${id}.`);
    seen.add(id);
    if (!VALID_SEVERITIES.has(String(rule.severity))) throw new Error(`Observation policy rule ${id} has an invalid severity.`);
    if (!VALID_SCOPES.has(String(rule.scope))) throw new Error(`Observation policy rule ${id} has an invalid scope.`);
    const selector = rule.selector && typeof rule.selector === "object" && !Array.isArray(rule.selector)
      ? rule.selector as Record<string, unknown>
      : {};
    const assertion = rule.assertion && typeof rule.assertion === "object" && !Array.isArray(rule.assertion)
      ? rule.assertion as Record<string, unknown>
      : null;
    if (!assertion || !VALID_FIELDS.has(String(assertion.field)) || !VALID_OPERATORS.has(String(assertion.operator))) {
      throw new Error(`Observation policy rule ${id} has an invalid assertion.`);
    }
    if (selector.category !== undefined && !VALID_CATEGORIES.has(String(selector.category))) {
      throw new Error(`Observation policy rule ${id} has an invalid selector category.`);
    }
    if (rule.scope === "observation" && ["impact", "severity", "type"].includes(String(assertion.field))) {
      throw new Error(`Observation policy rule ${id} uses a change-only field for an observation rule.`);
    }
    if (rule.scope === "change" && ["status", "confidence"].includes(String(assertion.field))) {
      throw new Error(`Observation policy rule ${id} uses an observation-only field for a change rule.`);
    }
    if (assertion.operator === "in" && !Array.isArray(assertion.value)) throw new Error(`Observation policy rule ${id} requires an array value for in.`);
    if ((assertion.operator === "gte" || assertion.operator === "lte") && typeof assertion.value !== "number") {
      throw new Error(`Observation policy rule ${id} requires a numeric assertion value.`);
    }
    return {
      id,
      title: boundedText(rule.title, `rule ${id} title`, 160),
      ...(typeof rule.description === "string" ? { description: rule.description.trim().slice(0, 500) } : {}),
      enabled: rule.enabled !== false,
      severity: rule.severity,
      scope: rule.scope,
      selector: {
        ...(typeof selector.kind === "string" ? { kind: selector.kind.slice(0, 160) } : {}),
        ...(typeof selector.kindPrefix === "string" ? { kindPrefix: selector.kindPrefix.slice(0, 160) } : {}),
        ...(typeof selector.category === "string" ? { category: selector.category } : {}),
      },
      assertion: {
        field: assertion.field,
        operator: assertion.operator,
        value: assertion.value,
      },
      requireMatch: rule.requireMatch === true,
    } as ObservationPolicyRule;
  });
  return {
    id: boundedText(input.id, "id", 64),
    name: boundedText(input.name, "name", 120),
    version: boundedText(input.version, "version", 32),
    rules,
  };
}

function matchesSelector(entity: PostureObservation | ObservationChange, rule: ObservationPolicyRule): boolean {
  const { selector } = rule;
  return (!selector.kind || entity.kind === selector.kind)
    && (!selector.kindPrefix || entity.kind.startsWith(selector.kindPrefix))
    && (!selector.category || entity.category === selector.category);
}

function actualValue(entity: PostureObservation | ObservationChange, field: ObservationPolicyRule["assertion"]["field"]): unknown {
  if (field === "value") return "current" in entity ? entity.current?.value ?? null : entity.value;
  return entity[field as keyof typeof entity] ?? null;
}

function assertionPasses(actual: unknown, rule: ObservationPolicyRule): boolean {
  const { operator, value } = rule.assertion;
  if (operator === "eq") return JSON.stringify(actual) === JSON.stringify(value);
  if (operator === "neq") return JSON.stringify(actual) !== JSON.stringify(value);
  if (operator === "in") return Array.isArray(value) && value.some((candidate) => JSON.stringify(candidate) === JSON.stringify(actual));
  if (operator === "gte") return typeof actual === "number" && typeof value === "number" && actual >= value;
  if (operator === "lte") return typeof actual === "number" && typeof value === "number" && actual <= value;
  return false;
}

function violationId(ruleId: string, entityId: string): string {
  return `pol_${createHash("sha256").update(`${ruleId}\u0000${entityId}`).digest("hex").slice(0, 20)}`;
}

function violationFor(rule: ObservationPolicyRule, entity: PostureObservation | ObservationChange | null): ObservationPolicyViolation {
  const actual = entity ? actualValue(entity, rule.assertion.field) : null;
  const isChange = entity && "observationId" in entity;
  const entityId = entity?.id ?? "missing";
  return {
    id: violationId(rule.id, entityId),
    ruleId: rule.id,
    title: rule.title,
    severity: rule.severity,
    scope: rule.scope,
    observationId: isChange ? entity.observationId : entity?.id ?? null,
    changeId: isChange ? entity.id : null,
    kind: entity?.kind ?? rule.selector.kind ?? rule.selector.kindPrefix ?? null,
    subject: entity?.subject ?? null,
    expected: rule.assertion,
    actual: actual as ObservationPolicyViolation["actual"],
    summary: entity
      ? `${rule.title}: ${rule.assertion.field} ${rule.assertion.operator} ${JSON.stringify(rule.assertion.value)} was not satisfied.`
      : `${rule.title}: no matching observation was available.`,
  };
}

export function evaluateObservationPolicy({
  ledger,
  drift = null,
  policy = DEFAULT_OBSERVATION_POLICY,
}: {
  ledger: ObservationLedger;
  drift?: ObservationDriftReport | null;
  policy?: ObservationPolicy;
}): ObservationPolicyEvaluation {
  const normalized = validateObservationPolicy(policy);
  const violations: ObservationPolicyViolation[] = [];
  const enabledRules = normalized.rules.filter((rule) => rule.enabled !== false);
  for (const rule of enabledRules) {
    const source = rule.scope === "change" ? drift?.changes ?? [] : ledger.observations;
    const matches = source.filter((entity) => matchesSelector(entity, rule));
    if (!matches.length && rule.requireMatch) violations.push(violationFor(rule, null));
    for (const entity of matches) {
      if (!assertionPasses(actualValue(entity, rule.assertion.field), rule)) violations.push(violationFor(rule, entity));
    }
  }
  const bySeverity: Record<ObservationPolicySeverity, number> = { info: 0, warning: 0, critical: 0 };
  for (const violation of violations) bySeverity[violation.severity] += 1;
  const highestSeverity = bySeverity.critical ? "critical" : bySeverity.warning ? "warning" : bySeverity.info ? "info" : null;
  return {
    version: "1.0",
    policy: { id: normalized.id, name: normalized.name, version: normalized.version },
    target: ledger.target,
    evaluatedAt: ledger.generatedAt,
    passed: violations.length === 0,
    violations,
    summary: {
      rulesEvaluated: enabledRules.length,
      violations: violations.length,
      bySeverity,
      highestSeverity,
    },
  };
}
