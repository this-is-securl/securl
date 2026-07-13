import type {
  DetectionEvidenceSnapshot,
  DetectionField,
  DetectionMatch,
  DetectionPack,
  DetectionPredicate,
  DetectionRule,
} from "./types.js";

const MAX_RULES_PER_PACK = 100;
const MAX_PREDICATE_GROUPS_PER_RULE = 8;
const MAX_PREDICATES_PER_GROUP = 8;
const MAX_FIELD_VALUE_LENGTH = 20_000;

const normalizeHeaderName = (name: string) => name.trim().toLowerCase();

export const detectionHeaderValue = (
  headers: Record<string, string | string[] | undefined>,
  name: string,
): string | null => {
  const normalizedName = normalizeHeaderName(name);
  const direct = headers[normalizedName];
  const value = direct ?? Object.entries(headers).find(([key]) => normalizeHeaderName(key) === normalizedName)?.[1];
  if (Array.isArray(value)) {
    return value.join(", ");
  }
  return value ?? null;
};

const fieldValue = (snapshot: DetectionEvidenceSnapshot, field: DetectionField): string | null => {
  if (field === "body") {
    return (snapshot.body ?? "").slice(0, MAX_FIELD_VALUE_LENGTH);
  }
  if (field.startsWith("headers.")) {
    return detectionHeaderValue(snapshot.headers, field.slice("headers.".length));
  }
  return null;
};

const matchesNamedPattern = (value: string, pattern: Extract<DetectionPredicate, { op: "namedPattern" }>["pattern"]) => {
  if (pattern === "akamaiReferenceId") {
    return /reference #\d+\.[a-z0-9.]+\.akamai/i.test(value);
  }
  return false;
};

const matchesPredicate = (snapshot: DetectionEvidenceSnapshot, predicate: DetectionPredicate): boolean => {
  const value = fieldValue(snapshot, predicate.field);
  if (predicate.op === "exists") {
    return Boolean(value);
  }
  if (!value) {
    return false;
  }
  if (predicate.op === "containsSubstring") {
    const haystack = predicate.caseSensitive ? value : value.toLowerCase();
    const needle = predicate.caseSensitive ? predicate.value : predicate.value.toLowerCase();
    return haystack.includes(needle);
  }
  if (predicate.op === "namedPattern") {
    return matchesNamedPattern(value, predicate.pattern);
  }
  return false;
};

const matchesRule = (snapshot: DetectionEvidenceSnapshot, rule: DetectionRule): boolean =>
  rule.when.some((group) => group.every((predicate) => matchesPredicate(snapshot, predicate)));

const validatePack = (pack: DetectionPack) => {
  if (pack.trust !== "bundled-first-party") {
    throw new Error(`Unsupported detection pack trust tier: ${pack.trust}`);
  }
  if (pack.rules.length > MAX_RULES_PER_PACK) {
    throw new Error(`Detection pack ${pack.id} exceeds the rule limit`);
  }
  for (const rule of pack.rules) {
    if (rule.when.length > MAX_PREDICATE_GROUPS_PER_RULE) {
      throw new Error(`Detection rule ${rule.id} exceeds the predicate-group limit`);
    }
    for (const group of rule.when) {
      if (group.length > MAX_PREDICATES_PER_GROUP) {
        throw new Error(`Detection rule ${rule.id} exceeds the predicate limit`);
      }
    }
  }
};

export const evaluateDetectionPacks = (
  snapshot: DetectionEvidenceSnapshot,
  packs: DetectionPack[],
): DetectionMatch[] => {
  const matches: DetectionMatch[] = [];
  for (const pack of packs) {
    validatePack(pack);
    const sortedRules = [...pack.rules].sort((left, right) => {
      const priorityDelta = right.priority - left.priority;
      if (priorityDelta !== 0) return priorityDelta;
      return left.id.localeCompare(right.id);
    });
    for (const rule of sortedRules) {
      if (!matchesRule(snapshot, rule)) {
        continue;
      }
      matches.push({
        packId: pack.id,
        packVersion: pack.version,
        ruleId: rule.id,
        provider: rule.provider,
        priority: rule.priority,
        outputs: rule.outputs,
      });
    }
  }
  return matches.sort((left, right) => {
    const priorityDelta = right.priority - left.priority;
    if (priorityDelta !== 0) return priorityDelta;
    const packDelta = left.packId.localeCompare(right.packId);
    if (packDelta !== 0) return packDelta;
    return left.ruleId.localeCompare(right.ruleId);
  });
};

export const evidenceForWafOutput = (
  snapshot: DetectionEvidenceSnapshot,
  output: NonNullable<DetectionRule["outputs"]["waf"]>,
): string => {
  for (const override of output.evidenceWhen ?? []) {
    if (override.op === "exists" && matchesPredicate(snapshot, override)) {
      return override.evidence;
    }
  }
  return output.evidence;
};

export const evidenceForTechnologyOutput = (
  snapshot: DetectionEvidenceSnapshot,
  output: NonNullable<DetectionRule["outputs"]["technology"]>,
): string => {
  for (const override of output.evidenceWhen ?? []) {
    if (override.op === "exists" && matchesPredicate(snapshot, {
      field: override.field,
      op: "exists",
    })) {
      return override.evidence;
    }
    if (
      override.op === "containsSubstring" &&
      typeof override.value === "string" &&
      matchesPredicate(snapshot, {
        field: override.field,
        op: "containsSubstring",
        value: override.value,
      })
    ) {
      return override.evidence;
    }
  }
  return output.evidence;
};
