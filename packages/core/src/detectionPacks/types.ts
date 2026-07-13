import type { TechnologyResult } from "../types.js";

export type DetectionConfidence = "high" | "medium" | "low";

export type DetectionField =
  | `headers.${string}`
  | "body";

export type DetectionPredicate =
  | {
      field: DetectionField;
      op: "exists";
    }
  | {
      field: DetectionField;
      op: "containsSubstring";
      value: string;
      caseSensitive?: boolean;
    }
  | {
      field: DetectionField;
      op: "namedPattern";
      pattern: "akamaiReferenceId";
    };

export interface DetectionRuleOutput {
  waf?: {
    name: string;
    confidence: DetectionConfidence;
    detection: "observed" | "inferred";
    evidence: string;
    evidenceWhen?: Array<{
      field: DetectionField;
      op: "exists";
      evidence: string;
    }>;
  };
  technology?: {
    name: string;
    category: TechnologyResult["category"];
    evidence: string;
    evidenceWhen?: Array<{
      field: DetectionField;
      op: "exists" | "containsSubstring";
      value?: string;
      evidence: string;
    }>;
    version: string | null;
    confidence: DetectionConfidence;
    detection: "observed" | "inferred";
  };
}

export interface DetectionRule {
  id: string;
  provider: string;
  priority: number;
  when: DetectionPredicate[][];
  outputs: DetectionRuleOutput;
}

export interface DetectionPack {
  id: string;
  version: string;
  trust: "bundled-first-party";
  rules: DetectionRule[];
}

export interface DetectionEvidenceSnapshot {
  headers: Record<string, string | string[] | undefined>;
  body?: string | null;
}

export interface DetectionMatch {
  packId: string;
  packVersion: string;
  ruleId: string;
  provider: string;
  priority: number;
  outputs: DetectionRuleOutput;
}
