import type { DetectionPack } from "./types.js";

export const EDGE_PROVIDER_PACK: DetectionPack = {
  id: "securl.first-party.edge-providers",
  version: "1.0.0",
  trust: "bundled-first-party",
  rules: [
    {
      id: "edge.cloudflare",
      provider: "Cloudflare",
      priority: 100,
      when: [
        [{ field: "headers.cf-ray", op: "exists" }],
        [{ field: "headers.cf-cache-status", op: "exists" }],
        [{ field: "headers.server", op: "containsSubstring", value: "cloudflare" }],
        [{ field: "body", op: "containsSubstring", value: "attention required" }],
        [{ field: "body", op: "containsSubstring", value: "cloudflare" }],
      ],
      outputs: {
        waf: {
          name: "Cloudflare",
          confidence: "high",
          detection: "observed",
          evidence: "Observed Cloudflare-branded edge response markers.",
          evidenceWhen: [
            {
              field: "headers.cf-ray",
              op: "exists",
              evidence: "Observed cf-ray / Cloudflare edge headers.",
            },
          ],
        },
        technology: {
          name: "Cloudflare",
          category: "network",
          evidence: "Observed in Cloudflare response headers",
          version: null,
          confidence: "high",
          detection: "observed",
        },
      },
    },
    {
      id: "edge.akamai",
      provider: "Akamai",
      priority: 90,
      when: [
        [{ field: "headers.x-akamai-transformed", op: "exists" }],
        [{ field: "headers.akamai-cache-status", op: "exists" }],
        [{ field: "headers.server", op: "containsSubstring", value: "akamai" }],
        [{ field: "body", op: "namedPattern", pattern: "akamaiReferenceId" }],
      ],
      outputs: {
        waf: {
          name: "Akamai",
          confidence: "high",
          detection: "observed",
          evidence: "Observed Akamai edge headers or block-page signatures.",
        },
        technology: {
          name: "Akamai",
          category: "network",
          evidence: "Observed in Akamai response headers",
          version: null,
          confidence: "high",
          detection: "observed",
        },
      },
    },
    {
      id: "edge.fastly",
      provider: "Fastly",
      priority: 80,
      when: [
        [{ field: "headers.x-cache", op: "containsSubstring", value: "fastly" }],
        [{ field: "headers.x-served-by", op: "containsSubstring", value: "cache-" }],
      ],
      outputs: {
        waf: {
          name: "Fastly",
          confidence: "medium",
          detection: "observed",
          evidence: "Observed Fastly cache headers.",
        },
        technology: {
          name: "Fastly",
          category: "network",
          evidence: "Observed in Fastly response headers",
          evidenceWhen: [
            {
              field: "headers.x-cache",
              op: "containsSubstring",
              value: "fastly",
              evidence: "Observed in X-Cache header",
            },
            {
              field: "headers.x-served-by",
              op: "containsSubstring",
              value: "cache-",
              evidence: "Observed in X-Served-By cache headers",
            },
          ],
          version: null,
          confidence: "high",
          detection: "observed",
        },
      },
    },
    {
      id: "edge.aws-cloudfront",
      provider: "AWS CloudFront / WAF",
      priority: 70,
      when: [
        [{ field: "headers.x-amz-cf-id", op: "exists" }],
      ],
      outputs: {
        waf: {
          name: "AWS CloudFront / WAF",
          confidence: "medium",
          detection: "observed",
          evidence: "Observed CloudFront edge headers.",
        },
        technology: {
          name: "Amazon CloudFront",
          category: "network",
          evidence: "Observed in CloudFront response headers",
          version: null,
          confidence: "high",
          detection: "observed",
        },
      },
    },
    {
      id: "edge.aws-cloudfront-server",
      provider: "AWS CloudFront / WAF",
      priority: 69,
      when: [
        [{ field: "headers.server", op: "containsSubstring", value: "cloudfront" }],
      ],
      outputs: {
        waf: {
          name: "AWS CloudFront / WAF",
          confidence: "medium",
          detection: "observed",
          evidence: "Observed CloudFront edge headers.",
        },
      },
    },
  ],
};

export const FIRST_PARTY_DETECTION_PACKS = [EDGE_PROVIDER_PACK];
