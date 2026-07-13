# Detection Packs Architecture Proposal

Status: proposed architecture slice, not implemented.

SecURL's current detection knowledge is intentionally static and compiled into the
engine. That keeps the package small, deterministic, and auditable, but the provider
catalogue is now duplicated across WAF, infrastructure, identity, CT/takeover, HTML, and
vendor-exposure code paths. The right next step is not arbitrary third-party plugins. It
is a constrained declarative detection-pack layer that can scale detection knowledge
without weakening the passive scanner boundary.

## Goals

- Let first-party and, later, reviewed contributor packs add provider and infrastructure
  inference rules without editing scan orchestration.
- Preserve deterministic scan output, package trust, SSRF controls, and bounded runtime.
- Make detection evidence fixture-driven and reviewable.
- Avoid executable third-party code in hosted production.
- Reduce duplication between existing provider tables.

## Current seams

The first pack candidates are the static, bounded inference tables already present in:

- `packages/core/src/wafFingerprint.ts` — response-header and body-marker WAF/CDN
  inference.
- `packages/core/src/infrastructure.ts` — DNS, reverse DNS, response-header, and technology
  provider signatures.
- `packages/core/src/identityProvider.ts` — identity-provider host/domain patterns.
- `packages/core/src/technology-detection.ts` — server/header technology inference.
- `packages/core/src/ctDiscovery.ts` — CT host categorisation, WAF sampling patterns, and
  takeover signatures.
- `packages/core/src/html-page-analysis.ts` and `packages/core/src/html-extraction.ts` —
  bounded HTML/client signal extraction.
- `packages/core/src/vendorExposure.ts` — inventory role, risk, data-flow, integrity, and
  review-priority projection from existing signals.

These seams all consume already-fetched bounded evidence. None needs independent network
I/O.

## Hard boundaries

Detection packs must not:

- perform network, filesystem, process, timer, random, or environment access;
- define arbitrary JavaScript callbacks;
- add redirect, DNS, TLS, HTTP, or certificate fetch behavior;
- bypass `network-validation.ts` or pinned public-target connection policy;
- use unreviewed regular expressions over unbounded input;
- alter scoring weights, scan duration, redirects, crawl depth, or API contracts;
- emit nondeterministic output based on import order or object iteration order.

All fetching remains centralised in the scanner. Packs receive immutable, size-bounded
evidence snapshots only.

## Evidence snapshot

The evaluator should receive a normalized evidence object derived from existing scan
artifacts:

```ts
interface DetectionEvidenceSnapshot {
  finalUrl: {
    href: string;
    hostname: string;
    registrableDomain: string | null;
    protocol: "http:" | "https:";
  };
  headers: Record<string, string>;
  html: {
    title: string | null;
    signature: string;
    externalScriptHosts: string[];
    externalStylesheetHosts: string[];
    firstPartyPaths: string[];
    missingSriScriptHosts: string[];
  };
  dns: {
    cnameTargets: string[];
    reverseDns: string[];
    addresses: string[];
  };
  redirects: Array<{
    statusCode: number;
    locationHost: string | null;
  }>;
  ctHosts: Array<{
    host: string;
    category: "auth" | "edge" | "api" | "admin" | "other";
    cnameTargets: string[];
    responseKind?: string;
    bodySignature?: string;
  }>;
}
```

Evidence fields should be capped using existing limits such as `TEXT_BODY_LIMIT`,
`HTML_SIGNATURE_LIMIT`, `SUMMARY_EVIDENCE_LIMIT`, `CT_SAMPLE_LIMIT`, and crawl/probe
limits in `scannerConfig.ts`.

## Pack schema shape

The first schema should stay small enough to implement and test without architecture
thrash:

```json
{
  "schemaVersion": "securl-detection-pack-v1",
  "pack": {
    "id": "securl.first-party.edge",
    "version": "1.0.0",
    "publisher": "this-is-securl",
    "trust": "bundled-first-party"
  },
  "rules": [
    {
      "id": "edge.cloudflare.cf-ray",
      "kind": "provider",
      "provider": "Cloudflare",
      "roles": ["edge", "cdn", "waf"],
      "confidence": "high",
      "priority": 100,
      "when": [
        { "field": "headers.cf-ray", "op": "exists" }
      ],
      "evidence": "Observed cf-ray response header.",
      "outputs": {
        "technology": { "category": "network" },
        "infrastructure": { "category": "edge" },
        "waf": { "detection": "observed" },
        "inventory": {
          "role": "infrastructure",
          "dataFlow": "content_delivery",
          "reviewPriority": "routine"
        }
      }
    }
  ]
}
```

Allowed match operations for v1:

- `exists`
- `equals`
- `containsToken`
- `containsSubstring`
- `domainEquals`
- `domainSuffix`
- `pathPrefix`
- `anyOf`
- `allOf`

Regular expressions should not be a public v1 operation. If a pattern vocabulary is
needed, use reviewed named predicates such as `looksLikeAkamaiReferenceId` or
`looksLikeDynamicDnsHost`, implemented in trusted engine code with bounded inputs and
tests.

## Evaluation model

1. Validate pack JSON against a bundled JSON Schema.
2. Reject packs exceeding hard limits:
   - max rules per pack;
   - max predicates per rule;
   - max evidence string length;
   - max provider/name/domain string length;
   - max output roles/categories.
3. Compile rules into indexes by evidence kind:
   - header exact key;
   - host/domain suffix;
   - CNAME/reverse-DNS suffix;
   - HTML host/path;
   - CT host category/body signature.
4. Evaluate using deterministic order:
   - pack trust tier;
   - pack ID;
   - rule priority descending;
   - rule ID.
5. Deduplicate outputs by stable IDs, not discovery order.
6. Return structured matches with:
   - `packId`;
   - `packVersion`;
   - `ruleId`;
   - `provider`;
   - `roles`;
   - `confidence`;
   - `evidence`;
   - `sourceFields`.

The evaluator should be pure and synchronous. It must not be able to await I/O.

## Trust tiers

Start with one tier only:

1. `bundled-first-party` — shipped inside the npm package, reviewed in normal PRs, covered
   by fixtures and release checks.

Do not add runtime-downloaded packs until the product has:

- signing/provenance;
- compatibility negotiation;
- incident rollback;
- hosted allow-listing;
- pack linting;
- worst-case benchmark gates;
- a human review story.

Executable third-party plugins are explicitly out of scope for this phase.

## Threat model

| Threat | Control |
| --- | --- |
| Malicious pack tries SSRF | Packs have no URL fetch, DNS, redirect, TLS, or callback capability. |
| ReDoS via regex | No arbitrary regex in public schema; named predicates only. |
| Event-loop monopolisation | Rule and predicate caps; indexed evaluation; benchmark gates. |
| Nondeterministic reports | Stable pack/rule order and output IDs. |
| Supply-chain compromise | Bundled first-party packs only for v1; npm provenance remains unchanged. |
| False confidence | Rules must declare confidence, evidence source, fixtures, and output scope. |
| Hosted/CLI divergence | Same bundled packs and evaluator used across package, API, and web. |

## Test and benchmark requirements

Before implementation is considered complete:

- fixture tests for each migrated provider/rule family;
- golden-output tests showing unchanged scan output for representative sites before and
  after migrating static tables;
- malicious-pack validation tests for overlarge fields, unsupported operations, bad IDs,
  unknown output categories, and regex/code injection attempts;
- benchmark for cold import, pack validation, compile time, and match time over synthetic
  catalogues;
- server smoke confirming hosted API capabilities and output contracts are unchanged.

## Rollout plan

1. Build an internal evaluator and schema in `packages/core/src/detectionPacks/`.
2. Migrate one low-risk duplicated seam first, preferably Cloudflare/Fastly/Akamai edge
   provider inference across WAF, infrastructure, and technology output.
3. Keep current exports and output DTOs unchanged.
4. Prove golden output equivalence.
5. Add package docs that frame packs as bundled declarative detection knowledge, not
   executable plugins.
6. Only after the internal migration is stable, consider a contributor-facing pack authoring
   guide for reviewed first-party inclusion.

## Non-goals

- No hosted scanner support for user-uploaded packs.
- No npm-installed third-party executable plugins.
- No dynamic remote pack registry.
- No new scan probes, crawl expansion, or enrichment network calls.
- No scoring changes merely because a provider was detected through a pack.
- No mobile client implementation work. Mobile may consume existing output only after a
  backend contract is shipped, deployed, validated, and explicitly handed off.

## Recommended next executable slice

Open a `PACKAGE_AFFECTING` architecture/implementation PR for an internal
`DetectionPack` schema and evaluator, then migrate the smallest duplicated edge-provider
rules. If output remains byte-for-byte compatible on fixtures and performance remains
within current bounds, that becomes the foundation for future declarative provider packs.
