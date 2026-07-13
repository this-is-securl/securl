# SecURL Product Roadmap

SecURL is evolving from a one-shot scanner into a public security posture intelligence layer for developers, mobile users, security teams, and lightweight automation.

The product thesis is simple: people should be able to understand how a public URL, service, vendor, or certificate looks from the outside without credentials, agents, invasive probing, or noisy reconnaissance. SecURL should make that read fast, repeatable, explainable, and useful everywhere: CLI, CI/CD, API, web, and mobile.

A useful mental model is the external security "recipe card." SBOMs help teams understand what an application is made of internally; SecURL should help them understand what that application exposes externally: public services, headers, cookies, TLS, DNS trust, certificate posture, third-party surface, visible vendors, policy fit, and what changed since the last known-good scan.

## Current Signals

The roadmap is based on the signals now visible across the product system:

- The `securl` npm package is getting meaningful weekly downloads, with provenance enabled and no install scripts.
- The iOS apps have real backend activity, especially Cert Watch live certificate reads.
- APNs delivery has been reliable in production, with zero observed failed or disabled-token delivery in recent telemetry.
- The web landing page is now instrumented as a routing funnel, but mobile and npm currently show the clearest engagement signals.
- The deprecated scoped package still receives residual downloads, which suggests historical discovery and automation paths are still alive.

## Current Operating Focus - July 2026

After a fast sequence of mobile releases and backend contract work, the next short window deliberately lets the mobile suite settle while the engine and public-facing surfaces get ahead again.

For the next few days, priority order is:

1. **Engine/package/API first**: improve the npm-consumable engine, hosted API contracts, policy/manifest examples, release evidence, and architecture/safety documentation.
2. **Public websites second**: make `securl.online` and `app.securl.online` explain the product system clearly, link to downloads and docs, and route interested users toward the web app, npm package, and self-hosted/mobile surfaces.
3. **Mobile later**: keep mobile contracts stable and additive, but avoid new mobile feature pressure until the current app wave has had time to settle in production.

This does not reduce the importance of the mobile suite. It preserves the principle that the engine is the source of truth, with web and mobile acting as increasingly polished views over the same passive posture intelligence.

## Product Tracks

### 1. Engine Authority

Goal: make `securl` the best lightweight outside-in posture engine for public URL security judgement.

Near-term work:

- Improve package-visible workflows that npm users can run without the hosted backend.
- Keep CLI, JSON, Markdown, SARIF, and CI outputs stable and useful.
- Promote `observationPolicy` into a first-class policy engine with named profiles, assertion results, and stable failure semantics.
- Add a `posture-manifest` output: a machine-readable external posture recipe card that records what was checked, what was skipped, evidence quality, signal clarity, engine version, policy profile, and timestamps.
- Treat CycloneDX/SBOM-style interoperability as a later export target for the posture manifest, not as a claim that SecURL is producing a dependency SBOM.
- Expand fast single-purpose commands where the engine already has focused capability, such as `securl cert`.
- Continue reducing false positives and making passive findings easier to trust.
- Keep package trust strong: provenance, no install scripts, small dependency surface, clear changelog, and explicit passive boundaries.

Delivered releases:

- `1.20`: Posture Manifest v1 and package/CLI integration examples.
- `1.21`: Policy Pack v1 with named profiles and deterministic assertion semantics.
- `1.22`: exported Posture Manifest JSON Schema and `securl schema manifest`.
- `1.23`: External Exposure Inventory v1 with stable provider IDs, roles, data-flow
  purpose, confidence/evidence, SRI status, and review priority across package, CLI,
  and hosted API consumers.
- Proposed next architecture slice: a constrained declarative detection-pack layer for
  provider, infrastructure, identity, WAF, and vendor-inventory inference. This should
  start as bundled first-party schema-validated rules with no network I/O, no arbitrary
  JavaScript, deterministic output, and benchmark gates. See
  [`DETECTION-PACKS.md`](./DETECTION-PACKS.md).

### 2. Monitoring As The Product

Goal: make monitoring the most valuable recurring use case, not just a saved scan list.

Near-term work:

- Deepen certificate timelines, renewal events, issuer/serial changes, expiry bands, and unreachable-state explanations.
- Make posture drift explanations more readable: what changed, why it matters, what to do next.
- Expand policy-based monitoring so users can define what matters to them without writing code, then monitor against that policy over time.
- Use posture manifests as the stored baseline for "what changed since last time" and "does this still meet the expected recipe card?"
- Keep push notifications quiet, deduplicated, and transition-driven.
- Add service-level health and user-facing confidence so apps can show whether monitoring is working.

Candidate releases (signal-gated after the post-1.23 settling window):

- `1.24`: monitoring event explanations and alert payload polish.
- `1.25`: policy-based monitoring templates and stable timeline DTOs.

### 3. Mobile-First Companion Suite

Goal: treat SecURL, Header Watch, and Cert Watch as first-class product surfaces over the same backend intelligence.

Near-term work:

- Prioritize APIs that reduce mobile polling, payload weight, and battery/network use.
- Keep `/mobile-summary`, `/monitoring-cert-summary`, `/monitoring-mobile-summary`, and push resources stable.
- Let mobile apps consume policy/manifest summaries as insight delivery, not local rule engines.
- Feed mobile-specific telemetry into product decisions without storing personal identifiers.
- Use Cert Watch usage as the sharpest signal for what mobile users currently understand and value.
- Keep Android self-hosted downloads discoverable while iOS distribution matures.

Candidate releases:

- `1.24`: mobile result resources that cover the complete scan-to-watch-list lifecycle.
- `1.25`: mobile monitoring polish milestone: concise policy summaries, clear drift, push reliability, and certificate attention states.

### 4. Developer Workflow

Goal: make SecURL useful before shipping, during CI, and inside lightweight internal security workflows.

Near-term work:

- Improve examples for `npx securl`, global installs, JSON/SARIF outputs, and saved report comparison.
- Add GitHub Actions examples that show policy profiles, score thresholds, regression checks, cert expiry checks, posture manifest upload, and SARIF upload.
- Make report artifacts useful for pull requests and vendor/supplier assessment notes.
- Keep CLI commands fast and narrowly scoped where possible.

Candidate releases:

- `1.20`: posture manifest and policy-gate CLI examples.
- `1.21`: complete CI examples and templates.
- `1.22`: evidence-backed SARIF and PR annotation polish.

### 5. Trust And Signal Layer

Goal: make the project feel serious, alive, privacy-conscious, and easy to evaluate.

Near-term work:

- Keep public docs current with package version, mobile apps, Android downloads, and deployment boundaries.
- Keep product pulse and telemetry privacy-safe, with aggregate attribution by app/client/channel.
- Record what is real traction versus smoke/deploy/internal noise.
- Keep release notes honest: package changes only get package bumps when npm consumers benefit.
- Preserve the passive boundary in all public messaging.

Candidate releases:

- Ongoing through every release, with a documentation refresh at each package milestone.

## Roadmap To 1.25

The path to `1.25` should make the current product thesis obvious:

| Version range | Theme | Intended outcome |
| --- | --- | --- |
| `1.16.x`-`1.19` | Certificate, monitoring, and growth loop foundations | npm, backend, web, and mobile clients share stable posture, certificate, sharing, and telemetry primitives. |
| `1.20` | Posture manifest v1 | Every scan can emit an external posture recipe card: checks run/skipped, evidence quality, signal clarity, engine version, timestamps, and policy profile. |
| `1.21` | Policy Pack v1 | Built-in baseline, production, strict, and vendor-review profiles can evaluate observations and fail CLI/CI runs deterministically. |
| `1.22` | Manifest schema contract | CI, evidence archives, and integrators can validate Posture Manifest v1 with the exported JSON Schema and `securl schema manifest`. |
| `1.23` | External exposure intelligence | Shipped: stable third-party, infrastructure, identity, AI, SRI, data-flow, and supply-chain inventory for package, CLI, and hosted API consumers. |
| `1.24` | Monitoring explanations | Push and monitoring timelines explain what changed, why it matters, which policy moved, and what to do next. |
| `1.25` | Mobile monitoring milestone | Cert Watch, Header Watch, and SecURL share a reliable, push-driven monitoring foundation with concise policy and manifest summaries. |

## Next Decision Gate - July 2026

Do not start another product slice merely because `1.24` is next numerically. Continue
observing clean production, package, mobile, and web-funnel signals after the 1.23 and
mobile release wave. The next deliberate choice is:

- **Monitoring explanations (`1.24`)** when recurring monitoring usage or real drift
  events show that explanation quality is the strongest constraint; or
- **Declarative detection packs** when engine scalability and contributor-friendly
  provider knowledge become the stronger constraint, starting with an internal evaluator
  and one low-risk duplicated edge-provider migration; or
- **Product Hunt launch** when the product and media pack are ready for a timed acquisition
  test and there is capacity to observe and respond to the resulting traffic.

Until one of those conditions is selected, favour reliability, compatibility, evidence,
and operational visibility over new surface area.

## Future 2.0 Shape

SecURL 2.0 should not mean "more checks." It should mean a stable product system:

- A stable engine API for public URL posture intelligence.
- A stable external posture manifest that acts as a public-facing security recipe card for apps, services, and vendors.
- A policy engine that can evaluate those manifests consistently across CLI, CI, API, web, and mobile.
- A mature CLI for CI, scheduled jobs, reports, and local checks.
- A hosted backend that owns scans, monitoring, push notifications, policies, and history.
- A mobile suite that gives focused lenses over the same intelligence layer.
- Optional interoperability exports for security teams that want posture data alongside SBOM, vendor-risk, or compliance evidence workflows.
- Clear privacy boundaries, passive collection limits, and trustworthy package/deployment practices.
- A coherent commercial foundation around recurring monitoring, history, reporting, API usage, and team workflows.

The 2.0 bar is crossed when SecURL is no longer primarily a scanner. It is the layer that watches public security posture, explains changes, and helps people decide what to fix first.

## Non-Goals

- No credentialed vulnerability scanning.
- No exploit attempts, fuzzing, brute forcing, or aggressive reconnaissance.
- No hidden install-time package telemetry.
- No storing raw personal/device identifiers for product analytics.
- No package bumps for backend-only or marketing-only changes unless npm consumers benefit.
