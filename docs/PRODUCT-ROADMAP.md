# SecURL Product Roadmap

SecURL is evolving from a one-shot scanner into a public security posture intelligence layer for developers, mobile users, security teams, lightweight automation, and teams that need trustworthy outside-in evidence without buying or operating a heavyweight scanner.

The product thesis is simple: people should be able to understand how a public URL, service, vendor, or certificate looks from the outside without credentials, agents, invasive probing, or noisy reconnaissance. SecURL should make that read fast, repeatable, explainable, and useful everywhere: CLI, CI/CD, API, web, and mobile.

A useful mental model is the external security "recipe card." SBOMs help teams understand what an application is made of internally; SecURL should help them understand what that application exposes externally: public services, headers, cookies, TLS, DNS trust, certificate posture, third-party surface, visible vendors, policy fit, and what changed since the last known-good scan.

The bigger ambition is an **external posture graph**: a durable, explainable record of
public-facing security signals over time. A single scan answers "what does this URL look
like today?" The platform should answer "what changed, which policy or vendor expectation
moved, who needs to care, and can I trust the evidence?"

## Current Signals

The roadmap is based on the signals now visible across the product system:

- The `securl` npm package is getting meaningful weekly downloads, with provenance enabled and no install scripts.
- The iOS apps have real backend activity, especially Cert Watch live certificate reads,
  SecURL monitoring-target creation, and share-card reads.
- App Store Connect now shows early organic acquisition across all three iOS apps:
  21 app units in the Jun 15-Jul 14 window, led by SecURL and Header Watch.
- APNs delivery has been reliable enough for continued use, but production telemetry now
  includes a small number of failed and disabled-token outcomes; push reliability should
  stay visible in every release/ritual rather than being treated as "done."
- The web landing page is now instrumented as a routing funnel, but mobile and npm currently show the clearest engagement signals.
- The deprecated scoped package still receives residual downloads, which suggests historical discovery and automation paths are still alive.

## Current Operating Focus - July 2026

After a fast sequence of mobile releases and backend contract work, the next short window deliberately lets the mobile suite settle while the engine and public-facing surfaces get ahead again.

For the next few days, priority order is:

1. **Engine/package/API first**: improve the npm-consumable engine, hosted API contracts, policy/manifest examples, release evidence, and architecture/safety documentation.
2. **Public websites second**: make `securl.online` and `app.securl.online` explain the product system clearly, link to downloads and docs, and route interested users toward the web app, npm package, and self-hosted/mobile surfaces.
3. **Mobile later**: keep mobile contracts stable and additive, but avoid new mobile feature pressure until the current app wave has had time to settle in production.

This does not reduce the importance of the mobile suite. It preserves the principle that the engine is the source of truth, with web and mobile acting as increasingly polished views over the same passive posture intelligence.

## Strategic Bets

The roadmap should be ambitious in five places, while preserving the passive, bounded,
privacy-conscious product boundary:

1. **SecURL as the external posture graph**: every scan, manifest, observation, policy
   result, detection-pack match, monitoring event, and alert becomes part of a stable
   evidence model that can be compared over time.
2. **Detection knowledge as a reviewed ecosystem**: detection packs should grow from
   bundled first-party rules into a contributor-friendly, reviewed catalogue for provider,
   infrastructure, identity, WAF, SaaS, AI, and vendor-supply-chain inference. This is the
   scale lever; the first implementation must stay locked down so the later ecosystem is
   credible.
3. **Monitoring as the control room**: the recurring product is not "run scan again"; it is
   a quiet watch layer that explains meaningful drift, routes it to the right surface, and
   proves nothing important has changed.
4. **Posture manifests as portable evidence**: manifests should become the artifact a team
   can attach to CI, a release, a vendor review, a customer security question, or an
   internal lightweight audit.
5. **Trust as product surface**: provenance, passive boundaries, SSRF protections,
   deterministic outputs, telemetry privacy, and release discipline are not background
   engineering chores. They are part of why users should trust a security tool that itself
   will be attacked.

## Product Tracks

### 1. Engine Authority

Goal: make `securl` the best lightweight outside-in posture engine for public URL security judgement, portable evidence, and automation-safe policy decisions.

Near-term work:

- Improve package-visible workflows that npm users can run without the hosted backend.
- Keep CLI, JSON, Markdown, SARIF, and CI outputs stable and useful.
- Promote `observationPolicy` into a first-class policy engine with named profiles, assertion results, and stable failure semantics.
- Add a `posture-manifest` output: a machine-readable external posture recipe card that records what was checked, what was skipped, evidence quality, signal clarity, engine version, policy profile, and timestamps.
- Treat CycloneDX/SBOM-style interoperability as a later export target for the posture manifest, not as a claim that SecURL is producing a dependency SBOM.
- Expand fast single-purpose commands where the engine already has focused capability, such as `securl cert`.
- Continue reducing false positives and making passive findings easier to trust.
- Keep package trust strong: provenance, no install scripts, small dependency surface, clear changelog, and explicit passive boundaries.
- Add pack-match provenance to internal observations before exposing it publicly, so future
  users can see which detection knowledge produced a provider or vendor claim.
- Build toward a maintained provider knowledge base that can explain roles, data-flow,
  ownership, evidence, confidence, and review priority consistently across CLI, API, web,
  and mobile.

Delivered releases:

- `1.20`: Posture Manifest v1 and package/CLI integration examples.
- `1.21`: Policy Pack v1 with named profiles and deterministic assertion semantics.
- `1.22`: exported Posture Manifest JSON Schema and `securl schema manifest`.
- `1.23`: External Exposure Inventory v1 with stable provider IDs, roles, data-flow
  purpose, confidence/evidence, SRI status, and review priority across package, CLI,
  and hosted API consumers.
- `1.24`: Detection-pack architecture foundation with an internal bundled-first-party
  evaluator and Cloudflare, Akamai, and Fastly WAF/technology detection migrated into a
  constrained pack. The slice deliberately preserves existing outputs while proving the
  rule seam, safety model, and package checks. See [`DETECTION-PACKS.md`](./DETECTION-PACKS.md).

### 2. Monitoring As The Product

Goal: make monitoring the most valuable recurring use case, not just a saved scan list.

Near-term work:

- Deepen certificate timelines, renewal events, issuer/serial changes, expiry bands, and unreachable-state explanations.
- Make posture drift explanations more readable: what changed, why it matters, what to do next.
- Expand policy-based monitoring so users can define what matters to them without writing code, then monitor against that policy over time.
- Use posture manifests as the stored baseline for "what changed since last time" and "does this still meet the expected recipe card?"
- Keep push notifications quiet, deduplicated, and transition-driven.
- Add service-level health and user-facing confidence so apps can show whether monitoring is working.
- Turn monitoring into an evidence timeline: users should be able to inspect when a signal
  first appeared, when it changed, whether it recovered, and whether the change mattered to
  their selected policy.
- Add team/automation destinations as first-class surfaces: webhook, email, CI evidence,
  and eventually Slack/issue-style handoff should all receive the same server-authored
  explanation rather than forcing each client to reinterpret raw scan data.

Candidate releases (signal-gated after the post-1.23 settling window):

- `1.25`: monitoring control-room polish: policy-fit summaries, stable timeline DTOs,
  attention rollups, and push-health feedback that works across web, API, and mobile.

### 3. Mobile-First Companion Suite

Goal: treat SecURL, Header Watch, and Cert Watch as first-class product surfaces over the same backend intelligence.

Near-term work:

- Prioritize APIs that reduce mobile polling, payload weight, and battery/network use.
- Keep `/mobile-summary`, `/monitoring-cert-summary`, `/monitoring-mobile-summary`, and push resources stable.
- Let mobile apps consume policy/manifest summaries as insight delivery, not local rule engines.
- Feed mobile-specific telemetry into product decisions without storing personal identifiers.
- Use Cert Watch usage as the sharpest signal for what mobile users currently understand and value.
- Keep Android self-hosted downloads discoverable while iOS distribution matures.
- Let mobile become the simplest "control room" for individuals: not a smaller copy of the
  web app, but the fastest way to know whether watched domains, certificates, and posture
  expectations are healthy.
- Keep the product-team boundary explicit: mobile should consume stable backend-authored
  summaries and events, not reimplement the engine or detection-pack logic.

Candidate releases:

- `1.25`: mobile monitoring polish milestone: concise policy summaries, clear drift,
  push reliability, certificate attention states, and release-following Android FCM
  activation evidence.

### 4. Developer Workflow

Goal: make SecURL useful before shipping, during CI, and inside lightweight internal security workflows.

Near-term work:

- Improve examples for `npx securl`, global installs, JSON/SARIF outputs, and saved report comparison.
- Add GitHub Actions examples that show policy profiles, score thresholds, regression checks, cert expiry checks, posture manifest upload, and SARIF upload.
- Make report artifacts useful for pull requests and vendor/supplier assessment notes.
- Keep CLI commands fast and narrowly scoped where possible.
- Make "external posture evidence for every release" a simple path: one command in CI,
  one manifest artifact, one policy verdict, one human-readable summary, and one optional
  SARIF/report output.
- Add scheduled/self-hosted examples so teams can run SecURL as a small watcher without
  adopting the hosted product.

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
- Treat security hardening as roadmap work: SSRF resistance, bounded parsing, ReDoS-safe
  detection, dependency review, alert-abuse controls, and release provenance should be
  visible in docs and verification scripts.
- Publish enough operational evidence that serious users can evaluate whether SecURL is a
  trustworthy security dependency, not just an attractive scanner UI.

Candidate releases:

- Ongoing through every release, with a documentation refresh at each package milestone.

### 6. Distribution And Commercial Shape

Goal: make the product useful enough to spread organically while leaving room for a
credible paid/service layer.

Near-term work:

- Keep the free package excellent: a high-trust CLI is the acquisition surface, proof point,
  and integration layer.
- Make the hosted API and apps the easiest way to get history, monitoring, alerts, share
  cards, and mobile access without operating infrastructure.
- Treat App Store units and backend product-pulse events as a paired signal: installs alone
  are not traction until they produce monitoring registrations, repeated reads, push
  registration, share cards, or return usage.
- Use Product Hunt, Show HN, dev.to, GitHub examples, and package docs as learning loops,
  not vanity launch checkboxes.
- Define a lightweight paid path around monitored targets, history retention, team/API
  usage, export/reporting, and alert destinations only after real usage shows which surface
  people return to.
- Avoid premature enterprise theatre. The credible wedge is "external posture evidence and
  monitoring for teams that do not have a security platform."

## Roadmap To 1.25

The path to `1.25` should make the current product thesis obvious:

| Version range | Theme | Intended outcome |
| --- | --- | --- |
| `1.16.x`-`1.19` | Certificate, monitoring, and growth loop foundations | npm, backend, web, and mobile clients share stable posture, certificate, sharing, and telemetry primitives. |
| `1.20` | Posture manifest v1 | Every scan can emit an external posture recipe card: checks run/skipped, evidence quality, signal clarity, engine version, timestamps, and policy profile. |
| `1.21` | Policy Pack v1 | Built-in baseline, production, strict, and vendor-review profiles can evaluate observations and fail CLI/CI runs deterministically. |
| `1.22` | Manifest schema contract | CI, evidence archives, and integrators can validate Posture Manifest v1 with the exported JSON Schema and `securl schema manifest`. |
| `1.23` | External exposure intelligence | Shipped: stable third-party, infrastructure, identity, AI, SRI, data-flow, and supply-chain inventory for package, CLI, and hosted API consumers. |
| `1.24` | Detection-pack architecture | Shipped: constrained internal detection-pack seam with first-party edge-provider migration and output-equivalence checks. |
| `1.25` | Monitoring control-room milestone | Cert Watch, Header Watch, SecURL, web, API, and alerts share a reliable, push-driven monitoring foundation with attention rollups, timeline DTOs, concise policy/manifest summaries, and visible push-health state. |

## Ambition To 1.30

The next five package/product milestones should turn the platform from "capable scanner"
into "credible external posture system":

| Version range | Strategic milestone | Intended outcome |
| --- | --- | --- |
| `1.24` | Internal detection packs | The detection-pack seam is real, tested, bounded, and used by at least one provider family without output drift. |
| `1.25` | Monitoring control-room polish | Mobile, web, API, and alerts share server-authored monitoring explanations, deep links, health status, and policy-aware next actions. |
| `1.26` | Provider knowledge base v1 | Provider, WAF, identity, infrastructure, AI, and vendor inventory signals share stable provider IDs, roles, evidence, and pack provenance. |
| `1.27` | Portable evidence workflows | CI and hosted users can save, compare, export, and share posture manifests and reports with enough context for vendor review or release evidence. |
| `1.28` | Reviewed contributor packs | Contributors can propose declarative detection-pack rules through fixtures, schema validation, benchmark gates, and human review without adding executable runtime plugins. |
| `1.29` | Team/API operating layer | Authenticated API keys, alert destinations, retention, audit-friendly exports, and team-oriented usage limits become coherent rather than ad hoc. |
| `1.30` | External posture graph | SecURL can explain the current state, historical drift, policy fit, provider/vendor exposure, and evidence quality for watched targets as one product system. |

## Roadmap Review - 2026-07-15

The roadmap does not need a wholesale refactor after `1.24`; the thematic structure is
working. It does need a sharper operating split for the next slice:

1. **Retention/control-room work must outrank new mobile surface area.** App Store units
   show early organic acquisition, but backend telemetry says the conversion question is
   now "do installers create watches, return, and receive useful alerts?" not "can we add
   another app feature?"
2. **Detection-pack work should continue, but stay internal and boring.** The next pack
   migration should be another low-risk provider family with golden-output equivalence,
   pack-match provenance, benchmark coverage, and no public plugin API.
3. **Trust hardening remains roadmap work, not cleanup.** SSRF, parser/ReDoS resilience,
   dependency hygiene, provenance, and push-health accounting are product differentiators
   for a security tool.
4. **Public-web messaging should catch up to the product system.** The product now has
   npm, hosted API, iOS apps, self-hosted Android APKs, monitoring, manifests, and
   detection packs; public pages should explain that system without overstating traction.

Net decision: keep the `1.25` milestone, but define it around **monitoring retention and
control-room confidence** rather than a bundle of mobile features.

## Next Decision Gate - July 2026

The selected next slice is **post-1.24 detection-pack follow-through plus monitoring
retention instrumentation**, with implementation order chosen by risk:

Current gate:

- Choose the next detection-pack migration by evidence and risk: prefer another duplicated
  low-risk provider family before attempting vendor-inventory or identity rules.
- Preserve output equivalence, add pack-match provenance internally, and keep packs
  declarative, schema-validated, deterministic, bounded, and unable to perform network I/O.
- Keep package-affecting architecture work separate from mobile delivery; there is no new
  mobile contract until a future API response shape intentionally exposes pack metadata or
  richer detection provenance behind a capability flag.
- In parallel, design the `1.25` monitoring-control-room API shape around attention
  rollups, stable timeline DTOs, policy-fit summaries, and push-health state, because those
  directly answer whether new installers become retained monitoring users.
- Continue monitoring production/mobile telemetry; if real alert confusion or push
  reliability becomes the stronger signal, move monitoring explanations and push-health
  feedback above pack migration.

Until the slice proves itself in production/package review, favour reliability,
compatibility, evidence, and operational visibility over new surface area.

## Opportunity Backlog

These are intentionally larger than the next sprint. They should shape architecture
choices now without becoming excuses to overbuild:

- **Hosted posture graph**: target history, provider timeline, observation freshness,
  policy state, monitoring health, alert delivery, and evidence quality as one queryable
  model.
- **Detection-pack workbench**: fixtures, golden-output comparisons, worst-case benchmark
  reports, and a review checklist for proposed provider rules.
- **External evidence bundle**: signed or provenance-linked export containing manifest,
  policy verdict, key evidence, report summary, engine version, and scan metadata.
- **Vendor/security questionnaire assist**: convert posture manifests and vendor exposure
  into concise evidence-backed answers for customer or supplier review.
- **Public benchmark corpus**: safe synthetic and public-fixture tests that track false
  positives, scan time, parser safety, and detection-pack growth.
- **Control-room surfaces**: a web/mobile view that starts from "what needs attention?"
  across watched targets instead of "which scan do you want to open?"
- **Self-hosted watcher**: a documented small deployment mode for teams that want scheduled
  monitoring and exports without the public hosted service.

## Future 2.0 Shape

SecURL 2.0 should not mean "more checks." It should mean a stable product system:

- A stable engine API for public URL posture intelligence.
- A stable external posture manifest that acts as a public-facing security recipe card for apps, services, and vendors.
- A policy engine that can evaluate those manifests consistently across CLI, CI, API, web, and mobile.
- A posture graph that keeps observations, provider signals, policy state, detection-pack
  provenance, monitoring events, alert delivery, and evidence freshness connected over
  time.
- A mature CLI for CI, scheduled jobs, reports, and local checks.
- A hosted backend that owns scans, monitoring, push notifications, policies, and history.
- A mobile suite that gives focused lenses over the same intelligence layer.
- A reviewed detection-pack ecosystem that scales provider and vendor knowledge without
  compromising passive safety or package trust.
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
