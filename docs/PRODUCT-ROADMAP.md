# SecURL Product Roadmap

SecURL is evolving from a one-shot scanner into a public security posture intelligence layer for developers, mobile users, security teams, and lightweight automation.

The product thesis is simple: people should be able to understand how a public URL, service, vendor, or certificate looks from the outside without credentials, agents, invasive probing, or noisy reconnaissance. SecURL should make that read fast, repeatable, explainable, and useful everywhere: CLI, CI/CD, API, web, and mobile.

## Current Signals

The roadmap is based on the signals now visible across the product system:

- The `securl` npm package is getting meaningful weekly downloads, with provenance enabled and no install scripts.
- The iOS apps have real backend activity, especially Cert Watch live certificate reads.
- APNs delivery has been reliable in production, with zero observed failed or disabled-token delivery in recent telemetry.
- The web landing page is useful for positioning, but mobile and npm currently show the clearest engagement signals.
- The deprecated scoped package still receives residual downloads, which suggests historical discovery and automation paths are still alive.

## Product Tracks

### 1. Engine Authority

Goal: make `securl` the best lightweight outside-in posture engine for public URL security judgement.

Near-term work:

- Improve package-visible workflows that npm users can run without the hosted backend.
- Keep CLI, JSON, Markdown, SARIF, and CI outputs stable and useful.
- Expand fast single-purpose commands where the engine already has focused capability, such as `securl cert`.
- Continue reducing false positives and making passive findings easier to trust.
- Keep package trust strong: provenance, no install scripts, small dependency surface, clear changelog, and explicit passive boundaries.

Candidate releases:

- `1.17`: certificate comparison and expiry-policy output for CLI/CI.
- `1.18`: richer machine-readable observation and drift exports for scheduled jobs.
- `1.19`: tighter vendor/supply-chain summaries and lightweight dependency-risk reporting.
- `1.20`: stable package-level integration examples for GitHub Actions, local cron, and vendor review workflows.

### 2. Monitoring As The Product

Goal: make monitoring the most valuable recurring use case, not just a saved scan list.

Near-term work:

- Deepen certificate timelines, renewal events, issuer/serial changes, expiry bands, and unreachable-state explanations.
- Make posture drift explanations more readable: what changed, why it matters, what to do next.
- Expand policy-based monitoring so users can define what matters to them without writing code.
- Keep push notifications quiet, deduplicated, and transition-driven.
- Add service-level health and user-facing confidence so apps can show whether monitoring is working.

Candidate releases:

- `1.21`: monitoring event explanations and alert payload polish.
- `1.22`: policy templates for common posture expectations.
- `1.23`: richer monitoring history summaries and stable timeline DTOs.

### 3. Mobile-First Companion Suite

Goal: treat SecURL, Header Watch, and Cert Watch as first-class product surfaces over the same backend intelligence.

Near-term work:

- Prioritize APIs that reduce mobile polling, payload weight, and battery/network use.
- Keep `/mobile-summary`, `/monitoring-cert-summary`, `/monitoring-mobile-summary`, and push resources stable.
- Feed mobile-specific telemetry into product decisions without storing personal identifiers.
- Use Cert Watch usage as the sharpest signal for what mobile users currently understand and value.
- Keep Android self-hosted downloads discoverable while iOS distribution matures.

Candidate releases:

- `1.24`: mobile result resources that cover the complete scan-to-watch-list lifecycle.
- `1.25`: mobile monitoring polish milestone: concise summaries, clear drift, push reliability, and certificate attention states.

### 4. Developer Workflow

Goal: make SecURL useful before shipping, during CI, and inside lightweight internal security workflows.

Near-term work:

- Improve examples for `npx securl`, global installs, JSON/SARIF outputs, and saved report comparison.
- Add GitHub Actions examples that show score thresholds, regression checks, cert expiry checks, and SARIF upload.
- Make report artifacts useful for pull requests and vendor/supplier assessment notes.
- Keep CLI commands fast and narrowly scoped where possible.

Candidate releases:

- `1.17`: certificate CLI policy checks.
- `1.18`: scheduled-job friendly output formats and stable exit codes.
- `1.20`: complete CI examples and templates.

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
| `1.16.x` | Certificate CLI | npm users can run fast Cert Watch-style checks without full scans. |
| `1.17` | Certificate policy | CLI/CI can fail on expiry windows, invalid certs, weak protocol, or issuer changes. |
| `1.18` | Drift and observations | Scheduled jobs can consume stable observation and drift artifacts. |
| `1.19` | Vendor and exposure intelligence | Reports better explain third-party, SRI, analytics, session replay, AI, and visible exposure risk. |
| `1.20` | Developer workflow | GitHub Actions and CI examples become first-class, copy-pasteable workflows. |
| `1.21` | Monitoring explanations | Push and monitoring timelines explain what changed and why it matters. |
| `1.22` | Policy templates | Common monitoring expectations become reusable policy presets. |
| `1.23` | History and timelines | Monitoring history becomes compact, readable, and app/API friendly. |
| `1.24` | Mobile resource maturity | Mobile clients can render most screens from compact purpose-built resources. |
| `1.25` | Mobile monitoring milestone | Cert Watch, Header Watch, and SecURL share a reliable, push-driven monitoring foundation. |

## Future 2.0 Shape

SecURL 2.0 should not mean "more checks." It should mean a stable product system:

- A stable engine API for public URL posture intelligence.
- A mature CLI for CI, scheduled jobs, reports, and local checks.
- A hosted backend that owns scans, monitoring, push notifications, policies, and history.
- A mobile suite that gives focused lenses over the same intelligence layer.
- Clear privacy boundaries, passive collection limits, and trustworthy package/deployment practices.
- A coherent commercial foundation around recurring monitoring, history, reporting, API usage, and team workflows.

The 2.0 bar is crossed when SecURL is no longer primarily a scanner. It is the layer that watches public security posture, explains changes, and helps people decide what to fix first.

## Non-Goals

- No credentialed vulnerability scanning.
- No exploit attempts, fuzzing, brute forcing, or aggressive reconnaissance.
- No hidden install-time package telemetry.
- No storing raw personal/device identifiers for product analytics.
- No package bumps for backend-only or marketing-only changes unless npm consumers benefit.

