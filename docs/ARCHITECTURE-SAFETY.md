# Architecture And Safety Truth

This document explains how SecURL is built and where its safety boundaries sit. It is written for developers, security reviewers, and integration teams who want to understand the shape of the system without reverse-engineering the repo.

SecURL has one core principle: it interprets public web posture from the outside. It does not attempt exploitation, credentialed testing, brute forcing, fuzzing, or invasive reconnaissance.

## System Shape

SecURL is split into four practical layers:

- **Core package**: `packages/core`, published as [`securl`](https://www.npmjs.com/package/securl), owns passive analysis, scoring, observations, manifests, policy evaluation, digest generation, drift helpers, and CLI output.
- **Backend API**: `server`, hosted on Railway for the public service, owns scan lifecycle, monitoring targets, durable queues, push notification delivery, telemetry aggregation, and owner-scoped resources.
- **Web app**: `src`, statically hosted on Hostinger at [`app.securl.online`](https://app.securl.online), renders scan/report/monitoring views over backend resources.
- **Mobile clients**: SecURL, Header Watch, and Cert Watch consume compact backend resources and do not compute the security intelligence locally.

The engine is the source of truth. Web and mobile surfaces should be insight delivery layers over stable engine/backend contracts.

## Passive Boundary

The core scanner is intentionally bounded:

- It uses normal HTTP(S), DNS, TLS, certificate, redirect, and public HTML signals.
- It reads browser-visible metadata, headers, cookies, trust files, DNS records, and lightweight page evidence.
- It provides scan modes so integrations can choose normal, quiet, or deeper passive collection.
- It avoids authenticated testing, exploit attempts, brute force, content mutation, credential stuffing, and active vulnerability probing.

The hosted backend keeps the same product boundary while adding service controls around user-supplied targets.

## Hosted API Safety Controls

The public backend is the riskiest trust boundary because it accepts URLs from clients. Current controls include:

- **URL scheme control**: scan targets are restricted to HTTP and HTTPS.
- **Credential rejection**: URLs with embedded credentials are rejected.
- **Global-unicast network boundary**: outbound targets must resolve exclusively to globally routable unicast addresses. Private and loopback space, local hostnames, cloud metadata, documentation and benchmark ranges, multicast, reserved/broadcast space, and mixed safe/unsafe DNS answers are blocked.
- **DNS rebinding protection**: outbound sockets are pinned to validated public addresses where the backend performs privileged delivery or scan actions.
- **Timeouts and bounded retries**: scans, certificate reads, scheduler work, APNs delivery, webhook delivery, and queue recovery use explicit limits.
- **Rate limiting**: scan creation is rate-limited, with distributed limiting available for multi-instance deployments.
- **Owner scoping**: scan, monitoring, device, and summary resources are scoped by bearer auth or client-owned owner tokens.
- **Fail-closed startup checks**: production deployment blocks unsafe auth and database/TLS configuration unless explicitly configured otherwise.
- **Redaction**: logs and telemetry avoid raw secrets, APNs tokens, owner tokens, and direct personal identifiers.

See also:

- [`OWASP-MITRE-SELF-REVIEW.md`](OWASP-MITRE-SELF-REVIEW.md)
- [`ABUSE-ALERTING.md`](ABUSE-ALERTING.md)
- [`REVERSE-PROXY-VERIFICATION.md`](REVERSE-PROXY-VERIFICATION.md)

## Data And Privacy Posture

SecURL needs target URLs to perform scans. The hosted backend stores scan and monitoring state so users can review history, share reports, and receive monitoring alerts.

It does not need user credentials for target systems, and mobile push registration does not require raw APNs tokens to be returned to clients after registration.

Telemetry is designed for product operations rather than identity tracking:

- Client metadata headers identify app, version, and channel.
- Product pulse uses aggregate counters and privacy-safe owner hashes.
- Raw device identifiers, APNs tokens, owner tokens, and personal contact data are not exposed in telemetry readouts.

## Package Safety Posture

The npm package is intended to be safe to install and evaluate:

- Published as `securl` with npm provenance enabled.
- No install scripts.
- Published from GitHub Actions through npm trusted publishing (OIDC), without a long-lived publish token.
- Package checks and release installs run under npm 12's default-deny policy for dependency scripts, Git dependencies, and remote URL dependencies.
- MIT licensed.
- Explicit Node engine requirement.
- CLI and library live in the same package so CI and local users consume the same engine semantics.

Package trust is tracked in [`PACKAGE-SIGNALS.md`](PACKAGE-SIGNALS.md).

## Integration Boundary

Clients should prefer smaller purpose-built API resources rather than coupling to the full scan object:

- `/summary` for lifecycle and score state.
- `/digest`, `/insights`, and `/mobile-summary` for product UI.
- `/observations`, `/observation-drift`, `/policy-evaluation`, and `/manifest` for technical integrations.
- `/export?format=json|markdown|sarif|ci-json` for reporting and automation.

See [`API-INTEGRATION-GUIDE.md`](API-INTEGRATION-GUIDE.md) and [`CONSUMER-API-MAP.md`](CONSUMER-API-MAP.md).

## Current Known Limits

SecURL does not prove a target is secure. It reports visible posture from the outside.

Known limits to keep in mind:

- Some checks are limited by target availability, redirects, DNS behavior, bot protection, or network failures.
- Passive HTML and vendor detection are conservative by design and may miss dynamically loaded client behavior.
- DNS, certificate, and trust signals can change between scans.
- Policy evaluation is only as strong as the observations and rules available at scan time.
- Hosted monitoring is designed for meaningful drift and attention states, not real-time incident response.

## Engineering Direction

The near-term direction is to make the engine and API easier to trust from the outside:

- Stronger policy and manifest examples.
- More evidence-backed integration outputs.
- Clearer public docs for CLI, CI, API, web, and mobile consumers.
- Continued passive-boundary hardening for the hosted backend.
- Public sites that explain what the engine does and how to consume it.
