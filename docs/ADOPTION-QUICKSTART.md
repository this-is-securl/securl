# SecURL Adoption Quickstart

SecURL should be useful before anyone signs up for a platform, installs an agent, or gives it credentials. This guide gives developers, founders, agencies, and lightweight security teams a practical path from one public URL to repeatable evidence.

Use SecURL only for public targets you own or are authorized to assess. The scanner is passive-first, but it still produces security posture evidence about real systems.

## The five-minute path

### 1. Run a hosted scan

Open [app.securl.online](https://app.securl.online), paste a public URL, and review:

- the letter grade and posture areas;
- the priority findings;
- consequence and remediation text;
- report export options;
- whether this is a target worth watching over time.

This is the fastest way to understand the product because it shows the full report workspace without any local setup.

### 2. Run the same check locally

Use the npm package when you want repeatability in a terminal, script, release process, or CI job:

```sh
npx securl scan example.com
npx securl scan example.com --format markdown --output securl-report.md
npx securl scan example.com --format manifest --output posture-manifest.json
```

Use Markdown when a human needs to read the result. Use JSON, SARIF, exposure, or manifest output when another tool needs to consume it.

### 3. Add a lightweight release gate

Start with a non-blocking CI artifact before failing builds. The first goal is to make outside-in posture visible on every release:

```sh
npx securl scan "$PUBLIC_URL" --format markdown --output securl-report.md
npx securl scan "$PUBLIC_URL" --format manifest --output posture-manifest.json
```

Once the team trusts the output, add policy checks, threshold checks, or SARIF upload as a second step. Do not turn SecURL into theatre: make the gate reflect a real risk decision your team is willing to maintain.

### 4. Save important targets for monitoring

A one-time scan answers “what does this look like today?” Monitoring answers “what changed?”

Use the hosted app or mobile suite to save production URLs, important marketing sites, customer-facing portals, and domains where certificate or header drift would hurt trust. SecURL monitoring is intended to stay quiet until a change deserves attention.

### 5. Share evidence

Use the output that matches the conversation:

- Markdown for pull requests, customer/security notes, and internal tickets.
- PDF for stakeholder-friendly review.
- JSON for scripts and internal dashboards.
- Posture Manifest for portable release evidence.
- Exposure output for vendor, infrastructure, identity, analytics, and AI-surface inventory.

## Suggested adoption plays

### Developer or founder

Run a hosted scan, fix the top two issues, then save the domain for monitoring. Add a monthly or release-time CLI scan so regressions are visible.

### Web agency or freelancer

Run SecURL before launch and attach the Markdown or PDF report to the handoff. Re-scan after DNS, CDN, or hosting changes.

### Small security or compliance team

Use posture manifests as lightweight evidence for public-facing apps. Keep the first workflow read-only and artifact-producing, then add policy gates only after the team agrees on thresholds.

### Mobile user

Use the SecURL, Header Watch, and Cert Watch apps as focused control-room views over watched targets. The mobile apps should consume backend-authored monitoring summaries rather than reinterpreting scan rules locally.

## What SecURL is not

SecURL is not a pentest, credentialed vulnerability scanner, exploit framework, subdomain brute-forcer, or replacement for a security program. It is outside-in public posture evidence: fast, passive-first, repeatable, and designed to explain what changed.
