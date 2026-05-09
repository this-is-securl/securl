# SecURL

[![npm version](https://img.shields.io/npm/v/%40ktbatterham%2Fexternal-posture-core)](https://www.npmjs.com/package/@ktbatterham/external-posture-core)
[![npm package](https://img.shields.io/badge/npm-package-red)](https://www.npmjs.com/package/@ktbatterham/external-posture-core)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

SecURL is a posture-first external security review tool for public web targets.

It gives you a quiet, evidence-led read of headers, TLS, cookies, redirects, trust signals, passive page risk, and public disclosure posture, then turns that into a client-ready report instead of raw scanner noise.

Live app: [app.securl.online](https://app.securl.online)  
Core package: [`@ktbatterham/external-posture-core`](https://www.npmjs.com/package/@ktbatterham/external-posture-core)

## Why SecURL

- Passive-first posture review without broad reconnaissance noise
- Clear analyst summaries and priority actions
- Browser-facing hardening checks across headers, redirects, TLS, cookies, and trust signals
- Quiet comparison over time with drift and history views
- Premium PDF, Markdown, and JSON outputs for stakeholder-friendly reporting

The short version:

- Shodan finds things.
- SecURL interprets them quietly.

## Screenshots

### Landing experience

![SecURL home screen](docs/images/securl-home.png)

### At-a-glance reporting

![SecURL overview report](docs/images/securl-overview.png)

### Trust and disclosure detail

![SecURL trust signals detail](docs/images/securl-trust-signals.png)

## What it checks

- Response headers such as HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, and CORP
- Redirect chains, TLS certificate posture, protocol and cipher details
- Cookie flags including `Secure`, `HttpOnly`, and `SameSite`
- Public trust and disclosure signals including `security.txt`, HSTS preload, and policy-page discovery
- Domain and email posture such as MX, SPF, DMARC, CAA, and MTA-STS
- Passive HTML signals including forms, third-party assets, missing SRI, inline scripts/styles, and light exposure clues
- Technology, provider, and AI-surface hints with conservative scoring

## Quick start

### Live app

Open [app.securl.online](https://app.securl.online) and scan a public target.

### CLI

```sh
npx @ktbatterham/external-posture-core scan example.com
npx @ktbatterham/external-posture-core scan example.com --format markdown --output report.md
npx @ktbatterham/external-posture-core compare current-report.json previous-report.json
```

Global install:

```sh
npm install -g @ktbatterham/external-posture-core
epi scan example.com
```

### Local development

```sh
npm install
npm run dev
```

That starts:

- frontend on `http://localhost:8080`
- API on `http://127.0.0.1:8787`

## Architecture

SecURL now has a clean split between:

- static frontend client
- Node backend API
- reusable scanner core package in [`packages/core`](packages/core)

That makes it much easier to:

- host the frontend separately from the backend
- evolve toward Android and iOS companion apps
- keep the scanner logic reusable in CLI and service contexts

## Package status

- Latest published core package: `@ktbatterham/external-posture-core@0.8.1`
- npm tag: `latest`

## Docs

For the deeper operational and architecture material, go straight to:

- [Backend API split-hosting notes](docs/BACKEND-API.md)
- [Public deploy checklist](docs/PUBLIC-DEPLOY-CHECKLIST.md)
- [iOS-capable backend notes](docs/IOS-CAPABLE-BACKEND.md)
- [Abuse and alerting notes](docs/ABUSE-ALERTING.md)
- [Reverse proxy verification](docs/REVERSE-PROXY-VERIFICATION.md)
- [OWASP/MITRE self-review](docs/OWASP-MITRE-SELF-REVIEW.md)

## Safety

Use this against systems you own or are authorized to assess.

SecURL is passive-first and intentionally conservative, but it is still a real external review tool. It cannot prove a target is secure, and it does not replace a penetration test, authenticated review, or broader security program.
