# Security Policy for `securl`

This package is published from the public source repository:

- `https://github.com/this-is-securl/securl`

## Reporting a vulnerability

Please report suspected vulnerabilities privately via:

- GitHub security advisory / private vulnerability report on the repository, or
- email `keithbatterham@pm.me`

Please avoid filing public issues for security-sensitive reports.

## Package trust signals

- public source repository
- reproducible package contents via `npm pack --dry-run`
- GitHub Actions release workflow
- npm provenance enabled at publish time
- no install scripts
- one runtime dependency (`node-html-parser`)

## Scope note

This package performs network-facing posture analysis by design. That can look high-risk to automated package reputation systems, but the intended use is defensive scanning against targets you own or are authorized to assess.

## Scope note

This package performs network-facing posture analysis by design. That can look high-risk to automated package reputation systems, but the intended use is defensive scanning against targets you own or are authorized to assess.
