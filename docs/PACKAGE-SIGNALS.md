# Package Signal Tracking

SecURL does not use hidden package telemetry.

The npm package must not phone home from install scripts, library imports, CLI startup, or normal scans. That would be especially damaging for a security tool. Package adoption should be measured from public, aggregate, or explicitly user-triggered signals only.

## Signal Sources

Use:

- npm public download counts for `securl`
- npm public download counts for the deprecated `@ktbatterham/external-posture-core` package
- npm package metadata, provenance, signatures, dependency count, maintainer count, and install-script checks
- Socket package health pages
- public GitHub `package.json` mentions where GitHub code search is available
- hosted backend telemetry for scans that go through the SecURL API

Do not use:

- `preinstall`, `install`, or `postinstall` callbacks
- hidden network requests from package import or CLI startup
- consumer fingerprinting
- persistent client identifiers in the package
- collection of target URLs from local CLI users unless the user explicitly sends a report

## Commands

Run the package signal check from the repo root:

```sh
npm run package:signals
```

For machine-readable output:

```sh
node scripts/fetchPackageSignals.mjs --json
```

The script reads public npm registry/download metadata for both package names. If the GitHub CLI is authenticated, it also runs a best-effort public code search for `package.json` mentions.

Hosted product/API telemetry remains separate:

```sh
npm run telemetry
```

The telemetry command first checks `TELEMETRY_TOKEN` and `TELEMETRY_BASE_URL` from the current shell, then falls back to Railway variables. If the local Railway project is not linked, it uses the production project/service defaults. Override those defaults with `RAILWAY_PROJECT_ID`, `RAILWAY_SERVICE_ID`, and `RAILWAY_ENVIRONMENT` when checking another deployment.

## Interpretation

npm downloads are directional, not identity. They can include CI, cache misses, local installs, mirrors, and automated tooling. They do not identify people, companies, private repos, or whether the package is actually used after installation.

The useful trend is consistency over time:

- `securl` downloads rising while the old scoped package declines
- public repos beginning to reference `securl`
- Socket/npm trust signals staying clean
- no install scripts and minimal dependency surface remaining true
- hosted scan telemetry showing real external API usage, not only owner smoke tests

## Release Hygiene

After each package release:

1. Confirm npm shows the new version as `latest`.
2. Confirm GitHub Releases marks the matching `securl-v<version>` release as latest.
3. Run `npm run package:signals`.
4. Check Socket after indexing catches up.
5. Revoke any short-lived npm token used for publishing.
