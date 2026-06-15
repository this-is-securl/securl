# Consumer API Map

Use this map when building web, iOS, CLI, report, or automation clients. The full scan result remains available, but most product surfaces should prefer the smaller purpose-built resources below.

## Primary Product Clients

For web and mobile experiences, prefer:

- `GET /api/scans/:id/summary`: scan lifecycle, score, grade, and target metadata.
- `GET /api/scans/:id/digest`: compact posture overview, top findings, score drivers, controls, trust, and timing.
- `GET /api/scans/:id/brief`: outside-observer exposure brief with public entry points, trust gaps, abuse indicators, and next actions.
- `GET /api/scans/:id/vendors`: vendor and supply-chain exposure brief with third-party providers, data-flow categories, SRI gaps, and review priorities.
- `GET /api/scans/:id/action-plan`: prioritized fix narrative combining remediation, evidence, score drivers, exposure, and vendor context.

These endpoints are stable additive resources. They are the safest shape for client UI because they avoid coupling screens to the full internal scan object.

## Investigation And Reporting

For deeper technical views, export, or analyst workflows, use:

- `GET /api/scans/:id/findings`: raw findings plus remediation and evidence summaries.
- `GET /api/scans/:id/evidence`: full supporting evidence from headers, TLS, DNS, HTML, exposure probes, vendors, CT discovery, and passive intelligence.
- `GET /api/scans/:id/drift`: scan-to-scan drift and risk events.
- `GET /api/scans/:id/comparison`: current and previous scan summaries with direct diff context.
- `GET /api/scans/:id/export?format=json|markdown|sarif|ci-json`: downloadable report and automation formats.

## Heavy Or Legacy Reads

`GET /api/scans/:id` includes the full result object and is useful for debugging or compatibility. New product UI should avoid relying on it unless a smaller resource does not yet expose the needed field.

## Capability Discovery

Clients should check `GET /api/capabilities` before assuming optional resources exist. The `scans.features` and `scans.resources` arrays advertise additive backend capabilities without requiring app releases.
