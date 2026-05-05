# OWASP/MITRE Self-Review (Application Code)

This document tracks how the scanner application itself is hardened before public deployment.

## Current Controls

1. `A01 Broken Access Control` / `MITRE Initial Access`
- Scan resources under `/api/scans` support API key enforcement (`API_KEY`) with explicit production opt-in required for unauthenticated mode.
- Production startup is blocked when auth is not configured and `ALLOW_UNAUTHENTICATED` is not explicitly set.

2. `A05 Security Misconfiguration` / `MITRE Reconnaissance`
- Static HTML responses include baseline security headers (`CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`).
- Server now rejects encoded/normalized static path traversal attempts at the boundary.

3. `A10 SSRF`-adjacent handling (operationally mapped under `A05` and `MITRE Initial Access/Reconnaissance`)
- URL input is validated at the server edge (`http/https` only, no embedded creds).
- Local/private hostnames and private IP ranges are rejected.
- DNS resolution is validated before scan dispatch; mixed/private resolution is blocked.

4. `A04 Insecure Design` / `MITRE Reconnaissance`
- Rate limiting is applied to `POST /api/scans`.
- Distributed rate limiting via Upstash REST is available and enforced for `DEPLOYMENT_MODE=multi-instance`.
- Client IP attribution defaults to socket peer; forwarded headers are used only when trust-proxy mode is enabled and the direct peer is private/local.
- Rate-limit bucket count is capped to prevent unbounded in-memory growth.

5. `A03 Injection` (export path)
- Report HTML export escapes untrusted values before interpolation.

## Remaining Gaps Before Public Exposure

1. Add structured audit logging + alerting thresholds for abuse patterns and repeated blocked targets.
2. Add end-to-end tests for proxy deployments (real reverse-proxy topology, not only localhost tests).
3. Add deployment guidance for TLS termination and trusted proxy configuration.
4. Add optional API-key scoped quotas for per-tenant fairness.
5. Add deny/allow policy options for high-risk target classes (optional enterprise mode).

## Recommended Next Deployment Gate

Require all of the following before public launch:
- `npm run build`
- `npm run test:core`
- `npm run test:server`
- `npm run lint`
- No open High/Critical code-scanning alerts on `main`
