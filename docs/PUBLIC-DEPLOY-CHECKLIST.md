# Public Deploy Checklist

Run this checklist before exposing the server publicly.

## 1) Environment and runtime

- Set `NODE_ENV=production`.
- Set `API_KEY` unless you intentionally allow unauthenticated access.
- If unauthenticated access is intentional, set `ALLOW_UNAUTHENTICATED=true` explicitly.
- Set `TRUST_PROXY=true` only when behind a trusted reverse proxy/load balancer.
- Set `DEPLOYMENT_MODE`:
  - `single-instance` for one server process (default).
  - `multi-instance` for scaled deployments.
- Optional rate-limit tuning:
  - `RATE_LIMIT_MAX_REQUESTS` (default `30`)
  - `RATE_LIMIT_WINDOW_MS` (default `900000`, 15 minutes)
  - `TARGET_RATE_LIMIT_MAX_REQUESTS` (default `10`)
  - `TARGET_RATE_LIMIT_WINDOW_MS` (default `900000`, 15 minutes)
- Set `RATE_LIMIT_BACKEND`:
  - `in-memory` for local/single-instance use.
  - `upstash` for distributed multi-instance deployments.
- When `RATE_LIMIT_BACKEND=upstash`, set:
  - `UPSTASH_REDIS_REST_URL`
  - `UPSTASH_REDIS_REST_TOKEN`

### Multi-instance safety gate

In `multi-instance`, startup is blocked unless the rate-limit backend is distributed (`RATE_LIMIT_BACKEND=upstash`) and credentials are configured.

## 2) Pre-release verification

- `npm run -s check:deploy`
- `npm run -s build`
- `npm run -s test:core`
- `npm run -s test:server`
- `npm run -s lint`
- Confirm no open High/Critical code-scanning alerts on `main`.

## 3) API and abuse protections

- Confirm `/api/scans` requires API key when `API_KEY` is set.
- Confirm rate limiting behavior from expected client origin path (through proxy in production).
- Confirm proxy IP attribution works as expected in your topology.
- Configure abuse alert thresholds:
  - `ABUSE_ALERT_THRESHOLD` (default `25`)
  - `ABUSE_ALERT_WINDOW_MS` (default `600000`, 10 minutes)
- Review abuse telemetry baseline in [`docs/ABUSE-ALERTING.md`](ABUSE-ALERTING.md).
- Run reverse-proxy checks from [`docs/REVERSE-PROXY-VERIFICATION.md`](REVERSE-PROXY-VERIFICATION.md).

## 4) Security headers and static serving

- Confirm static responses include:
  - `Content-Security-Policy`
  - `X-Frame-Options: DENY`
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy: no-referrer`
- Confirm encoded traversal attempts are rejected.

## 5) Smoke tests after deploy

- `GET /api/health` returns `ok: true`.
- Health payload includes deployment mode and rate-limit metadata.
- Run one known-safe scan and verify sanitized error responses for invalid targets.
- For the Railway backend, deploy and smoke-check the current checkout with:

```sh
npm run deploy:railway -- --message "Deploy SecURL backend <version or commit>"
```

The Railway service currently has no connected GitHub source (`source.repo` is `null`). The repo includes a guarded `Deploy Railway Backend` workflow, but it only performs deployments when a repository secret named `RAILWAY_TOKEN` is configured. Until then, use the CLI command above.

## 6) Hostinger static frontend deploy

The Railway service remains backend/API-only. The static app build for `app.securl.online` can be deployed to Hostinger over SSH:

```sh
npm run deploy:hostinger
```

That command builds and verifies the Hostinger frontend bundle, then performs an `rsync --dry-run` to `/home/u765511792/domains/app.securl.online/public_html/`.

If the dry-run looks right, deploy live:

```sh
npm run deploy:hostinger:live
```

The live deploy creates a timestamped remote backup under `/home/u765511792/deploy-backups/`, syncs changed files, removes stale files from the remote `public_html`, and smoke-checks `https://app.securl.online`.
