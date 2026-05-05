# Reverse Proxy Verification (Nginx / Cloudflare)

Use this runbook after deploying behind a reverse proxy to validate trusted IP attribution and abuse protections.

## 1) Required Server Settings

- `TRUST_PROXY=true`
- `NODE_ENV=production`
- `API_KEY` set (recommended for public deployment)

If multi-instance:
- `DEPLOYMENT_MODE=multi-instance`
- `RATE_LIMIT_BACKEND=upstash`
- `UPSTASH_REDIS_REST_URL` and `UPSTASH_REDIS_REST_TOKEN` set

## 2) Proxy Forwarding Requirements

### Nginx

Ensure these headers are forwarded:

```nginx
proxy_set_header Host $host;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
```

### Cloudflare

- Keep default proxy forwarding behavior enabled.
- Confirm origin receives `X-Forwarded-For`.
- Optionally constrain origin access to Cloudflare IP ranges.

## 3) Trusted-Proxy Behavior Checks

Run checks against the public endpoint (or staging endpoint with same topology).

1. Health check:

```sh
curl -s https://<your-domain>/api/health
```

Confirm:
- `rateLimit.backend` matches intended backend.
- `rateLimit.distributed` is `true` for multi-instance.

2. API key enforcement:

```sh
curl -i "https://<your-domain>/api/scans"
```

Expect `401` when key is missing or invalid.

3. Requester quota:

Send repeated `POST /api/scans` requests from same client; confirm `429` and `Retry-After` appear after threshold.

4. Target quota:

Hit the same target repeatedly with `POST /api/scans` from one client; confirm target-specific `429` response text appears.

## 4) Validation Signals in Logs

Watch for:
- `trusted_proxy_mode`
- `rate_limit_exceeded`
- `target_quota_exceeded`
- `api_key_rejected`
- `abuse_alert_threshold_reached`

If `rate_limit_backend_error` appears repeatedly, treat as urgent and investigate Upstash connectivity/credentials.
