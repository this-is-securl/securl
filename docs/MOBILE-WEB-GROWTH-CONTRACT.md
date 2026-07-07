# Mobile to Web Growth Contract

This contract gives SecURL, Header Watch, and Cert Watch a consistent way to send high-intent users into the hosted web app without adding accounts, tracking identifiers, or extra user setup.

## Goals

- Turn mobile usage into web traffic when the user has a concrete URL in mind.
- Make scan reports easy to share outside the apps.
- Keep attribution aggregate and privacy-safe.
- Avoid coupling mobile screens to the full web app internals.

## Scanner Handoff

Use this when the app has a URL and wants the web app to run or display a richer SecURL scan.

```text
https://app.securl.online/?url={percentEncodedTargetUrl}&utm_source={appSource}&utm_medium=app&utm_campaign=mobile_handoff
```

The web app also accepts the older `target` parameter, but mobile apps should prefer `url`.

Recommended `utm_source` values:

- `securl_ios`
- `header_watch_ios`
- `cert_watch_ios`

Examples:

```text
https://app.securl.online/?url=https%3A%2F%2Fexample.com&utm_source=securl_ios&utm_medium=app&utm_campaign=mobile_handoff
https://app.securl.online/?url=https%3A%2F%2Fexample.com&utm_source=header_watch_ios&utm_medium=app&utm_campaign=mobile_handoff
https://app.securl.online/?url=https%3A%2F%2Fexample.com&utm_source=cert_watch_ios&utm_medium=app&utm_campaign=mobile_handoff
```

Suggested UI labels:

- SecURL: `Open full report on web`
- Header Watch: `Run full SecURL scan`
- Cert Watch: `Check full site posture`

## Public Report Sharing

Use this when the mobile app has a completed `scanId` from the backend and wants to share a public read-only report.

```text
https://app.securl.online/report/{scanId}?utm_source={appSource}&utm_medium=share&utm_campaign=mobile_shared_report
```

Suggested share text:

```text
Security posture report for {host}: {grade} ({score}/100)
View the SecURL report: {shareUrl}
```

For Cert Watch-only flows where no posture scan exists yet, prefer the scanner handoff URL instead of inventing a report URL.

### Share Card Metadata

Before opening the native share sheet, clients can fetch a lightweight public payload:

```text
GET https://securl-app-production.up.railway.app/api/scans/{scanId}/share-card
```

The response includes:

- `shareCard.title`
- `shareCard.summary`
- `shareCard.target.host`
- `shareCard.posture.grade`
- `shareCard.posture.score`
- `shareCard.topIssues`
- `shareCard.scoreDrivers`
- `shareCard.nextBestAction`
- `shareCard.share.text`
- `shareCard.share.reportUrl`
- `shareCard.share.scannerUrl`

Use `shareCard.share.text` as the default native share message. If the endpoint returns `404` or `409`, fall back to the scanner handoff URL.

## Suggested Placement

### SecURL iOS

- Result screen primary overflow action: `Share report`
- Result screen secondary action: `Open full report on web`
- Monitor target detail: `Open latest web report` when a completed `scanId` exists

### Header Watch

- Result screen: `Run full SecURL scan`
- Share sheet: use scanner handoff unless the app has a completed backend `scanId`
- Regression/change screen: link to the latest web report when available

### Cert Watch

- Certificate detail screen: `Check full site posture`
- Expiring/expired cert alert detail: `Open full SecURL scan`
- Watch-list row overflow: scanner handoff for that target

## Backend Headers

Continue sending the first-party client metadata headers on backend requests:

```http
X-SecURL-Client: securl-ios
X-SecURL-Client-Version: 1.0.5+20
X-SecURL-Client-Channel: app-store
```

Use the matching client name for each app:

- `securl-ios`
- `header-watch-ios`
- `cert-watch-ios`

Do not send device IDs, APNs tokens, installation IDs, or user identifiers in these headers.

## Expected Telemetry

After adoption, the backend/web pulse should show:

- `handoff_started` events with modes like `securl_ios:mobile_handoff`
- `shared_report_viewed` events with `utm_source` from the originating app
- Higher web page-load counts from `utm:mobile_handoff` and `utm:mobile_shared_report`
- Continued app-specific backend events through the `X-SecURL-Client` headers

## QA Checklist

- Tapping a scanner handoff opens `app.securl.online` and starts a scan automatically.
- `url=` works for all three apps; `target=` remains a backward-compatible fallback.
- The target URL is percent-encoded exactly once.
- Shared report URLs open without authentication.
- If a report is missing or expired, the page shows `Run your own scan`.
- UTM parameters never include the target host, user names, device IDs, APNs tokens, or other identifiers.
