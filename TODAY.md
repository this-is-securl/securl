# Current Working Notes

## Status

- `main` is in sync with `origin/main`.
- Latest published npm package: `securl@1.23.1` (`packages/core`), with npm
  provenance enabled and no install scripts.
- Railway hosts the backend/API service.
- Hostinger hosts the static product and app sites.
- Mobile and npm are currently the clearest engagement channels; separate genuine usage
  from smoke/deploy checks and incomplete-day telemetry.
- Android FCM push support is merged but capability-gated off until Railway has FCM
  service-account credentials. Do not mark it `BACKEND_READY` or trigger mobile until
  `/api/capabilities` advertises `android-fcm-push-v1`.

## Current Priorities

1. Keep the backend/mobile API contract stable.
2. Watch telemetry and product pulse for real mobile usage versus local QA.
3. Keep package, hosted API, public-web, and release/provenance status accurate.
4. Only bump npm when `packages/core` or the published package surface changes.
5. Evaluate the declarative detection-pack/plugin architecture as a backend-owned
   architecture slice before writing implementation code.

## Routine Checks

- `npm run telemetry`
- `npm run product:pulse`
- `npm run package:signals`
- `npm run lint`
- `npm run test:server`

## Release Notes

- Backend-only deploys should be captured in `CHANGELOG.md`.
- Package changes should be captured in `packages/core/CHANGELOG.md` and released through `packages/core/RELEASING.md`.
