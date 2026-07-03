# Current Working Notes

## Status

- `main` is in sync with `origin/main`.
- Latest published npm package: `securl@1.15.0`.
- Railway hosts the backend/API service.
- Hostinger hosts the static product and app sites.
- Mobile is currently the most meaningful engagement channel.

## Current Priorities

1. Keep the backend/mobile API contract stable.
2. Watch telemetry and product pulse for real mobile usage versus local QA.
3. Ship mobile updates quickly when Apple allows them.
4. Only bump npm when `packages/core` or the published package surface changes.

## Routine Checks

- `npm run telemetry`
- `npm run product:pulse`
- `npm run package:signals`
- `npm run lint`
- `npm run test:server`

## Release Notes

- Backend-only deploys should be captured in `CHANGELOG.md`.
- Package changes should be captured in `packages/core/CHANGELOG.md` and released through `packages/core/RELEASING.md`.
