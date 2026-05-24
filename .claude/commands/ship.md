# /ship — Full shipping workflow with UX gate

Run this command instead of `npm run ship` directly. It enforces a UX review before building.

## Steps

1. **UX Review** — Work through every item in `docs/UX_CHECKLIST.md`. For each section:
   - Use the Chrome MCP to load the relevant page/state in the browser
   - Take a screenshot and verify the item visually
   - Mark PASS / FAIL / SKIP (with reason)

2. **Report** — Output a summary table:
   | # | Area | Status | Notes |
   |---|------|--------|-------|
   Ask the user: "UX review complete — X passed, Y failed. Proceed with ship?" and wait for explicit confirmation before continuing.

3. **If approved** — run:
   ```
   npm run ship
   ```
   then follow the normal Hostinger deploy steps (zip → upload).

4. **If any FAIL items** — list them clearly and ask whether to fix first or ship anyway. Never ship silently past a FAIL.

## Scope
This command covers the **app** (`app.securl.online`). For the **marketing site** (`securl.online`) use `/ship-marketing`.
