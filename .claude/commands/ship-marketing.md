# /ship-marketing — Marketing site shipping workflow with UX gate

Run this instead of `npm run build` in the marketing repo. Enforces a UX review first.

## Steps

1. **UX Review** — Work through the marketing-relevant sections of `docs/UX_CHECKLIST.md` (Hero, Value prop, Compare table, CTA flow, Mobile). For each:
   - Use the Chrome MCP to load `securl.online` (or local dev preview)
   - Take a screenshot and verify visually
   - Mark PASS / FAIL / SKIP

2. **Report** — Output a summary table and ask the user: "Marketing UX review complete — X passed, Y failed. Proceed with ship?" Wait for explicit confirmation.

3. **If approved** — in the `securl-marketing` repo:
   ```
   npm run build
   ```
   then zip and upload to Hostinger.

4. **If any FAIL items** — list them and ask whether to fix first or ship anyway.
