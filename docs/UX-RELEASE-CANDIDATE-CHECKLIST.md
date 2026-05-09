# UX Release Candidate Checklist

Use this checklist to sign off the current UI before cutting the next version.

## Test Targets

- `https://ek.co` (mixed/watch profile)
- `https://bbc.co.uk` (strong with some watch items)
- `https://github.com` (strong baseline)
- `https://wsj.com` (edge-managed / restricted response behavior)

## 1) Healthcheck + Top Block

- [ ] Target host and final URL render without overflow/truncation issues.
- [ ] Scan timestamp tile aligns with Analyst Read tile.
- [ ] Main Visible Risk tile width visually matches Analyst Read tile width.
- [ ] Overall Posture / HTTP Status / Response Time tiles align cleanly as a left group.
- [ ] Healthcheck tile appears first in the score tile row and uses the same card dimensions as category tiles.
- [ ] Healthcheck grade letter coloring matches status (`A/B=strong`, `C=watch`, `D/F=weak`).
- [ ] Export buttons are equal width and centered consistently.

## 2) Category + Priority Logic

- [ ] Weakest category in Category Scores is represented in Priority Actions.
- [ ] Priority Actions sort order reflects weakest category first.
- [ ] Priority reason text is present and clear on each action.
- [ ] No contradictory messaging (example: category marked strong while top action says same area is weak without evidence).

## 3) Monitoring UX

- [ ] With 0 snapshots, Monitoring panel hides cleanly (no empty noise block).
- [ ] With 1 snapshot, trend block shows: "One saved scan recorded. Trend will appear after the next scan."
- [ ] With 2+ snapshots, sparkline renders and trend label (`Improving` / `Degrading` / `Stable`) is accurate.
- [ ] Area delta lines only appear when a previous area snapshot exists.
- [ ] Monitoring alert cards have readable spacing and line-height on desktop and mobile widths.

## 4) Strengths vs Watch Points Language

- [ ] Panels use `Strengths` for positive/neutral outcomes.
- [ ] Panels use `Watch points` only for actionable caution items.
- [ ] No "No issues found" phrasing appears under warning-styled sections.

## 5) Posture Summary Readability

- [ ] Critical/Core Warnings/Context Warnings/Info tiles are visually balanced and readable.
- [ ] Category bars and labels have consistent spacing and no overlap at common breakpoints.
- [ ] "Weakest area in this scan" marker appears only on the lowest score tile.

## 6) Export Consistency (Markdown + PDF spot check)

- [ ] Export headline includes score/new/resolved change summary.
- [ ] Export headline explicitly states category deltas are omitted (by design).
- [ ] Executive summary wording matches app wording.
- [ ] Priority Actions order in export matches in-app order.
- [ ] No malformed list formatting or missing sections in Markdown/PDF export.

## 7) Assessment Limitation Behavior

- [ ] For edge-managed/blocked target (e.g., `wsj.com`), limitation banner appears with clear explanation.
- [ ] UI still renders coherent posture tiles even when crawl/fetch depth is limited.
- [ ] Priority Actions do not overclaim certainty for limited assessments.

## 8) Responsive / Visual Pass

- [ ] No card collisions or overflow at `1280px`, `1024px`, `768px`, `390px`.
- [ ] No clipped text on long hostnames or long risk descriptions.
- [ ] Tile vertical rhythm remains consistent between sections.
- [ ] Typography weight hierarchy feels consistent across Overview, Priority Actions, and Monitoring.

## Sign-off

- [ ] UX sign-off complete
- [ ] Any remaining defects captured as issues/PR follow-ups
- [ ] Release candidate approved for next version cut
