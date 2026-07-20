# Growth experiments

SecURL is pre-revenue. Acquisition, activation, retention, referral, and eventually
monetization are product outcomes, not a separate marketing backlog. Low traffic should
trigger small reversible experiments; it limits causal certainty but does not justify
holding a funnel that is not producing users.

## Experiment 001 — one-promise hosted scanner hero

- **Owner/surface:** SecURL backend/public web; `src/` deployed to
  `app.securl.online` through the established Hostinger workflow.
- **Started:** 2026-07-20.
- **Baseline:** 64 page loads / 42 aggregate unique visitors lifetime; 0 shared-report
  views; 0 copied links; no observable npm/docs-to-first-watch conversion. The baseline
  predates the local `utm_source=sec7_local_smoke` verification visit.
- **Problem:** the first screen offered a scan form plus three competing outbound links
  and several product narratives before the user experienced value.
- **Hypothesis:** one promise (scan once, know when the site changes) and one primary CTA
  (scan my site free) will improve page-to-scan activation. Monitoring and mobile remain
  the post-result path rather than competing pre-scan choices.
- **Change:** focused hero copy and CTA, removed hero link pills, retained explicit free /
  no-sign-up / passive trust signals, aligned page metadata, and repaired cross-origin
  Safari beacon delivery with a CORS-safelisted MIME type.
- **Primary read:** genuine page loads → `scan_started` → `scan_completed`, by aggregate
  source. Secondary read: `monitoring_saved`; guardrails: scan failures, auth rejects, and
  runtime latency. Smoke, deploy, scratch, and incomplete-day traffic remain separate.
- **Review:** first directional review on 2026-07-27, with an earlier adjustment allowed
  if traffic stays flat or a clear usability failure appears. Do not require statistical
  significance for another reversible copy, hierarchy, or routing iteration.
- **Rollback:** redeploy the previous known-good Hostinger build or revert the focused PR;
  backend contracts, mobile clients, downloads, and npm consumers are unaffected.

## Experiment rules

1. One primary hypothesis and CTA per acquisition experiment.
2. Record the baseline before deployment and use privacy-safe aggregate attribution.
3. Separate real usage from smoke, deploy, scratch, and incomplete-day data.
4. Prefer cheap reversible changes; require stronger evidence for security-sensitive,
   expensive, irreversible, or contract-breaking decisions.
5. Keep a short decision log: keep, iterate, or revert, and why.
