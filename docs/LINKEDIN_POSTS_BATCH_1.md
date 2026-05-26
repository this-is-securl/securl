LinkedIn Posts — Batch 1
Account: Keith's personal LinkedIn (or SecURL company page if created)
Tone: Professional but direct. Talking to CTOs, engineering managers, and dev leads at SMBs.
Remember: plain prose, no bullet lists, no bold headers.

---

POST 1 — Stat hook (most shareable, lead with this)

We scanned 25 well-known SaaS homepages last week. Revolut, Notion, HubSpot, Vercel, Netlify, Snyk, and 19 others.

Not one of them scored an A on their external security posture.

80% had no strong Content-Security-Policy. 24% were setting cookies without proper security flags. These are all things that show up as public signals — nothing invasive, just what any browser sees when it loads the page.

This is not a criticism of the companies involved. It is a consequence of how security checks get prioritised: they are invisible, they do not break anything when they are missing, and they are easy to defer.

The tool we used is free and takes 30 seconds. You can check your own site at securl.online. The results include every finding ranked by what to actually fix first — not just a raw list of headers.

---

POST 2 — The agency/freelancer angle

If you deliver web projects professionally, this is worth building into your process.

When a project goes live, most handoff docs cover performance, accessibility, and responsiveness. Security posture — HTTP headers, DNS/email trust, TLS configuration — is almost never included.

It takes 30 seconds to scan a site with SecURL and generate a graded report. You can export a PDF that shows the client their posture score, the findings ranked by severity, and what to prioritise next. It is a concrete, professional addition to any project handoff.

It also protects you. If a client asks "how secure is this?" six months after launch, you have a record of what the posture was at delivery.

securl.online — free to scan, PDF export included.

---

POST 3 — The "not just headers" angle (differentiates from securityheaders.com)

A lot of developers think "security scan" means a headers check. It is a reasonable assumption — securityheaders.com is the go-to tool and it does exactly that.

But headers are one layer. The external security posture of a website also includes whether your email domain can be spoofed (DMARC, SPF, DKIM), whether your TLS configuration is current, whether the third-party scripts your page loads are from reputable sources, whether your cookies are set with appropriate flags, and whether your domain has published DNS records that constrain which certificate authorities can issue certs for it.

None of those show up in a headers check.

SecURL reads all of them in a single pass and gives you one grade with every finding ranked by what matters first. It is free to use. securl.online.

---

POST 4 — The developer tool irony angle (builds on real scan data)

We scanned the homepages of several companies that specifically sell developer tooling and security products. The grades were mostly B and C.

This is not hypocrisy. It is a predictable consequence of how these things get prioritised. The product team ships features. Security posture reviews happen when a customer asks for them or when a compliance audit comes up. The homepage header config from 2022 is still the homepage header config in 2026.

The takeaway is not that these companies are doing something wrong. It is that external posture is something every team needs to check deliberately and on a schedule — because it does not check itself, and it does not break anything when it drifts.

What does yours look like right now? Free scan at securl.online.

---

POSTING SCHEDULE SUGGESTION

Week 1: Post 1 (stat hook) — Tuesday morning
Week 1: Post 3 (not just headers) — Thursday
Week 2: Post 2 (agency angle) — Tuesday
Week 2: Post 4 (developer tool irony) — Thursday

Best times for LinkedIn: 8–9am and 12–1pm on weekdays. Tuesday and Thursday outperform Monday and Friday.

Engagement tip: reply to every comment within 24 hours, even if just to acknowledge the point. LinkedIn's algorithm rewards active threads significantly.
