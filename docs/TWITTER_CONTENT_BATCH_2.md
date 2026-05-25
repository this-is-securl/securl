Twitter Content — Batch 2
Account: @ThisIsSecURL
Based on: real scans of 25 SaaS/developer tool homepages (May 2026)
Sites scanned: Revolut, Wise, Checkout.com, Onfido, Snyk, Freetrade, Zopa, Habito,
Beamery, Gousto, Deliveroo, ASOS, Intercom, HubSpot, Pipedrive, Loom, Notion,
Linear, Vercel, Netlify, Supabase, HashiCorp, Datadog, Cloudflare, PagerDuty

---

TWEET 3 — Stat post (replace the old placeholder version)

We scanned 25 well-known SaaS homepages this week.

Not one of them scored an A.

80% have no strong Content-Security-Policy — including Vercel, Notion, HubSpot, and Netlify.

24% set cookies without proper security flags.

These are companies whose engineers absolutely know better. It just slips through without something watching the whole picture.

Check yours free → app.securl.online

---

TWEET — Scan result: Vercel (grade C, irony angle — they host millions of sites)

We scanned vercel.com.

Grade: C

Vercel hosts millions of production websites. Their own homepage has no strong Content-Security-Policy, 3 cookies without proper security flags, and no DMARC reject policy.

Worth noting: they're far from the worst in the batch. Most of the names you'd recognise are in the same bracket.

These are all public-response signals — nothing invasive, just what any browser sees.

Scan your own site → app.securl.online

---

TWEET — Scan result: Cloudflare (grade B, interesting because they sell security)

We scanned cloudflare.com.

Grade: B

Cloudflare sells security products to half the internet. Their own homepage has a weak Content-Security-Policy and 3 cookies without full security flags set.

Still a B, which puts them ahead of most. But it's a useful reminder that posture is a continuous job, not a checkbox.

Check your own → app.securl.online

---

TWEET — Scan result: Snyk (grade B, they sell security tooling)

We scanned snyk.io.

Grade: B

Snyk sells security tooling to development teams. Their homepage has DMARC properly set to quarantine, a valid CSP, no cookie issues, and an email deliverability grade of A.

The headers side has room to improve, but the DNS/email posture is solid. Good example of what the email layer looks like when it's done right.

Scan your own → app.securl.online

---

TWEET — Educational: what a C actually means

A C grade from SecURL isn't "you got hacked."

It means: you have the basics (HTTPS, a reasonable TLS cert, likely DMARC), but you're missing things that make you low-hanging fruit.

No Content-Security-Policy. Cookies without HttpOnly. Headers that were forgotten between the last deploy and the next audit.

Most C-grade sites are one afternoon's work from a B.

Check where you stand → app.securl.online

---

THREAD — "We scanned 25 SaaS homepages" (thread format for reach)

Tweet 1/5:
We scanned 25 well-known SaaS and developer tool homepages — Revolut, Notion, HubSpot, Vercel, Netlify, Snyk, and 19 others.

Here's what we found. 🧵

Tweet 2/5:
Not one of them scored an A.

80% had no strong Content-Security-Policy. That includes companies that specifically sell security products, and companies that host other people's production infrastructure.

It's not incompetence — it's the nature of the problem. Headers are invisible. They don't break anything when they're missing.

Tweet 3/5:
The DMARC picture was better. Only 1 of 25 had no DMARC record at all (PagerDuty).

Most had reject or quarantine policies in place. Email trust has clearly become a priority in the last few years — probably driven by Google and Yahoo's 2024 sender requirements.

Tweet 4/5:
24% had cookies set without proper security flags — cookies being served without Secure or HttpOnly attributes. On homepages, not login pages, which means this isn't session cookies. Still worth fixing.

Grade breakdown:
→ 2 sites: U (unscored — scan errors)
→ 13 sites: C
→ 10 sites: B
→ 0 sites: A

Tweet 5/5:
The point isn't to shame anyone. Most of this is fixable in an afternoon.

The point is that even well-resourced teams at known companies miss this stuff without something checking the whole picture.

That's what SecURL is for. Paste a URL, get the read in 30 seconds.

→ app.securl.online

---

POSTING ORDER SUGGESTION

1. Stat post (Tweet 3, updated) — best for organic reach, schedule for 8am Tuesday
2. Thread ("We scanned 25 SaaS homepages") — Wednesday lunchtime
3. Vercel scan result — Thursday morning (irony angle gets tech audience)
4. "What a C grade means" educational — Friday
5. Snyk scan result — following Monday (positive framing, good for engagement)
6. Cloudflare scan result — following Wednesday
