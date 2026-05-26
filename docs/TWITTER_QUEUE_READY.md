Twitter Queue — Ready to Post
These are trimmed to fit 280 chars. Post in this order (schedule from batch 2).

---

TWEET — Vercel scan result (Thursday this week)
~269 Twitter chars

We scanned vercel.com.

Grade: C

Vercel hosts millions of production sites. No strong CSP, 3 cookies without security flags, no DMARC reject policy.

Not the worst in the batch — most names you'd recognise are in the same bracket.

Scan yours → app.securl.online

---

TWEET — What a C means (Friday)
~265 Twitter chars

A C from SecURL doesn't mean "you got hacked."

It means: HTTPS is there, TLS is probably fine, but there's no CSP, cookies are missing security flags, and headers drifted after the last deploy.

One afternoon's work from a B.

Check yours → app.securl.online

---

TWEET — Snyk result (following Monday)
~255 Twitter chars

We scanned snyk.io.

Grade: B

DMARC to quarantine, valid CSP, no cookie issues, email grade A. Solid DNS/email posture.

Headers have room to improve — but the email trust layer is exactly what done right looks like.

Scan yours → app.securl.online

---

TWEET — Cloudflare result (following Wednesday)
~273 Twitter chars

We scanned cloudflare.com.

Grade: B

Cloudflare sells security to half the internet. Their homepage has a weak CSP and 3 cookies without full security flags.

Still a B, ahead of most. But posture is a continuous job, not a checkbox.

Check yours → app.securl.online

---

THREAD — "We scanned 25 SaaS homepages" (5 parts, best for reach)
Post as a thread. Each tweet is under 280 chars.

1/5
We scanned 25 well-known SaaS and developer tool homepages — Revolut, Notion, HubSpot, Vercel, Netlify, Snyk, and 19 others.

Here's what we found. 🧵

2/5
Not one scored an A.

80% had no strong CSP. That includes companies that sell security products and companies that host other people's production infrastructure.

It's not incompetence — headers are invisible. They don't break anything when they're missing.

3/5
The DMARC picture was better. Only 1 of 25 had no DMARC record at all.

Most had reject or quarantine in place. Email trust has become a priority — probably driven by Google and Yahoo's 2024 sender requirements.

4/5
24% had cookies set without proper security flags. On homepages, not login pages.

Grade breakdown:
→ 2 sites: U (scan errors)
→ 13 sites: C
→ 10 sites: B
→ 0 sites: A

5/5
The point isn't to shame anyone. Most of this is fixable in an afternoon.

The point is that even well-resourced teams miss this without something watching the whole picture.

That's what SecURL is for. Paste a URL, get the read in 30 seconds.

→ app.securl.online
