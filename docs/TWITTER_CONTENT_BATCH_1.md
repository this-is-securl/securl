# Twitter Content — Batch 1
**Account:** @ThisIsSecURL  
**Goal:** Establish what SecURL is, build early followers, drive first trial scans

---

## Tweet 1 — Launch / Introduction
*Pin this one.*

```
We built SecURL.

Paste a URL → get an A–F security posture grade in ~30 seconds.

It checks headers, TLS, DMARC, SPF, DNSSEC, third-party scripts, and more — then ranks what to fix first.

Free to try: app.securl.online
```

---

## Tweet 2 — The relatable dev pain point

```
"Are we secure enough for this client?"

You know you should have DMARC. You know Content-Security-Policy matters. But auditing it manually takes hours.

SecURL does it in 30 seconds. One URL. One grade. Everything ranked.

→ app.securl.online
```

---

## Tweet 3 — Stat post (engagement bait, shareable)

```
We scanned 50 UK SaaS homepages this week.

Results:
• 68% had no Content-Security-Policy
• 54% had no DMARC policy (anyone can spoof their email domain)
• 31% were still serving cookies without Secure or HttpOnly flags
• 12% had TLS misconfigurations

Most of these are 30-minute fixes.

Check yours free → app.securl.online
```

*(Note: replace these with real numbers from actual scans before posting)*

---

## Tweet 4 — "Did you know" educational

```
Did you know your email domain can be spoofed even if you don't send email?

Without a DMARC policy, anyone can send emails "from" you@yourcompany.com.

It takes about 20 minutes to fix. SecURL tells you instantly whether you're exposed.

Free check → app.securl.online
```

---

## Tweet 5 — Scan result post (template — fill with a real scan)

```
We scanned [COMPANY]'s public homepage.

Grade: [X]

Findings:
• [Finding 1]
• [Finding 2]  
• [Finding 3]

These are all public-response signals — nothing invasive, just what any browser sees.

Scan your own site → app.securl.online
```

**Suggested targets to scan and post about:**
- A well-known developer tool (Vercel, Netlify, Railway)
- A major UK SaaS (Monzo, Revolut homepage, not login)
- A household brand with likely poor security posture (big retailer)
- Keep it positive when grade is good ("here's what an A looks like")
- When grade is poor, frame as "here's what external tools see" not "they have a vulnerability"

---

## Tweet 6 — Dev agency pitch

```
Web agencies: do your clients ever ask "are we secure?"

Add a SecURL scan to your project handoff.
• Professional A–F grade
• Ranked findings with fix guidance
• PDF export for the client file

Looks great on an invoice. Takes 30 seconds.

→ app.securl.online
```

---

## Thread — "What's in an A grade?" (post as thread, high educational value)

**Tweet 1/6:**
```
What does an "A" security grade actually mean for your website?

Thread 🧵
```

**Tweet 2/6:**
```
Content-Security-Policy: controls what scripts can run on your page.

An A-grade CSP blocks inline scripts, restricts third-party sources, and prevents data exfiltration.

Most sites have none. Takes an afternoon to implement.
```

**Tweet 3/6:**
```
HSTS (HTTP Strict Transport Security): tells browsers to ONLY connect over HTTPS.

Without it, someone on public WiFi could downgrade your connection to HTTP.

One header. One line of config. Permanent protection.
```

**Tweet 4/6:**
```
DMARC + SPF: your email domain's trust signals.

Without them, anyone can send "from" your domain. Phishing your customers. Impersonating your support team.

Most sites don't have both configured correctly.
```

**Tweet 5/6:**
```
X-Frame-Options / frame-ancestors: prevents clickjacking.

Your login page embedded in an attacker's iframe, buttons overlaid to capture clicks.

One header prevents it entirely.
```

**Tweet 6/6:**
```
An A grade means you've covered the basics that most sites skip.

It doesn't mean you're unhackable. But it means you're not low-hanging fruit.

Check your grade free in 30 seconds:
→ app.securl.online
```

---

## Posting schedule (Buffer)

| Day | Tweet |
|-----|-------|
| Mon | Tweet 1 (pin immediately) |
| Tue | Tweet 3 (stat post — best for engagement) |
| Wed | Tweet 4 (DMARC educational) |
| Thu | Thread — "What's in an A grade?" |
| Fri | Tweet 2 (relatable pain point) |
| Next Mon | Tweet 6 (agency pitch) |
| Next Wed | First real scan result post |

**Best times:** 8–9am GMT (commute), 12–1pm GMT (lunch), 5–6pm GMT (end of day)
