# SecURL Marketing Plan

**Goal:** Generate enough recurring revenue to sustain the product, with Keith mostly hands-off after initial setup.

**Model:** Claude handles content creation, community engagement drafts, and campaign execution. Keith signs up for tools and approves/posts anything that requires his identity or payment.

---

## 1. Who We're Selling To

### Primary: Developers who own security at small companies
- 1–50 person companies, no dedicated security team
- The dev who gets asked "are we GDPR / SOC 2 ready?"
- Feels anxiety about headers, DMARC, TLS — knows they should fix it, doesn't know where to start
- Pain: audit prep, customer security questionnaires, "our client wants a security report"

### Secondary: Freelancers & agencies
- Web agencies doing security handoff to clients
- Freelancers who want to add a "security audit" line to their invoice
- Need a client-presentable PDF, not a raw curl output

### Tertiary: Security-curious CTOs / founders
- Wants assurance their stack is "not embarrassing"
- Will respond to "paste your URL and find out in 30 seconds"

### Who we're NOT targeting (yet)
- Enterprise (too slow a sales cycle)
- Pentesters (tool is too lightweight — they know this)

---

## 2. Revenue Model

### Tiers (to be implemented — current: all free)

| Tier | Price | Features |
|------|-------|---------|
| **Free** | $0 | 3 scans/day, 30-day history, no PDF export |
| **Pro** | $9/month | Unlimited scans, full history, PDF export, monitoring (1 target) |
| **Team** | $29/month | 5 seats, 10 monitored targets, priority support |

**Payment stack (Keith to sign up):**
- **Lemon Squeezy** (recommended over Stripe for indie devs — handles EU VAT automatically, simpler setup, no code-heavy Stripe integration needed)
- Sign up at: https://lemonsqueezy.com

**Revenue target:** 50 Pro subscribers = $450 MRR (covers hosting + sustain). 200 Pro = $1,800 MRR (meaningful income).

---

## 3. Channels — Prioritised by ROI

### Tier 1: Free, high-leverage (Claude can do 90% of work)

#### A. Product Hunt launch
- **When:** After billing is live (so there's something to convert to)
- **What:** Full PH launch — tagline, gallery, maker comment, 5-day follow-up
- **Keith needs to:** Create a Product Hunt account, schedule the launch date
- **Claude does:** Draft all copy, respond to comments (Keith approves before posting)
- **Realistic outcome:** 200–800 upvotes if timed well, 50–200 trial signups in week 1

#### B. Hacker News "Show HN"
- **When:** Same week as PH or independent
- **Post format:** `Show HN: SecURL – paste a URL, get an A–F security posture grade in 30s`
- **Keith needs to:** Post from his HN account (or create one)
- **Claude does:** Draft the post body, prep FAQ answers for comments
- **Realistic outcome:** 50–300 points if it resonates, direct traffic spike

#### C. Twitter/X — automated scan results
- **The hook:** Auto-post "we scanned the homepage of [well-known company] — their grade is X" with a screenshot of the report
- **Cadence:** 3–4 posts/week
- **Owned channel:** [@ThisIsSecURL](https://x.com/ThisIsSecURL)
- **Keith needs to:** Connect @ThisIsSecURL to a social scheduler (Buffer free tier is enough to start)
- **Claude does:** Draft all posts, suggest which companies to scan (interesting grades, notable findings)
- **Rules:** Only scan public-facing homepages. Never name a finding as a "vulnerability." Frame as "here's what external tools see."

#### D. LinkedIn — dev/security audience
- **Content type:** Short "did you know?" posts + scan result screenshots
- **Cadence:** 2x/week
- **Examples:**
  - "75% of the top 100 UK SaaS companies have no DMARC policy. Here's what that means for email spoofing."
  - "We scanned 20 dev agency websites. Only 3 had a Content-Security-Policy. Here's why it matters."
- **Keith needs to:** Either post from personal LinkedIn or create a SecURL company page
- **Claude does:** Draft all posts

#### E. Dev.to / Hashnode articles
- **Format:** How-to articles that rank on Google
- **Owned channel:** [dev.to/thisissecurl](https://dev.to/thisissecurl)
- **Article ideas:**
  1. "What is a Content-Security-Policy and why does your site need one?"
  2. "DMARC explained: stop people spoofing your email domain in 20 minutes"
  3. "How to check your website's security headers (free tools + what to look for)"
  4. "The 5 security headers every SaaS should have — and how to add them"
- **Each article ends with:** "You can scan your site for free at SecURL"
- **Keith needs to:** Create a Dev.to or Hashnode account
- **Claude does:** Write all articles (Keith reviews before publishing)

---

### Tier 2: Medium effort, medium return

#### F. Reddit — /r/webdev, /r/netsec, /r/selfhosted
- **Approach:** Helpful comments first (no spam). Mention SecURL only when directly relevant.
- **Example:** Someone asks "how do I check my security headers?" → reply with a helpful answer + "SecURL also gives you a full graded report if you want it all in one place"
- **Keith needs to:** Share Reddit login with Claude (or paste comment drafts for Keith to post)
- **Claude does:** Monitor for relevant threads (can search weekly), draft comments

#### G. Cold email to web agencies
- **List:** Small web agencies (10–50 people) that build sites but don't offer security audits
- **Pitch:** "Add a SecURL security audit as a line item in your proposals. Looks professional, takes 30 seconds."
- **Volume:** Start with 50 personalised emails/week
- **Keith needs to:** Sign up for Hunter.io (free tier) for email finding, Apollo.io or similar for sequencing (or just Gmail BCC batch)
- **Claude does:** Build prospect list, write email sequences

#### H. Security communities
- **Targets:** OWASP Slack, DevSecOps community Slack, security newsletters (e.g. tldr.security, tldrsec)
- **Approach:** Sponsor or just participate genuinely
- **Newsletter sponsorship cost:** ~$150–500/issue (tldrsec, etc.) — only when revenue justifies it

---

### Tier 3: Longer term (do after $500 MRR)

#### I. SEO / content site
- Target keywords: "security headers checker", "DMARC checker free", "website security scan free"
- Build comparison pages: "SecURL vs securityheaders.com", "DMARC checker comparison"
- Timeline: 3–6 months to see organic traffic

#### J. Integrations / ecosystem
- GitHub Action: "SecURL scan on every deploy"
- Zapier/Make integration: trigger a scan, get grade back as webhook
- These make the product stickier and open up B2B word-of-mouth

---

## 4. Content Calendar (First 8 Weeks)

### What Claude will produce each week

| Week | Deliverable |
|------|-------------|
| 1 | Twitter account set up. First 5 tweets drafted. Dev.to article #1 drafted. |
| 2 | HN Show HN post drafted. LinkedIn posts #1–4 drafted. |
| 3 | PH launch page copy drafted. Dev.to article #2 drafted. |
| 4 | **PH Launch week.** 5 follow-up comments drafted. |
| 5 | Agency cold email sequence drafted (10 emails). Reddit comment queue. |
| 6 | Dev.to article #3. LinkedIn posts #5–8. |
| 7 | Analyse what's working (traffic, signups). Double down on best channel. |
| 8 | Dev.to article #4. Plan month 3. |

---

## 5. What Keith Needs to Sign Up For

These are the only accounts/tools needed to execute the above:

| Service | Purpose | Cost | URL |
|---------|---------|------|-----|
| **Lemon Squeezy** | Billing / payments | Free to set up (takes % of revenue) | lemonsqueezy.com |
| **Buffer** | Social media scheduling | Free (3 channels, 10 posts queue) | buffer.com |
| **Dev.to** | Article publishing | Free | [dev.to/thisissecurl](https://dev.to/thisissecurl) |
| **Twitter/X** | Scan result posts | Free | [@ThisIsSecURL](https://x.com/ThisIsSecURL) |
| **LinkedIn** | B2B audience | Free (personal or company page) | linkedin.com |
| **Product Hunt** | Launch | Free | producthunt.com |
| **Hunter.io** | Agency email finding | Free (25 searches/month) | hunter.io |

**Total upfront cost: $0.** Everything on the list has a free tier that's sufficient to start.

---

## 6. How This Stays Hands-Off for Keith

**The workflow:**

1. Claude drafts content in batches (1–2 times/week)
2. Keith reviews a doc or message, replies "looks good" or with minor edits
3. Keith either schedules via Buffer (30 seconds) or Claude pastes to a connected tool

**What Claude can do fully autonomously:**
- Scan public company websites and draft tweet threads with results
- Write and draft blog articles
- Monitor Reddit/HN for relevant questions
- Draft responses to comments (Keith approves before posting)
- Track which posts got traction and adjust strategy

**What Keith must do himself (unavoidable):**
- Sign up for accounts (above list)
- Connect Buffer to social channels
- Post the HN and PH submissions (from his account, builds credibility)
- Approve billing/Lemon Squeezy setup
- Respond to genuine user questions/support

---

## 7. Success Metrics

| Metric | Month 1 | Month 3 | Month 6 |
|--------|---------|---------|---------|
| Weekly scans | 50 | 300 | 1,000 |
| Pro subscribers | 0 | 10 | 50 |
| MRR | $0 | $90 | $450 |
| Twitter followers | 50 | 300 | 1,000 |
| Dev.to article views | 500 | 3,000 | 10,000 |

These are conservative. A good HN or PH day can blow month-1 targets in a single week.

---

## 8. Next Actions (in order)

1. **Keith:** Sign up for Lemon Squeezy and share the account so billing can be configured
2. **Claude:** Draft the first 5 @ThisIsSecURL posts + Dev.to article #1 for review
3. **Keith:** Connect @ThisIsSecURL and Dev.to to the publishing workflow
4. **Claude:** Draft the HN Show HN post and PH launch copy for review
5. **Keith:** Create Buffer account, connect Twitter/X + LinkedIn
6. **Both:** Set a PH launch date (aim for a Tuesday or Wednesday, never Friday)
