# Dev.to Article Draft #1
**Title:** What are HTTP security headers — and which ones does your site actually need?  
**Tags:** security, webdev, tutorial, beginners  
**Target keyword:** "HTTP security headers"  
**CTA:** Check your site with SecURL (free)

---

## Article

If you've ever run a security scan on your website and seen warnings about "missing headers," you've probably wondered: what are they, do I actually need them, and how do I add them?

This is the practical version of that answer — no academic theory, just what each header does, when you need it, and how to add it.

### What is an HTTP security header?

When your server responds to a browser's request, it sends back not just the page content, but also a set of metadata fields called **headers**. Most of these are technical plumbing (`Content-Type`, `Cache-Control`, etc.). Security headers are a subset that tell the browser how to behave to protect the user.

They're set by your server — not your HTML — and they're free. There's no excuse not to have them.

### The five you actually need

#### 1. Strict-Transport-Security (HSTS)

**What it does:** Tells browsers to only connect to your site over HTTPS, even if someone types `http://` or clicks an old `http://` link.

**Why it matters:** Without HSTS, someone on public WiFi could perform an SSL strip attack — downgrading your connection to plain HTTP and reading everything.

**How to add it (Nginx):**
```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

**How to add it (Express/Node):**
```js
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }));
```

**Risk without it:** Medium. Mostly relevant on public networks.

---

#### 2. Content-Security-Policy (CSP)

**What it does:** A whitelist of where scripts, styles, images, and other resources are allowed to load from. Anything not on the list gets blocked.

**Why it matters:** Prevents cross-site scripting (XSS) attacks, where an attacker injects malicious JavaScript into your page. It also prevents data exfiltration — even if something does get injected, CSP can block it from calling home.

**A reasonable starting point:**
```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; object-src 'none'; frame-ancestors 'none';
```

**Note:** CSP is the most complex header to configure if you use third-party scripts (analytics, chat widgets, etc.). Start with report-only mode:
```
Content-Security-Policy-Report-Only: default-src 'self'; ...
```
This logs violations without blocking anything, so you can see what you'd break before enforcing.

**Risk without it:** High for apps that accept any user input.

---

#### 3. X-Frame-Options

**What it does:** Prevents your site from being embedded in an `<iframe>` on another domain.

**Why it matters:** Clickjacking — an attacker overlays your login page in an invisible iframe on their site, then tricks users into clicking buttons they can't see.

**How to add it:**
```
X-Frame-Options: DENY
```
Or if you need to allow specific origins, use CSP's `frame-ancestors` instead (more flexible, modern equivalent).

**Risk without it:** Medium. Login pages and financial UIs are at most risk.

---

#### 4. X-Content-Type-Options

**What it does:** Tells the browser not to try to guess (sniff) what type of content a file is — just use what the server declares.

**Why it matters:** Without it, a browser might execute a file as JavaScript even if the server sent it as `text/plain`. Attackers can exploit this with uploaded files.

**How to add it:**
```
X-Content-Type-Options: nosniff
```

**Risk without it:** Low-Medium. Required for any site with file uploads.

---

#### 5. Referrer-Policy

**What it does:** Controls how much URL information is sent in the `Referer` header when a user clicks a link from your site to another site.

**Why it matters:** Without it, if a user clicks an external link from `yourapp.com/dashboard/project/12345`, that URL — including the project ID — gets sent to the third-party site's server.

**A safe default:**
```
Referrer-Policy: strict-origin-when-cross-origin
```

**Risk without it:** Low. But it leaks information you probably don't intend to share.

---

### The email-related ones (often missed)

These aren't HTTP headers — they're DNS records — but they're checked in most security scans and they matter.

**SPF (Sender Policy Framework):** Lists which servers are allowed to send email from your domain. Without it, anyone can claim to send from `you@yourcompany.com`.

**DMARC:** Tells receiving mail servers what to do when an email fails SPF/DKIM checks. Without it, spoofed emails might still get delivered.

**DKIM:** Cryptographically signs your outgoing email so recipients can verify it actually came from you.

Most email providers (Google Workspace, Postmark, SendGrid) give you these records to add to your DNS. It takes about 20 minutes and costs nothing.

---

### How to check what you have

You can check manually with `curl`:

```bash
curl -I https://yoursite.com
```

This shows your response headers. But it won't tell you whether your values are correct, whether your DMARC is misconfigured, or give you a prioritised fix list.

A faster option: paste your URL into [SecURL](https://app.securl.online) — it checks headers, TLS, DNS/email records, and more, gives you an A–F grade, and ranks what to fix first. Free, no account needed.

---

### Common mistakes

**"I use Cloudflare / a CDN, so I'm fine"**  
CDNs add some headers (like HSTS) but not all. You still need to configure CSP and others at your origin.

**"My site is just a marketing site, not an app"**  
Marketing sites get compromised too — often more easily, because they have less scrutiny. A compromised marketing site that loads malicious JS affects everyone who visits it.

**"I'll add these before we go to production"**  
Ship them now. The headers take minutes to add and they have zero performance cost.

---

### Summary

| Header | Priority | Difficulty |
|--------|----------|-----------|
| Strict-Transport-Security | Must-have | Easy |
| X-Content-Type-Options | Must-have | Easy |
| X-Frame-Options | Must-have | Easy |
| Referrer-Policy | Should-have | Easy |
| Content-Security-Policy | Should-have | Medium–Hard |
| SPF + DMARC + DKIM | Must-have | Medium |

Start with the easy ones — you can ship them in an afternoon. CSP is worth doing properly, so take the time to get it right with report-only mode first.

---

*Check your site's current grade at [SecURL](https://app.securl.online) — free, no account needed.*
