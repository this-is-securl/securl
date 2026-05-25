Dev.to Article Draft #4
Title: The five security headers every SaaS product should have before it goes live
Tags: security, webdev, saas, devops
Target keyword: "security headers SaaS" / "security headers checklist"
CTA: Check whether yours are in place at SecURL (free, 30 seconds)

---

ARTICLE

Most SaaS products launch without security headers. Not because the team does not care, but because headers are invisible. They do not show up in a browser. They do not cause errors if they are missing. They do not block any user journey. So they get missed during development, skipped in the launch checklist, and discovered weeks later when someone runs a security scan.

Here are the five that every SaaS product should have before it goes live, in order of how much they matter and how quickly you can add them.


Strict-Transport-Security

This header tells browsers to always connect to your site over HTTPS — not just on the current visit, but on every future visit, forever (or until the max-age expires). Without it, a browser that receives a redirect from http:// to https:// on the first request is vulnerable to a network attacker intercepting that initial connection before the redirect happens.

Add it with a long max-age and includeSubDomains:

```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

That max-age is two years. Once a browser has seen this header, it will refuse to make an insecure connection to your domain for two years. If you add preload and submit your domain to the HSTS preload list (at hstspreload.org), browsers will enforce HTTPS even on the very first visit.

There is no reason not to have this on every SaaS product. It takes thirty seconds to add and never needs to change.


X-Content-Type-Options

This one prevents browsers from guessing content types. Without it, a browser might try to execute a file as JavaScript even if your server sent it as text/plain, because the content looks like JavaScript. This is called MIME sniffing, and it is an attack surface.

The fix is one line:

```
X-Content-Type-Options: nosniff
```

Set it and forget it. It never needs to change.


X-Frame-Options

This header prevents your pages from being embedded in an iframe on an attacker's website. Without it, a clickjacking attack is possible: an attacker puts your login page inside an invisible iframe, overlays their own interface on top, and tricks users into entering credentials or clicking buttons they cannot see.

```
X-Frame-Options: DENY
```

Use DENY unless you have a specific reason to allow framing by same-origin (in which case, use SAMEORIGIN). If you have a Content-Security-Policy in place, the frame-ancestors directive does the same job and takes precedence in modern browsers. You can set both for compatibility.


Referrer-Policy

When a user clicks a link from your site to another domain, browsers include a Referer header showing where the user came from. By default this includes the full URL — path and query string. If any of your URLs contain tokens, IDs, or anything sensitive (password reset links, magic login links, session identifiers in URLs), this leaks information to third parties every time a user navigates away.

```
Referrer-Policy: strict-origin-when-cross-origin
```

This policy sends the full URL for same-origin requests (useful for analytics) and only the origin — not the path or query string — for cross-origin requests. It is a reasonable default for almost every SaaS product.


Content-Security-Policy

Save the hardest for last. CSP is the most powerful header on this list and the one most teams put off because it takes actual work to configure correctly.

A Content-Security-Policy tells the browser exactly which sources are allowed to load scripts, styles, images, fonts, and other resources on your page. A strict CSP can make the difference between a successful XSS attack that exfiltrates user data and an XSS that is blocked before it can do anything.

The reason teams skip it: you have to audit everything your page loads. Every script, every stylesheet, every analytics vendor, every font. Anything not on the list gets blocked. If you ship a CSP that is too strict, you will break your own product.

The pragmatic approach is to start with Content-Security-Policy-Report-Only. This header applies your policy but does not enforce it — it just sends reports to a URL you specify whenever something would have been blocked. You can watch the violations for a week, add legitimate sources to your policy, and only switch to enforcing mode once you are confident nothing legitimate will be blocked.

A minimal starting point:

```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'
```

You will need to extend this for every external service you load. Google Fonts, Stripe, analytics, intercom, customer support widgets — each one needs to be explicitly allowed.

It is the most work of the five headers. It is also the most protection.


In practice

These five cover the most commonly exploited gaps in SaaS security posture without requiring any changes to your application logic. They are purely HTTP headers. No code changes, no database migrations, no deployment risk beyond the config change itself.

None of them are perfect defences in isolation. A determined attacker with an XSS vector will look for ways around a CSP. HSTS only matters for network-based downgrade attacks. But they are the baseline — the things that separate a site that has thought about the basics from one that has not.

If you want to see where your product currently stands, paste your URL into SecURL at app.securl.online. It will check all five of these plus TLS configuration, DNS/email trust, cookie security, and third-party script surface in a single pass, with every finding ranked by what to fix first.
