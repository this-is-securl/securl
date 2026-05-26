Dev.to Article Draft #3
Title: How to check your website's security headers (and what to do with the results)
Tags: security, webdev, tutorial, beginners
Target keyword: "check website security headers" / "security headers checker"
CTA: Scan your full site posture free at SecURL

---

ARTICLE

If you search "check security headers," you will find several tools that return a simple pass/fail list. You paste a URL, you get a table. Some things are green, some are red, and you are left wondering which ones matter, what the red ones actually mean, and whether fixing them will take an afternoon or a week.

This article covers what security headers are, which ones you actually need, and how to get from a scan result to a real fix.


What are security headers

When your web server responds to a request, it sends headers alongside the page content. Most of these are functional: Content-Type, Cache-Control, Content-Length. Security headers are a specific subset that instruct the browser how to behave to protect the user from common attacks.

They sit in the HTTP response. They cost nothing to add. And because they are often not tested during normal development, they are easy to forget about and easy to miss when auditing.

The good news is that most of them can be added in an afternoon, either directly in your server config or through middleware.


The ones that actually matter

Content-Security-Policy is the most powerful and the most misunderstood. It tells the browser which sources of scripts, styles, images, and other resources are allowed to load on your page. A well-configured CSP stops an attacker who has injected malicious script from being able to load external resources, exfiltrate data, or phone home. Most sites have none. Of the 25 SaaS homepages we recently scanned — including well-known names like Vercel, Notion, and HubSpot — 80% had no strong CSP in place.

CSP is the hardest one to get right because it requires you to audit exactly what your page loads and where it comes from. But even a basic policy is better than nothing, and a report-only policy lets you see violations without blocking anything while you build toward a full implementation.

Strict-Transport-Security (HSTS) tells browsers to always connect to your site over HTTPS, even if the user types http:// or follows an http:// link. Without it, a network attacker can intercept the initial request and downgrade the connection. With it, the browser refuses to make insecure connections. It is one line of config and should be on every site that uses HTTPS — which is every site.

X-Frame-Options (or the frame-ancestors directive in a CSP) prevents your pages from being loaded inside an iframe on another domain. Without it, an attacker can embed your login page inside their own page and use visual tricks to capture user input. This is called clickjacking. It takes one header to prevent it.

X-Content-Type-Options with the value nosniff stops browsers from guessing the content type of a response. Without it, some browsers will try to execute a file if it looks like JavaScript, even if the server sent it with a non-script content type. One header. Never needs to change.

Referrer-Policy controls how much information about the current page is sent in the Referer header when a user navigates to another site. The default browser behaviour leaks full URLs, including any path and query string. If your URLs contain anything sensitive — session tokens, search terms, user IDs — you want to control this.

Permissions-Policy (formerly Feature-Policy) lets you disable access to browser features your site does not use: camera, microphone, geolocation, payment, and so on. If a third-party script loaded on your page tries to access the camera, a restrictive Permissions-Policy stops it.


What the scan results actually mean

Most header checkers return a binary: present or missing. That is useful but incomplete. A Content-Security-Policy of default-src *; is technically present but does nothing. An X-Frame-Options header is superseded by CSP frame-ancestors and may be ignored by modern browsers.

What you actually want to know is: given my specific configuration, what is the real-world risk, and what should I fix first?

For a CSP, the key questions are: is unsafe-inline allowed for scripts (bad), is default-src set to a wildcard (bad), is there a proper restriction on where data can be sent (form-action, connect-src)?

For HSTS, the key questions are: is includeSubDomains set, and is preload in place?

For X-Content-Type-Options, it is simply present or absent. Same for X-Frame-Options once you know CSP frame-ancestors is not overriding it.


How to add headers to your site

In Nginx, add headers to your server block:

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

In Apache, add them to your virtual host config or .htaccess:

```apache
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "DENY"
```

In Express (Node.js), the Helmet middleware handles most of these with sensible defaults:

```javascript
const helmet = require('helmet');
app.use(helmet());
```

In Next.js, headers go in next.config.js:

```javascript
const securityHeaders = [
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
];
```

For Vercel, Netlify, and Cloudflare Pages, you configure headers through their platform config files. Vercel uses vercel.json, Netlify uses a _headers file, Cloudflare Pages uses the same _headers format.


After you add them

Scan your site again after making changes to confirm the headers are being returned correctly. Headers set on the wrong routes, cached responses, or CDN stripping can all cause headers to not appear where you expect them.

SecURL at app.securl.online gives you the full read: which headers are present, what their values are, whether the values are configured correctly, and what the remaining gaps are. It also checks your DNS/email trust, TLS config, cookie security, and third-party surface in the same pass — so you are not running five separate tools to get the full picture.
