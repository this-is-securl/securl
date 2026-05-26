Show HN: SecURL – paste any URL, get an A–F security posture grade in ~30s

---

TITLE (copy exactly):
Show HN: SecURL – paste any URL, get an A–F security posture grade in ~30s

URL: https://app.securl.online

---

BODY (post this as your comment on the thread):

I built this because I kept getting the same question from clients and coworkers: "are we secure enough?" There's no quick answer. securityheaders.com covers headers. SSL Labs covers TLS. Mozilla Observatory covers a few things in between. None of them give you a single grade that covers the whole picture.

SecURL reads headers, TLS config, DNS/email trust (SPF, DMARC, DNSSEC, MTA-STS, BIMI), third-party script surface, session replay and analytics vendor detection, cookie security, public exposure signals, and more — then ranks every finding by severity so you know what to fix first.

The output is an A–F grade with findings mapped to OWASP and MITRE ATT&CK references. You can export a PDF if you need to show it to someone who isn't a developer. There's also monitoring so you get alerted if a header disappears after a deploy.

I scanned 25 well-known SaaS homepages last week as a sanity check. 80% had no strong Content-Security-Policy. Not one of them scored an A. These are companies whose product teams know better — it just slips through the cracks without something that checks the whole picture at once.

Everything is passive — we read what any browser would see. No active probing, no footprint on the target.

Stack: React + Vite + Tailwind on the front end, Node.js backend on Railway, Supabase for auth and storage.

Try it: https://app.securl.online

Happy to answer questions about how the scanner works, what signals we read, or how the scoring model was put together.

---

PREP: FAQ answers for likely HN comments

Q: How is this different from securityheaders.com?
A: securityheaders.com is excellent at what it does — HTTP headers. SecURL covers headers as one of seven areas: it also reads DNS/email trust (DMARC, SPF, DNSSEC, MTA-STS, BIMI), TLS config, cookie security, third-party script surface, passive intelligence (tech stack, AI surface exposure, analytics/session replay vendor detection), and public disclosure signals. The grade reflects all of those together, ranked by what actually matters first.

Q: Is this active or passive scanning?
A: Passive only. We read public HTTP responses, DNS records, and publicly accessible metadata — the same signals any browser or external observer would see. We don't crawl, probe ports, send probes, or do anything that would show up in server logs as unusual traffic.

Q: What's the business model?
A: Free to use now. Paid tiers will add unlimited scans, full history, monitoring beyond one target, and team seats. Billing isn't live yet.

Q: How does the A–F grade work?
A: Each finding has a severity weight (critical/warning/info). The score is a composite across all seven posture areas with critical findings weighted heavily. The grade band maps score to letter: A is 85+, B is 70–84, etc. The exact model is in the open source core package.

Q: What's the tech stack?
A: Scanner core in TypeScript (Node.js), React/Vite/Tailwind on the front end, Supabase for auth and storage, Railway for the API, Hostinger for the static front end.

Q: Can I self-host it?
A: The scanner core is the extractable part. The full app has some hosted dependencies (Supabase, the Railway API). If there's interest I'd consider making the scanner core more standalone.

Q: What happens to scan results?
A: Scans are stored so you can share a link and so monitoring works. We don't sell data or use results for training. Scans can be deleted.
