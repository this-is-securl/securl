# SecURL UX Review Checklist

Run this checklist before every production ship. Use `/ship` or `/ship-marketing` which runs this automatically.

---

## APP — app.securl.online

### 1. Page load & first impression
- [ ] Dark background (`#040c08`) fills the full viewport — no white flash or gap at top/bottom
- [ ] Logo "Sec**URL**" renders correctly (teal "URL")
- [ ] Hero headline and subtext are readable at 1440px and 375px
- [ ] No layout shift visible on load

### 2. URL input & scan trigger
- [ ] Input placeholder text is clear and helpful
- [ ] Submit button is clearly actionable (not greyed, good contrast)
- [ ] Pressing Enter triggers the scan
- [ ] Scanning a URL shows a meaningful progress state (not a blank page)
- [ ] Invalid URL (e.g. `notaurl`) shows a helpful, non-technical error message

### 3. Report — Overview
- [ ] Grade ring renders correctly (colour matches grade: green A, blue B, amber C, orange D, red F)
- [ ] Score is labelled "Score:" not "Weighted signal"
- [ ] Summary text is readable (zinc-300, not too small)
- [ ] Export buttons (PDF/JSON) are visible and functional

### 4. Report — Navigation tabs
- [ ] All tab labels fit without truncation at 1280px wide
- [ ] Active tab is clearly highlighted
- [ ] Tab bar scrolls on mobile (375px) without breaking layout
- [ ] Share button sits above the tab bar (not competing for horizontal space)

### 5. Report — Section panels
- [ ] Each active finding shows a severity badge (Critical/High/Medium/Low)
- [ ] OWASP/MITRE references are present where applicable
- [ ] "No issues" state looks intentional (not empty/broken)
- [ ] Panel headers are consistent (same font size, same uppercase tracking style)

### 6. Recent scans / History
- [ ] Grade letters are coloured (green for A, red for F, etc.) — not all teal
- [ ] Clicking a recent scan opens it (may re-scan in anon mode — this is expected)
- [ ] Scan list doesn't overflow its container

### 7. Authentication
- [ ] Sign In / Sign Up flow is reachable from the app
- [ ] After sign-in, user name/avatar is shown
- [ ] Sign out works and clears state cleanly

### 8. Mobile (375px viewport)
- [ ] Hero + URL input usable on mobile
- [ ] Report tabs scroll horizontally — no overflow breaking layout
- [ ] Grade ring is centred and not cut off
- [ ] Touch targets ≥ 44px (buttons, tabs)

### 9. Dark mode consistency
- [ ] No white or near-white backgrounds visible anywhere in the app
- [ ] All text meets minimum contrast (zinc-300 on dark bg minimum)
- [ ] No blue browser-default link colours bleeding through

### 10. Performance / polish
- [ ] No visible console errors (open DevTools before checking)
- [ ] Page title is "SecURL — Security Posture Intelligence"
- [ ] OG image and meta description are set (check via `curl -s <url> | grep og:`)

---

## MARKETING — securl.online

### 11. Hero section
- [ ] Headline reads clearly and communicates the value prop in one sentence
- [ ] CTA button ("Try it free →") links to `https://app.securl.online`
- [ ] Hero renders well at 1440px and 375px
- [ ] No typos in above-fold copy

### 12. Value proposition / Feature grid
- [ ] All feature icons are visually distinct (no two look identical)
- [ ] Copy says "public-response checks" or "passive" — never "active scanning"
- [ ] Feature descriptions are factually accurate (cross-check against what the app actually does)

### 13. Comparison table
- [ ] SecURL column is highlighted (teal, distinct from competitors)
- [ ] All competitor columns are accurate (no false claims)
- [ ] Footer text says "Public-response checks plus passive intelligence" — not "Active checks"
- [ ] Table is readable on mobile (horizontal scroll or responsive layout)

### 14. CTA / conversion
- [ ] At least one CTA link above the fold and one at the bottom of the page
- [ ] All "Try it free" / "Try SecURL" links go to `https://app.securl.online`
- [ ] Android downloads link goes to `https://securl.online/downloads`
- [ ] No broken links (check with browser)

### 15. Trust & credibility
- [ ] No placeholder lorem ipsum text anywhere
- [ ] No "coming soon" labels on shipped features
- [ ] Privacy policy / terms links are present in footer (or noted as TODO)

---

## Sign-off

After running all checks, record:

```
Date: ____-__-__
Reviewer: ____________
App version: __________
Items passed: __ / 35
Items failed: __
Items skipped (with reason): __
Notes: 
```

A ship is approved when all **critical** items pass (items 1–6, 11–14). Items 7–10 and 15 are important but can be shipped with known issues logged.
