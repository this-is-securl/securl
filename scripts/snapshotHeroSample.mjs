#!/usr/bin/env node
// Snapshot a real SecURL grade for the landing page's "Sample result" card.
//
// The pre-scan hero (src/pages/Index.tsx -> HeroPreviewCard) shows one example
// of "what your scan produces". That card must show a real grade — we grade
// other people's sites, so a fabricated sample on our own landing page is a
// credibility liability (it previously hardcoded a portswigger "B/74" that the
// engine never actually returns).
//
// This runs a live standard-mode scan against one curated domain via the SecURL
// API, pulls the compact /digest, and regenerates src/data/heroSample.ts. It is
// a manual/committed step (`npm run snapshot:hero-sample`), NOT a build hook —
// the build stays offline and deterministic. Re-run it after the engine is
// redeployed so the sample tracks the live grade.
//
//   npm run snapshot:hero-sample                 # default domain
//   node scripts/snapshotHeroSample.mjs acme.com # override domain
//
import { mkdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const BASE = (process.env.SECURL_API_BASE || "https://securl-app-production.up.railway.app").replace(/\/+$/, "");
const MODE = "standard"; // matches the app's default scan mode
const DEFAULT_DOMAIN = "github.com";

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT_FILE = resolve(__dirname, "../src/data/heroSample.ts");

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function makeOwnerToken() {
  const hex = [...Array(40)].map(() => Math.floor(Math.random() * 16).toString(16)).join("");
  return `hero-sample-${hex}`;
}

async function jsonOrThrow(res, what) {
  const text = await res.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    throw new Error(`${what}: non-JSON response (${res.status}): ${text.slice(0, 200)}`);
  }
  if (!res.ok) throw new Error(`${what}: HTTP ${res.status}: ${text.slice(0, 200)}`);
  return body;
}

async function scanDomain(domain, owner) {
  const url = domain.startsWith("http") ? domain : `https://${domain}`;
  const create = await jsonOrThrow(
    await fetch(`${BASE}/api/scans`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-scan-owner": owner },
      body: JSON.stringify({ url, mode: MODE }),
    }),
    `create ${domain}`,
  );
  const id = create?.scan?.id;
  if (!id) throw new Error(`create ${domain}: no scan id`);

  for (let attempt = 0; attempt < 60; attempt += 1) {
    await sleep(2000);
    const poll = await jsonOrThrow(
      await fetch(`${BASE}/api/scans/${encodeURIComponent(id)}`, { headers: { "x-scan-owner": owner } }),
      `poll ${domain}`,
    );
    const status = poll?.scan?.status;
    if (status === "completed") break;
    if (status === "failed") throw new Error(`scan ${domain} failed: ${poll?.scan?.error ?? "unknown"}`);
  }

  const digestRes = await jsonOrThrow(
    await fetch(`${BASE}/api/scans/${encodeURIComponent(id)}/digest`, { headers: { "x-scan-owner": owner } }),
    `digest ${domain}`,
  );
  return digestRes.digest;
}

// "Cross-Origin-Opener-Policy is missing" -> "COOP missing", etc.
const PHRASE_RULES = [
  [/cookie/i, "Cookie hygiene"],
  [/content-security-policy.*missing|\bcsp is missing\b/i, "CSP missing"],
  [/content-security-policy|\bcsp\b/i, "Weak CSP"],
  [/strict-transport-security|\bhsts\b/i, (t) => (/missing/i.test(t) ? "HSTS missing" : "HSTS weak")],
  [/cross-origin-opener-policy/i, "COOP missing"],
  [/cross-origin-resource-policy/i, "CORP missing"],
  [/cross-origin-embedder-policy/i, "COEP missing"],
  [/permissions-policy/i, "Permissions-Policy"],
  [/x-frame-options|clickjack/i, "X-Frame-Options"],
  [/x-content-type-options|mime.?sniff/i, "MIME sniffing"],
  [/referrer-policy/i, "Referrer-Policy"],
];

function chipLabel(title) {
  for (const [re, out] of PHRASE_RULES) {
    if (re.test(title)) return typeof out === "function" ? out(title) : out;
  }
  let label = title.replace(/\bis missing\b/i, "missing").trim();
  if (label.length > 24) label = `${label.slice(0, 23)}…`;
  return label;
}

function areaChip(driver) {
  const area = String(driver?.areaLabel ?? "").trim();
  return area ? { label: `${area} gaps`, sev: "info" } : null;
}

function buildChips(digest) {
  const top = Array.isArray(digest?.findings?.top) ? digest.findings.top : [];
  const drivers = Array.isArray(digest?.posture?.scoreDrivers) ? digest.posture.scoreDrivers : [];
  const chips = [];
  const seen = new Set();
  const push = (chip) => {
    if (!chip || seen.has(chip.label) || chips.length >= 3) return;
    seen.add(chip.label);
    chips.push(chip);
  };
  for (const f of top) push({ label: chipLabel(f.title), sev: f.severity });
  for (const d of drivers) push(areaChip(d));
  return chips;
}

function postureLabel(grade) {
  const g = grade.toUpperCase();
  if (g === "A+" || g === "A") return "Excellent posture";
  if (g === "B") return "Good posture";
  if (g === "C") return "Mixed posture";
  if (g === "D") return "Needs attention";
  return "Critical posture";
}

function renderFile(sample, generatedAt) {
  const chips = sample.chips
    .map((c) => `    { label: ${JSON.stringify(c.label)}, sev: ${JSON.stringify(c.sev)} },`)
    .join("\n");
  return `// AUTO-GENERATED by scripts/snapshotHeroSample.mjs — do not edit by hand.
// A real standard-mode SecURL grade, snapshotted ${generatedAt}.
// Refresh with: npm run snapshot:hero-sample
export type HeroSampleChipSeverity = "critical" | "warning" | "info";

export interface HeroSampleChip {
  label: string;
  sev: HeroSampleChipSeverity;
}

export interface HeroSample {
  domain: string;
  grade: string;
  score: number;
  label: string;
  critical: number;
  warning: number;
  info: number;
  chips: HeroSampleChip[];
}

export const HERO_SAMPLE_GENERATED_AT = ${JSON.stringify(generatedAt)};

export const HERO_SAMPLE: HeroSample = {
  domain: ${JSON.stringify(sample.domain)},
  grade: ${JSON.stringify(sample.grade)},
  score: ${sample.score},
  label: ${JSON.stringify(sample.label)},
  critical: ${sample.critical},
  warning: ${sample.warning},
  info: ${sample.info},
  chips: [
${chips}
  ],
};
`;
}

async function main() {
  const domain = process.argv.slice(2).find((a) => !a.startsWith("--")) || DEFAULT_DOMAIN;
  const owner = makeOwnerToken();
  console.log(`Snapshotting ${domain} via ${BASE} (mode=${MODE})`);

  const digest = await scanDomain(domain, owner);
  const sev = digest?.findings?.bySeverity ?? { critical: 0, warning: 0, info: 0 };
  const grade = String(digest?.posture?.grade ?? "U");
  const sample = {
    domain: String(digest?.target?.host ?? domain).replace(/^www\./i, ""),
    grade,
    score: Number(digest?.posture?.score ?? 0),
    label: postureLabel(grade),
    critical: Number(sev.critical ?? 0),
    warning: Number(sev.warning ?? 0),
    info: Number(sev.info ?? 0),
    chips: buildChips(digest),
  };
  console.log(`  ${sample.domain} -> ${sample.grade}/${sample.score} (${sample.chips.map((c) => c.label).join(", ")})`);

  const generatedAt = new Date().toISOString();
  await mkdir(dirname(OUT_FILE), { recursive: true });
  await writeFile(OUT_FILE, renderFile(sample, generatedAt), "utf8");
  console.log(`Wrote ${OUT_FILE}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
