import { analyzeUrl } from "@ktbatterham/external-posture-core";

const target = process.argv[2] ?? "https://example.com";
const result = await analyzeUrl(target, {
  scanMode: "quiet",
});

console.log(JSON.stringify({
  url: result.finalUrl,
  score: result.score,
  grade: result.grade,
  mainRisk: result.executiveSummary?.mainRisk ?? null,
  findings: result.issues.map((issue) => ({
    severity: issue.severity,
    title: issue.title,
  })),
}, null, 2));
