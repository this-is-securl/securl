import { writeFile } from "node:fs/promises";
import { readFile } from "node:fs/promises";
import process from "node:process";
import { analyzeUrl, buildHistoryDiffFromSnapshots, formatErrorMessage, snapshotFromAnalysis } from "./index.js";
import type { AnalysisResult, HistoryDiff, ScanIssue } from "./types.js";

type OutputFormat = "json" | "markdown" | "summary" | "sarif" | "ci-json";
type FailOnSeverity = Exclude<ScanIssue["severity"], "good">;
type ScanMode = "standard" | "quiet" | "deep-passive";
type ParsedArgs =
  | { command: "help" }
  | {
      command: "scan";
      targets: string[];
      format: OutputFormat;
      outputPath: string | null;
      baselinePath: string | null;
      failOnSeverity: FailOnSeverity | null;
      failOnRegression: boolean;
      failIfScoreBelow: number | null;
      scanMode: ScanMode;
    }
  | {
      command: "compare";
      currentPath: string;
      baselinePath: string;
      format: OutputFormat;
      outputPath: string | null;
      failOnSeverity: FailOnSeverity | null;
      failOnRegression: boolean;
      failIfScoreBelow: number | null;
    };

const usage = `SecURL CLI

Usage:
  securl scan <target...> [--format json|markdown|summary|sarif|ci-json] [--baseline <report.json>] [--output <file>] [--quiet|--deep-passive] [--fail-on info|warning|critical] [--fail-on-regression] [--fail-if-score-below <0-100>]
  securl compare <current-report.json> <baseline-report.json> [--format json|markdown|summary|sarif|ci-json] [--output <file>] [--fail-on info|warning|critical] [--fail-on-regression] [--fail-if-score-below <0-100>]

Examples:
  npx securl scan example.com
  npx securl scan example.com github.com bbc.co.uk
  npx securl scan https://example.com --format markdown
  npx securl scan example.com --format sarif --output findings.sarif
  npx securl scan example.com --format ci-json --output ci.json
  npx securl scan example.com --format json --output report.json
  npx securl scan example.com --quiet
  npx securl scan example.com --deep-passive
  npx securl scan example.com --baseline previous-report.json
  npx securl scan example.com --baseline previous-report.json --fail-on-regression
  npx securl scan example.com github.com --fail-on warning
  npx securl scan example.com github.com --fail-if-score-below 75
  npx securl compare current-report.json baseline-report.json
  npx securl compare current-report.json baseline-report.json --format sarif --fail-on critical

Scan modes:
  default scan   Fetches the primary response plus bounded passive enrichment: HTML, DNS/mail, CT, OSV, exposure, CORS, API-surface, and public trust signals.
  --quiet        Keeps primary response, TLS, headers, cookies, redirects, DNS/mail, CT summary, infrastructure, and public trust checks; skips page-body analysis, related-page crawl, security.txt fetch, identity discovery, exposure probes, CORS probes, API probes, OSV lookups, and CT host sampling.
  --deep-passive Expands passive CT host sampling, related-page crawl, exposure probes, and API-surface probes while keeping strict request limits and scan timeout bounds.

CI policy modes:
  --fail-on warning          Fail when findings at or above the selected severity are present.
  --fail-on-regression       Fail when a baseline comparison finds score, issue, or status regressions.
  --fail-if-score-below 75   Fail when any scanned target falls below the selected score.
`;

process.once("SIGINT", () => {
  process.stderr.write("\nScan interrupted. No temporary files were created by the CLI.\n");
  process.exit(130);
});

const parseArgs = (argv: string[]): ParsedArgs => {
  const args = [...argv];
  const command = args.shift();

  if (!command || command === "--help" || command === "-h" || command === "help") {
    return { command: "help" as const };
  }

  if (!["scan", "compare"].includes(command)) {
    throw new Error(`Unknown command: ${command}`);
  }

  let format: OutputFormat = "summary";
  let outputPath: string | null = null;
  let baselinePath: string | null = null;
  let failOnSeverity: FailOnSeverity | null = null;
  let failOnRegression = false;
  let failIfScoreBelow: number | null = null;
  let scanMode: ScanMode = "standard";
  const positionals: string[] = [];

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];

    if (arg === "--format") {
      const value = args[index + 1];
      if (!value || !["json", "markdown", "summary", "sarif", "ci-json"].includes(value)) {
        throw new Error("Invalid --format value. Use json, markdown, summary, sarif, or ci-json.");
      }
      format = value as OutputFormat;
      index += 1;
      continue;
    }

    if (arg === "--output") {
      const value = args[index + 1];
      if (!value) {
        throw new Error("Missing --output value.");
      }
      outputPath = value;
      index += 1;
      continue;
    }

    if (arg === "--baseline") {
      const value = args[index + 1];
      if (!value) {
        throw new Error("Missing --baseline value.");
      }
      baselinePath = value;
      index += 1;
      continue;
    }

    if (arg === "--help" || arg === "-h") {
      return { command: "help" as const };
    }

    if (arg === "--fail-on") {
      const value = args[index + 1];
      if (!value || !["info", "warning", "critical"].includes(value)) {
        throw new Error("Invalid --fail-on value. Use info, warning, or critical.");
      }
      failOnSeverity = value as FailOnSeverity;
      index += 1;
      continue;
    }

    if (arg === "--fail-on-regression") {
      failOnRegression = true;
      continue;
    }

    if (arg === "--fail-if-score-below") {
      const value = args[index + 1];
      const threshold = value ? Number(value) : Number.NaN;
      if (!value || !Number.isFinite(threshold) || threshold < 0 || threshold > 100) {
        throw new Error("Invalid --fail-if-score-below value. Use a number between 0 and 100.");
      }
      failIfScoreBelow = threshold;
      index += 1;
      continue;
    }

    if (arg === "--quiet") {
      if (scanMode === "deep-passive") {
        throw new Error("Choose either --quiet or --deep-passive, not both.");
      }
      scanMode = "quiet";
      continue;
    }

    if (arg === "--deep-passive") {
      if (scanMode === "quiet") {
        throw new Error("Choose either --quiet or --deep-passive, not both.");
      }
      scanMode = "deep-passive";
      continue;
    }

    if (arg.startsWith("--")) {
      throw new Error(`Unknown argument: ${arg}`);
    }

    positionals.push(arg);
  }

  if (command === "scan") {
    if (!positionals.length) {
      throw new Error("Missing target. Usage: securl scan <target...>");
    }
    if (positionals.length > 1 && baselinePath) {
      throw new Error("Baseline comparison is only supported for a single target scan. Use the compare command for saved reports.");
    }
    if (failOnRegression && !baselinePath) {
      throw new Error("Regression policy mode requires --baseline for scan. Use compare for saved reports.");
    }

    return {
      command: "scan",
      targets: positionals,
      format,
      outputPath,
      baselinePath,
      failOnSeverity,
      failOnRegression,
      failIfScoreBelow,
      scanMode,
    };
  }

  const [currentPath, compareBaselinePath] = positionals;
  if (!currentPath || !compareBaselinePath) {
    throw new Error("Missing report paths. Usage: securl compare <current-report.json> <baseline-report.json>");
  }

  return {
    command: "compare",
    currentPath,
    baselinePath: compareBaselinePath,
    format,
    outputPath,
    failOnSeverity,
    failOnRegression,
    failIfScoreBelow,
  };
};

const parseBaselineAnalysis = async (baselinePath: string) => {
  const raw = await readFile(baselinePath, "utf8");
  let parsed: AnalysisResult | { analysis?: AnalysisResult };

  try {
    parsed = JSON.parse(raw) as AnalysisResult | { analysis?: AnalysisResult };
  } catch {
    throw new Error("Baseline file is not valid JSON.");
  }

  if (parsed && typeof parsed === "object" && "analysis" in parsed && parsed.analysis) {
    return parsed.analysis;
  }

  if (parsed && typeof parsed === "object" && "finalUrl" in parsed && "score" in parsed) {
    return parsed as AnalysisResult;
  }

  throw new Error("Baseline file must contain a prior analysis JSON report.");
};

const formatDiffSummary = (diff: HistoryDiff | null) => {
  if (!diff) {
    return "Changes since baseline: No comparable baseline was provided.";
  }

  return [
    "Changes since baseline:",
    ...(
      diff.summary.length
        ? diff.summary
        : ["No material posture changes summarized."]
    ).map((item) => `- ${item}`),
  ].join("\n");
};

const formatComparisonSummary = (current: AnalysisResult, baseline: AnalysisResult, diff: HistoryDiff) =>
  [
    `Current: ${current.finalUrl}`,
    `Baseline: ${baseline.finalUrl}`,
    `Score change: ${baseline.score}/100 (${baseline.grade}) -> ${current.score}/100 (${current.grade})`,
    `Status change: ${baseline.statusCode} -> ${current.statusCode}`,
    "",
    formatDiffSummary(diff),
  ].join("\n");

const formatSummary = (analysis: AnalysisResult, diff: HistoryDiff | null = null) =>
  [
    `Target: ${analysis.inputUrl}`,
    `Final URL: ${analysis.finalUrl}`,
    `Score: ${analysis.score}/100 (${analysis.grade})`,
    `Status: ${analysis.statusCode}`,
    `Summary: ${analysis.summary}`,
    `Top issues: ${analysis.issues.length ? analysis.issues.slice(0, 5).map((issue) => issue.title).join("; ") : "None recorded"}`,
    `Identity: ${analysis.identityProvider.provider ?? "None observed"}${analysis.identityProvider.protocol ? ` (${analysis.identityProvider.protocol.toUpperCase()})` : ""}`,
    `WAF/Edge: ${analysis.wafFingerprint.providers.length ? analysis.wafFingerprint.providers.map((provider) => provider.name).join(", ") : "None conclusively identified"}`,
    `CT coverage: ${analysis.ctDiscovery.coverageSummary}`,
    ...(diff ? ["", formatDiffSummary(diff)] : []),
  ].join("\n");

const formatBatchSummary = (analyses: AnalysisResult[]) => {
  const averageScore = analyses.length
    ? Math.round(analyses.reduce((total, analysis) => total + analysis.score, 0) / analyses.length)
    : 0;
  const gradeCounts = analyses.reduce<Record<string, number>>((counts, analysis) => {
    counts[analysis.grade] = (counts[analysis.grade] ?? 0) + 1;
    return counts;
  }, {});
  const gradeSummary = Object.entries(gradeCounts)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([grade, count]) => `${grade}:${count}`)
    .join(", ");
  const weakest = [...analyses].sort((left, right) => left.score - right.score).slice(0, 3);

  return [
    `Batch results (${analyses.length} targets):`,
    `Average score: ${averageScore}/100`,
    `Grade distribution: ${gradeSummary || "None"}`,
    ...(weakest.length
      ? [
          "Weakest targets:",
          ...weakest.map((analysis) => `- ${analysis.host}: ${analysis.score}/100 (${analysis.grade})`),
        ]
      : []),
    "",
    "Per-target results:",
    ...analyses.map(
      (analysis) =>
        `- ${analysis.host}: ${analysis.score}/100 (${analysis.grade}) | status ${analysis.statusCode} | ${analysis.finalUrl}`,
    ),
  ].join("\n");
};

const formatMarkdown = (analysis: AnalysisResult, diff: HistoryDiff | null = null) =>
  [
    `# SecURL: ${analysis.host}`,
    "",
    `- Final URL: ${analysis.finalUrl}`,
    `- Scanned: ${new Date(analysis.scannedAt).toISOString()}`,
    `- Score: ${analysis.score}/100`,
    `- Grade: ${analysis.grade}`,
    `- HTTP status: ${analysis.statusCode}`,
    "",
    "## Executive Summary",
    "",
    `- Overview: ${analysis.executiveSummary.overview}`,
    `- Main risk: ${analysis.executiveSummary.mainRisk}`,
    ...analysis.executiveSummary.takeaways.map((takeaway) => `- ${takeaway}`),
    "",
    "## Key Findings",
    "",
    ...(analysis.issues.length
      ? analysis.issues.slice(0, 10).map((issue) => `- [${issue.severity}] ${issue.title}: ${issue.detail}`)
      : ["- No core findings recorded."]),
    "",
    "## Identity Provider",
    "",
    `- Provider: ${analysis.identityProvider.provider ?? "Not identified"}`,
    `- Protocol: ${analysis.identityProvider.protocol ?? "Not inferred"}`,
    `- OIDC config: ${analysis.identityProvider.openIdConfigurationUrl ?? "Not observed"}`,
    "",
    "## WAF & Edge Fingerprint",
    "",
    `- Summary: ${analysis.wafFingerprint.summary}`,
    ...(analysis.wafFingerprint.providers.length
      ? analysis.wafFingerprint.providers.map((provider) => `- ${provider.name} (${provider.confidence} confidence): ${provider.evidence}`)
      : ["- No branded WAF or edge provider was conclusively identified."]),
    "",
    "## Certificate Transparency",
    "",
    `- Coverage summary: ${analysis.ctDiscovery.coverageSummary}`,
    ...(analysis.ctDiscovery.prioritizedHosts.length
      ? analysis.ctDiscovery.prioritizedHosts.slice(0, 8).map((host) => `- ${host.host} [${host.priority} ${host.category}]`)
      : ["- No prioritized CT hosts recorded."]),
    ...(diff
      ? [
          "",
          "## Changes Since Baseline",
          "",
          ...(diff.summary.length ? diff.summary.map((item) => `- ${item}`) : ["- No material posture changes summarized."]),
        ]
      : []),
  ].join("\n");

const formatBatchMarkdown = (analyses: AnalysisResult[]) => {
  const averageScore = analyses.length
    ? Math.round(analyses.reduce((total, analysis) => total + analysis.score, 0) / analyses.length)
    : 0;
  const strongest = [...analyses].sort((left, right) => right.score - left.score).slice(0, 3);
  const weakest = [...analyses].sort((left, right) => left.score - right.score).slice(0, 3);

  return [
    "# SecURL Batch Scan",
    "",
    `- Targets scanned: ${analyses.length}`,
    `- Average score: ${averageScore}/100`,
    ...(strongest.length
      ? [`- Strongest: ${strongest.map((analysis) => `${analysis.host} (${analysis.score})`).join(", ")}`]
      : []),
    ...(weakest.length
      ? [`- Weakest: ${weakest.map((analysis) => `${analysis.host} (${analysis.score})`).join(", ")}`]
      : []),
    "",
    "| Target | Score | Grade | Status | Final URL |",
    "| --- | ---: | :---: | ---: | --- |",
    ...analyses.map(
      (analysis) =>
        `| ${analysis.host} | ${analysis.score}/100 | ${analysis.grade} | ${analysis.statusCode} | ${analysis.finalUrl} |`,
    ),
  ].join("\n");
};

const severityRank: Record<FailOnSeverity, number> = {
  info: 1,
  warning: 2,
  critical: 3,
};

const hasIssuesAtOrAboveThreshold = (analyses: AnalysisResult[], threshold: FailOnSeverity) => {
  const minimumRank = severityRank[threshold];
  return analyses.some((analysis) =>
    analysis.issues.some((issue) => severityRank[issue.severity] >= minimumRank),
  );
};

const statusClass = (statusCode: number) => {
  if (statusCode >= 500) {
    return 4;
  }
  if (statusCode >= 400) {
    return 3;
  }
  if (statusCode >= 300) {
    return 2;
  }
  if (statusCode >= 200) {
    return 1;
  }
  return 2;
};

const isRegression = (diff: HistoryDiff) => {
  const scoreRegressed = (diff.scoreDelta ?? 0) < 0;
  const newIssuesDetected = diff.newIssues.length > 0;
  const statusWorsened = diff.statusCodeDelta
    ? statusClass(diff.statusCodeDelta.to) > statusClass(diff.statusCodeDelta.from)
    : false;
  return scoreRegressed || newIssuesDetected || statusWorsened;
};

const formatPolicyFailureMessages = (
  analyses: AnalysisResult[],
  options: {
    failOnSeverity: FailOnSeverity | null;
    failOnRegression: boolean;
    failIfScoreBelow: number | null;
    diff: HistoryDiff | null;
  },
) => {
  const messages: string[] = [];
  if (options.failOnSeverity && hasIssuesAtOrAboveThreshold(analyses, options.failOnSeverity)) {
    messages.push(`Policy failed: findings at or above "${options.failOnSeverity}" were detected.`);
  }
  if (options.failIfScoreBelow !== null) {
    const belowThreshold = analyses.filter((analysis) => analysis.score < options.failIfScoreBelow!);
    if (belowThreshold.length) {
      messages.push(
        `Policy failed: score fell below ${options.failIfScoreBelow} for ${belowThreshold.map((analysis) => `${analysis.host} (${analysis.score})`).join(", ")}.`,
      );
    }
  }
  if (options.failOnRegression && options.diff && isRegression(options.diff)) {
    messages.push("Policy failed: baseline comparison detected a regression.");
  }
  return messages;
};

const summarizeIssueSeverities = (analysis: AnalysisResult) =>
  analysis.issues.reduce<Record<FailOnSeverity, number>>(
    (counts, issue) => {
      counts[issue.severity] += 1;
      return counts;
    },
    { info: 0, warning: 0, critical: 0 },
  );

const buildPolicySummary = (
  policyMessages: string[],
  options: {
    failOnSeverity: FailOnSeverity | null;
    failOnRegression: boolean;
    failIfScoreBelow: number | null;
  },
) => ({
  passed: policyMessages.length === 0,
  failures: policyMessages,
  failOnSeverity: options.failOnSeverity,
  failOnRegression: options.failOnRegression,
  failIfScoreBelow: options.failIfScoreBelow,
});

const toSarifLevel = (severity: ScanIssue["severity"]) => {
  if (severity === "critical") {
    return "error";
  }
  if (severity === "warning") {
    return "warning";
  }
  return "note";
};

const toRuleId = (title: string) =>
  title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "") || "external-posture-finding";

const buildSarifLog = (
  analyses: AnalysisResult[],
  options: {
    baselineByHost?: Map<string, AnalysisResult>;
    newIssueOnly?: boolean;
  } = {},
) => {
  const rules = new Map<
    string,
    {
      id: string;
      name: string;
      shortDescription: { text: string };
      fullDescription: { text: string };
      help: { text: string };
      properties: { tags: string[] };
    }
  >();
  const results: Array<Record<string, unknown>> = [];

  for (const analysis of analyses) {
    const baseline = options.baselineByHost?.get(analysis.host) ?? null;
    const newIssueTitles = options.newIssueOnly && baseline
      ? new Set(
          buildHistoryDiffFromSnapshots(
            snapshotFromAnalysis(analysis),
            snapshotFromAnalysis(baseline),
          ).newIssues,
        )
      : null;

    for (const issue of analysis.issues) {
      if (newIssueTitles && !newIssueTitles.has(issue.title)) {
        continue;
      }

      const ruleId = toRuleId(issue.title);
      if (!rules.has(ruleId)) {
        rules.set(ruleId, {
          id: ruleId,
          name: issue.title,
          shortDescription: { text: issue.title },
          fullDescription: { text: issue.detail },
          help: { text: issue.detail },
          properties: {
            tags: [...issue.owasp, ...issue.mitre, issue.area, issue.source, issue.confidence],
          },
        });
      }

      const message = baseline && newIssueTitles
        ? `${issue.detail} New compared with baseline ${baseline.finalUrl}.`
        : issue.detail;

      results.push({
        ruleId,
        level: toSarifLevel(issue.severity),
        message: { text: message },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: analysis.finalUrl },
            },
          },
        ],
        properties: {
          host: analysis.host,
          scannedAt: analysis.scannedAt,
          score: analysis.score,
          grade: analysis.grade,
          statusCode: analysis.statusCode,
          severity: issue.severity,
          area: issue.area,
          confidence: issue.confidence,
          source: issue.source,
          owasp: issue.owasp,
          mitre: issue.mitre,
        },
      });
    }
  }

  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "SecURL",
            informationUri: "https://www.npmjs.com/package/securl",
            rules: [...rules.values()],
          },
        },
        results,
      },
    ],
  };
};

const renderSingleOutput = (analysis: AnalysisResult, format: OutputFormat, diff: HistoryDiff | null = null) => {
  if (format === "json") {
    return `${JSON.stringify(diff ? { analysis, diff } : analysis, null, 2)}\n`;
  }
  if (format === "sarif") {
    return `${JSON.stringify(buildSarifLog([analysis]), null, 2)}\n`;
  }
  if (format === "markdown") {
    return `${formatMarkdown(analysis, diff)}\n`;
  }
  return `${formatSummary(analysis, diff)}\n`;
};

const renderBatchOutput = (analyses: AnalysisResult[], format: OutputFormat) => {
  if (format === "json") {
    return `${JSON.stringify({ analyses }, null, 2)}\n`;
  }
  if (format === "sarif") {
    return `${JSON.stringify(buildSarifLog(analyses), null, 2)}\n`;
  }
  if (format === "markdown") {
    return `${formatBatchMarkdown(analyses)}\n`;
  }
  return `${formatBatchSummary(analyses)}\n`;
};

const renderComparisonOutput = (
  current: AnalysisResult,
  baseline: AnalysisResult,
  diff: HistoryDiff,
  format: OutputFormat,
) => {
  if (format === "json") {
    return `${JSON.stringify({ current, baseline, diff }, null, 2)}\n`;
  }
  if (format === "sarif") {
    return `${JSON.stringify(
      buildSarifLog([current], {
        baselineByHost: new Map([[current.host, baseline]]),
        newIssueOnly: true,
      }),
      null,
      2,
    )}\n`;
  }
  if (format === "markdown") {
    return `${[
      `# SecURL Comparison: ${current.host}`,
      "",
      `- Current: ${current.finalUrl}`,
      `- Baseline: ${baseline.finalUrl}`,
      `- Score change: ${baseline.score}/100 (${baseline.grade}) -> ${current.score}/100 (${current.grade})`,
      `- Status change: ${baseline.statusCode} -> ${current.statusCode}`,
      "",
      "## Changes Since Baseline",
      "",
      ...(diff.summary.length ? diff.summary.map((item) => `- ${item}`) : ["- No material posture changes summarized."]),
    ].join("\n")}\n`;
  }
  return `${formatComparisonSummary(current, baseline, diff)}\n`;
};

const shouldShowProgress = (parsed: Extract<ParsedArgs, { command: "scan" }>) =>
  parsed.targets.length > 1
  && parsed.format === "summary"
  && !parsed.outputPath
  && Boolean(process.stderr.isTTY);

const scanTargets = async (parsed: Extract<ParsedArgs, { command: "scan" }>): Promise<AnalysisResult[]> => {
  const analyses: AnalysisResult[] = [];
  const showProgress = shouldShowProgress(parsed);

  for (const [index, target] of parsed.targets.entries()) {
    if (showProgress) {
      process.stderr.write(`Scanning ${index + 1}/${parsed.targets.length}: ${target}\n`);
    }
    analyses.push(await analyzeUrl(target, { scanMode: parsed.scanMode }));
  }

  if (showProgress) {
    process.stderr.write(`Completed ${analyses.length}/${parsed.targets.length} scans.\n`);
  }

  return analyses;
};

const main = async () => {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.command === "help") {
      process.stdout.write(usage);
      return;
    }

    let output: string;
    let policyMessages: string[] = [];

    if (parsed.command === "scan") {
      const analyses = await scanTargets(parsed);

      if (analyses.length === 1) {
        const [analysis] = analyses;
        const baselineAnalysis = parsed.baselinePath ? await parseBaselineAnalysis(parsed.baselinePath) : null;
        const diff = baselineAnalysis
          ? buildHistoryDiffFromSnapshots(snapshotFromAnalysis(analysis), snapshotFromAnalysis(baselineAnalysis))
          : null;
        policyMessages = formatPolicyFailureMessages(analyses, {
          failOnSeverity: parsed.failOnSeverity,
          failOnRegression: parsed.failOnRegression,
          failIfScoreBelow: parsed.failIfScoreBelow,
          diff,
        });
        if (parsed.format === "ci-json") {
          output = `${JSON.stringify(
            {
              mode: "scan",
              targetCount: 1,
              analysis: {
                host: analysis.host,
                finalUrl: analysis.finalUrl,
                score: analysis.score,
                grade: analysis.grade,
                statusCode: analysis.statusCode,
                issueCounts: summarizeIssueSeverities(analysis),
              },
              diff,
              policy: buildPolicySummary(policyMessages, {
                failOnSeverity: parsed.failOnSeverity,
                failOnRegression: parsed.failOnRegression,
                failIfScoreBelow: parsed.failIfScoreBelow,
              }),
            },
            null,
            2,
          )}\n`;
        } else {
          output = renderSingleOutput(analysis, parsed.format, diff);
        }
      } else {
        policyMessages = formatPolicyFailureMessages(analyses, {
          failOnSeverity: parsed.failOnSeverity,
          failOnRegression: false,
          failIfScoreBelow: parsed.failIfScoreBelow,
          diff: null,
        });
        if (parsed.format === "ci-json") {
          output = `${JSON.stringify(
            {
              mode: "scan",
              targetCount: analyses.length,
              analyses: analyses.map((analysis) => ({
                host: analysis.host,
                finalUrl: analysis.finalUrl,
                score: analysis.score,
                grade: analysis.grade,
                statusCode: analysis.statusCode,
                issueCounts: summarizeIssueSeverities(analysis),
              })),
              policy: buildPolicySummary(policyMessages, {
                failOnSeverity: parsed.failOnSeverity,
                failOnRegression: false,
                failIfScoreBelow: parsed.failIfScoreBelow,
              }),
            },
            null,
            2,
          )}\n`;
        } else {
          output = renderBatchOutput(analyses, parsed.format);
        }
      }

      if (parsed.outputPath) {
        await writeFile(parsed.outputPath, output, "utf8");
      } else {
        process.stdout.write(output);
      }
      if (policyMessages.length) {
        process.stderr.write(`${policyMessages.join("\n")}\n`);
        process.exitCode = 1;
      }
      return;
    }

    const currentAnalysis = await parseBaselineAnalysis(parsed.currentPath);
    const baselineAnalysis = await parseBaselineAnalysis(parsed.baselinePath);
    const diff = buildHistoryDiffFromSnapshots(
      snapshotFromAnalysis(currentAnalysis),
      snapshotFromAnalysis(baselineAnalysis),
    );
    policyMessages = formatPolicyFailureMessages([currentAnalysis], {
      failOnSeverity: parsed.failOnSeverity,
      failOnRegression: parsed.failOnRegression,
      failIfScoreBelow: parsed.failIfScoreBelow,
      diff,
    });
    if (parsed.format === "ci-json") {
      output = `${JSON.stringify(
        {
          mode: "compare",
          current: {
            host: currentAnalysis.host,
            finalUrl: currentAnalysis.finalUrl,
            score: currentAnalysis.score,
            grade: currentAnalysis.grade,
            statusCode: currentAnalysis.statusCode,
            issueCounts: summarizeIssueSeverities(currentAnalysis),
          },
          baseline: {
            host: baselineAnalysis.host,
            finalUrl: baselineAnalysis.finalUrl,
            score: baselineAnalysis.score,
            grade: baselineAnalysis.grade,
            statusCode: baselineAnalysis.statusCode,
            issueCounts: summarizeIssueSeverities(baselineAnalysis),
          },
          diff,
          policy: buildPolicySummary(policyMessages, {
            failOnSeverity: parsed.failOnSeverity,
            failOnRegression: parsed.failOnRegression,
            failIfScoreBelow: parsed.failIfScoreBelow,
          }),
        },
        null,
        2,
      )}\n`;
    } else {
      output = renderComparisonOutput(currentAnalysis, baselineAnalysis, diff, parsed.format);
    }

    if (parsed.outputPath) {
      await writeFile(parsed.outputPath, output, "utf8");
    } else {
      process.stdout.write(output);
    }
    if (policyMessages.length) {
      process.stderr.write(`${policyMessages.join("\n")}\n`);
      process.exitCode = 1;
    }
  } catch (error) {
    process.stderr.write(`${formatErrorMessage(error)}\n`);
    process.stderr.write("Use --help for CLI usage.\n");
    process.exitCode = 1;
  }
};

void main();
