#!/usr/bin/env node
import { execFileSync } from "node:child_process";

const PACKAGES = [
  {
    name: "securl",
    socketUrl: "https://socket.dev/npm/package/securl",
  },
  {
    name: "@ktbatterham/external-posture-core",
    socketUrl: "https://socket.dev/npm/package/@ktbatterham/external-posture-core",
  },
];

const NPM_REGISTRY = "https://registry.npmjs.org";
const NPM_DOWNLOADS = "https://api.npmjs.org/downloads";

const encodePackageName = (packageName) => encodeURIComponent(packageName);

const fetchJson = async (url) => {
  const response = await fetch(url, {
    headers: {
      Accept: "application/json",
      "User-Agent": "securl-package-signals/1.0",
    },
  });

  const text = await response.text();
  if (!response.ok) {
    throw new Error(`HTTP ${response.status} for ${url}: ${text.slice(0, 160)}`);
  }

  return JSON.parse(text);
};

const fetchOptionalJson = async (url) => {
  const response = await fetch(url, {
    headers: {
      Accept: "application/json",
      "User-Agent": "securl-package-signals/1.0",
    },
  });

  const text = await response.text();
  if (response.status === 404) {
    return null;
  }
  if (!response.ok) {
    throw new Error(`HTTP ${response.status} for ${url}: ${text.slice(0, 160)}`);
  }

  return JSON.parse(text);
};

const fetchPackageMetadata = async (packageName) => {
  const metadata = await fetchJson(`${NPM_REGISTRY}/${encodePackageName(packageName)}`);
  const latestVersion = metadata["dist-tags"]?.latest;
  const latest = latestVersion ? metadata.versions?.[latestVersion] : undefined;

  return {
    name: metadata.name,
    latestVersion,
    createdAt: metadata.time?.created,
    modifiedAt: metadata.time?.modified,
    versionCount: Object.keys(metadata.versions || {}).length,
    maintainers: metadata.maintainers || [],
    deprecated: latest?.deprecated || metadata.deprecated || "",
    license: latest?.license || metadata.license || "",
    repository: latest?.repository || metadata.repository || null,
    homepage: latest?.homepage || metadata.homepage || "",
    hasInstallScripts: Boolean(
      latest?.scripts?.install ||
        latest?.scripts?.preinstall ||
        latest?.scripts?.postinstall,
    ),
    dependencyCount: Object.keys(latest?.dependencies || {}).length,
    unpackedSize: latest?.dist?.unpackedSize || 0,
    fileCount: latest?.dist?.fileCount || 0,
    hasProvenance: Boolean(latest?.dist?.attestations?.url),
    tarball: latest?.dist?.tarball || "",
  };
};

const fetchDownloadPoint = async (range, packageName) => {
  const data = await fetchOptionalJson(`${NPM_DOWNLOADS}/point/${range}/${encodePackageName(packageName)}`);
  return {
    downloads: data?.downloads || 0,
    indexed: Boolean(data),
  };
};

const fetchDownloadRange = async (range, packageName) => {
  const data = await fetchOptionalJson(`${NPM_DOWNLOADS}/range/${range}/${encodePackageName(packageName)}`);
  return {
    downloads: data?.downloads || [],
    indexed: Boolean(data),
  };
};

const sumDownloads = (rows) => rows.reduce((total, row) => total + Number(row.downloads || 0), 0);

const runGitHubCodeSearch = (query) => {
  try {
    const raw = execFileSync("gh", [
      "search",
      "code",
      query,
      "--filename",
      "package.json",
      "--json",
      "repository,path,url",
      "--limit",
      "20",
    ], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });

    return JSON.parse(raw);
  } catch {
    return null;
  }
};

const fetchGitHubSignals = () => {
  const current = runGitHubCodeSearch('"securl"');
  const legacy = runGitHubCodeSearch('"@ktbatterham/external-posture-core"');

  return {
    current,
    legacy,
  };
};

const formatNumber = (value) => Number(value || 0).toLocaleString();

const formatBytes = (bytes) => {
  const value = Number(bytes || 0);
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} kB`;
  return `${(value / 1024 / 1024).toFixed(1)} MB`;
};

const printPackage = (signals) => {
  const {
    packageConfig,
    metadata,
    downloads,
    dailyDownloads,
  } = signals;

  console.log(packageConfig.name);
  console.log(`  Latest: ${metadata.latestVersion || "unknown"}`);
  console.log(`  Created: ${metadata.createdAt || "unknown"}`);
  console.log(`  Modified: ${metadata.modifiedAt || "unknown"}`);
  console.log(`  Versions: ${formatNumber(metadata.versionCount)}`);
  console.log(`  Maintainers: ${formatNumber(metadata.maintainers.length)}`);
  console.log(`  License: ${metadata.license || "unknown"}`);
  console.log(`  Dependencies: ${formatNumber(metadata.dependencyCount)}`);
  console.log(`  Package size: ${formatBytes(metadata.unpackedSize)} unpacked across ${formatNumber(metadata.fileCount)} files`);
  console.log(`  Install scripts: ${metadata.hasInstallScripts ? "yes" : "no"}`);
  console.log(`  npm provenance: ${metadata.hasProvenance ? "yes" : "no"}`);
  if (metadata.deprecated) {
    console.log(`  Deprecated: ${metadata.deprecated}`);
  }
  console.log(`  Downloads indexed: ${downloads.indexed ? "yes" : "not yet"}`);
  console.log(`  Downloads last day: ${formatNumber(downloads.lastDay)}`);
  console.log(`  Downloads last week: ${formatNumber(downloads.lastWeek)}`);
  console.log(`  Downloads last month: ${formatNumber(downloads.lastMonth)}`);

  const recent = dailyDownloads.slice(-7);
  if (recent.length) {
    console.log("  Recent daily downloads:");
    for (const row of recent) {
      console.log(`    - ${row.day}: ${formatNumber(row.downloads)}`);
    }
  }

  console.log(`  npm: https://www.npmjs.com/package/${packageConfig.name}`);
  console.log(`  Socket: ${packageConfig.socketUrl}`);
  console.log("");
};

const printGitHubSignals = (githubSignals) => {
  console.log("Public GitHub code signals");
  if (!githubSignals.current || !githubSignals.legacy) {
    console.log("  Skipped: GitHub CLI code search was not available or not authenticated.");
    console.log("  Tip: run `gh auth login`, then rerun `npm run package:signals`.");
    return;
  }

  const groups = [
    ["securl package.json mentions", githubSignals.current],
    ["legacy package.json mentions", githubSignals.legacy],
  ];

  for (const [label, rows] of groups) {
    console.log(`  ${label}: ${formatNumber(rows.length)}`);
    for (const row of rows.slice(0, 8)) {
      const repo = row.repository?.fullName || row.repository?.nameWithOwner || "unknown";
      console.log(`    - ${repo}/${row.path}`);
    }
  }
};

const collectPackageSignals = async (packageConfig) => {
  const [
    metadata,
    lastDayResult,
    lastWeekResult,
    lastMonthResult,
    dailyDownloadsResult,
  ] = await Promise.all([
    fetchPackageMetadata(packageConfig.name),
    fetchDownloadPoint("last-day", packageConfig.name),
    fetchDownloadPoint("last-week", packageConfig.name),
    fetchDownloadPoint("last-month", packageConfig.name),
    fetchDownloadRange("last-month", packageConfig.name),
  ]);

  return {
    packageConfig,
    metadata,
    downloads: {
      indexed: lastDayResult.indexed || lastWeekResult.indexed || lastMonthResult.indexed || dailyDownloadsResult.indexed,
      lastDay: lastDayResult.downloads,
      lastWeek: lastWeekResult.downloads,
      lastMonth: lastMonthResult.downloads,
      lastMonthRangeTotal: sumDownloads(dailyDownloadsResult.downloads),
    },
    dailyDownloads: dailyDownloadsResult.downloads,
  };
};

const main = async () => {
  const json = process.argv.includes("--json");
  const packages = await Promise.all(PACKAGES.map(collectPackageSignals));
  const github = fetchGitHubSignals();
  const generatedAt = new Date().toISOString();

  if (json) {
    console.log(JSON.stringify({
      generatedAt,
      packages,
      github,
      privacy: {
        installHooks: false,
        packageTelemetry: false,
        signalSources: [
          "npm registry metadata",
          "npm public download counts",
          "optional public GitHub code search",
          "Socket package pages",
        ],
      },
    }, null, 2));
    return;
  }

  console.log("SecURL package signals");
  console.log("");
  console.log(`Generated: ${generatedAt}`);
  console.log("Privacy: public metadata only; no package telemetry, no install hooks, no consumer identity.");
  console.log("");

  for (const packageSignals of packages) {
    printPackage(packageSignals);
  }

  printGitHubSignals(github);
};

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
