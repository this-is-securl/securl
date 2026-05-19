#!/usr/bin/env node
// Verifies the production dist/ is correctly built before shipping
import { readFileSync, readdirSync } from "fs";
import { join } from "path";

const REQUIRED_API_URL = "securl-app-production.up.railway.app";
const DIST = join(process.cwd(), "dist");

// 1. dist/index.html must exist
const indexHtml = readFileSync(join(DIST, "index.html"), "utf8");
if (!indexHtml.includes("/assets/")) {
  throw new Error("dist/index.html does not reference any assets — build may be empty");
}

// 2. At least one JS bundle must exist in dist/assets/
const assets = readdirSync(join(DIST, "assets"));
const jsBundles = assets.filter(f => f.endsWith(".js"));
if (jsBundles.length === 0) {
  throw new Error("No JS bundles found in dist/assets/");
}

// 3. The Railway API URL must be present in the bundle
const bundleContent = jsBundles.map(f => readFileSync(join(DIST, "assets", f), "utf8")).join("");
if (!bundleContent.includes(REQUIRED_API_URL)) {
  throw new Error(
    `API URL "${REQUIRED_API_URL}" not found in bundle.\n` +
    `Run "npm run build:hostinger" not "npm run build" for production.`
  );
}

// 4. The /report/:id route must be in the bundle (regression check for shareable reports)
if (!bundleContent.includes("/report/")) {
  throw new Error("Shareable report route not found in bundle — possible routing regression");
}

console.log("✓ dist/index.html present");
console.log(`✓ ${jsBundles.length} JS bundle(s) found`);
console.log(`✓ API URL present: ${REQUIRED_API_URL}`);
console.log("✓ Shareable report route present");
console.log("\nBuild verified — safe to ship.");
