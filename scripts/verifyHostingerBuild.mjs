import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const expectedApiBaseUrl = "https://securl-app-production.up.railway.app";
const expectedApiBaseUrlBytes = Buffer.from(expectedApiBaseUrl, "utf8");
const distDir = new URL("../dist/", import.meta.url);
const assetsDir = new URL("../dist/assets/", import.meta.url);

const fail = (message) => {
  console.error(`[hostinger-build] ${message}`);
  process.exit(1);
};

if (!existsSync(distDir)) {
  fail("dist/ does not exist. Run npm run build:hostinger first.");
}

if (!existsSync(assetsDir)) {
  fail("dist/assets/ does not exist. The frontend build looks incomplete.");
}

const filesToCheck = [
  join(distDir.pathname, "index.html"),
  ...readdirSync(assetsDir)
    .filter((filename) => filename.endsWith(".js"))
    .map((filename) => join(assetsDir.pathname, filename)),
];

const containsExpectedApiBase = filesToCheck.some((filename) =>
  readFileSync(filename).includes(expectedApiBaseUrlBytes),
);

if (!containsExpectedApiBase) {
  fail(
    `built frontend does not contain ${expectedApiBaseUrl}. ` +
      "Do not upload this build to Hostinger.",
  );
}

console.log(`[hostinger-build] verified API base URL: ${expectedApiBaseUrl}`);
