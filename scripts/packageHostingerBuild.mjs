import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, rmSync } from "node:fs";
import { basename, join } from "node:path";

const distDir = new URL("../dist/", import.meta.url).pathname;
const deploymentsDir = new URL("../deployments/", import.meta.url).pathname;

const fail = (message) => {
  console.error(`[hostinger-build] ${message}`);
  process.exit(1);
};

if (!existsSync(distDir)) {
  fail("dist/ does not exist. Run npm run build:hostinger first.");
}

mkdirSync(deploymentsDir, { recursive: true });

const dateStamp = new Date().toISOString().slice(0, 10);
const commit = execFileSync("git", ["rev-parse", "--short", "HEAD"], {
  encoding: "utf8",
}).trim();
const outputPath = join(deploymentsDir, `securl-hostinger-${dateStamp}-${commit}.zip`);

rmSync(outputPath, { force: true });

execFileSync("zip", ["-r", outputPath, "."], {
  cwd: distDir,
  stdio: "inherit",
});

console.log(`[hostinger-build] wrote ${basename(outputPath)}`);
console.log(outputPath);
