import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

const config = {
  siteName: "app.securl.online",
  publicUrl: "https://app.securl.online",
  buildScripts: [
    ["npm", ["run", "build:hostinger"]],
    ["npm", ["run", "verify:hostinger"]],
  ],
  distDir: resolve(process.cwd(), "dist"),
  requiredFiles: ["index.html", ".htaccess"],
  preservePatterns: ["google*.html", ".well-known/acme-challenge/***"],
  sshHost: process.env.HOSTINGER_SSH_HOST || "141.136.43.111",
  sshPort: process.env.HOSTINGER_SSH_PORT || "65002",
  sshUser: process.env.HOSTINGER_SSH_USER || "u765511792",
  remotePath: process.env.HOSTINGER_REMOTE_PATH || "/home/u765511792/domains/app.securl.online/public_html",
};

const args = new Set(process.argv.slice(2));
const live = args.has("--live");
const skipBuild = args.has("--skip-build");
const skipBackup = args.has("--no-backup");
const skipSmoke = args.has("--skip-smoke");
const dryRun = !live;

function fail(message) {
  console.error(`[hostinger-deploy] ${message}`);
  process.exit(1);
}

function run(command, commandArgs, options = {}) {
  console.log(`[hostinger-deploy] ${command} ${commandArgs.join(" ")}`);
  const result = spawnSync(command, commandArgs, {
    stdio: "inherit",
    ...options,
  });
  if (result.error) {
    fail(result.error.message);
  }
  if (result.status !== 0) {
    fail(`${command} exited with ${result.status}`);
  }
}

function shellQuote(value) {
  return `'${String(value).replaceAll("'", "'\\''")}'`;
}

function timestamp() {
  return new Date().toISOString().replaceAll(/[:.]/g, "-");
}

async function smokeCheck() {
  const response = await fetch(config.publicUrl, {
    headers: {
      "User-Agent": "SecURL Hostinger deploy smoke",
    },
  });
  if (!response.ok) {
    fail(`${config.publicUrl} returned HTTP ${response.status}`);
  }
  const html = await response.text();
  if (!html.includes("<!doctype html") && !html.includes("<!DOCTYPE html")) {
    fail(`${config.publicUrl} did not look like an HTML document`);
  }
  console.log(`[hostinger-deploy] smoke ok: ${config.publicUrl}`);
}

if (args.has("--help")) {
  console.log(`
Usage:
  npm run deploy:hostinger           # build and dry-run rsync
  npm run deploy:hostinger -- --live # build, backup remote, deploy, smoke

Options:
  --live        Run the real rsync deploy. Default is dry-run.
  --skip-build  Reuse the existing dist/ directory.
  --no-backup   Skip the remote tar.gz backup before live deploy.
  --skip-smoke  Skip the HTTP smoke check after live deploy.

Environment overrides:
  HOSTINGER_SSH_HOST
  HOSTINGER_SSH_PORT
  HOSTINGER_SSH_USER
  HOSTINGER_REMOTE_PATH
`);
  process.exit(0);
}

console.log(`[hostinger-deploy] target: ${config.siteName}`);
console.log(`[hostinger-deploy] mode: ${dryRun ? "dry-run" : "live"}`);
console.log(`[hostinger-deploy] remote: ${config.sshUser}@${config.sshHost}:${config.remotePath}`);

if (!skipBuild) {
  for (const [command, commandArgs] of config.buildScripts) {
    run(command, commandArgs);
  }
}

if (!existsSync(config.distDir)) {
  fail(`${config.distDir} does not exist`);
}

for (const file of config.requiredFiles) {
  const path = resolve(config.distDir, file);
  if (!existsSync(path)) {
    fail(`${file} missing from ${config.distDir}`);
  }
}

const sshTarget = `${config.sshUser}@${config.sshHost}`;
const sshArgs = ["-p", config.sshPort, "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", sshTarget];
run("ssh", [...sshArgs, `test -d ${shellQuote(config.remotePath)} && test -w ${shellQuote(config.remotePath)}`]);

if (live && !skipBackup) {
  const backupName = `${config.siteName}-${timestamp()}.tar.gz`;
  const backupPath = `/home/${config.sshUser}/deploy-backups/${backupName}`;
  const backupCommand = [
    `mkdir -p ${shellQuote(`/home/${config.sshUser}/deploy-backups`)}`,
    `tar -czf ${shellQuote(backupPath)} -C ${shellQuote(config.remotePath)} .`,
  ].join(" && ");
  run("ssh", [...sshArgs, backupCommand]);
  console.log(`[hostinger-deploy] backup: ${backupPath}`);
}

const rsyncArgs = [
  "-az",
  "--delete",
  "--itemize-changes",
  "--human-readable",
  ...config.preservePatterns.flatMap((pattern) => ["--exclude", pattern]),
  ...(dryRun ? ["--dry-run"] : []),
  "-e",
  `ssh -p ${config.sshPort} -o BatchMode=yes`,
  `${config.distDir}/`,
  `${sshTarget}:${config.remotePath}/`,
];
run("rsync", rsyncArgs);

if (dryRun) {
  console.log("[hostinger-deploy] dry-run complete. Re-run with -- --live to deploy.");
} else if (!skipSmoke) {
  await smokeCheck();
}
