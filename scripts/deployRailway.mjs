#!/usr/bin/env node

import { spawnSync } from "node:child_process";

const PROJECT_ID = process.env.RAILWAY_PROJECT_ID || "4b7db7be-d86e-4403-a5e5-09742df8be34";
const SERVICE_ID = process.env.RAILWAY_SERVICE_ID || "4e47698c-9680-4778-992c-5573e2edadeb";
const ENVIRONMENT_ID = process.env.RAILWAY_ENVIRONMENT_ID || "15babe57-cb44-4b18-9693-25241f9b68a8";
const DEFAULT_MESSAGE = "Deploy SecURL backend";

const args = process.argv.slice(2);
const shouldSmoke = !args.includes("--skip-smoke");
const messageArgIndex = args.indexOf("--message");
const message = messageArgIndex >= 0 && args[messageArgIndex + 1]
  ? args[messageArgIndex + 1]
  : process.env.RAILWAY_DEPLOY_MESSAGE || DEFAULT_MESSAGE;

function run(command, commandArgs, options = {}) {
  console.log(`[railway-deploy] ${command} ${commandArgs.join(" ")}`);
  const result = spawnSync(command, commandArgs, {
    stdio: options.capture ? ["ignore", "pipe", "inherit"] : "inherit",
    encoding: "utf8",
    env: process.env,
  });
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
  return result.stdout || "";
}

function deploymentStatus(deploymentId) {
  const raw = run("railway", [
    "deployment",
    "list",
    "--json",
    "--service",
    SERVICE_ID,
    "--environment",
    ENVIRONMENT_ID,
    "--project",
    PROJECT_ID,
  ], { capture: true });
  const deployments = JSON.parse(raw);
  return deployments.find((deployment) => deployment.id === deploymentId)?.status || "UNKNOWN";
}

function waitForDeployment(deploymentId) {
  const terminalFailureStates = new Set(["CRASHED", "FAILED", "REMOVED"]);
  for (let attempt = 1; attempt <= 60; attempt += 1) {
    const currentStatus = deploymentStatus(deploymentId);
    console.log(`[railway-deploy] deployment ${deploymentId}: ${currentStatus}`);
    if (currentStatus === "SUCCESS") {
      return;
    }
    if (terminalFailureStates.has(currentStatus)) {
      throw new Error(`Railway deployment ended in ${currentStatus}.`);
    }
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10000);
  }
  throw new Error(`Railway deployment ${deploymentId} did not become healthy within 10 minutes.`);
}

const raw = run("railway", [
  "up",
  "--detach",
  "--json",
  "--service",
  SERVICE_ID,
  "--environment",
  ENVIRONMENT_ID,
  "--project",
  PROJECT_ID,
  "--message",
  message,
], { capture: true });

const payload = JSON.parse(raw);
if (!payload.deploymentId) {
  throw new Error("Railway did not return a deploymentId.");
}

console.log(`[railway-deploy] deployment: ${payload.deploymentId}`);
if (payload.logsUrl) {
  console.log(`[railway-deploy] logs: ${payload.logsUrl}`);
}

waitForDeployment(payload.deploymentId);

if (shouldSmoke) {
  run("npm", ["run", "smoke:api"]);
}
