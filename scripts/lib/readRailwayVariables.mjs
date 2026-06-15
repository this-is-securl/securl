import { execFileSync } from "node:child_process";

const DEFAULT_RAILWAY_PROJECT_ID = "4b7db7be-d86e-4403-a5e5-09742df8be34";
const DEFAULT_RAILWAY_SERVICE_ID = "4e47698c-9680-4778-992c-5573e2edadeb";
const DEFAULT_RAILWAY_ENVIRONMENT = "production";

const parseJsonObject = (raw) => {
  const parsed = JSON.parse(raw);
  return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
};

const readFromLinkedProject = () => {
  const raw = execFileSync("railway", ["variables", "--json"], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  return parseJsonObject(raw);
};

const readFromExplicitService = () => {
  const projectId = process.env.RAILWAY_PROJECT_ID || DEFAULT_RAILWAY_PROJECT_ID;
  const serviceId = process.env.RAILWAY_SERVICE_ID || DEFAULT_RAILWAY_SERVICE_ID;
  const environment = process.env.RAILWAY_ENVIRONMENT || DEFAULT_RAILWAY_ENVIRONMENT;
  const raw = execFileSync("railway", [
    "variable",
    "list",
    "--project",
    projectId,
    "--service",
    serviceId,
    "--environment",
    environment,
    "--json",
  ], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  return parseJsonObject(raw);
};

export const readRailwayVariables = () => {
  const failures = [];

  for (const [label, reader] of [
    ["linked project", readFromLinkedProject],
    ["explicit service", readFromExplicitService],
  ]) {
    try {
      return reader();
    } catch (error) {
      failures.push(`${label}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  return {
    __railwayReadError: failures.join("; ") || "Railway variables were not available.",
  };
};
