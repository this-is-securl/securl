import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import fs from "fs";
import path from "path";
import { execSync } from "child_process";

const readJsonVersion = (filePath: string) => {
  const raw = fs.readFileSync(filePath, "utf-8");
  return JSON.parse(raw).version as string;
};

const rootPackageVersion = readJsonVersion(path.resolve(__dirname, "./package.json"));
const corePackageVersion = readJsonVersion(path.resolve(__dirname, "./packages/core/package.json"));

const resolveBuildSha = () => {
  const envSha =
    process.env.RAILWAY_GIT_COMMIT_SHA ||
    process.env.VERCEL_GIT_COMMIT_SHA ||
    process.env.GITHUB_SHA ||
    process.env.SOURCE_COMMIT ||
    process.env.COMMIT_SHA;

  if (envSha) {
    return envSha.slice(0, 7);
  }

  try {
    return execSync("git rev-parse --short HEAD", { cwd: __dirname, stdio: ["ignore", "pipe", "ignore"] })
      .toString()
      .trim();
  } catch {
    return "unknown";
  }
};

const buildSha = resolveBuildSha();
const buildDate = new Date().toISOString();
const apiBaseUrl = (process.env.VITE_API_BASE_URL || "").trim();

// https://vitejs.dev/config/
export default defineConfig(() => ({
  server: {
    host: "::",
    port: 8080,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8787",
        changeOrigin: true,
      },
    },
  },
  plugins: [
    react(),
  ].filter(Boolean),
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  define: {
    __APP_VERSION__: JSON.stringify(rootPackageVersion),
    __CORE_VERSION__: JSON.stringify(corePackageVersion),
    __BUILD_SHA__: JSON.stringify(buildSha),
    __BUILD_DATE__: JSON.stringify(buildDate),
    __API_BASE_URL__: JSON.stringify(apiBaseUrl),
  },
}));
