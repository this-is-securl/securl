const HOSTED_SCANNER_URL = "https://app.securl.online/";

export type CliGrowthBridgeContext = {
  targetUrl: string;
  targetCount: number;
  format: string;
  outputPath: string | null;
  baselinePath: string | null;
  hasPolicy: boolean;
  stdoutIsTty: boolean;
  stderrIsTty: boolean;
};

export const buildCliGrowthBridge = (context: CliGrowthBridgeContext): string | null => {
  if (
    context.targetCount !== 1
    || context.format !== "summary"
    || context.outputPath
    || context.baselinePath
    || context.hasPolicy
    || !context.stdoutIsTty
    || !context.stderrIsTty
  ) {
    return null;
  }

  const url = new URL(HOSTED_SCANNER_URL);
  url.searchParams.set("url", context.targetUrl);
  url.searchParams.set("utm_source", "securl_cli");
  url.searchParams.set("utm_medium", "cli");
  url.searchParams.set("utm_campaign", "package_scan_bridge");

  return `Open the full report and optional monitoring:\n${url.toString()}\n`;
};
