export interface InitialScanHandoff {
  target: string;
  source: string;
  medium: string;
  campaign: string;
}

const DEFAULT_HANDOFF_SOURCE = "direct";
const DEFAULT_HANDOFF_MEDIUM = "web";
const DEFAULT_HANDOFF_CAMPAIGN = "scan_handoff";

const readParam = (params: URLSearchParams, key: string, fallback = "") =>
  (params.get(key) ?? fallback).trim();

export const getInitialScanHandoff = (search: string): InitialScanHandoff | null => {
  const params = new URLSearchParams(search);
  const target = readParam(params, "url") || readParam(params, "target");
  if (!target) {
    return null;
  }

  return {
    target,
    source: readParam(params, "utm_source", DEFAULT_HANDOFF_SOURCE),
    medium: readParam(params, "utm_medium", DEFAULT_HANDOFF_MEDIUM),
    campaign: readParam(params, "utm_campaign", DEFAULT_HANDOFF_CAMPAIGN),
  };
};

export const buildReportShareUrl = (
  origin: string,
  scanId: string,
  {
    source = "securl_web",
    medium = "share",
    campaign = "shared_report",
  }: {
    source?: string;
    medium?: string;
    campaign?: string;
  } = {},
) => {
  const url = new URL(`/report/${scanId}`, origin);
  url.searchParams.set("utm_source", source);
  url.searchParams.set("utm_medium", medium);
  url.searchParams.set("utm_campaign", campaign);
  return url.toString();
};

export const buildScannerHandoffUrl = (
  origin: string,
  target: string,
  {
    source,
    medium = "app",
    campaign = "mobile_handoff",
  }: {
    source: string;
    medium?: string;
    campaign?: string;
  },
) => {
  const url = new URL("/", origin);
  url.searchParams.set("url", target);
  url.searchParams.set("utm_source", source);
  url.searchParams.set("utm_medium", medium);
  url.searchParams.set("utm_campaign", campaign);
  return url.toString();
};
