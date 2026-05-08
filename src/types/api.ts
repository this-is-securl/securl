import type { AnalysisResult, HistoryDiff } from "@/types/analysis";

export type ApiScanStatus = "queued" | "running" | "completed" | "failed";

export interface ApiScanSummary {
  id: string;
  status: ApiScanStatus;
  url: string;
  mode: string;
  requestedAt: string;
  startedAt: string | null;
  completedAt: string | null;
  failureClass: string | null;
  error: string | null;
  score: number | null;
  grade: string | null;
  limited: boolean;
  limitedKind: string | null;
  title: string | null;
  mainRisk: string | null;
  findingsCount: number;
}

export interface ApiScanRecord {
  id: string;
  ownerId: string | null;
  status: ApiScanStatus;
  url: string;
  mode: string;
  requesterScope: string;
  clientIp: string;
  requestedAt: string;
  startedAt: string | null;
  completedAt: string | null;
  failureClass: string | null;
  error: string | null;
  result: AnalysisResult | null;
  summary: ApiScanSummary;
}

export interface ApiScanEvent {
  id: string;
  scanId: string;
  eventType: string;
  occurredAt: string;
  status: ApiScanStatus;
  failureClass: string | null;
  message: string | null;
  metadata: Record<string, unknown>;
}

export interface CreateScanResponse {
  scan: ApiScanSummary;
}

export interface GetScanResponse {
  scan: ApiScanRecord;
}

export interface ScanSummaryResponse {
  summary: ApiScanSummary;
}

export interface ScanFindingsResponse {
  findings: AnalysisResult["issues"];
  strengths: AnalysisResult["strengths"];
  priorityActions: string[];
}

export interface ScanEvidenceResponse {
  evidence: {
    headers: AnalysisResult["headers"];
    rawHeaders: AnalysisResult["rawHeaders"];
    cookies: AnalysisResult["cookies"];
    redirects: AnalysisResult["redirects"];
    certificate: AnalysisResult["certificate"] | null;
    exposure: AnalysisResult["exposure"] | null;
    apiSurface: AnalysisResult["apiSurface"] | null;
    corsSecurity: AnalysisResult["corsSecurity"] | null;
    htmlSecurity: AnalysisResult["htmlSecurity"] | null;
    domainSecurity: AnalysisResult["domainSecurity"] | null;
    securityTxt: AnalysisResult["securityTxt"] | null;
    publicSignals: AnalysisResult["publicSignals"] | null;
    infrastructure: AnalysisResult["infrastructure"] | null;
    identityProvider: AnalysisResult["identityProvider"] | null;
    thirdPartyTrust: AnalysisResult["thirdPartyTrust"] | null;
    aiSurface: AnalysisResult["aiSurface"] | null;
    technologies: AnalysisResult["technologies"];
    ctDiscovery: AnalysisResult["ctDiscovery"] | null;
    wafFingerprint: AnalysisResult["wafFingerprint"] | null;
    crawl: AnalysisResult["crawl"] | null;
  } | null;
}

export interface ScanHistoryResponse {
  scan: {
    id: string;
    status: ApiScanStatus;
    requestedAt: string;
    startedAt: string | null;
    completedAt: string | null;
  };
  events: ApiScanEvent[];
}

export interface TargetHistoryComparison {
  currentScanId: string;
  previousScanId: string;
  diff: HistoryDiff | null;
}

export interface TargetHistoryResponse {
  target: {
    url: string;
  };
  scans: ApiScanSummary[];
  comparison: TargetHistoryComparison | null;
}

export interface ApiMonitoringTarget {
  id: string;
  ownerId: string | null;
  requesterScope: string;
  url: string;
  label: string;
  cadence: "daily" | "weekly";
  addedAt: string;
  lastScannedAt: string | null;
  nextDueAt: string;
  due: boolean;
  latestScan: ApiScanSummary | null;
  previousScan: ApiScanSummary | null;
  scoreDelta: number | null;
}

export interface MonitoringTargetsResponse {
  targets: ApiMonitoringTarget[];
}

export interface MonitoringTargetResponse {
  target: ApiMonitoringTarget;
}
