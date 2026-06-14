import type { AnalysisResult, HistoryDiff, PostureRiskEvent } from "@/types/analysis";

export type ApiScanStatus = "queued" | "running" | "completed" | "failed";

export type ApiVersion = "2026-05-14";

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
  scanTiming: AnalysisResult["scanTiming"] | null;
}

export interface VersionedApiResponse {
  apiVersion: ApiVersion;
}

export interface CapabilitiesResponse extends VersionedApiResponse {
  service: {
    name: string;
    appVersion: string;
    corePackage: string;
    coreVersion: string;
    serveFrontend: boolean;
  };
  auth: {
    methods: string[];
    anonymousScanOwner: boolean;
  };
  scans: {
    modes: Array<"standard" | "quiet" | "deep-passive">;
    statuses: ApiScanStatus[];
    features: string[];
    scoring: {
      model: string;
      version: string;
      gradeScale: string[];
      scoreRange: {
        min: number;
        max: number;
      };
    };
    maxDurationMs: {
      standard: number;
      quiet: number;
      deepPassive: number;
    };
    concurrency: number;
    resources: string[];
  };
  monitoring: {
    enabled: boolean;
    cadences: Array<"daily" | "weekly">;
    scheduler: {
      enabled: boolean;
      mode: "standard" | "quiet" | "deep-passive";
      intervalMs: number | null;
      limit: number | null;
    };
    resources: string[];
  };
  exports: {
    formats: string[];
    shareLinks: boolean;
  };
  safety: {
    passiveFirst: boolean;
    publicTargetsOnly: boolean;
    blocksPrivateNetworkTargets: boolean;
  };
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

export interface CreateScanResponse extends VersionedApiResponse {
  scan: ApiScanSummary;
  fromCache?: boolean;
}

export interface GetScanResponse extends VersionedApiResponse {
  scan: ApiScanRecord;
}

export interface ScansResponse extends VersionedApiResponse {
  scans: ApiScanSummary[];
}

export interface ScanSummaryResponse extends VersionedApiResponse {
  summary: ApiScanSummary;
}

export interface ScanFindingsResponse extends VersionedApiResponse {
  findings: AnalysisResult["issues"];
  strengths: AnalysisResult["strengths"];
  priorityActions: string[];
  remediationPlan: AnalysisResult["remediationPlan"] | null;
  evidenceSummary: AnalysisResult["evidenceSummary"] | null;
}

export interface ScanEvidenceResponse extends VersionedApiResponse {
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
    evidenceSummary: AnalysisResult["evidenceSummary"] | null;
  } | null;
}

export interface ScanHistoryResponse extends VersionedApiResponse {
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
  riskEvents: PostureRiskEvent[];
}

export interface TargetHistoryResponse extends VersionedApiResponse {
  target: {
    url: string;
  };
  scans: ApiScanSummary[];
  comparison: TargetHistoryComparison | null;
}

export interface ScanComparisonResponse extends VersionedApiResponse {
  scan: ApiScanSummary;
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

export interface MonitoringTargetsResponse extends VersionedApiResponse {
  targets: ApiMonitoringTarget[];
}

export interface MonitoringTargetResponse extends VersionedApiResponse {
  target: ApiMonitoringTarget;
}

export interface DeleteMonitoringTargetResponse extends VersionedApiResponse {
  ok: boolean;
}

export interface MonitoringTargetDetailResponse extends VersionedApiResponse {
  target: ApiMonitoringTarget;
  scans: ApiScanSummary[];
  comparison: TargetHistoryComparison | null;
  events: ApiScanEvent[];
}

export interface AuthUser {
  id: string;
  email: string;
  displayName: string | null;
  createdAt: string;
}

export interface AuthSession {
  token?: string;
  createdAt: string;
  expiresAt: string;
  lastSeenAt?: string;
}

export interface AuthSessionResponse {
  user: AuthUser;
  session: AuthSession;
}

export interface AuthStatusResponse {
  authenticated: boolean;
  user?: AuthUser;
  session?: AuthSession;
}
