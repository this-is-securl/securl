import type { ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import {
  LayoutDashboard,
  AlertTriangle,
  BarChart3,
  ListTodo,
  Wrench,
  Globe,
  ShieldCheck,
  Server,
} from "lucide-react";
import { FindingsPanel } from "@/components/FindingsPanel";
import { PostureSummaryPanel } from "@/components/PostureSummaryPanel";
import { TaxonomySummaryPanel } from "@/components/TaxonomySummaryPanel";
import { PriorityActionsPanel } from "@/components/PriorityActionsPanel";
import { RemediationPanel } from "@/components/RemediationPanel";
import { DomainSecurityPanel } from "@/components/DomainSecurityPanel";
import { PublicSignalsPanel } from "@/components/PublicSignalsPanel";
import { DisclosureTrustPanel } from "@/components/DisclosureTrustPanel";
import { IdentityProviderPanel } from "@/components/IdentityProviderPanel";
import { InfrastructurePanel } from "@/components/InfrastructurePanel";
import { PassiveIntelligencePanel } from "@/components/PassiveIntelligencePanel";
import { WafFingerprintPanel } from "@/components/WafFingerprintPanel";
import { CtDiscoveryPanel } from "@/components/CtDiscoveryPanel";
import { AiSurfacePanel } from "@/components/AiSurfacePanel";
import { ThirdPartyTrustPanel } from "@/components/ThirdPartyTrustPanel";
import { AuthSurfacePanel } from "@/components/AuthSurfacePanel";
import { DataCollectionPanel } from "@/components/DataCollectionPanel";
import { ExposurePanel } from "@/components/ExposurePanel";
import { CorsSecurityPanel } from "@/components/CorsSecurityPanel";
import { ApiSurfacePanel } from "@/components/ApiSurfacePanel";
import { OverviewSection } from "@/components/report/OverviewSection";
import type { AreaScore } from "@/lib/posture";
import { getPriorityActions } from "@/lib/priorities";
import type { AnalysisResult, HistoryDiff } from "@/types/analysis";
import type { StoredHistorySnapshot } from "@/lib/scanWorkspace";

export type ReportWorkspaceSectionKey =
  | "overview"
  | "findings-top"
  | "findings-themes"
  | "findings-actions"
  | "findings-remediation"
  | "trust-domain"
  | "trust-signals"
  | "infrastructure-edge";

export interface ReportWorkspaceSection {
  key: ReportWorkspaceSectionKey;
  title: string;
  summary: string;
  context?: string;
  badge?: string;
  icon: LucideIcon;
  content: ReactNode;
}

interface BuildReportWorkspaceSectionsOptions {
  analysisData: AnalysisResult;
  currentScanWasCached?: boolean;
  historyDiff: HistoryDiff | null;
  history: StoredHistorySnapshot[];
  areaScores: AreaScore[];
  exportPdf: () => void;
  exportMarkdown: () => void;
  exportReport: () => void;
}

export const buildReportWorkspaceSections = ({
  analysisData,
  currentScanWasCached = false,
  historyDiff,
  history,
  areaScores,
  exportPdf,
  exportMarkdown,
  exportReport,
}: BuildReportWorkspaceSectionsOptions): ReportWorkspaceSection[] => {
  const criticalCount = analysisData.issues.filter((issue) => issue.severity === "critical").length;
  const warningCount = analysisData.issues.filter((issue) => issue.severity === "warning").length;
  const remediationCount = analysisData.remediation.length;
  const priorityActionCount = getPriorityActions(analysisData).length;
  const mappedThemeCount = analysisData.issues.filter((issue) => issue.owasp.length || issue.mitre.length).length;
  const trustSignalIssueCount = analysisData.publicSignals.issues.length + analysisData.securityTxt.issues.length;
  const domainIssueCount = analysisData.domainSecurity.issues.length;
  const edgeSignalCount =
    (analysisData.passiveIntelligence?.issues.length ?? 0) +
    analysisData.infrastructure.issues.length +
    analysisData.wafFingerprint.issues.length +
    analysisData.ctDiscovery.issues.length +
    analysisData.exposure.issues.length +
    analysisData.apiSurface.issues.length +
    analysisData.corsSecurity.issues.length;
  const surfaceSignalCount =
    analysisData.thirdPartyTrust.issues.length + analysisData.aiSurface.issues.length;
  const authCollectionSignalCount =
    analysisData.htmlSecurity.forms.length + analysisData.htmlSecurity.passiveLeakSignals.length;
  const categoryCount = areaScores.length;

  return [
  {
    key: "overview",
    title: "At a glance",
    summary: "Grade, priorities, exports, and monitoring.",
    context: `${analysisData.grade} grade • ${analysisData.grade === "A" || analysisData.grade === "B" ? "Strong" : analysisData.grade === "C" ? "Mixed" : "Needs attention"}`,
    badge: undefined,
    icon: LayoutDashboard,
    content: (
      <OverviewSection
        analysisData={analysisData}
        scanWasCached={currentScanWasCached}
        historyDiff={historyDiff}
        history={history}
        areaScores={areaScores}
        exportPdf={exportPdf}
        exportMarkdown={exportMarkdown}
        exportReport={exportReport}
        compact
      />
    ),
  },
  {
    key: "findings-top",
    title: "Top findings",
    summary: "The most important issues to understand first.",
    context: `${criticalCount} critical • ${warningCount} warning • ${analysisData.strengths.length} strengths`,
    badge: criticalCount > 0 ? `${criticalCount} critical` : warningCount > 0 ? `${warningCount} warning` : undefined,
    icon: AlertTriangle,
    content: <FindingsPanel issues={analysisData.issues} strengths={analysisData.strengths} />,
  },
  {
    key: "findings-themes",
    title: "Risk themes",
    summary: "Grouped posture themes across browser, domain, trust, and exposure.",
    context: `${categoryCount} posture areas • ${mappedThemeCount} mapped findings`,
    badge: `${categoryCount} areas`,
    icon: BarChart3,
    content: (
      <div className="space-y-8">
        <PostureSummaryPanel analysis={analysisData} />
        <TaxonomySummaryPanel analysis={analysisData} />
      </div>
    ),
  },
  {
    key: "findings-actions",
    title: "Priority actions",
    summary: "What should be done first and why it matters.",
    context: `${priorityActionCount} recommended next steps`,
    badge: priorityActionCount > 0 ? `${priorityActionCount} actions` : undefined,
    icon: ListTodo,
    content: <PriorityActionsPanel analysis={analysisData} />,
  },
  {
    key: "findings-remediation",
    title: "Fix snippets",
    summary: "Implementation examples by platform.",
    context: remediationCount ? `${remediationCount} platform snippets` : "No generated snippets",
    badge: remediationCount > 0 ? `${remediationCount} snippets` : undefined,
    icon: Wrench,
    content: <RemediationPanel remediation={analysisData.remediation} />,
  },
  {
    key: "trust-domain",
    title: "Domain & email",
    summary: "Mail and DNS foundation.",
    context: domainIssueCount ? `${domainIssueCount} DNS or mail findings` : "Baseline looks steady",
    badge: domainIssueCount > 0 ? `${domainIssueCount} findings` : undefined,
    icon: Globe,
    content: <DomainSecurityPanel domainSecurity={analysisData.domainSecurity} />,
  },
  {
    key: "trust-signals",
    title: "Trust signals",
    summary: "Disclosure readiness, public trust signals, and visible governance cues.",
    context: trustSignalIssueCount ? `${trustSignalIssueCount} disclosure or trust gaps` : "Public signals look healthy",
    badge: trustSignalIssueCount > 0 ? `${trustSignalIssueCount} gaps` : undefined,
    icon: ShieldCheck,
    content: (
      <div className="space-y-8">
        <PublicSignalsPanel publicSignals={analysisData.publicSignals} />
        <DisclosureTrustPanel analysis={analysisData} />
      </div>
    ),
  },
  {
    key: "infrastructure-edge",
    title: "Infrastructure & edge",
    summary: "Hosting, WAF, CDN, third-party, AI surface, and exposure observations.",
    context:
      edgeSignalCount || surfaceSignalCount || authCollectionSignalCount
        ? `${edgeSignalCount + surfaceSignalCount + authCollectionSignalCount} infra and surface signals`
        : "No major infrastructure or surface concerns surfaced",
    badge:
      edgeSignalCount + surfaceSignalCount + authCollectionSignalCount > 0
        ? `${edgeSignalCount + surfaceSignalCount + authCollectionSignalCount} signals`
        : undefined,
    icon: Server,
    content: (
      <div className="space-y-8">
        <IdentityProviderPanel identityProvider={analysisData.identityProvider} />
        <PassiveIntelligencePanel passiveIntelligence={analysisData.passiveIntelligence} />
        <InfrastructurePanel infrastructure={analysisData.infrastructure} />
        <WafFingerprintPanel wafFingerprint={analysisData.wafFingerprint} />
        <CtDiscoveryPanel ctDiscovery={analysisData.ctDiscovery} />
        <AiSurfacePanel aiSurface={analysisData.aiSurface} />
        <ThirdPartyTrustPanel thirdPartyTrust={analysisData.thirdPartyTrust} />
        <AuthSurfacePanel htmlSecurity={analysisData.htmlSecurity} />
        <DataCollectionPanel htmlSecurity={analysisData.htmlSecurity} />
        <ExposurePanel exposure={analysisData.exposure} />
        <CorsSecurityPanel corsSecurity={analysisData.corsSecurity} />
        <ApiSurfacePanel apiSurface={analysisData.apiSurface} />
      </div>
    ),
  },
];
};
