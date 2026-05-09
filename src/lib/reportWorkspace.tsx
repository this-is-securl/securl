import type { ReactNode } from "react";
import { FindingsPanel } from "@/components/FindingsPanel";
import { TaxonomySummaryPanel } from "@/components/TaxonomySummaryPanel";
import { PriorityActionsPanel } from "@/components/PriorityActionsPanel";
import { RemediationPanel } from "@/components/RemediationPanel";
import { DomainSecurityPanel } from "@/components/DomainSecurityPanel";
import { PublicSignalsPanel } from "@/components/PublicSignalsPanel";
import { DisclosureTrustPanel } from "@/components/DisclosureTrustPanel";
import { IdentityProviderPanel } from "@/components/IdentityProviderPanel";
import { InfrastructurePanel } from "@/components/InfrastructurePanel";
import { WafFingerprintPanel } from "@/components/WafFingerprintPanel";
import { CtDiscoveryPanel } from "@/components/CtDiscoveryPanel";
import { HtmlSecurityPanel } from "@/components/HtmlSecurityPanel";
import { ClientExposurePanel } from "@/components/ClientExposurePanel";
import { AiSurfacePanel } from "@/components/AiSurfacePanel";
import { ThirdPartyTrustPanel } from "@/components/ThirdPartyTrustPanel";
import { AuthSurfacePanel } from "@/components/AuthSurfacePanel";
import { DataCollectionPanel } from "@/components/DataCollectionPanel";
import { ExposurePanel } from "@/components/ExposurePanel";
import { CorsSecurityPanel } from "@/components/CorsSecurityPanel";
import { ApiSurfacePanel } from "@/components/ApiSurfacePanel";
import { EvidenceSection } from "@/components/report/EvidenceSection";
import { OverviewSection } from "@/components/report/OverviewSection";
import type { AreaScore } from "@/lib/posture";
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
  | "trust-edge"
  | "client-page"
  | "client-surface"
  | "client-auth"
  | "exposure-checks"
  | "exposure-api"
  | "evidence";

export interface ReportWorkspaceSection {
  key: ReportWorkspaceSectionKey;
  title: string;
  summary: string;
  content: ReactNode;
}

interface BuildReportWorkspaceSectionsOptions {
  analysisData: AnalysisResult;
  historyDiff: HistoryDiff | null;
  history: StoredHistorySnapshot[];
  areaScores: AreaScore[];
  exportPdf: () => void;
  exportMarkdown: () => void;
  exportReport: () => void;
}

export const buildReportWorkspaceSections = ({
  analysisData,
  historyDiff,
  history,
  areaScores,
  exportPdf,
  exportMarkdown,
  exportReport,
}: BuildReportWorkspaceSectionsOptions): ReportWorkspaceSection[] => [
  {
    key: "overview",
    title: "At a glance",
    summary: "Score, priorities, exports, and monitoring.",
    content: (
      <OverviewSection
        analysisData={analysisData}
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
    summary: "Strengths and highest-priority issues.",
    content: <FindingsPanel issues={analysisData.issues} strengths={analysisData.strengths} />,
  },
  {
    key: "findings-themes",
    title: "Risk themes",
    summary: "OWASP and MITRE reads.",
    content: <TaxonomySummaryPanel analysis={analysisData} />,
  },
  {
    key: "findings-actions",
    title: "Priority actions",
    summary: "What to fix first.",
    content: <PriorityActionsPanel analysis={analysisData} />,
  },
  {
    key: "findings-remediation",
    title: "Fix snippets",
    summary: "Implementation examples by platform.",
    content: <RemediationPanel remediation={analysisData.remediation} />,
  },
  {
    key: "trust-domain",
    title: "Domain & email",
    summary: "Mail and DNS foundation.",
    content: <DomainSecurityPanel domainSecurity={analysisData.domainSecurity} />,
  },
  {
    key: "trust-signals",
    title: "Trust signals",
    summary: "Disclosure and public signals.",
    content: (
      <div className="space-y-8">
        <PublicSignalsPanel publicSignals={analysisData.publicSignals} />
        <DisclosureTrustPanel analysis={analysisData} />
      </div>
    ),
  },
  {
    key: "trust-edge",
    title: "Identity & edge",
    summary: "Identity, infra, WAF, and CT.",
    content: (
      <div className="space-y-8">
        <IdentityProviderPanel identityProvider={analysisData.identityProvider} />
        <InfrastructurePanel infrastructure={analysisData.infrastructure} />
        <WafFingerprintPanel wafFingerprint={analysisData.wafFingerprint} />
        <CtDiscoveryPanel ctDiscovery={analysisData.ctDiscovery} />
      </div>
    ),
  },
  {
    key: "client-page",
    title: "Page security",
    summary: "HTML and browser-facing posture.",
    content: (
      <div className="space-y-8">
        <HtmlSecurityPanel htmlSecurity={analysisData.htmlSecurity} />
        <ClientExposurePanel htmlSecurity={analysisData.htmlSecurity} />
      </div>
    ),
  },
  {
    key: "client-surface",
    title: "Third-party & AI",
    summary: "Suppliers and AI surface.",
    content: (
      <div className="space-y-8">
        <AiSurfacePanel aiSurface={analysisData.aiSurface} />
        <ThirdPartyTrustPanel thirdPartyTrust={analysisData.thirdPartyTrust} />
      </div>
    ),
  },
  {
    key: "client-auth",
    title: "Auth & collection",
    summary: "Auth paths and collection clues.",
    content: (
      <div className="space-y-8">
        <AuthSurfacePanel htmlSecurity={analysisData.htmlSecurity} />
        <DataCollectionPanel htmlSecurity={analysisData.htmlSecurity} />
      </div>
    ),
  },
  {
    key: "exposure-checks",
    title: "Exposure checks",
    summary: "Low-noise path probes.",
    content: <ExposurePanel exposure={analysisData.exposure} />,
  },
  {
    key: "exposure-api",
    title: "API & CORS",
    summary: "API hints and cross-origin posture.",
    content: (
      <div className="space-y-8">
        <CorsSecurityPanel corsSecurity={analysisData.corsSecurity} />
        <ApiSurfacePanel apiSurface={analysisData.apiSurface} />
      </div>
    ),
  },
  {
    key: "evidence",
    title: "Raw evidence and history",
    summary: "Headers, redirects, certs, cookies, and history.",
    content: <EvidenceSection analysisData={analysisData} history={history} historyDiff={historyDiff} compact />,
  },
];
