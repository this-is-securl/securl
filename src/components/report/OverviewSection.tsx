import { ArrowRight, BellRing, Download, ShieldAlert, Sparkles } from "lucide-react";
import { MonitoringPanel } from "@/components/MonitoringPanel";
import { PostureSummaryPanel } from "@/components/PostureSummaryPanel";
import { PriorityActionsPanel } from "@/components/PriorityActionsPanel";
import { Button } from "@/components/ui/button";
import { AnalysisResult, HistoryDiff, HistorySnapshot } from "@/types/analysis";
import { getHttpStatusDetails } from "@/lib/httpStatus";
import { getMonitoringAlerts, getPriorityActions } from "@/lib/priorities";
import { sectionTitleClass } from "./ReportSectionHeader";

const trafficLightStyles = {
  strong: {
    ring: "border-white/10",
    pill: "bg-slate-300",
    text: "text-slate-100",
    bar: "from-slate-200 via-slate-300 to-slate-400",
  },
  watch: {
    ring: "border-[#b56a2c]/45",
    pill: "bg-[#b56a2c]",
    text: "text-[#f0d5bc]",
    bar: "from-[#9d5a28] via-[#b56a2c] to-[#d08a4b]",
  },
  weak: {
    ring: "border-[#8e5c3b]/45",
    pill: "bg-[#8e5c3b]",
    text: "text-[#e2c0a2]",
    bar: "from-[#74452b] via-[#8e5c3b] to-[#b56a2c]",
  },
} as const;

const healthcheckStyles = {
  strong: {
    tile: "border-white/10 bg-white/[0.04]",
    dot: "bg-slate-300",
    grade: "text-slate-100",
  },
  watch: {
    tile: "border-[#b56a2c]/35 bg-[#b56a2c]/12",
    dot: "bg-[#b56a2c]",
    grade: "text-[#f0d5bc]",
  },
  weak: {
    tile: "border-[#8e5c3b]/35 bg-[#8e5c3b]/12",
    dot: "bg-[#8e5c3b]",
    grade: "text-[#e2c0a2]",
  },
} as const;

const healthcheckStatusForGrade = (grade: string): keyof typeof healthcheckStyles => {
  const normalized = grade.trim().toUpperCase();
  if (normalized === "A" || normalized === "B") return "strong";
  if (normalized === "C") return "watch";
  return "weak";
};

const DONUT_RADIUS = 52;
const DONUT_CIRCUMFERENCE = 2 * Math.PI * DONUT_RADIUS;

interface OverviewSectionProps {
  analysisData: AnalysisResult;
  historyDiff: HistoryDiff | null;
  history: Array<HistorySnapshot & {
    areaScores?: Array<{
      key: string;
      label: string;
      score: number;
      status: "strong" | "watch" | "weak";
    }>;
  }>;
  areaScores: Array<{
    key: string;
    label: string;
    score: number;
    status: keyof typeof trafficLightStyles;
  }>;
  exportPdf: () => void;
  exportMarkdown: () => void;
  exportReport: () => void;
  compact?: boolean;
}

export const OverviewSection = ({
  analysisData,
  historyDiff,
  history,
  areaScores,
  exportPdf,
  exportMarkdown,
  exportReport,
  compact = false,
}: OverviewSectionProps) => {
  const isLimitedAssessment = analysisData.assessmentLimitation.limited;
  const healthcheckStyle = healthcheckStyles[healthcheckStatusForGrade(analysisData.grade)];
  const sortedAreaScores = [...areaScores].sort((left, right) => left.score - right.score);
  const limitedReadLabel =
    analysisData.assessmentLimitation.kind === "blocked_edge_response" ||
    analysisData.assessmentLimitation.kind === "auth_required"
      ? "Blocked read"
      : "Limited read";
  const hasTrainingSurfaceNarrative =
    analysisData.executiveSummary.overview.toLowerCase().includes("lab or training surface") ||
    analysisData.executiveSummary.takeaways.some((takeaway) =>
      takeaway.toLowerCase().includes("lab or training surface"),
    );
  const overallPercent = Math.max(0, Math.min(100, analysisData.score));
  const donutOffset = DONUT_CIRCUMFERENCE - (overallPercent / 100) * DONUT_CIRCUMFERENCE;
  const priorityActions = getPriorityActions(analysisData).slice(0, 3);
  const monitoringAlerts = getMonitoringAlerts(analysisData, historyDiff);
  const strongestArea = [...areaScores].sort((left, right) => right.score - left.score)[0] ?? null;
  const weakestArea = sortedAreaScores[0] ?? null;
  const criticalCount = analysisData.issues.filter((issue) => issue.severity === "critical").length;
  const warningCount = analysisData.issues.filter((issue) => issue.severity === "warning").length;
  const scanOutcomeLabel = isLimitedAssessment
    ? limitedReadLabel
    : `${analysisData.grade} / ${overallPercent}%`;
  const scanOutcomeDetail = isLimitedAssessment
    ? "Directional read only"
    : "Executive posture verdict";
  const monitoringStatus = historyDiff
    ? historyDiff.scoreDelta === null || historyDiff.scoreDelta === 0
      ? "Stable since the previous saved scan"
      : historyDiff.scoreDelta > 0
        ? `Improved by ${historyDiff.scoreDelta} points`
        : `Regressed by ${Math.abs(historyDiff.scoreDelta)} points`
    : history.length > 0
      ? "Baseline recorded. The next saved scan will show movement."
      : "Monitoring starts once this target has a saved history.";
  const monitoringTone = historyDiff && (historyDiff.scoreDelta ?? 0) < 0
    ? "text-[#f0d5bc]"
    : monitoringAlerts.some((alert) => alert.severity === "warning")
      ? "text-[#f0d5bc]"
      : "text-slate-300";

  return (
    <div id="overview" className="space-y-6">
      {analysisData.assessmentLimitation.limited ? (
        <div className="rounded-[1.75rem] border border-[#b56a2c]/35 bg-[#b56a2c]/12 px-5 py-4 text-[#f4dfcd]">
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-[#d89a63]">
            {analysisData.assessmentLimitation.title}
          </p>
          <p className="mt-2 text-sm leading-7 text-[#f0d5bc]/90">
            {analysisData.assessmentLimitation.detail}
          </p>
        </div>
      ) : null}

      <div className="space-y-4">
        <div className="rounded-[2rem] border border-white/10 bg-[linear-gradient(135deg,rgba(11,18,32,0.95),rgba(16,24,39,0.92))] px-6 py-6 shadow-[0_30px_80px_-48px_rgba(0,0,0,0.8)] ring-1 ring-white/[0.04]">
          <div className="grid gap-5 xl:grid-cols-[minmax(0,1.15fr)_320px] xl:items-start">
            <div className="space-y-4">
              <div>
                <p className={sectionTitleClass}>Target</p>
                <p className="mt-3 text-3xl font-semibold tracking-tight text-white">{analysisData.host}</p>
                <p className="mt-2 break-all text-sm text-slate-400">{analysisData.finalUrl}</p>
              </div>

              <div className="rounded-[1.5rem] border border-white/10 bg-white/[0.04] px-5 py-5 shadow-[0_18px_40px_-30px_rgba(0,0,0,0.75)]">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">{scanOutcomeDetail}</p>
                    <p className={`mt-2 text-3xl font-semibold tracking-[-0.04em] ${healthcheckStyle.grade}`}>
                      {scanOutcomeLabel}
                    </p>
                  </div>
                  <span className={`inline-flex h-3 w-3 rounded-full ${healthcheckStyle.dot}`} aria-hidden="true" />
                </div>
                <div className="mt-4 rounded-[1.2rem] border border-white/10 bg-slate-950/45 px-4 py-4">
                  <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500">Main visible risk</p>
                  <p className="mt-2 text-base font-semibold leading-7 text-white">
                    {analysisData.executiveSummary.mainRisk}
                  </p>
                </div>
                <div className="mt-4 flex items-start gap-2 text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">
                  <Sparkles className="mt-0.5 h-4 w-4 shrink-0 text-[#d89a63]" />
                  <span>Executive posture verdict</span>
                </div>
                {hasTrainingSurfaceNarrative ? (
                  <div className="mt-3 inline-flex items-center rounded-full border border-[#b56a2c]/35 bg-[#b56a2c]/12 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-[#f0d5bc]">
                    Training surface detected
                  </div>
                ) : null}
                <p className={`mt-3 text-base text-slate-300 ${compact ? "leading-7" : "leading-8"}`}>
                  {analysisData.executiveSummary.overview}
                </p>
              </div>
            </div>

            <div className="space-y-4">
              <div className={`rounded-[1.65rem] border px-6 py-6 shadow-[0_18px_40px_-30px_rgba(0,0,0,0.75)] ${healthcheckStyle.tile}`}>
                <div className="flex h-full flex-col items-center justify-center text-center">
                  <p className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-400">
                    {isLimitedAssessment ? "Directional read" : "Overall posture"}
                  </p>
                  <div className="relative mt-5 h-44 w-44">
                    <svg viewBox="0 0 140 140" className="h-44 w-44 -rotate-90">
                      <circle
                        cx="70"
                        cy="70"
                        r={DONUT_RADIUS}
                        fill="none"
                        stroke="rgba(255,255,255,0.08)"
                        strokeWidth="12"
                      />
                      <circle
                        cx="70"
                        cy="70"
                        r={DONUT_RADIUS}
                        fill="none"
                        stroke="url(#healthcheck-gradient)"
                        strokeWidth="12"
                        strokeLinecap="round"
                        strokeDasharray={DONUT_CIRCUMFERENCE}
                        strokeDashoffset={donutOffset}
                      />
                      <defs>
                        <linearGradient id="healthcheck-gradient" x1="0%" y1="0%" x2="100%" y2="0%">
                          <stop offset="0%" stopColor={healthcheckStyle.dot.includes("b56a2c") ? "#8e5c3b" : "#cbd5e1"} />
                          <stop offset="55%" stopColor={healthcheckStyle.dot.includes("b56a2c") ? "#b56a2c" : "#dbe4f0"} />
                          <stop offset="100%" stopColor={healthcheckStyle.dot.includes("8e5c3b") ? "#d08a4b" : "#f8fafc"} />
                        </linearGradient>
                      </defs>
                    </svg>
                    <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                      <span className={`text-5xl font-semibold leading-none ${healthcheckStyle.grade}`}>{analysisData.grade}</span>
                      <span className="mt-2 text-lg font-semibold text-slate-200">{overallPercent}%</span>
                    </div>
                  </div>
                  <p className="mt-5 text-sm leading-6 text-slate-300">
                    {isLimitedAssessment
                      ? "This read is directional only because the public surface limited a full assessment."
                      : "A normalized posture score across the major passive-read areas, tuned for a fast executive read."}
                  </p>
                </div>
              </div>

              <div className="rounded-[1.5rem] border border-white/10 bg-white/[0.04] px-5 py-5 shadow-[0_18px_40px_-30px_rgba(0,0,0,0.75)]">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">Monitoring status</p>
                    <p className="mt-2 text-lg font-semibold text-white">
                      {history.length ? `${history.length} saved snapshot${history.length === 1 ? "" : "s"}` : "Not yet started"}
                    </p>
                  </div>
                  <BellRing className="h-5 w-5 text-[#d89a63]" />
                </div>
                <p className={`mt-3 text-sm leading-6 ${monitoringTone}`}>
                  {monitoringStatus}
                </p>
              </div>
            </div>
          </div>

          <div className="mt-5 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <div className="rounded-[1.35rem] border border-white/10 bg-white/[0.04] px-5 py-5 shadow-[0_18px_40px_-30px_rgba(0,0,0,0.75)]">
              <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500">Critical issues</p>
              <p className="mt-3 text-3xl font-semibold text-[#f0d5bc]">{criticalCount}</p>
              <p className="mt-2 text-sm text-slate-400">Highest-priority items for immediate attention.</p>
            </div>
            <div className="rounded-[1.35rem] border border-white/10 bg-white/[0.04] px-5 py-5 shadow-[0_18px_40px_-30px_rgba(0,0,0,0.75)]">
              <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500">Warning issues</p>
              <p className="mt-3 text-3xl font-semibold text-[#e2c0a2]">{warningCount}</p>
              <p className="mt-2 text-sm text-slate-400">Important weaknesses that shape the posture score.</p>
            </div>
            <div className="rounded-[1.35rem] border border-white/10 bg-white/[0.04] px-5 py-5 shadow-[0_18px_40px_-30px_rgba(0,0,0,0.75)]">
              <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500">Observed strengths</p>
              <p className="mt-3 text-3xl font-semibold text-slate-100">{analysisData.strengths.length}</p>
              <p className="mt-2 text-sm text-slate-400">Signals that reduce concern or reinforce baseline confidence.</p>
            </div>
            <div className="rounded-[1.35rem] border border-white/10 bg-white/[0.04] px-5 py-5 shadow-[0_18px_40px_-30px_rgba(0,0,0,0.75)]">
              <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500">Monitoring alerts</p>
              <p className="mt-3 text-3xl font-semibold text-slate-100">{monitoringAlerts.length}</p>
              <p className="mt-2 text-sm text-slate-400">
                {monitoringAlerts.length ? monitoringAlerts[0]?.title : "No alerting changes surfaced from saved history."}
              </p>
            </div>
          </div>

          <div className="mt-5 grid gap-4 xl:grid-cols-[1.02fr_0.98fr]">
            {isLimitedAssessment ? (
              <div className="rounded-[1.5rem] border border-white/10 bg-white/[0.04] px-5 py-5 shadow-[0_18px_40px_-30px_rgba(0,0,0,0.75)]">
                <div className="flex items-center justify-between gap-3">
                  <p className="text-sm font-semibold text-white">Assessment constraints</p>
                  <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500">Directional read only</p>
                </div>
                <div className="mt-4 grid gap-3 md:grid-cols-2">
                  <div className="rounded-[1.15rem] border border-white/10 bg-slate-950/45 px-4 py-4">
                    <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Why this result is constrained</p>
                    <p className="mt-3 text-base font-semibold leading-7 text-white">{analysisData.assessmentLimitation.title}</p>
                    <p className="mt-2 text-sm leading-6 text-slate-300">{analysisData.assessmentLimitation.detail}</p>
                  </div>
                  <div className="rounded-[1.15rem] border border-white/10 bg-slate-950/45 px-4 py-4">
                    <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">How to read this</p>
                    <p className="mt-3 text-sm leading-6 text-slate-300">
                      Use this result as a transport and access-control signal, not as a full category-by-category posture verdict.
                    </p>
                  </div>
                </div>
              </div>
            ) : (
              <div className="rounded-[1.5rem] border border-white/10 bg-white/[0.04] px-5 py-5 shadow-[0_18px_40px_-30px_rgba(0,0,0,0.75)]">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">Category scores</p>
                    <p className="mt-2 text-lg font-semibold text-white">Where risk is concentrated</p>
                  </div>
                </div>
                <div className="mt-4 space-y-3">
                  {sortedAreaScores.map((area) => {
                    const style = trafficLightStyles[area.status];
                    return (
                      <div key={area.key} className="grid gap-2 md:grid-cols-[13rem_1fr_auto] md:items-center">
                        <div className="flex items-center gap-3">
                          <span className={`inline-flex h-2.5 w-2.5 rounded-full ${style.pill}`} aria-hidden="true" />
                          <p className="text-sm font-medium text-slate-200">{area.label}</p>
                        </div>
                        <div className="relative h-3 overflow-hidden rounded-full bg-white/[0.06] ring-1 ring-white/[0.05]">
                          <div
                            className={`absolute inset-y-0 left-0 rounded-full bg-gradient-to-r ${style.bar}`}
                            style={{ width: `${area.score}%` }}
                          />
                        </div>
                        <div className="flex min-w-[6.25rem] items-baseline justify-end gap-2 text-right">
                          <span className={`text-lg font-semibold leading-none ${style.text}`}>{area.score}%</span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            <div className="rounded-[1.5rem] border border-white/10 bg-[linear-gradient(180deg,rgba(255,255,255,0.05),rgba(255,255,255,0.03))] px-5 py-5 shadow-[0_18px_40px_-30px_rgba(0,0,0,0.75)]">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">What to do next</p>
                  <p className="mt-2 text-lg font-semibold text-white">Priority actions for this target</p>
                </div>
                <ShieldAlert className="h-5 w-5 text-[#d89a63]" />
              </div>
              {priorityActions.length ? (
                <div className="mt-4 space-y-3">
                  {priorityActions.map((action, index) => (
                    <div key={`${action.area}-${action.title}`} className="rounded-[1.2rem] border border-white/10 bg-slate-950/45 px-4 py-4">
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="inline-flex h-6 min-w-6 items-center justify-center rounded-full bg-[#b56a2c]/16 px-2 text-[11px] font-semibold uppercase tracking-[0.16em] text-[#f0d5bc]">
                              {index + 1}
                            </span>
                            <p className="text-sm font-semibold text-white">{action.title}</p>
                          </div>
                          <p className="mt-2 text-sm leading-6 text-slate-300">{action.detail}</p>
                        </div>
                        <span className="shrink-0 rounded-full border border-white/10 bg-white/[0.04] px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-300">
                          {action.severity}
                        </span>
                      </div>
                      <div className="mt-3 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-500">
                        <ArrowRight className="h-3.5 w-3.5" />
                        {action.area}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="mt-4 rounded-[1.2rem] border border-white/10 bg-slate-950/45 px-4 py-4 text-sm leading-6 text-slate-300">
                  No immediate remediation is being prioritized from the current public evidence.
                </div>
              )}
            </div>
          </div>

          <div className="mt-5 grid gap-4 lg:grid-cols-[0.95fr_1.05fr]">
            <div className="rounded-[1.5rem] border border-white/10 bg-white/[0.04] px-5 py-5 shadow-[0_18px_40px_-30px_rgba(0,0,0,0.75)]">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">Scan facts</p>
                  <p className="mt-2 text-lg font-semibold text-white">Capture details</p>
                </div>
              </div>
              <div className="mt-4 grid gap-3 sm:grid-cols-3">
                <div className="rounded-[1.1rem] border border-white/10 bg-slate-950/45 px-3 py-3">
                  <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500">Scanned</p>
                  <p className="mt-2 text-sm font-semibold text-white">{new Date(analysisData.scannedAt).toLocaleString()}</p>
                </div>
                <div className="rounded-[1.1rem] border border-white/10 bg-slate-950/45 px-3 py-3">
                  <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500">HTTP</p>
                  <p className="mt-2 text-2xl font-semibold text-white">{analysisData.statusCode}</p>
                  <p className="mt-1 text-[11px] uppercase tracking-[0.16em] text-slate-500">{getHttpStatusDetails(analysisData.statusCode).label}</p>
                </div>
                <div className="rounded-[1.1rem] border border-white/10 bg-slate-950/45 px-3 py-3">
                  <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500">Latency</p>
                  <p className="mt-2 text-2xl font-semibold text-white">{analysisData.responseTimeMs}ms</p>
                </div>
              </div>
            </div>

            <div className="rounded-[1.5rem] border border-white/10 bg-white/[0.04] px-5 py-5 shadow-[0_18px_40px_-30px_rgba(0,0,0,0.75)]">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">Report outputs</p>
                  <p className="mt-2 text-lg font-semibold text-white">Share or hand off this scan</p>
                </div>
                <Download className="h-4 w-4 text-[#d89a63]" />
              </div>
              <p className="mt-3 text-sm leading-6 text-slate-400">
                Export the executive read as a PDF, keep the technical version in Markdown, or pass the raw result onward as JSON.
              </p>
              <div className="mt-4 grid gap-3 sm:grid-cols-3">
                <Button variant="outline" className="h-11 w-full justify-center rounded-2xl border-white/10 bg-white/[0.04] font-medium text-slate-100 hover:bg-white/[0.08]" onClick={exportPdf}>
                  Export PDF
                </Button>
                <Button variant="outline" className="h-11 w-full justify-center rounded-2xl border-white/10 bg-white/[0.04] font-medium text-slate-100 hover:bg-white/[0.08]" onClick={exportMarkdown}>
                  Export Markdown
                </Button>
                <Button variant="outline" className="h-11 w-full justify-center rounded-2xl border-white/10 bg-white/[0.04] font-medium text-slate-100 hover:bg-white/[0.08]" onClick={exportReport}>
                  Export JSON
                </Button>
              </div>
            </div>
          </div>
        </div>
      </div>

      {!compact ? (
        <>
          <div className="space-y-4">
            <p className={sectionTitleClass}>Posture summary</p>
            <PostureSummaryPanel analysis={analysisData} />
          </div>

          <div className="space-y-4">
            <PriorityActionsPanel analysis={analysisData} />
            <MonitoringPanel analysis={analysisData} diff={historyDiff} history={history} />
          </div>
        </>
      ) : null}
    </div>
  );
};
