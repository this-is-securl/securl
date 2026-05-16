import {
  AlertTriangle,
  ArrowRight,
  BellRing,
  Download,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  TrendingUp,
} from "lucide-react";
import { GRADE_PALETTE } from "@/components/SecurityGrade";
import { MonitoringPanel } from "@/components/MonitoringPanel";
import { PostureSummaryPanel } from "@/components/PostureSummaryPanel";
import { PriorityActionsPanel } from "@/components/PriorityActionsPanel";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { AnalysisResult, HistoryDiff, HistorySnapshot } from "@/types/analysis";
import { getHttpStatusDetails } from "@/lib/httpStatus";
import { getMonitoringAlerts, getPriorityActions } from "@/lib/priorities";
import { sectionTitleClass } from "./ReportSectionHeader";

type TrafficLightStatus = "strong" | "watch" | "weak";

const DONUT_RADIUS = 122;
const DONUT_SIZE   = 280;
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
    status: TrafficLightStatus;
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
  const sortedAreaScores = [...areaScores].sort((left, right) => left.score - right.score);
  const hasTrainingSurfaceNarrative =
    analysisData.executiveSummary.overview.toLowerCase().includes("lab or training surface") ||
    analysisData.executiveSummary.takeaways.some((takeaway) =>
      takeaway.toLowerCase().includes("lab or training surface"),
    );
  const overallPercent = Math.max(0, Math.min(100, analysisData.score));
  const donutOffset = DONUT_CIRCUMFERENCE - (overallPercent / 100) * DONUT_CIRCUMFERENCE;
  const priorityActions = getPriorityActions(analysisData).slice(0, 3);
  const monitoringAlerts = getMonitoringAlerts(analysisData, historyDiff);
  const topTakeaways = analysisData.executiveSummary.takeaways.slice(0, 3);
  const criticalCount = analysisData.issues.filter((issue) => issue.severity === "critical").length;
  const warningCount = analysisData.issues.filter((issue) => issue.severity === "warning").length;
  const overallPostureLabel = isLimitedAssessment
    ? "Limited external read"
    : analysisData.grade === "A" || analysisData.grade === "B"
      ? "Strong"
      : analysisData.grade === "C"
        ? "Mixed"
        : "Needs attention";
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
    <div id="overview" className="space-y-8">
      {analysisData.assessmentLimitation.limited ? (
        <div className="rounded-[1.75rem] border border-[#b56a2c]/35 bg-[#b56a2c]/12 px-6 py-5 text-[#f4dfcd]">
          <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-[#d89a63]">
            {analysisData.assessmentLimitation.title}
          </p>
          <p className="mt-2 text-sm leading-7 text-[#f0d5bc]/90">
            {analysisData.assessmentLimitation.detail}
          </p>
        </div>
      ) : null}

      <div className="space-y-5">
        <div className="rounded-[2rem] border border-zinc-800/70 bg-[#0d1420] p-8 shadow-[0_40px_80px_-24px_rgba(0,0,0,0.7),0_1px_0_rgba(255,255,255,0.05)_inset]">
          <div className="grid gap-10 xl:grid-cols-[240px_minmax(0,1fr)]">

            {/* ── LEFT: Ring gauge — first thing the eye hits ── */}
            {(() => {
              const gp = GRADE_PALETTE[analysisData.grade] ?? GRADE_PALETTE.U;
              const gradeFontSize = analysisData.grade.length > 1 ? "text-[7rem]" : "text-[9rem]";
              return (
                <div
                  className="flex flex-col items-center rounded-[1.7rem] px-5 py-7 shadow-[0_24px_56px_-32px_rgba(0,0,0,0.75)] text-center"
                  style={{
                    border: `1px solid ${gp.borderColor}`,
                    background: `linear-gradient(160deg, ${gp.stroke}0a 0%, rgba(11,18,32,0.98) 40%, rgba(16,24,39,0.95) 100%)`,
                  }}
                >
                  <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-400">
                    {isLimitedAssessment ? "Directional read" : "Posture score"}
                  </p>

                  {/* Ring — 224 px, dominant anchor */}
                  <div className="relative mt-5" style={{ width: DONUT_SIZE, height: DONUT_SIZE }}>
                    <div
                      className="pointer-events-none absolute inset-0 rounded-full"
                      style={{ background: `radial-gradient(circle, ${gp.glow} 0%, transparent 65%)`, filter: "blur(32px) brightness(1.4)" }}
                    />
                    <div
                      className="pointer-events-none absolute -inset-6 rounded-full opacity-50"
                      style={{ background: `radial-gradient(circle, ${gp.stroke}28 0%, transparent 55%)`, filter: "blur(48px)" }}
                    />
                    <svg
                      viewBox={`0 0 ${DONUT_SIZE} ${DONUT_SIZE}`}
                      width={DONUT_SIZE}
                      height={DONUT_SIZE}
                      className="relative -rotate-90"
                    >
                      <circle cx={DONUT_SIZE / 2} cy={DONUT_SIZE / 2} r={DONUT_RADIUS}
                        fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="18"
                      />
                      <circle cx={DONUT_SIZE / 2} cy={DONUT_SIZE / 2} r={DONUT_RADIUS}
                        fill="none" stroke={gp.stroke} strokeWidth="18"
                        strokeLinecap="round"
                        strokeDasharray={DONUT_CIRCUMFERENCE}
                        strokeDashoffset={donutOffset}
                        filter={`drop-shadow(0 0 12px ${gp.stroke}aa)`}
                      />
                    </svg>
                    <div className="absolute inset-0 flex flex-col items-center justify-center gap-1.5">
                      <span
                        className={`font-black leading-none tracking-[-0.05em] ${gradeFontSize}`}
                        style={{ color: gp.textColor }}
                      >
                        {analysisData.grade}
                      </span>
                      <span className="text-sm font-semibold tracking-[-0.01em] text-slate-400">
                        {overallPercent}/100
                      </span>
                      <span
                        className="mt-1 inline-flex rounded-full px-3 py-1 text-[10px] font-bold uppercase tracking-[0.18em]"
                        style={{
                          color: gp.textColor,
                          background: `${gp.stroke}20`,
                          border: `1px solid ${gp.stroke}38`
                        }}
                      >
                        {overallPostureLabel}
                      </span>
                    </div>
                  </div>

                  {/* Monitoring pulse — compact, below ring */}
                  <div className="mt-6 w-full rounded-[1.5rem] border border-white/[0.08] bg-slate-950/60 px-4 py-4 text-left shadow-[0_8px_24px_-12px_rgba(0,0,0,0.5)]">
                    <div className="flex items-center justify-between gap-2">
                      <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-500">Monitoring</p>
                      <BellRing className="h-3.5 w-3.5 text-[#d89a63]/60" />
                    </div>
                    <p className={`mt-2 text-[13px] font-semibold leading-5 ${monitoringTone}`}>
                      {history.length ? `${history.length} snapshot${history.length === 1 ? "" : "s"}` : "Not yet started"}
                    </p>
                    <p className="mt-1.5 text-xs leading-5 text-slate-500">{monitoringStatus}</p>
                  </div>
                </div>
              );
            })()}

            {/* ── RIGHT: Target identity + executive verdict ── */}
            <div className="space-y-5">
              <div className="space-y-2">
                <p className={sectionTitleClass}>Target</p>
                <p className="text-[2.75rem] font-black tracking-[-0.04em] text-white">{analysisData.host}</p>
                <p className="break-all text-sm text-slate-400">{analysisData.finalUrl}</p>
              </div>

              <div className="rounded-[1.75rem] border border-white/[0.1] bg-slate-950/50 p-7 shadow-[0_18px_40px_-30px_rgba(0,0,0,0.75)]">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge variant="outline" className="border-white/10 bg-white/[0.05] px-3 py-1 text-[11px] font-bold uppercase tracking-[0.2em] text-slate-300">
                    Overall posture: {overallPostureLabel}
                  </Badge>
                  {hasTrainingSurfaceNarrative ? (
                    <Badge variant="outline" className="border-[#b56a2c]/30 bg-[#b56a2c]/12 px-3 py-1 text-[11px] font-bold uppercase tracking-[0.2em] text-[#f0d5bc]">
                      Training surface
                    </Badge>
                  ) : null}
                </div>

                <div className="mt-5">
                  <div className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-[0.2em] text-slate-400">
                    <Sparkles className="h-3.5 w-3.5 text-[#d89a63]" />
                    Executive posture verdict
                  </div>
                  <p className={`mt-3 text-xl font-bold leading-8 tracking-[-0.03em] text-white sm:text-2xl ${compact ? "" : "max-w-2xl"}`}>
                    {analysisData.executiveSummary.mainRisk}
                  </p>
                  <p className="mt-4 text-sm leading-relaxed text-slate-200">
                    {analysisData.executiveSummary.overview}
                  </p>
                </div>

                <div className="mt-5 rounded-[1.1rem] border border-white/10 bg-slate-950/45 p-4">
                  <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-500">What stands out</p>
                  <div className="mt-3 flex flex-wrap gap-2">
                    {topTakeaways.map((takeaway) => (
                      <Badge
                        key={takeaway}
                        variant="outline"
                        className="rounded-full border-white/10 bg-white/[0.04] px-3 py-1 text-[11px] leading-5 text-slate-200"
                      >
                        {takeaway}
                      </Badge>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="mt-8 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            {/* Critical */}
            <div className="rounded-[1.5rem] border border-red-500/25 bg-red-500/[0.08] px-5 py-6 transition-transform duration-200 hover:-translate-y-0.5">
              <div className="flex items-center justify-between gap-2">
                <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-red-400">Critical</p>
                <AlertTriangle className="h-3.5 w-3.5 text-red-400/60" />
              </div>
              <p className="mt-3 text-4xl font-black leading-none tracking-[-0.04em] text-red-300">{criticalCount}</p>
              <p className="mt-2.5 text-xs leading-5 text-red-300/60">Highest-priority items for immediate attention.</p>
            </div>
            {/* Warning */}
            <div className="rounded-[1.5rem] border border-amber-500/25 bg-amber-500/[0.08] px-5 py-6 transition-transform duration-200 hover:-translate-y-0.5">
              <div className="flex items-center justify-between gap-2">
                <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-amber-400">Warning</p>
                <ShieldAlert className="h-3.5 w-3.5 text-amber-400/60" />
              </div>
              <p className="mt-3 text-4xl font-black leading-none tracking-[-0.04em] text-amber-300">{warningCount}</p>
              <p className="mt-2.5 text-xs leading-5 text-amber-300/60">Important weaknesses shaping the posture score.</p>
            </div>
            {/* Strengths */}
            <div className="rounded-[1.5rem] border border-emerald-500/25 bg-emerald-500/[0.08] px-5 py-6 transition-transform duration-200 hover:-translate-y-0.5">
              <div className="flex items-center justify-between gap-2">
                <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-emerald-400">Strengths</p>
                <ShieldCheck className="h-3.5 w-3.5 text-emerald-400/60" />
              </div>
              <p className="mt-3 text-4xl font-black leading-none tracking-[-0.04em] text-emerald-300">{analysisData.strengths.length}</p>
              <p className="mt-2.5 text-xs leading-5 text-emerald-300/60">Signals reducing concern or reinforcing confidence.</p>
            </div>
            {/* Monitoring */}
            <div className="rounded-[1.5rem] border border-white/[0.08] bg-slate-950/60 px-5 py-6 transition-transform duration-200 hover:-translate-y-0.5">
              <div className="flex items-center justify-between gap-2">
                <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-400">Monitoring</p>
                <TrendingUp className="h-3.5 w-3.5 text-slate-500" />
              </div>
              <p className="mt-3 text-4xl font-black leading-none tracking-[-0.04em] text-slate-200">{monitoringAlerts.length}</p>
              <p className="mt-2.5 text-xs leading-5 text-slate-500">
                {monitoringAlerts.length ? monitoringAlerts[0]?.title : "No alerting changes from saved history."}
              </p>
            </div>
          </div>

          <div className="mt-8 grid gap-5 xl:grid-cols-[1.08fr_0.92fr]">
            {isLimitedAssessment ? (
              <div className="rounded-[1.75rem] border border-zinc-800/60 bg-slate-950/60 px-7 py-7 shadow-[0_12px_32px_-16px_rgba(0,0,0,0.5)]">
                <div className="flex items-center justify-between gap-3">
                  <p className="text-base font-semibold tracking-[-0.02em] text-white">Assessment constraints</p>
                  <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-500">Directional read only</p>
                </div>
                <div className="mt-5 grid gap-3 md:grid-cols-2">
                  <div className="rounded-[1.15rem] border border-white/10 bg-slate-950/45 px-4 py-4">
                    <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-500">Why this result is constrained</p>
                    <p className="mt-3 text-base font-semibold leading-7 text-white">{analysisData.assessmentLimitation.title}</p>
                    <p className="mt-2 text-sm leading-6 text-slate-300">{analysisData.assessmentLimitation.detail}</p>
                  </div>
                  <div className="rounded-[1.15rem] border border-white/10 bg-slate-950/45 px-4 py-4">
                    <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-500">How to read this</p>
                    <p className="mt-3 text-sm leading-6 text-slate-300">
                      Use this result as a transport and access-control signal, not as a full category-by-category posture verdict.
                    </p>
                  </div>
                </div>
              </div>
            ) : (
              <div className="rounded-[1.75rem] border border-zinc-800/60 bg-slate-950/60 px-7 py-7 shadow-[0_12px_32px_-16px_rgba(0,0,0,0.5)]">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-400">Category scores</p>
                    <p className="mt-2 text-xl font-bold tracking-[-0.03em] text-white">Where risk is concentrated</p>
                  </div>
                </div>
                <div className="mt-5 space-y-3">
                  {sortedAreaScores.map((area) => {
                    const barColor = area.status === "strong" ? "#22c55e" : area.status === "watch" ? "#f59e0b" : "#ef4444";
                    const scoreColor = area.status === "strong" ? "#4ade80" : area.status === "watch" ? "#fbbf24" : "#f87171";
                    return (
                      <div key={area.key} className="grid gap-2 md:grid-cols-[12rem_1fr_4.5rem] md:items-center">
                        <p className="text-sm font-semibold text-slate-200">{area.label}</p>
                        <div className="relative h-2 overflow-hidden rounded-full bg-white/[0.06]">
                          <div
                            className="absolute inset-y-0 left-0 rounded-full transition-all duration-500"
                            style={{ width: `${area.score}%`, background: barColor, opacity: 0.9, boxShadow: `0 0 8px ${barColor}55` }}
                          />
                        </div>
                        <p className="text-right text-sm font-semibold leading-none" style={{ color: scoreColor }}>
                          {area.score}
                          <span className="ml-0.5 text-[11px] font-medium text-slate-500">/100</span>
                        </p>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            <div className="rounded-[1.75rem] border border-zinc-800/60 bg-slate-950/60 px-7 py-7 shadow-[0_12px_32px_-16px_rgba(0,0,0,0.5)]">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-400">What to do next</p>
                  <p className="mt-2 text-xl font-semibold tracking-[-0.02em] text-white">Priority actions</p>
                </div>
                <ShieldAlert className="h-4.5 w-4.5 text-[#d89a63]" />
              </div>
              {priorityActions.length ? (
                <div className="mt-5 space-y-3">
                  {priorityActions.map((action, index) => {
                    const accentColor = action.severity === "critical" ? "#f87171" : action.severity === "warning" ? "#fbbf24" : "#94a3b8";
                    const accentBg    = action.severity === "critical" ? "rgba(239,68,68,0.10)"  : action.severity === "warning" ? "rgba(245,158,11,0.10)" : "rgba(100,116,139,0.08)";
                    const accentBorder= action.severity === "critical" ? "rgba(239,68,68,0.25)"  : action.severity === "warning" ? "rgba(245,158,11,0.25)" : "rgba(100,116,139,0.18)";
                    return (
                      <div
                        key={`${action.area}-${action.title}`}
                        className="overflow-hidden rounded-[1.15rem] border"
                        style={{ borderColor: accentBorder, background: accentBg }}
                      >
                        <div className="px-4 py-4">
                          <div className="flex flex-wrap items-center gap-2.5">
                            <span
                              className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-[10px] font-bold"
                              style={{ background: accentColor, color: "#0a0e1a" }}
                            >
                              {index + 1}
                            </span>
                            <p className="text-sm font-semibold text-white">{action.title}</p>
                          </div>
                          <p className="mt-2 text-xs leading-5 text-slate-400">{action.detail}</p>
                          <div className="mt-2.5 flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-[0.16em]" style={{ color: accentColor, opacity: 0.65 }}>
                            <ArrowRight className="h-3 w-3" />
                            {action.area}
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div className="mt-5 rounded-[1.15rem] border border-white/10 bg-slate-950/45 px-4 py-4 text-sm leading-6 text-slate-400">
                  No immediate remediation is being prioritized from the current public evidence.
                </div>
              )}
            </div>
          </div>

          <div className="mt-8 grid gap-5 lg:grid-cols-[0.95fr_1.05fr]">
            <div className="rounded-[1.75rem] border border-zinc-800/60 bg-slate-950/60 px-7 py-7 shadow-[0_12px_32px_-16px_rgba(0,0,0,0.5)]">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-400">Scan facts</p>
                  <p className="mt-2 text-xl font-semibold tracking-[-0.02em] text-white">Capture details</p>
                </div>
              </div>
              <div className="mt-5 grid gap-3 sm:grid-cols-3">
                <div className="rounded-[1.1rem] border border-white/10 bg-slate-950/45 px-4 py-4">
                  <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-500">Scanned</p>
                  <p className="mt-2.5 text-sm font-semibold leading-6 text-white">{new Date(analysisData.scannedAt).toLocaleString()}</p>
                </div>
                <div className="rounded-[1.1rem] border border-white/10 bg-slate-950/45 px-4 py-4">
                  <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-500">HTTP</p>
                  <p className="mt-2.5 text-2xl font-bold tracking-[-0.03em] text-white">{analysisData.statusCode}</p>
                  <p className="mt-1 text-[11px] uppercase tracking-[0.14em] text-slate-500">{getHttpStatusDetails(analysisData.statusCode).label}</p>
                </div>
                <div className="rounded-[1.1rem] border border-white/10 bg-slate-950/45 px-4 py-4">
                  <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-500">Latency</p>
                  <p className="mt-2.5 text-2xl font-bold tracking-[-0.03em] text-white">{analysisData.responseTimeMs}ms</p>
                </div>
              </div>
            </div>

            <div className="rounded-[1.75rem] border border-zinc-800/60 bg-slate-950/60 px-7 py-7 shadow-[0_12px_32px_-16px_rgba(0,0,0,0.5)]">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-400">Report outputs</p>
                  <p className="mt-2 text-xl font-semibold tracking-[-0.02em] text-white">Share or hand off this scan</p>
                </div>
                <Download className="h-4 w-4 text-[#d89a63]" />
              </div>
              <p className="mt-3 text-sm leading-6 text-slate-400">
                Export the executive read as a PDF, keep the technical version in Markdown, or pass the raw result onward as JSON.
              </p>
              <div className="mt-5 grid gap-3 sm:grid-cols-3">
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
          <div className="space-y-5">
            <p className={sectionTitleClass}>Posture summary</p>
            <PostureSummaryPanel analysis={analysisData} />
          </div>

          <div className="space-y-5">
            <PriorityActionsPanel analysis={analysisData} />
            <MonitoringPanel analysis={analysisData} diff={historyDiff} history={history} />
          </div>
        </>
      ) : null}
    </div>
  );
};
