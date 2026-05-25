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

function relativeTime(iso: string): string {
  const diffMs = Date.now() - new Date(iso).getTime();
  const s = Math.floor(diffMs / 1000);
  if (s < 90) return "just now";
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return new Date(iso).toLocaleDateString();
}

// ── Ring constants ────────────────────────────────────────────────────────────
// The numeric score drives the arc, but the letter grade is the product verdict.
const DONUT_RADIUS = 96;
const DONUT_SIZE   = 220;
const DONUT_CIRCUMFERENCE = 2 * Math.PI * DONUT_RADIUS;
// strokeWidth 14 → inner clearance = 96-7 = 89 → inner ⌀ ≈ 178 px

interface OverviewSectionProps {
  analysisData: AnalysisResult;
  scanWasCached?: boolean;
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

// ── Shared sub-card style ─────────────────────────────────────────────────────
const subCard = "rounded-[1.75rem] border border-white/[0.09] bg-white/[0.04] px-6 py-6 shadow-[0_4px_16px_rgba(0,0,0,0.3)]";
const eyebrow  = "text-[10px] font-bold uppercase tracking-[0.24em] text-zinc-500";
const cardTitle = "mt-2 text-xl font-black tracking-[-0.03em] text-white";

export const OverviewSection = ({
  analysisData,
  scanWasCached = false,
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
  const warningCount  = analysisData.issues.filter((issue) => issue.severity === "warning").length;
  const overallPostureLabel = isLimitedAssessment
    ? "Limited read"
    : analysisData.grade === "A" || analysisData.grade === "B"
      ? "Strong"
      : analysisData.grade === "C"
        ? "Mixed"
        : "Needs attention";
  const monitoringStatus = historyDiff
    ? historyDiff.scoreDelta === null || historyDiff.scoreDelta === 0
      ? "Stable since last scan"
      : historyDiff.scoreDelta > 0
        ? `+${historyDiff.scoreDelta} pts from last scan`
        : `${historyDiff.scoreDelta} pts from last scan`
    : history.length > 0
      ? "Baseline recorded."
      : "Monitoring not yet started.";
  const monitoringTone = historyDiff && (historyDiff.scoreDelta ?? 0) < 0
    ? "text-amber-300"
    : "text-zinc-200";

  return (
    <div id="overview" className="space-y-8">
      {/* ── Assessment limitation banner ── */}
      {analysisData.assessmentLimitation.limited ? (
        <div className="rounded-[1.75rem] border border-amber-500/20 bg-amber-500/[0.06] px-6 py-5">
          <p className={eyebrow + " text-amber-500/70"}>
            {analysisData.assessmentLimitation.title}
          </p>
          <p className="mt-2 text-sm leading-relaxed text-amber-200/80">
            {analysisData.assessmentLimitation.detail}
          </p>
        </div>
      ) : null}

      {/* ── Main overview card ── */}
      <div className="rounded-[2rem] border border-white/[0.09] bg-white/[0.04] p-8 shadow-[0_40px_96px_-24px_rgba(0,0,0,0.75),0_1px_0_rgba(255,255,255,0.07)_inset]">

        {/* ── TOP: Ring gauge + executive verdict ── */}
        <div className="grid grid-cols-1 gap-8 lg:gap-10 xl:grid-cols-[260px_minmax(0,1fr)]">

          {/* LEFT: Score gauge */}
          {(() => {
            const gp = GRADE_PALETTE[analysisData.grade] ?? GRADE_PALETTE.U;
            // A+ is two chars — needs smaller font to fit inside ring
            const gradeFont = analysisData.grade.length > 1 ? "text-[5.5rem]" : "text-[7.5rem]";
            return (
              <div
                className="flex flex-col items-center rounded-[1.75rem] px-5 py-8 text-center"
                style={{
                  border: `1px solid ${gp.stroke}22`,
                  background: `radial-gradient(ellipse 160% 60% at 50% 0%, ${gp.stroke}0d 0%, transparent 55%), #09090b`,
                }}
              >
                <p className={eyebrow}>
                  {isLimitedAssessment ? "Directional read" : "Posture grade"}
                </p>

                {/* Ring */}
                <div className="relative mt-5" style={{ width: DONUT_SIZE, height: DONUT_SIZE }}>
                  {/* Single soft glow layer — calm, not aggressive */}
                  <div
                    className="pointer-events-none absolute inset-0 rounded-full"
                    style={{
                      background: `radial-gradient(circle, ${gp.glow} 0%, transparent 68%)`,
                      filter: "blur(24px)",
                    }}
                  />
                  <svg
                    viewBox={`0 0 ${DONUT_SIZE} ${DONUT_SIZE}`}
                    width={DONUT_SIZE}
                    height={DONUT_SIZE}
                    className="relative -rotate-90"
                  >
                    {/* Track */}
                    <circle
                      cx={DONUT_SIZE / 2} cy={DONUT_SIZE / 2} r={DONUT_RADIUS}
                      fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="14"
                    />
                    {/* Progress arc */}
                    <circle
                      cx={DONUT_SIZE / 2} cy={DONUT_SIZE / 2} r={DONUT_RADIUS}
                      fill="none" stroke={gp.stroke} strokeWidth="14"
                      strokeLinecap="round"
                      strokeDasharray={DONUT_CIRCUMFERENCE}
                      strokeDashoffset={donutOffset}
                      filter={`drop-shadow(0 0 6px ${gp.stroke}88)`}
                    />
                  </svg>

                  {/* Inner: grade letter only — large, dominant */}
                  <div className="absolute inset-0 flex flex-col items-center justify-center gap-1">
                    <span
                      className={`font-black leading-none tracking-[-0.06em] ${gradeFont}`}
                      style={{ color: gp.textColor }}
                    >
                      {analysisData.grade}
                    </span>
                  </div>
                </div>

                {/* Verdict and weighted signal — the score is supporting context, not the headline. */}
                <p
                  className="mt-4 text-[11px] font-bold uppercase tracking-[0.24em]"
                  style={{ color: gp.textColor, opacity: 0.8 }}
                >
                  {overallPostureLabel}
                </p>
                <p className="mt-1 text-[11px] font-medium text-zinc-600">
                  Score: {overallPercent}
                </p>

                {/* Scan freshness */}
                <div className="mt-3 flex items-center justify-center gap-2">
                  {scanWasCached ? (
                    <span className="inline-flex items-center gap-1.5 rounded-full border border-[#b56a2c]/20 bg-[#b56a2c]/[0.08] px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.18em] text-[#d89a63]">
                      <span className="h-1.5 w-1.5 rounded-full bg-[#b56a2c]" />
                      Cached · {relativeTime(analysisData.scannedAt)}
                    </span>
                  ) : (
                    <span className="text-[10px] font-medium text-zinc-700">
                      Scanned {relativeTime(analysisData.scannedAt)}
                    </span>
                  )}
                </div>

                {/* Monitoring — clean, no inner card, just a divider section */}
                <div className="mt-6 w-full border-t border-white/[0.06] pt-5 text-left">
                  <div className="flex items-center justify-between gap-2">
                    <p className={eyebrow}>Monitoring</p>
                    <BellRing className="h-3 w-3 text-zinc-600" />
                  </div>
                  <p className={`mt-2 text-[13px] font-semibold leading-5 ${monitoringTone}`}>
                    {history.length
                      ? `${history.length} snapshot${history.length === 1 ? "" : "s"}`
                      : "No history yet"}
                  </p>
                  <p className="mt-1 text-[11px] leading-5 text-zinc-600">{monitoringStatus}</p>
                </div>
              </div>
            );
          })()}

          {/* RIGHT: Target identity + executive verdict */}
          <div className="space-y-6">
            <div className="space-y-1.5">
              <p className={sectionTitleClass}>Target</p>
              <p className="text-2xl font-black tracking-[-0.04em] text-white leading-none sm:text-[2.5rem]">{analysisData.host}</p>
              <p className="break-all text-sm text-zinc-500 mt-1">{analysisData.finalUrl}</p>
            </div>

            {/* Executive verdict */}
            <div className="rounded-[1.75rem] border border-white/[0.08] bg-zinc-950/50 p-7 shadow-[0_4px_16px_rgba(0,0,0,0.3)]">
              <div className="flex flex-wrap items-center gap-2 mb-5">
                <Badge variant="outline" className="border-white/[0.08] bg-white/[0.04] px-3 py-1 text-[10px] font-bold uppercase tracking-[0.22em] text-zinc-400">
                  Overall posture: {overallPostureLabel}
                </Badge>
                {hasTrainingSurfaceNarrative ? (
                  <Badge variant="outline" className="border-amber-500/25 bg-amber-500/[0.08] px-3 py-1 text-[10px] font-bold uppercase tracking-[0.22em] text-amber-300">
                    Training surface
                  </Badge>
                ) : null}
              </div>

              <div className="flex items-center gap-2 mb-3">
                <Sparkles className="h-3.5 w-3.5 shrink-0 text-[#d89a63]" />
                <p className={eyebrow}>Executive verdict</p>
              </div>
              <p className={`text-xl font-bold leading-8 tracking-[-0.03em] text-white sm:text-2xl ${compact ? "" : "max-w-2xl"}`}>
                {analysisData.executiveSummary.mainRisk}
              </p>
              <p className="mt-3 text-sm leading-relaxed text-zinc-300">
                {analysisData.executiveSummary.overview}
              </p>

              {topTakeaways.length > 0 && (
                <div className="mt-5 border-t border-white/[0.06] pt-5">
                  <p className={eyebrow + " mb-3"}>What stands out</p>
                  <div className="flex flex-wrap gap-2">
                    {topTakeaways.map((takeaway) => (
                      <Badge
                        key={takeaway}
                        variant="outline"
                        className="rounded-full border-white/[0.08] bg-white/[0.03] px-3 py-1 text-[11px] leading-5 text-zinc-300"
                      >
                        {takeaway}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* ── STAT TILES: left-accent rail style ── */}
        <div className="mt-8 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {/* Critical */}
          <div className="group relative overflow-hidden rounded-3xl bg-white/[0.04] px-5 py-6 ring-1 ring-white/[0.06] transition-all duration-200 hover:ring-white/[0.10] hover:-translate-y-px">
            <div className="absolute inset-y-0 left-0 w-[3px] rounded-r-[2px] bg-rose-500/70" />
            <div className="flex items-start justify-between gap-2">
              <div>
                <p className={eyebrow}>Critical</p>
                <p className="mt-3 text-[2.5rem] font-black leading-none tracking-[-0.04em] text-white">{criticalCount}</p>
              </div>
              <AlertTriangle className="mt-0.5 h-4 w-4 text-rose-500/50 shrink-0" />
            </div>
            <p className="mt-3 text-xs leading-5 text-zinc-500">Highest-priority findings.</p>
          </div>

          {/* Warning */}
          <div className="group relative overflow-hidden rounded-3xl bg-white/[0.04] px-5 py-6 ring-1 ring-white/[0.06] transition-all duration-200 hover:ring-white/[0.10] hover:-translate-y-px">
            <div className="absolute inset-y-0 left-0 w-[3px] rounded-r-[2px] bg-amber-400/70" />
            <div className="flex items-start justify-between gap-2">
              <div>
                <p className={eyebrow}>Warning</p>
                <p className="mt-3 text-[2.5rem] font-black leading-none tracking-[-0.04em] text-white">{warningCount}</p>
              </div>
              <ShieldAlert className="mt-0.5 h-4 w-4 text-amber-400/50 shrink-0" />
            </div>
            <p className="mt-3 text-xs leading-5 text-zinc-500">Weaknesses behind the grade.</p>
          </div>

          {/* Strengths */}
          <div className="group relative overflow-hidden rounded-3xl bg-white/[0.04] px-5 py-6 ring-1 ring-white/[0.06] transition-all duration-200 hover:ring-white/[0.10] hover:-translate-y-px">
            <div className="absolute inset-y-0 left-0 w-[3px] rounded-r-[2px] bg-emerald-500/70" />
            <div className="flex items-start justify-between gap-2">
              <div>
                <p className={eyebrow}>Strengths</p>
                <p className="mt-3 text-[2.5rem] font-black leading-none tracking-[-0.04em] text-white">{analysisData.strengths.length}</p>
              </div>
              <ShieldCheck className="mt-0.5 h-4 w-4 text-emerald-500/50 shrink-0" />
            </div>
            <p className="mt-3 text-xs leading-5 text-zinc-500">Signals reducing concern.</p>
          </div>

          {/* Monitoring */}
          <div className="group relative overflow-hidden rounded-3xl bg-white/[0.04] px-5 py-6 ring-1 ring-white/[0.06] transition-all duration-200 hover:ring-white/[0.10] hover:-translate-y-px">
            <div className="absolute inset-y-0 left-0 w-[3px] rounded-r-[2px] bg-zinc-600/60" />
            <div className="flex items-start justify-between gap-2">
              <div>
                <p className={eyebrow}>Alerts</p>
                <p className="mt-3 text-[2.5rem] font-black leading-none tracking-[-0.04em] text-white">{monitoringAlerts.length}</p>
              </div>
              <TrendingUp className="mt-0.5 h-4 w-4 text-zinc-600 shrink-0" />
            </div>
            <p className="mt-3 text-xs leading-5 text-zinc-500">
              {monitoringAlerts.length ? monitoringAlerts[0]?.title : "No alerting changes."}
            </p>
          </div>
        </div>

        {/* ── BOTTOM ROW 1: Category scores + Priority actions ── */}
        <div className="mt-6 grid grid-cols-1 gap-5 xl:grid-cols-[1.08fr_0.92fr]">
          {isLimitedAssessment ? (
            <div className={subCard}>
              <div className="flex items-center justify-between gap-3 mb-5">
                <div>
                  <p className={eyebrow}>Assessment constraints</p>
                  <p className={cardTitle}>Limited read</p>
                </div>
                <span className="text-[10px] font-bold uppercase tracking-[0.22em] text-zinc-500">Directional only</span>
              </div>
              <div className="grid gap-3 md:grid-cols-2">
                <div className="rounded-[1.25rem] border border-white/[0.08] bg-zinc-950/50 px-4 py-4">
                  <p className={eyebrow + " mb-2"}>Why constrained</p>
                  <p className="text-base font-semibold leading-7 text-white">{analysisData.assessmentLimitation.title}</p>
                  <p className="mt-1.5 text-sm leading-relaxed text-zinc-300">{analysisData.assessmentLimitation.detail}</p>
                </div>
                <div className="rounded-[1.25rem] border border-white/[0.08] bg-zinc-950/50 px-4 py-4">
                  <p className={eyebrow + " mb-2"}>How to read this</p>
                  <p className="mt-1.5 text-sm leading-relaxed text-zinc-300">
                    Use this result as a transport and access-control signal, not as a full posture verdict.
                  </p>
                </div>
              </div>
            </div>
          ) : (
            <div className={subCard}>
              <p className={eyebrow}>Category signals</p>
              <p className={cardTitle}>Where risk is concentrated</p>
              <div className="mt-5 space-y-3.5">
                {sortedAreaScores.map((area) => {
                  const barColor =
                    area.status === "strong" ? "#22c55e"
                    : area.status === "watch"  ? "#f59e0b"
                    : "#ef4444";
                  const scoreColor =
                    area.status === "strong" ? "#4ade80"
                    : area.status === "watch"  ? "#fbbf24"
                    : "#f87171";
                  return (
                    <div key={area.key} className="grid gap-2 md:grid-cols-[10rem_1fr_3.5rem] md:items-center">
                      <p className="text-sm font-medium text-zinc-300">{area.label}</p>
                      <div className="relative h-1.5 overflow-hidden rounded-full bg-white/[0.05]">
                        <div
                          className="absolute inset-y-0 left-0 rounded-full transition-all duration-700"
                          style={{ width: `${area.score}%`, background: barColor }}
                        />
                      </div>
                      <p className="text-right text-sm font-bold tabular-nums" style={{ color: scoreColor }}>
                        {area.score}
                      </p>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          <div className={subCard}>
            <div className="flex items-center justify-between gap-3 mb-5">
              <div>
                <p className={eyebrow}>What to do next</p>
                <p className={cardTitle}>Priority actions</p>
              </div>
              <ShieldAlert className="h-4 w-4 text-[#d89a63] shrink-0" />
            </div>
            {priorityActions.length ? (
              <div className="space-y-3">
                {priorityActions.map((action, index) => {
                  const accentColor =
                    action.severity === "critical" ? "#f87171"
                    : action.severity === "warning"  ? "#fbbf24"
                    : "#71717a";
                  return (
                    <div
                      key={`${action.area}-${action.title}`}
                      className="flex gap-3.5 rounded-[1.25rem] border border-white/[0.08] bg-zinc-950/50 px-4 py-4"
                    >
                      <span
                        className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-[10px] font-black"
                        style={{ background: accentColor, color: "#09090b" }}
                      >
                        {index + 1}
                      </span>
                      <div className="min-w-0">
                        <p className="text-sm font-semibold text-white">{action.title}</p>
                        <p className="mt-1 text-xs leading-5 text-zinc-500">{action.detail}</p>
                        <div
                          className="mt-2 flex items-center gap-1 text-[10px] font-bold uppercase tracking-[0.18em]"
                          style={{ color: accentColor }}
                        >
                          <ArrowRight className="h-3 w-3" />
                          {action.area}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="rounded-[1.25rem] border border-white/[0.08] bg-zinc-950/50 px-4 py-4 text-sm leading-relaxed text-zinc-500">
                No immediate remediation being prioritized from current public evidence.
              </div>
            )}
          </div>
        </div>

        {/* ── BOTTOM ROW 2: Scan facts + Export ── */}
        <div className="mt-5 grid gap-5 lg:grid-cols-[0.95fr_1.05fr]">
          <div className={subCard}>
            <p className={eyebrow}>Scan facts</p>
            <p className={cardTitle}>Capture details</p>
            <div className="mt-5 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
              <div className="rounded-[1.25rem] border border-white/[0.08] bg-zinc-950/50 px-4 py-4">
                <p className={eyebrow + " mb-2"}>Scanned</p>
                <p className="text-sm font-semibold leading-6 text-white">{new Date(analysisData.scannedAt).toLocaleString()}</p>
              </div>
              <div className="rounded-[1.25rem] border border-white/[0.08] bg-zinc-950/50 px-4 py-4">
                <p className={eyebrow + " mb-2"}>HTTP</p>
                <p className="text-2xl font-black tracking-[-0.03em] text-white">{analysisData.statusCode}</p>
                <p className="mt-0.5 text-[10px] uppercase tracking-[0.16em] text-zinc-500">{getHttpStatusDetails(analysisData.statusCode).label}</p>
              </div>
              <div className="rounded-[1.25rem] border border-white/[0.08] bg-zinc-950/50 px-4 py-4">
                <p className={eyebrow + " mb-2"}>Latency</p>
                <p className="text-2xl font-black tracking-[-0.03em] text-white">{analysisData.responseTimeMs}<span className="ml-0.5 text-sm font-medium text-zinc-500">ms</span></p>
              </div>
            </div>
          </div>

          <div className={subCard}>
            <div className="flex items-center justify-between gap-3 mb-1">
              <div>
                <p className={eyebrow}>Report outputs</p>
                <p className={cardTitle}>Share or hand off</p>
              </div>
              <Download className="h-4 w-4 text-[#d89a63] shrink-0" />
            </div>
            <p className="mt-2 mb-5 text-sm leading-relaxed text-zinc-500">
              Export as PDF for executives, Markdown for engineering, or raw JSON for integrations.
            </p>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
              <Button
                variant="outline"
                className="h-11 w-full justify-center rounded-xl border-zinc-800 bg-white/[0.03] font-semibold text-zinc-200 hover:bg-white/[0.07] hover:border-zinc-700 transition-all duration-150"
                onClick={exportPdf}
              >
                PDF
              </Button>
              <Button
                variant="outline"
                className="h-11 w-full justify-center rounded-xl border-zinc-800 bg-white/[0.03] font-semibold text-zinc-200 hover:bg-white/[0.07] hover:border-zinc-700 transition-all duration-150"
                onClick={exportMarkdown}
              >
                Markdown
              </Button>
              <Button
                variant="outline"
                className="h-11 w-full justify-center rounded-xl border-zinc-800 bg-white/[0.03] font-semibold text-zinc-200 hover:bg-white/[0.07] hover:border-zinc-700 transition-all duration-150"
                onClick={exportReport}
              >
                JSON
              </Button>
            </div>
          </div>
        </div>
      </div>

      {/* ── Sub-panels (non-compact only) ── */}
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
