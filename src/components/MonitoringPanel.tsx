import { BellRing, Minus, TrendingDown, TrendingUp } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState, StatusAlert } from "@/components/ui/panel-primitives";
import { AnalysisResult, HistoryDiff, HistorySnapshot } from "@/types/analysis";
import { getMonitoringAlerts } from "@/lib/priorities";
import { getAreaScores } from "@/lib/posture";

interface MonitoringPanelProps {
  analysis: AnalysisResult;
  diff: HistoryDiff | null;
  history: Array<HistorySnapshot & {
    areaScores?: Array<{
      key: string;
      label: string;
      score: number;
      status: "strong" | "watch" | "weak";
    }>;
  }>;
}

const variantMap = {
  warning: "warning",
  info: "info",
} as const;

const formatSignedDelta = (value: number | null) => {
  if (value === null) {
    return "0";
  }

  return `${value > 0 ? "+" : ""}${value}`;
};

const formatSparklineAxis = (scoreSeries: number[]) =>
  scoreSeries.map((score, index) => ({
    id: `${index}-${score}`,
    score,
    label: index === scoreSeries.length - 1 ? "Now" : `${index + 1}`,
  }));

const getChangeLead = (diff: HistoryDiff | null) => {
  if (!diff) {
    return {
      eyebrow: "No comparison yet",
      title: "Saved monitoring starts after the next scan.",
      detail: "Once this target has at least two local snapshots, SecURL will call out regressions, improvements, and neutral churn here.",
      tone: "neutral" as const,
    };
  }

  const statusCodeDelta = diff.statusCodeDelta;
  const hasRegression =
    (diff.scoreDelta ?? 0) < 0 ||
    diff.newIssues.length > 0 ||
    (statusCodeDelta?.from !== null &&
      statusCodeDelta?.to !== null &&
      statusCodeDelta?.from !== statusCodeDelta?.to &&
      (statusCodeDelta?.to ?? 0) >= 400);
  const hasImprovement = (diff.scoreDelta ?? 0) > 0 || diff.resolvedIssues.length > 0;
  const hasSurfaceChange =
    diff.headerChanges.length > 0 ||
    diff.newThirdPartyProviders.length > 0 ||
    diff.wafProviderChanges.newProviders.length > 0 ||
    diff.identityProviderChange !== null;

  if (hasRegression) {
    return {
      eyebrow: "Regression detected",
      title: "This target looks weaker than the previous saved snapshot.",
      detail:
        diff.newIssues.length > 0
          ? `${diff.newIssues.length} new finding${diff.newIssues.length === 1 ? "" : "s"} appeared, so this read deserves a fresh look first.`
          : `The score moved ${formatSignedDelta(diff.scoreDelta)} since the last saved scan.`,
      tone: "warning" as const,
    };
  }

  if (hasImprovement) {
    return {
      eyebrow: "Improvement observed",
      title: "The latest read looks healthier than the previous saved snapshot.",
      detail:
        diff.resolvedIssues.length > 0
          ? `${diff.resolvedIssues.length} finding${diff.resolvedIssues.length === 1 ? "" : "s"} no longer appear in this scan.`
          : `The score moved ${formatSignedDelta(diff.scoreDelta)} since the last saved scan.`,
      tone: "info" as const,
    };
  }

  if (hasSurfaceChange) {
    return {
      eyebrow: "Surface shifted",
      title: "The overall posture is steady, but the visible surface has moved.",
      detail: "Headers, providers, or identity signals changed without creating a clear score swing.",
      tone: "info" as const,
    };
  }

  return {
    eyebrow: "Little changed",
    title: "The latest saved snapshot is broadly in line with the last one.",
    detail: "No meaningful regressions or improvements stood out in this comparison window.",
    tone: "neutral" as const,
  };
};

export const MonitoringPanel = ({ analysis, diff, history }: MonitoringPanelProps) => {
  const alerts = getMonitoringAlerts(analysis, diff);
  const scoreSeries = history
    .slice(0, 7)
    .reverse()
    .map((snapshot) => snapshot.score);
  const latestScore = scoreSeries.at(-1) ?? analysis.score;
  const firstScore = scoreSeries[0] ?? analysis.score;
  const trendDelta = latestScore - firstScore;
  const trendDirection = trendDelta > 1 ? "up" : trendDelta < -1 ? "down" : "flat";
  const changeLead = getChangeLead(diff);

  const currentAreaScores = getAreaScores(analysis);
  const previousAreaScores = history[1]?.areaScores ?? null;
  const areaDeltas = previousAreaScores
    ? currentAreaScores
        .map((area) => {
          const previousArea = previousAreaScores.find((item) => item.key === area.key);
          const delta = previousArea ? area.score - previousArea.score : 0;
          return { label: area.label, delta };
        })
        .filter((item) => item.delta !== 0)
        .sort((left, right) => Math.abs(right.delta) - Math.abs(left.delta))
        .slice(0, 4)
    : [];

  const sparklinePoints = (() => {
    if (scoreSeries.length < 2) {
      return "";
    }
    const width = 180;
    const height = 44;
    const max = Math.max(...scoreSeries);
    const min = Math.min(...scoreSeries);
    const range = Math.max(max - min, 1);
    return scoreSeries
      .map((score, index) => {
        const x = (index / (scoreSeries.length - 1)) * width;
        const y = height - ((score - min) / range) * height;
        return `${x.toFixed(2)},${y.toFixed(2)}`;
      })
      .join(" ");
  })();
  const sparklineAxis = formatSparklineAxis(scoreSeries);

  if (!alerts.length && scoreSeries.length === 0) {
    return (
      <Card className="rounded-[1.75rem] border-white/10 bg-white/[0.04] shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2">
            <BellRing className="h-5 w-5 text-[#d89a63]" />
            Monitoring
          </CardTitle>
        </CardHeader>
      <CardContent>
        <EmptyState>
            No saved history or monitoring alerts are available for this target yet, so change-over-time tracking has not started.
        </EmptyState>
      </CardContent>
    </Card>
  );
  }

  return (
    <Card className="rounded-[1.75rem] border-white/10 bg-white/[0.04] shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2">
          <BellRing className="h-5 w-5 text-[#d89a63]" />
          Monitoring
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="rounded-[1.35rem] border border-white/10 bg-[linear-gradient(180deg,rgba(255,255,255,0.03),rgba(15,23,42,0.35))] p-4 shadow-[0_18px_40px_-28px_rgba(0,0,0,0.7)]">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="max-w-2xl">
              <p
                className={`text-[11px] font-bold uppercase tracking-[0.2em] ${
                  changeLead.tone === "warning"
                    ? "text-[#d89a63]"
                    : changeLead.tone === "info"
                      ? "text-[#cdd7e6]"
                      : "text-slate-400"
                }`}
              >
                {changeLead.eyebrow}
              </p>
              <p className="mt-2 text-lg font-semibold text-slate-50">{changeLead.title}</p>
              <p className="mt-2 text-sm leading-6 text-slate-300">{changeLead.detail}</p>
            </div>
            {diff ? (
              <p className="text-xs uppercase tracking-[0.16em] text-slate-500">Since last scan</p>
            ) : null}
          </div>

          {diff ? (
            <>
              <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                <div className="rounded-[1.15rem] border border-white/10 bg-slate-950/45 px-4 py-4">
                <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-500">Score</p>
                <p className="mt-3 text-3xl font-semibold text-white">
                  {formatSignedDelta(diff.scoreDelta)}
                </p>
                <p className="mt-2 text-xs text-slate-400">
                  {diff.previousScore !== null ? `From ${diff.previousScore}` : "No prior score"}
                </p>
                </div>
                <div className="rounded-[1.15rem] border border-white/10 bg-slate-950/45 px-4 py-4">
                <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-500">New findings</p>
                <p className="mt-3 text-3xl font-semibold text-white">{diff.newIssues.length}</p>
                <p className="mt-2 line-clamp-2 text-xs leading-5 text-slate-400">
                  {diff.newIssues[0] ?? "No new findings"}
                </p>
                </div>
                <div className="rounded-[1.15rem] border border-white/10 bg-slate-950/45 px-4 py-4">
                <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-500">Resolved</p>
                <p className="mt-3 text-3xl font-semibold text-white">{diff.resolvedIssues.length}</p>
                <p className="mt-2 line-clamp-2 text-xs leading-5 text-slate-400">
                  {diff.resolvedIssues[0] ?? "No resolved findings"}
                </p>
                </div>
                <div className="rounded-[1.15rem] border border-white/10 bg-slate-950/45 px-4 py-4">
                <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-500">Header changes</p>
                <p className="mt-3 text-3xl font-semibold text-white">{diff.headerChanges.length}</p>
                <p className="mt-2 line-clamp-2 text-xs leading-5 text-slate-400">
                  {diff.headerChanges[0]?.label ?? "No header movement"}
                </p>
                </div>
              </div>
              {areaDeltas.length ? (
                <div className="mt-4 rounded-[1.15rem] border border-white/10 bg-slate-950/35 px-4 py-3">
                  <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-500">Most moved areas</p>
                  <div className="mt-3 grid gap-2 md:grid-cols-2">
                    {areaDeltas.map((item) => (
                      <div key={item.label} className="text-sm text-slate-300">
                        <span className="font-medium text-white">{item.label}</span>: {formatSignedDelta(item.delta)}
                      </div>
                    ))}
                  </div>
                </div>
              ) : null}
            </>
          ) : null}
        </div>

        <div className="rounded-[1.35rem] border border-white/10 bg-[linear-gradient(180deg,rgba(255,255,255,0.03),rgba(15,23,42,0.35))] p-4 shadow-[0_18px_40px_-28px_rgba(0,0,0,0.7)]">
          <div className="flex items-center justify-between gap-3">
            <div>
              <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-400">Score trend</p>
              <p className="mt-2 text-sm text-slate-300">
                {scoreSeries.length >= 2
                  ? "Short-window movement across recent saved scans."
                  : scoreSeries.length === 1
                    ? "One saved scan recorded. Trend appears after the next scan."
                    : "Trend appears after at least two saved scans for this target."}
              </p>
            </div>
            {scoreSeries.length >= 2 ? (
              <div className="flex items-center gap-1 text-sm font-semibold text-slate-200">
                {trendDirection === "up" ? <TrendingUp className="h-4 w-4 text-[#d89a63]" /> : null}
                {trendDirection === "down" ? <TrendingDown className="h-4 w-4 text-[#c78455]" /> : null}
                {trendDirection === "flat" ? <Minus className="h-4 w-4 text-slate-400" /> : null}
                <span>
                  {trendDirection === "up" ? "Improving" : trendDirection === "down" ? "Degrading" : "Stable"}
                </span>
              </div>
            ) : null}
          </div>

          {scoreSeries.length >= 2 ? (
            <div className="mt-4 rounded-[1.15rem] border border-white/10 bg-slate-950/35 px-4 py-4">
              <div className="flex items-center justify-between gap-4">
                <svg
                  viewBox="0 0 180 44"
                  className="h-11 w-full max-w-[220px]"
                  role="img"
                  aria-label="Security score trend sparkline"
                >
                  <polyline
                    fill="none"
                    stroke={trendDirection === "down" ? "#c78455" : trendDirection === "up" ? "#d89a63" : "#64748b"}
                    strokeWidth="2.5"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    points={sparklinePoints}
                  />
                </svg>
                <div className="rounded-full border border-white/10 bg-white/[0.04] px-3 py-2 text-sm font-semibold text-slate-200">
                  {trendDelta > 0 ? "+" : ""}
                  {trendDelta} over window
                </div>
              </div>
              <div className="mt-4 grid grid-cols-4 gap-2 sm:grid-cols-7">
                {sparklineAxis.map((point, index) => (
                  <div key={point.id} className="rounded-xl border border-white/10 bg-white/[0.03] px-2 py-2 text-center">
                    <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">
                      {index === 0 ? "Start" : point.label}
                    </p>
                    <p className="mt-1 text-sm font-semibold text-slate-100">{point.score}</p>
                  </div>
                ))}
              </div>
            </div>
          ) : null}
        </div>

        {alerts.length ? (
          <div className="overflow-hidden rounded-[1.35rem] border border-white/10 bg-white/[0.03] shadow-[0_18px_40px_-28px_rgba(0,0,0,0.7)]">
            {alerts.map((alert, index) => (
              <div
                key={`${alert.title}-${alert.detail}`}
                className={`px-4 py-4 ${index < alerts.length - 1 ? "border-b border-white/10" : ""}`}
              >
                <StatusAlert variant={variantMap[alert.severity]} className="py-0">
                  <div className="font-semibold">{alert.title}</div>
                  <p className="mt-2 text-sm leading-6 opacity-90">{alert.detail}</p>
                </StatusAlert>
              </div>
            ))}
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
};
