import { History, Minus, TrendingDown, TrendingUp } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/panel-primitives";
import { HistoryDiff, HistorySnapshot } from "@/types/analysis";

interface HistoryPanelProps {
  history: HistorySnapshot[];
  diff: HistoryDiff | null;
}

const formatSignedDelta = (value: number | null) => {
  if (value === null) {
    return "0";
  }

  return `${value > 0 ? "+" : ""}${value}`;
};

const compactList = (items: string[], empty: string) => {
  if (!items.length) {
    return empty;
  }

  if (items.length === 1) {
    return items[0];
  }

  return `${items[0]} (+${items.length - 1} more)`;
};

const getTrendState = (delta: number) => {
  if (delta >= 5) {
    return {
      label: "Improving",
      icon: TrendingUp,
      iconClassName: "text-[#22c55e]",
      stroke: "#22c55e",
      detail: "Scores have moved upward across saved scans.",
    };
  }

  if (delta <= -5) {
    return {
      label: "Degrading",
      icon: TrendingDown,
      iconClassName: "text-rose-400",
      stroke: "#f87171",
      detail: "Recent saved scans have trended weaker.",
    };
  }

  return {
    label: "Stable",
    icon: Minus,
    iconClassName: "text-zinc-400",
    stroke: "#94a3b8",
    detail: "Recent saved scans are broadly flat.",
  };
};

const getHistoryLead = (diff: HistoryDiff | null, trendDelta: number, trendCount: number) => {
  if (!diff) {
    return {
      eyebrow: "Saved snapshots",
      title:
        trendCount > 1
          ? "This target has a usable history trail even without a current side-by-side diff."
          : "The first saved snapshot is in place. The next scan will unlock a comparison read.",
      detail:
        trendCount > 1
          ? `The score trend is ${trendDelta > 0 ? "up" : trendDelta < 0 ? "down" : "flat"} across ${trendCount} saved scans.`
          : "Save another scan for this target to get regressions, improvements, and summary deltas here.",
    };
  }

  const scoreDelta = diff.scoreDelta ?? 0;

  if (scoreDelta < 0 || diff.newIssues.length > 0) {
    return {
      eyebrow: "History shows regression",
      title: "The latest snapshot looks weaker than the previous saved scan.",
      detail:
        diff.newIssues.length > 0
          ? compactList(diff.newIssues, "New findings appeared.")
          : `The score moved ${formatSignedDelta(diff.scoreDelta)} from the last saved baseline.`,
    };
  }

  if (scoreDelta > 0 || diff.resolvedIssues.length > 0) {
    return {
      eyebrow: "History shows improvement",
      title: "The latest snapshot looks healthier than the previous saved scan.",
      detail:
        diff.resolvedIssues.length > 0
          ? compactList(diff.resolvedIssues, "Resolved findings no longer appear.")
          : `The score moved ${formatSignedDelta(diff.scoreDelta)} from the last saved baseline.`,
    };
  }

  return {
    eyebrow: "History is steady",
    title: "The latest saved snapshot is broadly in line with the previous one.",
    detail: diff.summary[0] ?? "No meaningful regressions or improvements stood out in the latest comparison.",
  };
};

export const HistoryPanel = ({ history, diff }: HistoryPanelProps) => {
  if (!history.length) {
    return (
      <Card className="border-white/10 bg-white/[0.04] shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <History className="h-5 w-5 text-[#d89a63]" />
            Scan History
          </CardTitle>
        </CardHeader>
        <CardContent>
          <EmptyState>
            No prior saved scans are available for this target yet, so change-over-time comparison is not available.
          </EmptyState>
        </CardContent>
      </Card>
    );
  }

  const trendPoints = [...history].slice(0, 8).reverse();
  const trendScores = trendPoints.map((snapshot) => snapshot.score);
  const minScore = Math.min(...trendScores);
  const maxScore = Math.max(...trendScores);
  const range = Math.max(maxScore - minScore, 1);
  const latestTrendPoint = trendPoints.at(-1);
  const firstTrendPoint = trendPoints[0];
  const trendDelta =
    trendPoints.length > 1 && latestTrendPoint && firstTrendPoint ? latestTrendPoint.score - firstTrendPoint.score : 0;
  const trendState = getTrendState(trendDelta);
  const lead = getHistoryLead(diff, trendDelta, trendPoints.length);
  const TrendIcon = trendState.icon;

  const sparkline = trendPoints
    .map((snapshot, index) => {
      const x = trendPoints.length === 1 ? 0 : (index / (trendPoints.length - 1)) * 100;
      const y = 100 - ((snapshot.score - minScore) / range) * 100;
      return `${x},${y}`;
    })
    .join(" ");

  const supportingChanges = [
    {
      label: "New findings",
      value: diff?.newIssues.length ?? 0,
      detail: compactList(diff?.newIssues ?? [], "No new findings"),
    },
    {
      label: "Resolved",
      value: diff?.resolvedIssues.length ?? 0,
      detail: compactList(diff?.resolvedIssues ?? [], "No resolved findings"),
    },
    {
      label: "Header changes",
      value: diff?.headerChanges.length ?? 0,
      detail: diff?.headerChanges[0]?.label ?? "No header movement",
    },
  ];

  const movementSummary = [
    {
      label: "Third-party providers",
      detail: diff
        ? compactList(
            [
              ...diff.newThirdPartyProviders.map((provider) => `New: ${provider}`),
              ...diff.removedThirdPartyProviders.map((provider) => `Removed: ${provider}`),
            ],
            "No provider movement"
          )
        : "No side-by-side comparison yet",
    },
    {
      label: "Identity / WAF",
      detail: diff
        ? compactList(
            [
              ...(diff.identityProviderChange
                ? [`IdP: ${diff.identityProviderChange.from ?? "none"} -> ${diff.identityProviderChange.to ?? "none"}`]
                : []),
              ...diff.wafProviderChanges.newProviders.map((provider) => `New WAF: ${provider}`),
              ...diff.wafProviderChanges.removedProviders.map((provider) => `Removed WAF: ${provider}`),
            ],
            "No identity or WAF movement"
          )
        : "No side-by-side comparison yet",
    },
    {
      label: "CT / AI surface",
      detail: diff
        ? compactList(
            [
              ...diff.ctPriorityHostChanges.newHosts.map((host) => `New CT host: ${host}`),
              ...diff.newAiVendors.map((vendor) => `New AI vendor: ${vendor}`),
              ...diff.removedAiVendors.map((vendor) => `Removed AI vendor: ${vendor}`),
            ],
            "No CT or AI surface movement"
          )
        : "No side-by-side comparison yet",
    },
    {
      label: "Transport",
      detail: diff
        ? `HTTP ${diff.statusCodeDelta?.from ?? "unknown"} -> ${diff.statusCodeDelta?.to ?? "unknown"}; cert days ${diff.certificateDaysRemainingDelta?.from ?? "unknown"} -> ${diff.certificateDaysRemainingDelta?.to ?? "unknown"}`
        : "No side-by-side comparison yet",
    },
  ];
  const timelineBadges = trendPoints.map((snapshot, index) => ({
    id: `${snapshot.scannedAt}-${snapshot.score}`,
    label: index === trendPoints.length - 1 ? "Latest" : index === 0 ? "Start" : `${index + 1}`,
    score: snapshot.score,
    grade: snapshot.grade,
  }));

  return (
    <Card className="border-white/10 bg-white/[0.04] shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <History className="h-5 w-5 text-[#d89a63]" />
          Scan History
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="rounded-[1.35rem] border border-white/10 bg-[linear-gradient(180deg,rgba(255,255,255,0.03),rgba(15,23,42,0.35))] p-4 shadow-[0_18px_40px_-28px_rgba(0,0,0,0.7)]">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="max-w-2xl">
              <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-[#d89a63]">{lead.eyebrow}</p>
              <p className="mt-2 text-lg font-semibold text-zinc-50">{lead.title}</p>
              <p className="mt-2 text-sm leading-6 text-zinc-300">{lead.detail}</p>
            </div>
            <div className="rounded-[1.15rem] border border-white/10 bg-zinc-950/45 px-4 py-3">
              <div className="flex items-center gap-2 text-sm font-semibold text-zinc-100">
                <TrendIcon className={`h-4 w-4 ${trendState.iconClassName}`} />
                {trendState.label}
              </div>
              <p className="mt-2 text-xs leading-5 text-zinc-400">{trendState.detail}</p>
            </div>
          </div>

          <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <div className="rounded-[1.15rem] border border-white/10 bg-zinc-950/45 px-4 py-4">
              <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-500">Score change</p>
              <p className="mt-3 text-3xl font-semibold text-white">{diff ? formatSignedDelta(diff.scoreDelta) : "—"}</p>
              <p className="mt-2 text-xs text-zinc-400">
                {diff?.previousScore !== null && diff?.previousScore !== undefined
                  ? `From ${diff.previousGrade} / ${diff.previousScore}`
                  : `Across ${trendPoints.length} saved scan${trendPoints.length === 1 ? "" : "s"}`}
              </p>
            </div>

            {supportingChanges.map((item) => (
              <div key={item.label} className="rounded-[1.15rem] border border-white/10 bg-zinc-950/45 px-4 py-4">
                <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-500">{item.label}</p>
                <p className="mt-3 text-3xl font-semibold text-white">{diff ? item.value : "—"}</p>
                <p className="mt-2 line-clamp-2 text-xs leading-5 text-zinc-400">{item.detail}</p>
              </div>
            ))}
          </div>
        </div>

        <div className="rounded-[1.35rem] border border-white/10 bg-[linear-gradient(180deg,rgba(255,255,255,0.03),rgba(15,23,42,0.35))] p-4 shadow-[0_18px_40px_-28px_rgba(0,0,0,0.7)]">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-400">Trend window</p>
              <p className="mt-2 text-sm text-zinc-300">
                {trendPoints.length > 1
                  ? `${trendState.label} over ${trendPoints.length} saved scans.`
                  : "Only one saved scan is available so far."}
              </p>
            </div>
            {trendPoints.length > 1 ? (
              <div className="flex items-center gap-2 text-sm font-semibold text-zinc-200">
                <TrendIcon className={`h-4 w-4 ${trendState.iconClassName}`} />
                <span>{formatSignedDelta(trendDelta)}</span>
              </div>
            ) : null}
          </div>
          {trendPoints.length > 1 ? (
            <div className="mt-4 rounded-[1.15rem] border border-white/10 bg-zinc-950/35 px-4 py-4">
              <svg viewBox="0 0 100 40" className="h-12 w-full overflow-visible">
                <polyline
                  fill="none"
                  stroke={trendState.stroke}
                  strokeWidth="3.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  points={sparkline
                    .split(" ")
                    .map((point) => {
                      const [x, y] = point.split(",");
                      return `${x},${Number(y) * 0.4}`;
                    })
                    .join(" ")}
                />
              </svg>
              <div className="mt-4 grid grid-cols-4 gap-2 sm:grid-cols-8">
                {timelineBadges.map((point) => (
                  <div key={point.id} className="rounded-xl border border-white/10 bg-white/[0.03] px-2 py-2 text-center">
                    <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-zinc-500">{point.label}</p>
                    <p className="mt-1 text-sm font-semibold text-zinc-100">{point.score}</p>
                    <p className="text-[10px] uppercase tracking-[0.16em] text-zinc-400">{point.grade}</p>
                  </div>
                ))}
              </div>
            </div>
          ) : null}
        </div>

        {diff?.summary.length ? (
          <div className="rounded-[1.35rem] border border-white/10 bg-white/[0.03] p-4 shadow-[0_18px_40px_-28px_rgba(0,0,0,0.7)]">
            <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-400">Change summary</p>
            <div className="mt-3 space-y-2 text-sm text-zinc-300">
              {diff.summary.map((item) => (
                <p key={item}>{item}</p>
              ))}
            </div>
          </div>
        ) : null}

        <div className="grid gap-3 xl:grid-cols-2">
          {movementSummary.map((item) => (
            <div key={item.label} className="rounded-[1.15rem] border border-white/10 bg-zinc-950/35 px-4 py-4">
              <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-500">{item.label}</p>
              <p className="mt-3 text-sm leading-6 text-zinc-300">{item.detail}</p>
            </div>
          ))}
        </div>

        <div className="grid gap-3">
          {history.map((snapshot) => (
            <div key={`${snapshot.scannedAt}-${snapshot.finalUrl}`} className="rounded-[1.15rem] border border-white/10 bg-zinc-950/35 px-4 py-4">
              <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
                <div className="min-w-0">
                  <p className="truncate text-sm font-semibold text-zinc-50" title={snapshot.finalUrl}>
                    {snapshot.finalUrl}
                  </p>
                  <p className="text-xs text-zinc-400">{new Date(snapshot.scannedAt).toLocaleString()}</p>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant="secondary" className="bg-white/[0.1] text-zinc-100">
                    {snapshot.grade}
                  </Badge>
                  <span className="text-sm font-semibold text-zinc-200">{snapshot.score}/100</span>
                </div>
              </div>
              <div className="mt-3">
                <div className="h-2 overflow-hidden rounded-full bg-white/10">
                  <div
                    className="h-full rounded-full bg-gradient-to-r from-[#7f1d1d] via-amber-500/70 to-[#22c55e] transition-all duration-700"
                    style={{ width: `${Math.max(6, Math.min(snapshot.score, 100))}%` }}
                  />
                </div>
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};
