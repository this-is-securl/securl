import { BarChart3 } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { StatBox } from "@/components/ui/panel-primitives";
import { AnalysisResult } from "@/types/analysis";
import { getAreaScores, getUnifiedIssueSummary } from "@/lib/posture";

interface PostureSummaryPanelProps {
  analysis: AnalysisResult;
}

export const PostureSummaryPanel = ({ analysis }: PostureSummaryPanelProps) => {
  const severityCounts = getUnifiedIssueSummary(analysis);
  const areaScores = getAreaScores(analysis);
  const rankedAreaScores = [...areaScores].sort((left, right) => left.score - right.score);

  return (
    <Card className="rounded-[2rem] border border-white/[0.09] bg-white/[0.04] shadow-[0_40px_96px_-24px_rgba(0,0,0,0.75),0_1px_0_rgba(255,255,255,0.07)_inset]">
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-xl font-black tracking-[-0.03em] text-white">
          <BarChart3 className="h-5 w-5 text-[#d89a63]" />
          Posture Summary
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-4">
          <StatBox variant="critical" label="Critical" value={<p className="text-[2.25rem] font-black leading-none tracking-[-0.04em]">{severityCounts.critical}</p>} />
          <StatBox
            variant="warning"
            label="Priority Warnings"
            value={<p className="text-[2.25rem] font-black leading-none tracking-[-0.04em]">{severityCounts.priorityWarnings}</p>}
            note={<p className="text-xs text-zinc-400">Actionable normalized findings only.</p>}
          />
          <StatBox
            variant="info"
            label="Supporting Watch Items"
            value={<p className="text-[2.25rem] font-black leading-none tracking-[-0.04em]">{severityCounts.supportingWatchItems}</p>}
            note={<p className="text-xs text-zinc-400">Panel-level evidence; not added to warnings.</p>}
          />
          <StatBox
            variant="info"
            label="Observed Signals"
            value={<p className="text-[2.25rem] font-black leading-none tracking-[-0.04em]">{severityCounts.observedSignals}</p>}
            note={<p className="text-xs text-zinc-400">Informational findings plus interesting probes.</p>}
          />
        </div>

        <div className="rounded-[1.5rem] border border-white/[0.08] bg-zinc-950/50 p-6">
          <p className="text-[10px] font-bold uppercase tracking-[0.24em] text-zinc-500 mb-4">Category scores</p>
          <div className="space-y-1">
            {rankedAreaScores.map((area, index) => {
              const barColor =
                area.status === "strong" ? "#22c55e"
                : area.status === "watch"  ? "#f59e0b"
                : "#ef4444";
              const scoreColor =
                area.status === "strong" ? "#4ade80"
                : area.status === "watch"  ? "#fbbf24"
                : "#f87171";
              return (
                <div
                  key={area.key}
                  className={`py-3 ${index < rankedAreaScores.length - 1 ? "border-b border-white/[0.05]" : ""}`}
                >
                  <div className="grid gap-2 md:grid-cols-[10rem_1fr_2.5rem] md:items-center">
                    <p className="text-sm font-medium text-zinc-300">{area.label}</p>
                    <div className="relative h-1.5 overflow-hidden rounded-full bg-white/[0.05]">
                      <div
                        className="absolute inset-y-0 left-0 rounded-full transition-all duration-700"
                        style={{ width: `${area.score}%`, background: barColor }}
                      />
                    </div>
                    <p className="text-right text-sm font-black tabular-nums" style={{ color: scoreColor }}>
                      {area.score}
                    </p>
                  </div>
                  {index === 0 && (
                    <p className="mt-1 text-[10px] text-zinc-600 md:ml-[10.5rem]">Weakest area</p>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        <div className="grid gap-4 md:grid-cols-3">
          <StatBox
            label="Header gaps"
            value={<p className="text-3xl font-black tracking-[-0.03em]">{analysis.headers.filter((header) => header.status !== "present").length}</p>}
          />
          <StatBox
            label="Cookie watch items"
            value={<p className="text-3xl font-black tracking-[-0.03em]">{analysis.cookies.reduce((count, cookie) => count + cookie.issues.length, 0)}</p>}
          />
          <StatBox
            label="Crawled same-origin pages"
            value={<p className="text-3xl font-black tracking-[-0.03em]">{analysis.crawl.pages.filter((page) => page.sameOrigin).length}</p>}
          />
        </div>
      </CardContent>
    </Card>
  );
};
