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
    <Card className="rounded-[1.75rem] border border-zinc-800/60 bg-[#0d1420] shadow-[0_32px_64px_-24px_rgba(0,0,0,0.6),0_1px_0_rgba(255,255,255,0.04)_inset]">
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-xl font-bold tracking-[-0.03em] text-white">
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
            note={<p className="text-xs text-slate-400">Actionable normalized findings only.</p>}
          />
          <StatBox
            variant="info"
            label="Supporting Watch Items"
            value={<p className="text-[2.25rem] font-black leading-none tracking-[-0.04em]">{severityCounts.supportingWatchItems}</p>}
            note={<p className="text-xs text-slate-400">Panel-level evidence; not added to warnings.</p>}
          />
          <StatBox
            variant="info"
            label="Observed Signals"
            value={<p className="text-[2.25rem] font-black leading-none tracking-[-0.04em]">{severityCounts.observedSignals}</p>}
            note={<p className="text-xs text-slate-400">Informational findings plus interesting probes.</p>}
          />
        </div>

        <div className="rounded-[1.5rem] border border-white/[0.08] bg-slate-950/60 p-4 shadow-[0_8px_24px_-12px_rgba(0,0,0,0.5)]">
          <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-500">Category scores</p>
          <div className="mt-3 grid gap-3">
            {rankedAreaScores.map((area, index) => (
              <div
                key={area.key}
                className="rounded-[1.1rem] border border-white/10 bg-slate-950/50 px-3 py-3 text-sm text-slate-200 shadow-[0_12px_28px_-20px_rgba(0,0,0,0.7)]"
              >
                <div className="flex items-center justify-between gap-3">
                  <span className="font-medium">{area.label}</span>
                  <span className="font-bold">{area.score}/100</span>
                </div>
                <div className="mt-2 h-[6px] rounded-full bg-white/[0.07]">
                  <div
                    className={`h-full rounded-full ${
                      area.status === "strong"
                        ? "bg-emerald-400/70"
                        : area.status === "watch"
                          ? "bg-amber-500/70"
                          : "bg-red-500/70"
                    }`}
                    style={{ width: `${area.score}%` }}
                  />
                </div>
                <p className="mt-2 text-xs leading-5 text-slate-400">
                  {index === 0 ? "Weakest area in this scan" : area.notes[0]}
                </p>
              </div>
            ))}
          </div>
        </div>

        <div className="grid gap-5 md:grid-cols-3">
          <StatBox
            label="Header gaps"
            value={<p className="text-2xl font-semibold">{analysis.headers.filter((header) => header.status !== "present").length}</p>}
          />
          <StatBox
            label="Cookie watch items"
            value={<p className="text-2xl font-semibold">{analysis.cookies.reduce((count, cookie) => count + cookie.issues.length, 0)}</p>}
          />
          <StatBox
            label="Crawled same-origin pages"
            value={<p className="text-2xl font-semibold">{analysis.crawl.pages.filter((page) => page.sameOrigin).length}</p>}
          />
        </div>
      </CardContent>
    </Card>
  );
};
