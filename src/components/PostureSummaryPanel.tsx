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
    <Card className="rounded-[1.75rem] border-white/10 bg-white/[0.04] shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2">
          <BarChart3 className="h-5 w-5 text-[#d89a63]" />
          Posture Summary
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <StatBox variant="warning" label="Critical" value={<p className="text-[2rem] font-bold leading-none tracking-[-0.04em]">{severityCounts.critical}</p>} />
          <StatBox
            variant="warning"
            label="Priority Warnings"
            value={<p className="text-[2rem] font-bold leading-none tracking-[-0.04em]">{severityCounts.priorityWarnings}</p>}
            note={<p className="text-xs text-slate-400">Actionable normalized findings only.</p>}
          />
          <StatBox
            variant="info"
            label="Supporting Watch Items"
            value={<p className="text-[2rem] font-bold leading-none tracking-[-0.04em]">{severityCounts.supportingWatchItems}</p>}
            note={<p className="text-xs text-slate-400">Panel-level evidence; not added to warnings.</p>}
          />
          <StatBox
            variant="info"
            label="Observed Signals"
            value={<p className="text-[2rem] font-bold leading-none tracking-[-0.04em]">{severityCounts.observedSignals}</p>}
            note={<p className="text-xs text-slate-400">Informational findings plus interesting probes.</p>}
          />
        </div>

        <div className="rounded-[1.5rem] border border-white/10 bg-white/[0.03] p-4 shadow-[0_18px_40px_-28px_rgba(0,0,0,0.7)]">
          <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-500">Category scores</p>
          <div className="mt-3 grid gap-2">
            {rankedAreaScores.map((area, index) => (
              <div
                key={area.key}
                className="rounded-[1.1rem] border border-white/10 bg-slate-950/50 px-3 py-3 text-sm text-slate-200 shadow-[0_12px_28px_-20px_rgba(0,0,0,0.7)]"
              >
                <div className="flex items-center justify-between gap-3">
                  <span className="font-medium">{area.label}</span>
                  <span className="font-semibold">{area.score}/100</span>
                </div>
                <div className="mt-2 h-[5px] rounded-full bg-white/[0.07]">
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

        <div className="grid gap-4 md:grid-cols-3">
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
