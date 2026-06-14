import { BarChart3 } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { StatBox } from "@/components/ui/panel-primitives";
import { AnalysisResult } from "@/types/analysis";
import { getAreaScores, getUnifiedIssueSummary } from "@/lib/posture";

const SOURCE_LABELS: Record<string, string> = {
  headers: "Headers",
  tls: "TLS",
  cookies: "Cookies",
  dns: "DNS",
  html: "HTML",
  public_record: "Public record",
  third_party: "Third-party",
  ai: "AI surface",
  availability: "Availability",
  breadth: "Coverage",
  assessment_limit: "Assessment limit",
};

interface PostureSummaryPanelProps {
  analysis: AnalysisResult;
}

export const PostureSummaryPanel = ({ analysis }: PostureSummaryPanelProps) => {
  const severityCounts = getUnifiedIssueSummary(analysis);
  const areaScores = getAreaScores(analysis);
  const rankedAreaScores = [...areaScores].sort((left, right) => left.score - right.score);
  const evidenceSummary = analysis.evidenceSummary;
  const topEvidence = evidenceSummary?.topEvidence?.slice(0, 4) ?? [];

  return (
    <Card className="rounded-4xl border border-white/9 bg-white/4 shadow-[0_40px_96px_-24px_rgba(0,0,0,0.75),0_1px_0_rgba(255,255,255,0.07)_inset]">
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

        <div className="rounded-3xl border border-white/8 bg-zinc-950/50 p-6">
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
                  className={`py-3 ${index < rankedAreaScores.length - 1 ? "border-b border-white/5" : ""}`}
                >
                  <div className="grid gap-2 md:grid-cols-[10rem_1fr_2.5rem] md:items-center">
                    <p className="text-sm font-medium text-zinc-300">{area.label}</p>
                    <div className="relative h-1.5 overflow-hidden rounded-full bg-white/5">
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
                    <p className="mt-1 text-[10px] text-zinc-600 md:ml-42">Weakest area</p>
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

        {analysis.scoreDrivers && analysis.scoreDrivers.length > 0 && (
          <div className="rounded-3xl border border-white/8 bg-zinc-950/50 p-6">
            <p className="text-[10px] font-bold uppercase tracking-[0.24em] text-zinc-500 mb-4">Score drivers</p>
            <div className="space-y-0">
              {analysis.scoreDrivers.map((driver, index) => {
                const isPositive = driver.impact >= 0;
                const impactColor = isPositive ? "#4ade80" : "#f87171";
                const impactPrefix = isPositive ? "+" : "";
                const isLast = index === analysis.scoreDrivers!.length - 1;
                return (
                  <div
                    key={index}
                    className={`py-3 ${!isLast ? "border-b border-white/5" : ""}`}
                  >
                    <div className="flex items-start justify-between gap-4">
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2 mb-0.5">
                          <span className="text-[9px] font-bold uppercase tracking-[0.2em] text-zinc-600">{driver.areaLabel}</span>
                          <span className="text-[9px] text-zinc-700">·</span>
                          <span className="text-[9px] font-medium uppercase tracking-[0.15em] text-zinc-700">{SOURCE_LABELS[driver.source] ?? driver.source}</span>
                        </div>
                        <p className="text-sm font-medium text-zinc-300 leading-snug">{driver.label}</p>
                        <p className="text-xs text-zinc-500 mt-0.5 leading-relaxed">{driver.detail}</p>
                      </div>
                      <p className="text-sm font-black tabular-nums shrink-0 mt-3" style={{ color: impactColor }}>
                        {impactPrefix}{driver.impact}
                      </p>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {evidenceSummary && (
          <div className="rounded-3xl border border-white/8 bg-zinc-950/50 p-6">
            <div className="mb-4 flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
              <div>
                <p className="text-[10px] font-bold uppercase tracking-[0.24em] text-zinc-500">Evidence summary</p>
                <p className="mt-2 max-w-3xl text-sm leading-relaxed text-zinc-300">{evidenceSummary.summary}</p>
              </div>
              <div className="grid grid-cols-3 gap-2 text-center md:min-w-72">
                <div className="rounded-2xl border border-white/8 bg-white/4 px-3 py-2">
                  <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-zinc-500">Total</p>
                  <p className="mt-1 text-xl font-black text-zinc-50">{evidenceSummary.totalEvidenceReferences}</p>
                </div>
                <div className="rounded-2xl border border-white/8 bg-white/4 px-3 py-2">
                  <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-zinc-500">Observed</p>
                  <p className="mt-1 text-xl font-black text-emerald-300">{evidenceSummary.observedCount}</p>
                </div>
                <div className="rounded-2xl border border-white/8 bg-white/4 px-3 py-2">
                  <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-zinc-500">Derived</p>
                  <p className="mt-1 text-xl font-black text-amber-200">{evidenceSummary.derivedCount}</p>
                </div>
              </div>
            </div>

            {topEvidence.length > 0 && (
              <div className="space-y-0">
                {topEvidence.map((item, index) => (
                  <div
                    key={`${item.kind}-${item.label}-${index}`}
                    className={`py-3 ${index < topEvidence.length - 1 ? "border-b border-white/5" : ""}`}
                  >
                    <div className="flex flex-col gap-2 md:flex-row md:items-start md:justify-between">
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-[9px] font-bold uppercase tracking-[0.2em] text-zinc-600">{item.kind.replace(/_/g, " ")}</span>
                          {item.areaLabel && (
                            <span className="text-[9px] font-medium uppercase tracking-[0.15em] text-zinc-700">{item.areaLabel}</span>
                          )}
                          {item.source && (
                            <span className="text-[9px] font-medium uppercase tracking-[0.15em] text-zinc-700">
                              {SOURCE_LABELS[String(item.source)] ?? String(item.source)}
                            </span>
                          )}
                        </div>
                        <p className="mt-1 text-sm font-medium text-zinc-200">{item.label}</p>
                        {item.observed && (
                          <p className="mt-0.5 wrap-break-word text-xs leading-relaxed text-zinc-500">{item.observed}</p>
                        )}
                        {item.relatedFinding && (
                          <p className="mt-1 text-[11px] text-zinc-600">{item.relatedFinding}</p>
                        )}
                      </div>
                      {typeof item.scoreImpact === "number" && (
                        <p className="shrink-0 text-sm font-black tabular-nums text-emerald-300 md:mt-3">+{item.scoreImpact}</p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
};
