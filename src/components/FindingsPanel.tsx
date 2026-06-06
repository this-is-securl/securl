import { AlertTriangle, Info, ShieldCheck, ShieldX, Sparkles, TriangleAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/panel-primitives";
import { ScanIssue } from "@/types/analysis";

interface FindingsPanelProps {
  issues: ScanIssue[];
  strengths: string[];
}

const severityWeight = { critical: 0, warning: 1, info: 2 } as const;
const confidenceWeight = { high: 0, medium: 1, low: 2 } as const;

const issueAccent = {
  critical: {
    icon: <ShieldX className="h-4 w-4" />,
    chip: "bg-rose-500/8 text-rose-300 border-rose-500/30",
    iconWrap: "bg-rose-500/8 text-rose-400",
  },
  warning: {
    icon: <AlertTriangle className="h-4 w-4" />,
    chip: "bg-amber-500/8 text-amber-300 border-amber-500/30",
    iconWrap: "bg-amber-500/8 text-amber-400",
  },
  info: {
    icon: <Info className="h-4 w-4" />,
    chip: "bg-white/8 text-zinc-200 border-white/10",
    iconWrap: "bg-white/8 text-zinc-200",
  },
} as const;

const confidenceStyles = {
  high: "bg-white/12 text-zinc-100 border-white/10",
  medium: "bg-zinc-700/40 text-zinc-300 border-white/10",
  low: "bg-white/6 text-zinc-300 border-white/10",
} as const;

export const FindingsPanel = ({ issues, strengths }: FindingsPanelProps) => {
  const rankedIssues = [...issues].sort((left, right) => {
    return (
      severityWeight[left.severity] - severityWeight[right.severity] ||
      confidenceWeight[left.confidence] - confidenceWeight[right.confidence]
    );
  });
  const topIssues = rankedIssues.slice(0, 6);
  const severityCounts = {
    critical: rankedIssues.filter((issue) => issue.severity === "critical").length,
    warning: rankedIssues.filter((issue) => issue.severity === "warning").length,
    info: rankedIssues.filter((issue) => issue.severity === "info").length,
  };

  return (
    <Card className="rounded-4xl border border-white/9 bg-white/4 shadow-[0_40px_96px_-24px_rgba(0,0,0,0.75),0_1px_0_rgba(255,255,255,0.07)_inset]">
      <CardHeader className="pb-3">
        <CardTitle className="text-xl font-black tracking-[-0.03em] text-white">Top Findings</CardTitle>
      </CardHeader>
      <CardContent className="space-y-5">
        <div className="grid gap-4 md:grid-cols-[1.05fr_0.95fr]">
          <div className="rounded-3xl border border-white/9 bg-white/4 p-6">
            <div className="flex items-center gap-2 mb-4">
              <TriangleAlert className="h-3.5 w-3.5 text-[#d89a63]" />
              <p className="text-[10px] font-bold uppercase tracking-[0.24em] text-zinc-500">Finding mix</p>
            </div>
            <div className="grid gap-2.5 sm:grid-cols-3">
              <div className="relative overflow-hidden rounded-xl bg-zinc-950/50 px-3.5 py-3.5 ring-1 ring-white/5">
                <div className="absolute inset-y-0 left-0 w-[2.5px] rounded-r-[2px] bg-rose-500/60" />
                <p className="text-[10px] font-bold uppercase tracking-[0.22em] text-zinc-500">Critical</p>
                <p className="mt-2 text-2xl font-black text-white">{severityCounts.critical}</p>
              </div>
              <div className="relative overflow-hidden rounded-xl bg-zinc-950/50 px-3.5 py-3.5 ring-1 ring-white/5">
                <div className="absolute inset-y-0 left-0 w-[2.5px] rounded-r-[2px] bg-amber-400/60" />
                <p className="text-[10px] font-bold uppercase tracking-[0.22em] text-zinc-500">Warning</p>
                <p className="mt-2 text-2xl font-black text-white">{severityCounts.warning}</p>
              </div>
              <div className="relative overflow-hidden rounded-xl bg-zinc-950/50 px-3.5 py-3.5 ring-1 ring-white/5">
                <div className="absolute inset-y-0 left-0 w-[2.5px] rounded-r-[2px] bg-zinc-600/60" />
                <p className="text-[10px] font-bold uppercase tracking-[0.22em] text-zinc-500">Info</p>
                <p className="mt-2 text-2xl font-black text-white">{severityCounts.info}</p>
              </div>
            </div>
          </div>

          <div className="rounded-3xl border border-white/9 bg-white/4 p-6">
            <div className="flex items-center gap-2 mb-3">
              <Sparkles className="h-3.5 w-3.5 text-[#d89a63]" />
              <p className="text-[10px] font-bold uppercase tracking-[0.24em] text-zinc-500">How to read this</p>
            </div>
            <p className="text-sm leading-relaxed text-zinc-300">
              The first finding gives the quickest read. Expand any row for confidence, mapped frameworks, and the exact surface where the signal was observed.
            </p>
          </div>
        </div>

        {strengths.length ? (
          <div className="rounded-3xl border border-white/9 bg-white/4 p-6">
            <div className="flex items-center gap-2 mb-3">
              <ShieldCheck className="h-3.5 w-3.5 text-emerald-500/70" />
              <p className="text-[10px] font-bold uppercase tracking-[0.24em] text-zinc-500">Observed strengths</p>
            </div>
            <div className="grid gap-2">
              {strengths.slice(0, 3).map((strength) => (
                <div
                  key={strength}
                  className="rounded-xl border border-white/8 bg-zinc-950/50 px-3.5 py-3 text-sm leading-relaxed text-zinc-300"
                >
                  {strength}
                </div>
              ))}
            </div>
          </div>
        ) : null}

        {topIssues.length ? (
          <div className="overflow-hidden rounded-3xl border border-white/9 bg-white/4">
            <Accordion type="single" collapsible {...(topIssues[0] ? { defaultValue: `finding-${topIssues[0].title}` } : {})}>
              {topIssues.map((issue, index) => {
                const accent = issueAccent[issue.severity];
                return (
                  <AccordionItem
                    key={`${issue.area}-${issue.title}-${issue.detail}`}
                    value={`finding-${issue.title}`}
                    className={`border-white/10 px-5 transition-colors duration-150 ${index === topIssues.length - 1 ? "border-b-0" : ""}`}
                  >
                    <AccordionTrigger className="py-5 hover:no-underline transition-colors duration-150">
                      <div className="grid w-full gap-3 text-left md:grid-cols-[minmax(0,1.35fr)_8.5rem_7.5rem] md:items-start">
                        <div className="min-w-0">
                          <div className="flex items-start gap-3">
                            <span className={`mt-0.5 inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-full ${accent.iconWrap}`}>
                              {accent.icon}
                            </span>
                            <div className="min-w-0">
                              <div className="flex flex-wrap items-center gap-2">
                                <p className="text-base font-semibold leading-6 text-white">{issue.title}</p>
                                <Badge variant="outline" className={accent.chip}>
                                  {issue.severity}
                                </Badge>
                              </div>
                              <p className="mt-1 line-clamp-2 text-sm leading-6 text-zinc-300">{issue.detail}</p>
                            </div>
                          </div>
                        </div>
                        <div className="md:pt-1">
                          <Badge variant="outline" className={confidenceStyles[issue.confidence]}>
                            {issue.confidence} confidence
                          </Badge>
                        </div>
                        <div className="md:pt-1">
                          <Badge variant="outline" className="border-white/10 bg-white/3 text-zinc-300">
                            {issue.source}
                          </Badge>
                        </div>
                      </div>
                    </AccordionTrigger>
                    <AccordionContent className="pb-4">
                      <div className="ml-12 rounded-[1.15rem] border border-white/10 bg-zinc-950/45 p-4">
                        <p className="text-sm leading-6 text-zinc-300">{issue.detail}</p>
                        <div className="mt-4 flex flex-wrap gap-2">
                          {issue.owasp.map((label) => (
                            <Badge key={label} variant="outline" className="border-white/10 bg-white/3 text-zinc-300">
                              {label}
                            </Badge>
                          ))}
                          {issue.mitre.map((label) => (
                            <Badge key={label} variant="outline" className="border-white/10 bg-white/3 text-zinc-300">
                              MITRE: {label}
                            </Badge>
                          ))}
                        </div>
                        <div className="mt-4 grid gap-3 md:grid-cols-2">
                          <div className="rounded-2xl border border-white/10 bg-white/3 px-4 py-3">
                            <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-500">Confidence read</p>
                            <p className="mt-2 text-sm leading-6 text-zinc-300">
                              This was assessed at <span className="font-semibold text-zinc-100">{issue.confidence}</span> confidence from the visible public response.
                            </p>
                          </div>
                          <div className="rounded-2xl border border-white/10 bg-white/3 px-4 py-3">
                            <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-500">Observed surface</p>
                            <p className="mt-2 text-sm leading-6 text-zinc-300">
                              Signal surfaced through <span className="font-semibold text-zinc-100">{issue.source}</span>.
                            </p>
                          </div>
                        </div>
                      </div>
                    </AccordionContent>
                  </AccordionItem>
                );
              })}
            </Accordion>
          </div>
        ) : (
          <EmptyState>No obvious issues were detected in the scanned response.</EmptyState>
        )}
      </CardContent>
    </Card>
  );
};
