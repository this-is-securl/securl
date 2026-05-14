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
    chip: "bg-[#8e5c3b]/18 text-[#f0d5bc] border-[#b56a2c]/30",
    iconWrap: "bg-[#8e5c3b]/18 text-[#f0d5bc]",
  },
  warning: {
    icon: <AlertTriangle className="h-4 w-4" />,
    chip: "bg-[#74452b]/18 text-[#e2c0a2] border-[#8e5c3b]/30",
    iconWrap: "bg-[#74452b]/18 text-[#e2c0a2]",
  },
  info: {
    icon: <Info className="h-4 w-4" />,
    chip: "bg-white/[0.08] text-slate-200 border-white/10",
    iconWrap: "bg-white/[0.08] text-slate-200",
  },
} as const;

const confidenceStyles = {
  high: "bg-white/[0.12] text-slate-100 border-white/10",
  medium: "bg-[#b56a2c]/14 text-[#f0d5bc] border-[#b56a2c]/25",
  low: "bg-white/[0.06] text-slate-300 border-white/10",
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
    <Card className="border-white/10 bg-white/[0.04] shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
      <CardHeader className="pb-3">
        <CardTitle>Top Findings</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-3 md:grid-cols-[1.05fr_0.95fr]">
          <div className="rounded-[1.35rem] border border-white/10 bg-white/[0.03] p-4 shadow-[0_18px_40px_-28px_rgba(0,0,0,0.7)]">
            <div className="flex items-center gap-2">
              <TriangleAlert className="h-4 w-4 text-[#d89a63]" />
              <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-400">Finding mix</p>
            </div>
            <div className="mt-4 grid gap-3 sm:grid-cols-3">
              <div className="rounded-[1.15rem] border border-white/10 bg-slate-950/45 px-4 py-4">
                <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-500">Critical</p>
                <p className="mt-2 text-2xl font-semibold text-[#f0d5bc]">{severityCounts.critical}</p>
              </div>
              <div className="rounded-[1.15rem] border border-white/10 bg-slate-950/45 px-4 py-4">
                <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-500">Warning</p>
                <p className="mt-2 text-2xl font-semibold text-[#e2c0a2]">{severityCounts.warning}</p>
              </div>
              <div className="rounded-[1.15rem] border border-white/10 bg-slate-950/45 px-4 py-4">
                <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-500">Informational</p>
                <p className="mt-2 text-2xl font-semibold text-slate-100">{severityCounts.info}</p>
              </div>
            </div>
          </div>

          <div className="rounded-[1.35rem] border border-white/10 bg-white/[0.03] p-4 shadow-[0_18px_40px_-28px_rgba(0,0,0,0.7)]">
            <div className="flex items-center gap-2">
              <Sparkles className="h-4 w-4 text-[#d89a63]" />
              <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-400">How to read this</p>
            </div>
            <p className="mt-3 text-sm leading-7 text-slate-300">
              The first finding gives the quickest read. Expand any card for confidence, mapped frameworks, and the exact surface where the signal was observed.
            </p>
          </div>
        </div>

        {strengths.length ? (
          <div className="rounded-[1.35rem] border border-white/10 bg-white/[0.03] p-4 shadow-[0_18px_40px_-28px_rgba(0,0,0,0.7)]">
            <div className="flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-[#d89a63]" />
              <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-400">Observed strengths</p>
            </div>
            <div className="mt-3 grid gap-2">
              {strengths.slice(0, 3).map((strength) => (
                <div
                  key={strength}
                  className="rounded-2xl border border-white/10 bg-slate-950/45 px-3 py-3 text-sm leading-6 text-slate-200"
                >
                  {strength}
                </div>
              ))}
            </div>
          </div>
        ) : null}

        {topIssues.length ? (
          <div className="overflow-hidden rounded-[1.35rem] border border-white/10 bg-white/[0.03] shadow-[0_18px_40px_-28px_rgba(0,0,0,0.7)]">
            <Accordion type="single" collapsible {...(topIssues[0] ? { defaultValue: `finding-${topIssues[0].title}` } : {})}>
              {topIssues.map((issue, index) => {
                const accent = issueAccent[issue.severity];
                return (
                  <AccordionItem
                    key={`${issue.area}-${issue.title}-${issue.detail}`}
                    value={`finding-${issue.title}`}
                    className={`border-white/10 px-4 ${index === topIssues.length - 1 ? "border-b-0" : ""}`}
                  >
                    <AccordionTrigger className="py-4 hover:no-underline">
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
                              <p className="mt-1 line-clamp-2 text-sm leading-6 text-slate-300">{issue.detail}</p>
                            </div>
                          </div>
                        </div>
                        <div className="md:pt-1">
                          <Badge variant="outline" className={confidenceStyles[issue.confidence]}>
                            {issue.confidence} confidence
                          </Badge>
                        </div>
                        <div className="md:pt-1">
                          <Badge variant="outline" className="border-white/10 bg-white/[0.03] text-slate-300">
                            {issue.source}
                          </Badge>
                        </div>
                      </div>
                    </AccordionTrigger>
                    <AccordionContent className="pb-4">
                      <div className="ml-12 rounded-[1.15rem] border border-white/10 bg-slate-950/45 p-4">
                        <p className="text-sm leading-6 text-slate-300">{issue.detail}</p>
                        <div className="mt-4 flex flex-wrap gap-2">
                          {issue.owasp.map((label) => (
                            <Badge key={label} variant="outline" className="border-white/10 bg-white/[0.03] text-slate-300">
                              {label}
                            </Badge>
                          ))}
                          {issue.mitre.map((label) => (
                            <Badge key={label} variant="outline" className="border-white/10 bg-white/[0.03] text-slate-300">
                              MITRE: {label}
                            </Badge>
                          ))}
                        </div>
                        <div className="mt-4 grid gap-3 md:grid-cols-2">
                          <div className="rounded-[1rem] border border-white/10 bg-white/[0.03] px-4 py-3">
                            <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-500">Confidence read</p>
                            <p className="mt-2 text-sm leading-6 text-slate-300">
                              This was assessed at <span className="font-semibold text-slate-100">{issue.confidence}</span> confidence from the visible public response.
                            </p>
                          </div>
                          <div className="rounded-[1rem] border border-white/10 bg-white/[0.03] px-4 py-3">
                            <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-500">Observed surface</p>
                            <p className="mt-2 text-sm leading-6 text-slate-300">
                              Signal surfaced through <span className="font-semibold text-slate-100">{issue.source}</span>.
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
