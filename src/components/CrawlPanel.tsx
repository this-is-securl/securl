import { GitCompareArrows, Route } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState, StatBox } from "@/components/ui/panel-primitives";
import { getHttpStatusDetails } from "@/lib/httpStatus";
import { CrawlSummary } from "@/types/analysis";

interface CrawlPanelProps {
  crawl: CrawlSummary;
}

const gradeStyles: Record<string, string> = {
  "A+": "bg-white/[0.08] text-zinc-100",
  A: "bg-white/[0.08] text-zinc-100",
  B: "bg-[#4f6676]/18 text-[#d9e4ea]",
  C: "bg-[#7f1d1d]/14 text-[#99f6e4]",
  D: "bg-[#14b8a6]/16 text-[#99f6e4]",
  F: "bg-[#14b8a6]/18 text-[#99f6e4]",
  Redirected: "bg-white/[0.08] text-zinc-100",
};

export const CrawlPanel = ({ crawl }: CrawlPanelProps) => {
  if (!crawl.pages.length) {
    return (
      <Card className="border-white/10 bg-white/[0.04] shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Route className="h-5 w-5" />
            Multi-Page Crawl
          </CardTitle>
        </CardHeader>
        <CardContent>
          <EmptyState>
            No additional same-origin pages were collected for comparative crawl analysis during this scan.
          </EmptyState>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="border-white/10 bg-white/[0.04] shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Route className="h-5 w-5" />
          Multi-Page Crawl
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-5">
        <div className="grid gap-4 md:grid-cols-2">
          <StatBox label="Strongest page" value={<p className="text-lg font-semibold">{crawl.strongestPage ?? "Unknown"}</p>} />
          <StatBox label="Weakest page" value={<p className="text-lg font-semibold">{crawl.weakestPage ?? "Unknown"}</p>} />
        </div>

        {crawl.discoverySources.length > 0 && (
          <StatBox
            label="Discovery sources"
            value={
              <div className="flex flex-wrap gap-2">
                {crawl.discoverySources.map((source) => (
                  <Badge key={source} variant="outline">{source}</Badge>
                ))}
              </div>
            }
          />
        )}

        {crawl.inconsistentHeaders.length > 0 && (
          <div className="rounded-[1.25rem] border border-[#14b8a6]/30 bg-[#14b8a6]/10 p-4">
            <div className="flex items-center gap-2 text-sm font-semibold text-[#99f6e4]">
              <GitCompareArrows className="h-4 w-4" />
              Inconsistent across routes
            </div>
            <div className="mt-3 flex flex-wrap gap-2">
              {crawl.inconsistentHeaders.map((header) => (
                <Badge key={header} variant="secondary" className="bg-[#7f1d1d]/14 text-[#99f6e4]">
                  {header}
                </Badge>
              ))}
            </div>
          </div>
        )}

        <div className="grid gap-3">
          {crawl.pages.map((page) => {
            const status = page.statusCode ? getHttpStatusDetails(page.statusCode) : null;
            return (
              <div key={`${page.path}-${page.label}`} className="rounded-[1.25rem] border border-white/10 bg-white/[0.04] p-4">
                <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                  <div className="min-w-0">
                    <div className="flex min-w-0 items-center gap-2">
                      <h3 className="shrink-0 font-semibold text-zinc-50">{page.label}</h3>
                      <code className="min-w-0 truncate rounded bg-zinc-950/55 px-2 py-0.5 text-xs text-zinc-300" title={page.path}>{page.path}</code>
                    </div>
                    <p className="mt-2 truncate text-sm text-zinc-400" title={page.finalUrl}>{page.finalUrl}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="secondary" className={gradeStyles[page.grade] ?? gradeStyles.F}>
                      {page.grade}
                    </Badge>
                    {page.sameOrigin ? (
                      <span className="text-sm font-semibold text-zinc-200">{page.score}/100</span>
                    ) : (
                      <span className="text-sm font-semibold text-zinc-200">off-origin redirect</span>
                    )}
                  </div>
                </div>
                <div className="mt-4 grid gap-3 text-sm md:grid-cols-3">
                  <div className="rounded-[1rem] bg-zinc-950/45 p-3 text-zinc-300">
                    <div>Status {page.statusCode ? `${page.statusCode} ${status?.label}` : "unreachable"} · {page.responseTimeMs}ms</div>
                    {status ? (
                      <div className="mt-1 text-xs leading-5 text-zinc-400">{status.meaning}</div>
                    ) : null}
                  </div>
                  <div className="rounded-[1rem] bg-zinc-950/45 p-3 text-zinc-300">
                    Missing: {!page.sameOrigin ? "not compared" : page.missingHeaders.length ? page.missingHeaders.join(", ") : "none"}
                  </div>
                  <div className="rounded-[1rem] bg-zinc-950/45 p-3 text-zinc-300">
                    Warnings: {!page.sameOrigin ? "not compared" : page.warningHeaders.length ? page.warningHeaders.join(", ") : "none"}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
};
