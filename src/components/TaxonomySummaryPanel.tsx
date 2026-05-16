import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AnalysisResult } from "@/types/analysis";
import { getDominantThemes } from "@/lib/reportInsights";
import { Layers3 } from "lucide-react";

interface TaxonomySummaryPanelProps {
  analysis: AnalysisResult;
}

interface ThemeItem {
  label: string;
  summary: string;
  whyItMatters: string;
  examples: string[];
}

interface ThemeColumnProps {
  title: string;
  emptyState: string;
  items: ThemeItem[];
}

const ThemeColumn = ({ title, emptyState, items }: ThemeColumnProps) => (
  <div className="rounded-[1.5rem] border border-white/10 bg-white/[0.03] p-4 shadow-[0_18px_40px_-28px_rgba(0,0,0,0.7)]">
    <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-400">{title}</p>
    <div className="mt-3 space-y-3">
      {items.length ? (
        items.map((item) => {
          const topExamples = item.examples.slice(0, 3);
          const remainingExampleCount = Math.max(item.examples.length - topExamples.length, 0);

          return (
            <div key={item.label} className="rounded-[1.1rem] border border-white/10 bg-zinc-950/50 p-4">
              <p className="text-sm font-semibold text-white">{item.label}</p>
              <p className="mt-2 text-sm leading-6 text-zinc-300">{item.summary}</p>
              <p className="mt-3 text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-400">Why it matters</p>
              <p className="mt-1 text-sm leading-6 text-zinc-400">{item.whyItMatters}</p>
              <div className="mt-3">
                <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-400">Driving findings</p>
                {topExamples.length ? (
                  <ul className="mt-2 space-y-1 text-sm text-zinc-300">
                    {topExamples.map((example) => (
                      <li key={example} className="flex items-start gap-2">
                        <span className="mt-2 inline-block h-1.5 w-1.5 shrink-0 rounded-full bg-[#14b8a6]" aria-hidden="true" />
                        <span>{example}</span>
                      </li>
                    ))}
                    {remainingExampleCount > 0 ? (
                      <li className="text-xs font-medium uppercase tracking-[0.16em] text-zinc-500">
                        +{remainingExampleCount} more finding{remainingExampleCount === 1 ? "" : "s"}
                      </li>
                    ) : null}
                  </ul>
                ) : (
                  <p className="mt-2 text-sm text-zinc-500">No example findings recorded.</p>
                )}
              </div>
            </div>
          );
        })
      ) : (
        <span className="text-sm text-zinc-500">{emptyState}</span>
      )}
    </div>
  </div>
);

export const TaxonomySummaryPanel = ({ analysis }: TaxonomySummaryPanelProps) => {
  const themes = getDominantThemes(analysis);

  return (
    <Card className="border-white/10 bg-white/[0.04] shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Layers3 className="h-5 w-5 text-[#2dd4bf]" />
          Risk Themes
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-5">
        <div className="rounded-[1.5rem] border border-white/10 bg-white/[0.03] p-5 shadow-[0_18px_40px_-28px_rgba(0,0,0,0.7)]">
          <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-400">Dominant read</p>
          <p className="mt-3 text-sm leading-7 text-zinc-300">{themes.summary}</p>
        </div>

        <div className="grid gap-4 md:grid-cols-2">
          <ThemeColumn title="OWASP themes" emptyState="No OWASP-tagged findings yet." items={themes.owasp} />
          <ThemeColumn title="MITRE relevance" emptyState="No MITRE-relevant mappings yet." items={themes.mitre} />
        </div>
      </CardContent>
    </Card>
  );
};
