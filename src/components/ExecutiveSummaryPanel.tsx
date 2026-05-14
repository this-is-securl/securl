import { NotebookText, Sparkles } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ExecutiveSummaryInfo } from "@/types/analysis";

interface ExecutiveSummaryPanelProps {
  summary: ExecutiveSummaryInfo;
}

const postureStyles = {
  strong: "border-white/10 bg-white/[0.04] text-slate-100",
  mixed: "border-[#8e5c3b]/30 bg-[#8e5c3b]/12 text-[#f0dfcf]",
  weak: "border-[#b56a2c]/35 bg-[#3a2a20] text-[#f4dfcd]",
} as const;

export const ExecutiveSummaryPanel = ({ summary }: ExecutiveSummaryPanelProps) => {
  return (
    <Card className="border-white/10 bg-white/[0.04] shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <NotebookText className="h-5 w-5" />
          Assessment context
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-5">
        <div className={`rounded-2xl border px-5 py-5 ${postureStyles[summary.posture]}`}>
          <div className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-[0.2em] opacity-75">
            <Sparkles className="h-4 w-4" />
            Analyst read
          </div>
          <p className="mt-3 text-xl font-semibold leading-8">{summary.overview}</p>
        </div>

        <div className="rounded-[1.35rem] border border-white/10 bg-white/[0.04] p-5">
          <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-400">Main visible risk</p>
          <p className="mt-3 text-base font-medium leading-7 text-slate-50">{summary.mainRisk}</p>
        </div>

        <div className="rounded-[1.35rem] border border-white/10 bg-white/[0.04] p-5">
          <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-400">What stands out</p>
          <div className="mt-4 space-y-3">
            {summary.takeaways.map((takeaway, index) => (
              <div key={takeaway} className="flex gap-3 rounded-[1.15rem] border border-white/10 bg-slate-950/45 px-4 py-4 text-sm text-slate-300">
                <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-[#b56a2c]/16 text-xs font-semibold text-[#f0d5bc]">
                  {index + 1}
                </div>
                <p className="leading-6">{takeaway}</p>
              </div>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
