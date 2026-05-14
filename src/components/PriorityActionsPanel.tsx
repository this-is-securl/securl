import { ListTodo } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/panel-primitives";
import { AnalysisResult } from "@/types/analysis";
import { getPriorityActions } from "@/lib/priorities";

interface PriorityActionsPanelProps {
  analysis: AnalysisResult;
}

const severityTone = {
  critical: {
    rail: "bg-red-500",
    chip: "bg-red-500/10 text-red-300 border-red-500/25",
  },
  warning: {
    rail: "bg-amber-500",
    chip: "bg-amber-500/10 text-amber-300 border-amber-500/25",
  },
  info: {
    rail: "bg-slate-500/50",
    chip: "bg-white/[0.08] text-slate-200 border-white/10",
  },
} as const;

export const PriorityActionsPanel = ({ analysis }: PriorityActionsPanelProps) => {
  const actions = getPriorityActions(analysis);

  if (!actions.length) {
    return (
      <Card className="rounded-[1.75rem] border-white/10 bg-white/[0.04] shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2">
            <ListTodo className="h-5 w-5 text-[#d89a63]" />
            Priority Actions for This Target
          </CardTitle>
        </CardHeader>
        <CardContent>
          <EmptyState>
            No target-side actions are being prioritized from the currently visible public evidence.
          </EmptyState>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="rounded-[1.75rem] border-white/10 bg-white/[0.04] shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2">
          <ListTodo className="h-5 w-5 text-[#d89a63]" />
          Priority Actions for This Target
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="overflow-hidden rounded-[1.35rem] border border-white/10 bg-white/[0.03] shadow-[0_18px_40px_-28px_rgba(0,0,0,0.7)]">
          {actions.map((action, index) => {
            const tone = severityTone[action.severity];
            return (
              <div
                key={`${action.area}-${action.title}`}
                className={`grid gap-3 px-4 py-4 md:grid-cols-[2rem_minmax(0,1fr)_11rem] md:items-start ${
                  index < actions.length - 1 ? "border-b border-white/10" : ""
                }`}
              >
                <div className="flex items-start justify-center pt-0.5">
                  <div className="flex flex-col items-center gap-2">
                    <span className={`h-7 w-1.5 rounded-full ${tone.rail}`} aria-hidden="true" />
                    <span className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-500">
                      {index + 1}
                    </span>
                  </div>
                </div>
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="text-base font-semibold text-white">{action.title}</p>
                    <span className={`inline-flex items-center rounded-full border px-2.5 py-1 text-[11px] font-bold uppercase tracking-[0.2em] ${tone.chip}`}>
                      {action.severity}
                    </span>
                  </div>
                  <p className="mt-2 text-sm leading-6 text-slate-300">{action.detail}</p>
                  {action.priorityReason ? (
                    <p className="mt-3 text-xs font-medium uppercase tracking-[0.14em] text-slate-500">
                      {action.priorityReason}
                    </p>
                  ) : null}
                </div>
                <div className="md:pt-1 md:text-right">
                  <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-500">Focus area</p>
                  <p className="mt-2 text-sm font-medium text-slate-200">{action.area}</p>
                </div>
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
};
