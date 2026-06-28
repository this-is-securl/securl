import { CheckCircle2, Gauge, ListTodo, ShieldCheck } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/panel-primitives";
import { AnalysisResult, RemediationPlanItem } from "@/types/analysis";
import { getPriorityActions } from "@/lib/priorities";

interface PriorityActionsPanelProps {
  analysis: AnalysisResult;
}

const severityTone = {
  critical: {
    rail: "bg-red-500",
    chip: "bg-red-500/10 text-rose-300 border-rose-500/25",
  },
  warning: {
    rail: "bg-amber-500",
    chip: "bg-amber-500/10 text-amber-300 border-amber-500/25",
  },
  info: {
    rail: "bg-zinc-500/50",
    chip: "bg-white/8 text-zinc-200 border-white/10",
  },
} as const;

const impactTone = {
  high: "border-rose-500/25 bg-rose-500/8 text-rose-200",
  medium: "border-amber-500/25 bg-amber-500/8 text-amber-200",
  low: "border-white/10 bg-white/6 text-zinc-300",
} as const;

const effortTone = {
  low: "border-emerald-500/25 bg-emerald-500/8 text-emerald-200",
  medium: "border-amber-500/25 bg-amber-500/8 text-amber-200",
  high: "border-rose-500/25 bg-rose-500/8 text-rose-200",
} as const;

const ownerLabels: Record<RemediationPlanItem["owner"], string> = {
  app: "App",
  edge: "Edge",
  dns: "DNS",
  identity: "Identity",
  third_party: "Third party",
};

const hasServerPlan = (analysis: AnalysisResult) =>
  Boolean(analysis.remediationPlan?.items && analysis.remediationPlan.items.length > 0);

export const PriorityActionsPanel = ({ analysis }: PriorityActionsPanelProps) => {
  if (hasServerPlan(analysis)) {
    const plan = analysis.remediationPlan!;
    return (
      <Card className="rounded-4xl border border-white/9 bg-white/4 shadow-[0_40px_96px_-24px_rgba(0,0,0,0.75),0_1px_0_rgba(255,255,255,0.07)_inset]">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-xl font-black tracking-[-0.03em] text-white">
            <ListTodo className="h-5 w-5 text-[#d89a63]" />
            Remediation Plan
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-5">
          <div className="grid gap-3 md:grid-cols-3">
            <div className="rounded-2xl border border-white/8 bg-zinc-950/45 p-4">
              <p className="text-[10px] font-bold uppercase tracking-[0.22em] text-zinc-500">Actions</p>
              <p className="mt-2 text-2xl font-black text-white">{plan.totalActions}</p>
            </div>
            <div className="rounded-2xl border border-white/8 bg-zinc-950/45 p-4">
              <p className="text-[10px] font-bold uppercase tracking-[0.22em] text-zinc-500">High impact</p>
              <p className="mt-2 text-2xl font-black text-white">{plan.highImpactActions}</p>
            </div>
            <div className="rounded-2xl border border-white/8 bg-zinc-950/45 p-4">
              <p className="text-[10px] font-bold uppercase tracking-[0.22em] text-zinc-500">Quick wins</p>
              <p className="mt-2 text-2xl font-black text-white">{plan.quickWins}</p>
            </div>
          </div>

          <div className="overflow-hidden rounded-3xl border border-white/8 bg-zinc-950/50">
            {plan.items.slice(0, 8).map((item, index) => (
              <div
                key={item.id}
                className={`grid gap-4 px-5 py-5 md:grid-cols-[2.25rem_minmax(0,1fr)_13rem] md:items-start ${
                  index < Math.min(plan.items.length, 8) - 1 ? "border-b border-white/6" : ""
                }`}
              >
                <div className="flex items-start justify-center pt-0.5">
                  <div className="flex flex-col items-center gap-2">
                    <span className="flex h-8 w-8 items-center justify-center rounded-full border border-[#d89a63]/25 bg-[#d89a63]/10 text-sm font-black text-[#f0d5bc]">
                      {item.priority}
                    </span>
                    {item.scoreImpact !== null ? (
                      <span className="text-[10px] font-bold text-zinc-500">-{item.scoreImpact}</span>
                    ) : null}
                  </div>
                </div>
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="text-base font-bold text-white">{item.title}</p>
                    <span className={`inline-flex rounded-full border px-2.5 py-1 text-[10px] font-bold uppercase tracking-[0.18em] ${impactTone[item.impact]}`}>
                      {item.impact} impact
                    </span>
                    <span className={`inline-flex rounded-full border px-2.5 py-1 text-[10px] font-bold uppercase tracking-[0.18em] ${effortTone[item.effort]}`}>
                      {item.effort} effort
                    </span>
                  </div>
                  <p className="mt-2 text-sm leading-7 text-zinc-300">{item.detail}</p>

                  <div className="mt-4 grid gap-3 lg:grid-cols-2">
                    <div className="rounded-2xl border border-white/8 bg-white/3 p-4">
                      <div className="flex items-center gap-2">
                        <Gauge className="h-3.5 w-3.5 text-[#d89a63]" />
                        <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-500">Action</p>
                      </div>
                      <p className="mt-2 text-sm leading-6 text-zinc-300">{item.action}</p>
                    </div>
                    <div className="rounded-2xl border border-white/8 bg-white/3 p-4">
                      <div className="flex items-center gap-2">
                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400/80" />
                        <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-500">Verify</p>
                      </div>
                      <p className="mt-2 text-sm leading-6 text-zinc-300">{item.verify}</p>
                    </div>
                  </div>

                  {item.relatedFindings.length ? (
                    <div className="mt-4 flex flex-wrap gap-2">
                      {item.relatedFindings.slice(0, 4).map((finding) => (
                        <span
                          key={finding}
                          className="rounded-full border border-white/10 bg-white/5 px-3 py-1 text-xs font-medium text-zinc-300"
                        >
                          {finding}
                        </span>
                      ))}
                    </div>
                  ) : null}

                  {item.evidence.length ? (
                    <div className="mt-4 rounded-2xl border border-white/8 bg-white/3 p-4">
                      <div className="flex items-center gap-2">
                        <ShieldCheck className="h-3.5 w-3.5 text-[#d89a63]" />
                        <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-500">Evidence</p>
                      </div>
                      <div className="mt-3 grid gap-2">
                        {item.evidence.slice(0, 3).map((evidence, evidenceIndex) => (
                          <p key={`${item.id}-${evidence.kind}-${evidenceIndex}`} className="text-xs leading-5 text-zinc-400">
                            <span className="font-semibold text-zinc-200">{evidence.label}:</span>{" "}
                            {evidence.observed ?? "not observed"}
                          </p>
                        ))}
                      </div>
                    </div>
                  ) : null}
                </div>
                <div className="rounded-2xl border border-white/8 bg-white/3 p-4 md:text-right">
                  <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-500">Owner</p>
                  <p className="mt-2 text-sm font-semibold text-zinc-100">{ownerLabels[item.owner]}</p>
                  <p className="mt-4 text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-500">Score impact</p>
                  <p className="mt-2 text-sm font-semibold text-zinc-100">
                    {item.scoreImpact === null ? "Finding" : `${item.scoreImpact} pts`}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    );
  }

  const actions = getPriorityActions(analysis);

  if (!actions.length) {
    return (
      <Card className="rounded-4xl border border-white/9 bg-white/4 shadow-[0_40px_96px_-24px_rgba(0,0,0,0.75),0_1px_0_rgba(255,255,255,0.07)_inset]">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-xl font-black tracking-[-0.03em] text-white">
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
    <Card className="rounded-4xl border border-white/9 bg-white/4 shadow-[0_40px_96px_-24px_rgba(0,0,0,0.75),0_1px_0_rgba(255,255,255,0.07)_inset]">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-xl font-black tracking-[-0.03em] text-white">
          <ListTodo className="h-5 w-5 text-[#d89a63]" />
          Priority Actions for This Target
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="overflow-hidden rounded-3xl border border-white/8 bg-zinc-950/50">
          {actions.map((action, index) => {
            const tone = severityTone[action.severity];
            return (
              <div
                key={`${action.area}-${action.title}`}
                className={`grid gap-3 px-5 py-5 md:grid-cols-[2rem_minmax(0,1fr)_11rem] md:items-start ${
                  index < actions.length - 1 ? "border-b border-white/6" : ""
                }`}
              >
                <div className="flex items-start justify-center pt-0.5">
                  <div className="flex flex-col items-center gap-2">
                    <span className={`h-8 w-[5px] rounded-full ${tone.rail}`} aria-hidden="true" />
                    <span className="text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-500">
                      {index + 1}
                    </span>
                  </div>
                </div>
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="text-base font-bold text-white">{action.title}</p>
                    <span className={`inline-flex items-center rounded-full border px-2.5 py-1 text-[11px] font-bold uppercase tracking-[0.2em] ${tone.chip}`}>
                      {action.severity}
                    </span>
                  </div>
                  <p className="mt-2 text-sm leading-7 text-zinc-300">{action.detail}</p>
                  {action.priorityReason ? (
                    <p className="mt-3 text-xs font-medium uppercase tracking-[0.14em] text-zinc-500">
                      {action.priorityReason}
                    </p>
                  ) : null}
                </div>
                <div className="md:pt-1 md:text-right">
                  <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-500">Focus area</p>
                  <p className="mt-2 text-sm font-medium text-zinc-200">{action.area}</p>
                </div>
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
};
