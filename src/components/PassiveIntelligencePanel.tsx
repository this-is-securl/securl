import {
  Activity,
  BrainCircuit,
  Cloud,
  Eye,
  Fingerprint,
  Globe,
  Radar,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState, SignalList, StatBox, TruncatedChip } from "@/components/ui/panel-primitives";
import type { PassiveIntelligenceInfo, PassiveIntelligenceSignal } from "@/types/analysis";

interface PassiveIntelligencePanelProps {
  passiveIntelligence?: PassiveIntelligenceInfo | null;
}

const categoryConfig: Record<
  PassiveIntelligenceSignal["category"],
  { label: string; icon: React.ReactNode }
> = {
  technology: { label: "Stack", icon: <Fingerprint className="h-4 w-4" /> },
  infrastructure: { label: "Edge", icon: <Cloud className="h-4 w-4" /> },
  telemetry: { label: "Telemetry", icon: <Activity className="h-4 w-4" /> },
  third_party: { label: "Third party", icon: <Globe className="h-4 w-4" /> },
  trust: { label: "Trust", icon: <ShieldCheck className="h-4 w-4" /> },
  email: { label: "Email", icon: <Globe className="h-4 w-4" /> },
  exposure: { label: "Exposure", icon: <Eye className="h-4 w-4" /> },
  ai: { label: "AI", icon: <BrainCircuit className="h-4 w-4" /> },
};

const riskClass: Record<PassiveIntelligenceSignal["risk"], string> = {
  attention: "border-rose-500/30 bg-rose-500/[0.10] text-rose-100",
  watch: "border-amber-500/30 bg-amber-500/[0.10] text-amber-100",
  neutral: "border-white/10 bg-white/[0.06] text-zinc-100",
  positive: "border-emerald-400/25 bg-emerald-400/[0.10] text-emerald-100",
};

const riskLabel: Record<PassiveIntelligenceSignal["risk"], string> = {
  attention: "Attention",
  watch: "Watch",
  neutral: "Context",
  positive: "Positive",
};

export const PassiveIntelligencePanel = ({ passiveIntelligence }: PassiveIntelligencePanelProps) => {
  if (!passiveIntelligence) {
    return (
      <Card className="border-white/10 bg-white/[0.04] shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-zinc-50">
            <Radar className="h-5 w-5 text-[#e0b286]" />
            Passive Intelligence
          </CardTitle>
        </CardHeader>
        <CardContent>
          <EmptyState>Passive intelligence was not available for this saved scan.</EmptyState>
        </CardContent>
      </Card>
    );
  }

  const watchCount = passiveIntelligence.signals.filter(
    (signal) => signal.risk === "attention" || signal.risk === "watch",
  ).length;
  const positiveCount = passiveIntelligence.signals.filter((signal) => signal.risk === "positive").length;

  return (
    <Card className="border-white/10 bg-white/[0.04] shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-zinc-50">
          <Radar className="h-5 w-5 text-[#e0b286]" />
          Passive Intelligence
        </CardTitle>
        <p className="text-sm leading-6 text-zinc-400">
          Stack, telemetry, trust, and exposure clues gathered from normal public responses only.
        </p>
      </CardHeader>
      <CardContent className="space-y-5">
        <div className="grid gap-3 md:grid-cols-3">
          <StatBox
            label="Passive signals"
            value={<p className="text-3xl font-bold">{passiveIntelligence.signals.length}</p>}
            note={<p className="text-xs">No active probing</p>}
          />
          <StatBox
            label="Watch items"
            value={<p className="text-3xl font-bold">{watchCount}</p>}
            variant={watchCount ? "warning" : "default"}
          />
          <StatBox
            label="Positive signals"
            value={<p className="text-3xl font-bold">{positiveCount}</p>}
          />
        </div>

        <div className="rounded-[1.5rem] border border-white/10 bg-zinc-950/45 p-5">
          <p className="text-[10px] font-bold uppercase tracking-[0.24em] text-[#e0b286]">Readout</p>
          <p className="mt-2 text-lg font-semibold leading-7 text-white">{passiveIntelligence.postureRead}</p>
          <div className="mt-4 grid gap-3 text-sm leading-6 text-zinc-300 md:grid-cols-3">
            <p>{passiveIntelligence.stackSummary}</p>
            <p>{passiveIntelligence.telemetrySummary}</p>
            <p>{passiveIntelligence.trustSummary}</p>
          </div>
        </div>

        {passiveIntelligence.signals.length ? (
          <div className="grid gap-3">
            {passiveIntelligence.signals.map((signal, index) => {
              const config = categoryConfig[signal.category];
              return (
                <div
                  key={`${signal.category}-${signal.title}-${index}`}
                  className="rounded-[1.35rem] border border-white/10 bg-[#111a14] px-4 py-4"
                >
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 text-sm font-semibold text-white">
                        <span className="text-zinc-400">{config.icon}</span>
                        {signal.title}
                      </div>
                      <p className="mt-2 text-sm leading-6 text-zinc-300">{signal.summary}</p>
                    </div>
                    <div className="flex flex-wrap justify-end gap-2">
                      <Badge variant="outline" className="border-white/10 bg-white/[0.06] text-zinc-100">
                        {config.label}
                      </Badge>
                      <Badge variant="outline" className={riskClass[signal.risk]}>
                        {riskLabel[signal.risk]}
                      </Badge>
                      <Badge variant="outline" className="border-white/10 bg-white/[0.06] text-zinc-300">
                        {signal.confidence}
                      </Badge>
                    </div>
                  </div>
                  {signal.evidence.length ? (
                    <div className="mt-3 flex flex-wrap gap-2">
                      {signal.evidence.slice(0, 6).map((item) => (
                        <TruncatedChip
                          key={item}
                          value={item}
                          className="border-white/10 bg-white/[0.04] text-zinc-300"
                          maxWidthClassName="max-w-[16rem]"
                        />
                      ))}
                    </div>
                  ) : null}
                  {signal.action ? (
                    <p className="mt-3 rounded-2xl border border-white/10 bg-white/[0.04] px-4 py-3 text-sm leading-6 text-zinc-300">
                      <span className="font-semibold text-zinc-100">Suggested check: </span>
                      {signal.action}
                    </p>
                  ) : null}
                </div>
              );
            })}
          </div>
        ) : (
          <EmptyState>No passive intelligence signals were generated for this scan.</EmptyState>
        )}

        <SignalList
          title="Collection boundary"
          items={[passiveIntelligence.collectionBoundary]}
          icon={<Sparkles />}
          variant="neutral"
        />
      </CardContent>
    </Card>
  );
};
