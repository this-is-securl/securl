import { AlertTriangle, CheckCircle2, Fingerprint, Radar, ShieldAlert, Sparkles } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState, SignalList, StatBox, TruncatedChip } from "@/components/ui/panel-primitives";
import type { CompromiseIndicator, CompromiseSignalsInfo } from "@/types/analysis";

interface CompromiseSignalsPanelProps {
  compromiseSignals?: CompromiseSignalsInfo | null;
}

const severityClass: Record<CompromiseIndicator["severity"], string> = {
  critical: "border-rose-500/35 bg-rose-500/[0.10] text-rose-100",
  warning: "border-amber-500/35 bg-amber-500/[0.10] text-amber-100",
  watch: "border-white/10 bg-white/[0.06] text-zinc-100",
  info: "border-white/[0.08] bg-white/[0.04] text-zinc-300",
};

const categoryLabel: Record<CompromiseIndicator["category"], string> = {
  credential_collection: "Credential flow",
  script_anomaly: "Script anomaly",
  supply_chain: "Supply chain",
  infrastructure: "Infrastructure",
  exposure: "Exposure",
  reputation: "Reputation",
};

const sourceLabel: Record<CompromiseIndicator["source"], string> = {
  html: "HTML",
  asset: "Asset",
  dns: "DNS",
  ct: "CT",
  public_record: "Public record",
  reputation: "Reputation",
  derived: "Derived",
};

export const CompromiseSignalsPanel = ({ compromiseSignals }: CompromiseSignalsPanelProps) => {
  if (!compromiseSignals) {
    return (
      <Card className="border-white/10 bg-white/[0.04] shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-zinc-50">
            <ShieldAlert className="h-5 w-5 text-[#e0b286]" />
            Public IOC & Abuse Indicators
          </CardTitle>
        </CardHeader>
        <CardContent>
          <EmptyState>Public IOC and abuse indicators were not available for this saved scan.</EmptyState>
        </CardContent>
      </Card>
    );
  }

  const urgentCount = compromiseSignals.indicators.filter(
    (indicator) => indicator.severity === "critical" || indicator.severity === "warning",
  ).length;
  const configuredReputationCount = compromiseSignals.reputationChecks.filter(
    (check) => check.status !== "not_configured",
  ).length;

  return (
    <Card className="border-white/10 bg-white/[0.04] shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-zinc-50">
          <ShieldAlert className="h-5 w-5 text-[#e0b286]" />
          Public IOC & Abuse Indicators
        </CardTitle>
        <p className="text-sm leading-6 text-zinc-400">
          Credential-flow, script, exposure, CT, and vulnerable-library indicators inferred from passive evidence.
        </p>
      </CardHeader>
      <CardContent className="space-y-5">
        <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
          <StatBox
            label="Indicators"
            value={<p className="text-3xl font-bold">{compromiseSignals.indicators.length}</p>}
            note={<p className="text-xs">{compromiseSignals.posture}</p>}
            variant={urgentCount ? "warning" : "default"}
          />
          <StatBox
            label="Urgent review"
            value={<p className="text-3xl font-bold">{urgentCount}</p>}
            variant={urgentCount ? "critical" : "default"}
          />
          <StatBox
            label="Reputation keys"
            value={<p className="text-3xl font-bold">{configuredReputationCount}</p>}
            note={<p className="text-xs">Lookups remain opt-in</p>}
          />
        </div>

        <div className="rounded-[1.35rem] border border-white/10 bg-zinc-950/45 p-5">
          <p className="text-[10px] font-bold uppercase tracking-[0.24em] text-[#e0b286]">Readout</p>
          <p className="mt-2 text-lg font-semibold leading-7 text-white">{compromiseSignals.summary}</p>
        </div>

        {compromiseSignals.issues.length > 0 && (
          <SignalList
            title="Issues to review"
            items={compromiseSignals.issues}
            icon={<AlertTriangle />}
            variant="warning"
          />
        )}

        {compromiseSignals.strengths.length > 0 && (
          <SignalList
            title="Strengths"
            items={compromiseSignals.strengths}
            icon={<CheckCircle2 />}
            variant="success"
          />
        )}

        {compromiseSignals.indicators.length ? (
          <div className="grid gap-3">
            {compromiseSignals.indicators.map((indicator, index) => (
              <div
                key={`${indicator.category}-${indicator.title}-${index}`}
                className="rounded-[1.35rem] border border-white/10 bg-white/[0.04] px-4 py-4"
              >
                <div className="flex flex-col items-start gap-3 sm:flex-row sm:items-start sm:justify-between">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 text-sm font-semibold text-white">
                      <Fingerprint className="h-4 w-4 text-zinc-400" />
                      {indicator.title}
                    </div>
                    <p className="mt-2 text-sm leading-6 text-zinc-300">{indicator.detail}</p>
                  </div>
                  <div className="flex flex-wrap justify-start gap-2 sm:justify-end">
                    <Badge variant="outline" className={severityClass[indicator.severity]}>
                      {indicator.severity}
                    </Badge>
                    <Badge variant="outline" className="border-white/10 bg-white/[0.06] text-zinc-100">
                      {categoryLabel[indicator.category]}
                    </Badge>
                    <Badge variant="outline" className="border-white/[0.08] bg-white/[0.04] text-zinc-500">
                      {sourceLabel[indicator.source]}
                    </Badge>
                  </div>
                </div>
                {indicator.evidence.length ? (
                  <div className="mt-3 flex flex-wrap gap-2">
                    {indicator.evidence.slice(0, 6).map((item) => (
                      <TruncatedChip
                        key={item}
                        value={item}
                        className="border-white/10 bg-white/[0.04] text-zinc-300"
                        maxWidthClassName="max-w-[18rem]"
                      />
                    ))}
                  </div>
                ) : null}
                {indicator.action ? (
                  <p className="mt-3 rounded-2xl border border-white/10 bg-white/[0.04] px-4 py-3 text-sm leading-6 text-zinc-300">
                    <span className="font-semibold text-zinc-100">Suggested check: </span>
                    {indicator.action}
                  </p>
                ) : null}
              </div>
            ))}
          </div>
        ) : (
          <EmptyState>No passive public IOC-style indicators were generated for this scan.</EmptyState>
        )}

        <SignalList
          title="Collection boundary"
          items={[compromiseSignals.collectionBoundary]}
          icon={<Sparkles />}
          variant="neutral"
        />

        {compromiseSignals.reputationChecks.length > 0 && (
          <SignalList
            title="Reputation providers"
            items={compromiseSignals.reputationChecks.map((check) => `${check.provider}: ${check.summary}`)}
            icon={<Radar />}
            variant="neutral"
          />
        )}
      </CardContent>
    </Card>
  );
};
