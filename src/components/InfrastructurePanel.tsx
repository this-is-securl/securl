import { Cloud, Info, Network } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState, SignalList, StatBox } from "@/components/ui/panel-primitives";
import { InfrastructureInfo } from "@/types/analysis";

interface InfrastructurePanelProps {
  infrastructure: InfrastructureInfo;
}

const sourceLabel = {
  dns: "DNS",
  reverse_dns: "Reverse DNS",
  headers: "Headers",
  technology: "Stack",
} as const;

const categoryClass = {
  cloud: "bg-white/[0.08] text-zinc-100",
  cdn: "bg-white/[0.08] text-zinc-100",
  edge: "bg-[#7f1d1d]/14 text-[#99f6e4]",
  paas: "bg-white/[0.08] text-zinc-100",
  hosting: "bg-[#14b8a6]/18 text-[#99f6e4]",
} as const;

export const InfrastructurePanel = ({ infrastructure }: InfrastructurePanelProps) => (
  <Card className="border-white/10 bg-white/[0.04] shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
    <CardHeader>
      <CardTitle className="flex items-center gap-2">
        <Network className="h-5 w-5 text-[#e0b286]" />
        Infrastructure Read
      </CardTitle>
      <p className="text-sm text-zinc-400">
        Passive hosting and edge-provider inference from DNS, reverse DNS, headers, and detected stack signals.
      </p>
    </CardHeader>
    <CardContent className="space-y-5">
      <div className="grid gap-3 md:grid-cols-3">
        <StatBox label="Providers" value={<p className="text-3xl font-bold">{infrastructure.providers.length}</p>} />
        <StatBox label="Addresses" value={<p className="text-3xl font-bold">{infrastructure.addresses.length}</p>} />
        <StatBox label="CNAMEs" value={<p className="text-3xl font-bold">{infrastructure.cnameTargets.length}</p>} />
      </div>

      {infrastructure.providers.length ? (
        <div className="grid gap-3">
          {infrastructure.providers.map((signal, index) => (
            <div
              key={`${signal.provider}-${signal.source}-${index}`}
              className="rounded-[1.25rem] border border-white/10 bg-zinc-950/45 px-4 py-3"
            >
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-2 font-semibold text-white">
                  <Cloud className="h-4 w-4 text-zinc-400" />
                  {signal.provider}
                </div>
                <div className="flex flex-wrap gap-2">
                  <Badge variant="secondary" className={categoryClass[signal.category]}>
                    {signal.category}
                  </Badge>
                  <Badge variant="secondary" className="bg-white/10 text-zinc-100">
                    {sourceLabel[signal.source]}
                  </Badge>
                </div>
              </div>
              <p className="mt-2 break-words text-sm text-zinc-300">{signal.evidence}</p>
            </div>
          ))}
        </div>
      ) : (
        <EmptyState>No obvious cloud, CDN, edge, or hosting provider was inferred from passive evidence.</EmptyState>
      )}

      <SignalList
        title="Infrastructure read"
        items={[infrastructure.summary]}
        icon={<Info />}
        variant={infrastructure.providers.length ? "success" : "neutral"}
      />
    </CardContent>
  </Card>
);
