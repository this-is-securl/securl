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
  edge: "bg-[#7f1d1d]/14 text-zinc-300",
  paas: "bg-white/[0.08] text-zinc-100",
  hosting: "bg-zinc-700/40 text-zinc-300",
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
        <StatBox
          label="IP addresses"
          value={
            infrastructure.addresses.length ? (
              <div className="flex flex-wrap gap-1.5">
                {infrastructure.addresses.map((addr) => (
                  <span key={addr} className="rounded-full border border-white/10 bg-white/[0.06] px-2.5 py-0.5 font-mono text-xs text-zinc-200">{addr}</span>
                ))}
              </div>
            ) : (
              <p className="text-sm text-zinc-400">None resolved</p>
            )
          }
        />
        <StatBox
          label="CNAME targets"
          value={
            infrastructure.cnameTargets.length ? (
              <div className="flex flex-wrap gap-1.5">
                {infrastructure.cnameTargets.map((cname) => (
                  <span key={cname} className="max-w-full overflow-hidden break-all rounded-full border border-white/10 bg-white/[0.06] px-2.5 py-0.5 font-mono text-xs text-zinc-200">{cname}</span>
                ))}
              </div>
            ) : (
              <p className="text-sm text-zinc-400">None</p>
            )
          }
        />
      </div>

      {infrastructure.reverseDns && infrastructure.reverseDns.length > 0 && (
        <StatBox
          label="Reverse DNS"
          value={
            <div className="flex flex-wrap gap-1.5">
              {infrastructure.reverseDns.map((ptr) => (
                <span key={ptr} className="max-w-full overflow-hidden break-all rounded-full border border-white/10 bg-white/[0.06] px-2.5 py-0.5 font-mono text-xs text-zinc-300">{ptr}</span>
              ))}
            </div>
          }
        />
      )}

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

      {infrastructure.waf && (
        <div className="rounded-[1.25rem] border border-white/10 bg-zinc-950/45 px-4 py-4">
          <div className="flex items-center justify-between gap-3">
            <p className="text-[10px] font-bold uppercase tracking-[0.24em] text-zinc-500">WAF / Edge Protection</p>
            <span className={`rounded-full px-3 py-1 text-[11px] font-bold uppercase tracking-[0.15em] ${infrastructure.waf.detected ? "bg-emerald-400/10 text-emerald-300" : "bg-white/[0.06] text-zinc-400"}`}>
              {infrastructure.waf.detected ? `Detected · ${infrastructure.waf.provider ?? "Unknown provider"}` : "No match"}
            </span>
          </div>
          <p className="mt-2 text-sm text-zinc-300">{infrastructure.waf.evidence}</p>
          <p className="mt-1 text-xs text-zinc-500">Confidence: {infrastructure.waf.confidence}</p>
        </div>
      )}

      {infrastructure.protocol && (
        <div className="rounded-[1.25rem] border border-white/10 bg-zinc-950/45 px-4 py-4">
          <p className="text-[10px] font-bold uppercase tracking-[0.24em] text-zinc-500">Protocol</p>
          <div className="mt-2 flex flex-wrap gap-2">
            <span className="rounded-full border border-white/10 bg-white/[0.06] px-3 py-1 text-xs text-zinc-200">
              {infrastructure.protocol.http === "unknown" ? "HTTP version unknown" : infrastructure.protocol.http}
            </span>
            {infrastructure.protocol.http3Advertised && (
              <span className="rounded-full border border-emerald-400/25 bg-emerald-400/[0.10] px-3 py-1 text-xs text-emerald-200">
                HTTP/3 advertised
              </span>
            )}
            {infrastructure.protocol.altSvc && (
              <span className="max-w-full overflow-hidden break-all rounded-full border border-white/[0.08] bg-white/[0.04] px-3 py-1 text-xs text-zinc-400">
                {infrastructure.protocol.altSvc}
              </span>
            )}
          </div>
        </div>
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
