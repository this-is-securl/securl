import { Info, ShieldAlert, ShieldCheck } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SignalList, StatBox, TruncatedChip } from "@/components/ui/panel-primitives";
import { CtDiscoveryInfo } from "@/types/analysis";

interface CtDiscoveryPanelProps {
  ctDiscovery: CtDiscoveryInfo;
}

export const CtDiscoveryPanel = ({ ctDiscovery }: CtDiscoveryPanelProps) => {
  const reviewItems = ctDiscovery.issues;
  const hasPositiveEvidence = ctDiscovery.strengths.length > 0;
  const strengthItems = [
    ...(hasPositiveEvidence
      ? ctDiscovery.strengths
      : ["CT enrichment did not add any positive coverage signals for this target."]),
    ...(reviewItems.length === 0 ? ["No CT-specific watch points were identified in this scan."] : []),
  ];

  return (
    <Card className="border-white/10 bg-white/[0.04] shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
      <CardHeader>
        <div className="flex items-center justify-between gap-3">
          <CardTitle>Certificate Transparency</CardTitle>
          <div className="rounded-full bg-white/10 px-3 py-1 text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-100">
            {ctDiscovery.subdomains.length} discovered
          </div>
        </div>
        <p className="text-sm text-zinc-400">
          Passive subdomain discovery from public CT logs. This does not touch the target directly.
        </p>
      </CardHeader>
      <CardContent className="space-y-6">
        <p className="text-sm leading-6 text-zinc-300">{ctDiscovery.coverageSummary}</p>

        <div className="grid gap-4 md:grid-cols-3">
          <StatBox label="Queried domain" value={<p className="text-lg font-semibold">{ctDiscovery.queriedDomain}</p>} />
          <StatBox label="Distinct subdomains" value={<p className="text-lg font-semibold">{ctDiscovery.subdomains.length}</p>} />
          <StatBox label="Wildcard entries" value={<p className="text-lg font-semibold">{ctDiscovery.wildcardEntries.length}</p>} />
        </div>

        <div className="grid gap-6 xl:grid-cols-[1.2fr_0.8fr]">
          <div className="rounded-[1.25rem] border border-white/10 bg-zinc-950/45 p-4">
            <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-400">Discovered hosts</p>
            {ctDiscovery.subdomains.length > 0 ? (
              <div className="mt-3 flex max-h-56 flex-wrap gap-2 overflow-y-auto pr-1">
                {ctDiscovery.subdomains.map((host) => (
                  <TruncatedChip key={host} value={host} variant="secondary" className="bg-white/10 text-zinc-100 shadow-sm" />
                ))}
              </div>
            ) : (
              <p className="mt-3 text-sm text-zinc-400">No distinct subdomains were returned from CT logs for this domain.</p>
            )}
          </div>

          <div className="rounded-[1.25rem] border border-white/10 bg-zinc-950/45 p-4">
            <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-400">Wildcard coverage</p>
            {ctDiscovery.wildcardEntries.length > 0 ? (
              <ul className="mt-3 space-y-2 text-sm text-zinc-300">
                {ctDiscovery.wildcardEntries.map((entry) => (
                  <li key={entry}>*.{entry}</li>
                ))}
              </ul>
            ) : (
              <p className="mt-3 text-sm text-zinc-400">No wildcard certificate entries were surfaced.</p>
            )}
            <p className="mt-4 text-xs text-zinc-500">Source: {ctDiscovery.sourceUrl}</p>
          </div>
        </div>

        <div className="grid gap-6 xl:grid-cols-2">
          <div className="rounded-[1.25rem] border border-white/10 bg-zinc-950/45 p-4">
            <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-400">Prioritized hosts</p>
            {ctDiscovery.prioritizedHosts.length > 0 ? (
              <ul className="mt-3 space-y-3 text-sm text-zinc-300">
                {ctDiscovery.prioritizedHosts.slice(0, 8).map((host) => (
                  <li key={host.host} className="rounded-[1.1rem] border border-white/10 bg-white/[0.04] p-3">
                    <div className="flex min-w-0 items-center justify-between gap-3">
                      <span className="min-w-0 truncate font-semibold text-white" title={host.host}>{host.host}</span>
                      <span className="text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-400">
                        {host.priority} {host.category}
                      </span>
                    </div>
                    <p className="mt-2 text-xs text-zinc-400">{host.evidence}</p>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="mt-3 text-sm text-zinc-400">No high-signal host categories were derived from CT results.</p>
            )}
          </div>

          <div className="rounded-[1.25rem] border border-white/10 bg-zinc-950/45 p-4">
            <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-400">Sampled coverage</p>
            {ctDiscovery.sampledHosts.length > 0 ? (
              <ul className="mt-3 space-y-3 text-sm text-zinc-300">
                {ctDiscovery.sampledHosts.map((host) => (
                  <li key={host.host} className="rounded-[1.1rem] border border-white/10 bg-white/[0.04] p-3">
                    <div className="flex min-w-0 items-center justify-between gap-3">
                      <span className="min-w-0 truncate font-semibold text-white" title={host.host}>{host.host}</span>
                      <span className="text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-400">
                        {host.reachable ? `${host.statusCode} ${host.responseKind}` : "unreachable"}
                      </span>
                    </div>
                    <p className="mt-2 text-xs text-zinc-400">{host.note}</p>
                    {host.suspectedTakeover ? (
                      <p className="mt-2 text-xs font-medium text-amber-200">
                        Possible takeover: {host.suspectedTakeover.provider} ({host.suspectedTakeover.confidence} confidence)
                      </p>
                    ) : null}
                    {host.cnameTargets.length ? (
                      <p className="mt-2 break-all text-xs text-zinc-400">CNAME: {host.cnameTargets.join(", ")}</p>
                    ) : null}
                    {(host.identityProvider || host.edgeProvider) && (
                      <p className="mt-2 text-xs text-zinc-400">
                        {host.identityProvider ? `IdP: ${host.identityProvider}` : "IdP: none"}
                        {host.edgeProvider ? ` | Edge: ${host.edgeProvider}` : ""}
                      </p>
                    )}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="mt-3 text-sm text-zinc-400">No best-effort CT host sampling was recorded.</p>
            )}
          </div>
        </div>

        <div className={`grid gap-3 ${reviewItems.length ? "xl:grid-cols-2" : ""}`}>
          <SignalList
            title={hasPositiveEvidence ? "Strengths" : "Evidence read"}
            items={strengthItems}
            icon={hasPositiveEvidence ? <ShieldCheck /> : <Info />}
            variant={hasPositiveEvidence ? "success" : "neutral"}
          />
          {reviewItems.length ? (
            <div className="rounded-[1.25rem] border border-amber-400/30 bg-amber-400/10 p-4">
              <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-amber-200">Watch points</p>
              <ul className="mt-3 space-y-2 text-sm text-amber-50">
                {reviewItems.map((item) => (
                  <li key={item} className="flex gap-2">
                    <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
                    {item}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </div>
      </CardContent>
    </Card>
  );
};
