import { Info, ShieldCheck, ShieldAlert } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SignalList, StatBox, TruncatedChip } from "@/components/ui/panel-primitives";
import { IdentityProviderInfo } from "@/types/analysis";

interface IdentityProviderPanelProps {
  identityProvider: IdentityProviderInfo;
}

export const IdentityProviderPanel = ({ identityProvider }: IdentityProviderPanelProps) => {
  const reviewItems = identityProvider.issues;
  const hasPositiveEvidence = identityProvider.strengths.length > 0;
  const strengthItems = [
    ...(hasPositiveEvidence
      ? identityProvider.strengths
      : ["No strong identity-provider signals were confirmed from passive evidence."]),
    ...(reviewItems.length === 0 && identityProvider.detected
      ? ["No immediate passive OAuth/OIDC watch points were identified."]
      : []),
    ...(reviewItems.length === 0 && !identityProvider.detected
      ? ["No passive OAuth/OIDC watch points were identified."]
      : []),
  ];

  return (
    <Card className="border-white/10 bg-white/[0.04] shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
      <CardHeader>
        <div className="flex items-center justify-between gap-3">
          <CardTitle>Identity Provider</CardTitle>
          <div className="rounded-full bg-white/10 px-3 py-1 text-[11px] font-bold uppercase tracking-[0.2em] text-slate-100">
            {identityProvider.detected ? "Detected" : "Not detected"}
          </div>
        </div>
        <p className="text-sm text-slate-400">
          Passive OAuth and OIDC exposure signals from redirects, login paths, and public well-known endpoints.
        </p>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <StatBox label="Provider" value={<p className="text-lg font-semibold">{identityProvider.provider ?? "No obvious provider"}</p>} />
          <StatBox label="Protocol" value={<p className="text-lg font-semibold">{identityProvider.protocol ? identityProvider.protocol.toUpperCase() : "Not inferred"}</p>} />
          <StatBox label="Redirect origins" value={<p className="text-lg font-semibold">{identityProvider.redirectOrigins.length}</p>} />
          <StatBox label="OIDC config" value={<p className="text-sm font-semibold">{identityProvider.openIdConfigurationUrl ? "Publicly reachable" : "Not observed"}</p>} />
        </div>

        <div className="grid gap-6 xl:grid-cols-2">
          <div className="space-y-3">
            <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-400">Observed endpoints</p>
            <div className="space-y-2 rounded-[1.25rem] border border-white/10 bg-slate-950/45 p-4 text-sm text-slate-300">
              <p className="break-words"><span className="font-semibold text-white">Issuer:</span> {identityProvider.issuer ?? "Not discovered"}</p>
              <p className="break-words"><span className="font-semibold text-white">Authorization:</span> {identityProvider.authorizationEndpoint ?? "Not discovered"}</p>
              <p className="break-words"><span className="font-semibold text-white">Token:</span> {identityProvider.tokenEndpoint ?? "Not discovered"}</p>
              <p className="break-words"><span className="font-semibold text-white">End session:</span> {identityProvider.endSessionEndpoint ?? "Not discovered"}</p>
              <p><span className="font-semibold text-white">Tenant brand:</span> {identityProvider.tenantBrand ?? "Not discovered"}</p>
              <p><span className="font-semibold text-white">Tenant region:</span> {identityProvider.tenantRegion ?? "Not discovered"}</p>
            </div>
          </div>

          <div className="space-y-3">
            <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-slate-400">Discovery</p>
            <div className="rounded-[1.25rem] border border-white/10 bg-slate-950/45 p-4 text-sm text-slate-300">
              {identityProvider.redirectOrigins.length > 0 && (
                <div className="mb-3">
                  <p className="font-semibold text-white">Redirect origins</p>
                  <ul className="mt-2 flex flex-wrap gap-2">
                    {identityProvider.redirectOrigins.map((origin) => (
                      <li key={origin}><TruncatedChip value={origin} /></li>
                    ))}
                  </ul>
                </div>
              )}
              {identityProvider.authHostCandidates.length > 0 && (
                <div className="mb-3">
                  <p className="font-semibold text-white">Auth-like hosts</p>
                  <ul className="mt-2 flex flex-wrap gap-2">
                    {identityProvider.authHostCandidates.map((host) => (
                      <li key={host}><TruncatedChip value={host} /></li>
                    ))}
                  </ul>
                </div>
              )}
              {identityProvider.loginPaths.length > 0 && (
                <div className="mb-3">
                  <p className="font-semibold text-white">Login-like paths</p>
                  <ul className="mt-2 flex flex-wrap gap-2">
                    {identityProvider.loginPaths.map((path) => (
                      <li key={path}><TruncatedChip value={path} /></li>
                    ))}
                  </ul>
                </div>
              )}
              {identityProvider.wellKnownEndpoints.length > 0 && (
                <div className="mb-3">
                  <p className="font-semibold text-white">Well-known endpoints</p>
                  <ul className="mt-2 flex flex-wrap gap-2">
                    {identityProvider.wellKnownEndpoints.map((endpoint) => (
                      <li key={endpoint}><TruncatedChip value={endpoint} /></li>
                    ))}
                  </ul>
                </div>
              )}
              {identityProvider.tenantSignals.length > 0 && (
                <div>
                  <p className="font-semibold text-white">Tenant clues</p>
                  <ul className="mt-2 space-y-1">
                    {identityProvider.tenantSignals.map((signal) => (
                      <li key={signal}>{signal}</li>
                    ))}
                  </ul>
                </div>
              )}
              {identityProvider.redirectUriSignals.length > 0 && (
                <div>
                  <p className="font-semibold text-white">Public redirect URI signals</p>
                  <ul className="mt-2 flex flex-wrap gap-2">
                    {identityProvider.redirectUriSignals.map((signal) => (
                      <li key={signal}><TruncatedChip value={signal} /></li>
                    ))}
                  </ul>
                </div>
              )}
              {identityProvider.redirectOrigins.length === 0 &&
                identityProvider.authHostCandidates.length === 0 &&
                identityProvider.loginPaths.length === 0 &&
                identityProvider.redirectUriSignals.length === 0 && <p>No passive IdP or OAuth discovery artifacts were recorded.</p>}
            </div>
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
