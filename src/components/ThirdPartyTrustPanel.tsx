import { Boxes, ShieldAlert, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { StatBox, StatusAlert } from "@/components/ui/panel-primitives";
import { ThirdPartyTrustInfo } from "@/types/analysis";

interface ThirdPartyTrustPanelProps {
  thirdPartyTrust: ThirdPartyTrustInfo;
}

const riskStyles = {
  low: "bg-white/8 text-zinc-100",
  medium: "bg-[#7f1d1d]/14 text-zinc-300",
  high: "bg-zinc-700/40 text-zinc-300",
} as const;

const categoryLabel = {
  analytics: "Analytics",
  consent: "Consent",
  support: "Support",
  ai: "AI",
  session_replay: "Session replay",
  payments: "Payments",
  social: "Social",
  ads: "Ads",
  cdn: "CDN",
  security: "Security",
  other: "Other",
} as const;

export const ThirdPartyTrustPanel = ({ thirdPartyTrust }: ThirdPartyTrustPanelProps) => {
  const highlightedProviders = [...thirdPartyTrust.providers]
    .sort((left, right) => {
      const riskRank = { high: 0, medium: 1, low: 2 } as const;
      return riskRank[left.risk] - riskRank[right.risk];
    })
    .slice(0, 6);
  const footprintLabel =
    thirdPartyTrust.totalProviders === 0 ? "Minimal" : thirdPartyTrust.totalProviders <= 5 ? "Moderate" : "Broad";

  return (
    <Card className="border-white/10 bg-white/4 shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Boxes className="h-5 w-5" />
          Third-Party Trust
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-5">
        <StatBox
          variant="info"
          label="Classification"
          value={<p className="text-lg font-semibold">{thirdPartyTrust.summary}</p>}
        />

        <div className="grid gap-4 md:grid-cols-3">
          <StatBox label="Providers" value={<p className="text-2xl font-semibold">{thirdPartyTrust.totalProviders}</p>} />
          <StatBox label="High risk" value={<p className="text-2xl font-semibold">{thirdPartyTrust.highRiskProviders}</p>} />
          <StatBox label="Footprint" value={<p className="text-2xl font-semibold">{footprintLabel}</p>} />
        </div>

        {highlightedProviders.length > 0 && (
          <StatBox
            label="Highlighted providers"
            value={
              <div className="grid gap-3">
                {highlightedProviders.map((provider) => (
                  <div key={provider.domain} className="rounded-[1.35rem] border border-white/10 bg-white/4 px-4 py-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-medium text-zinc-50">{provider.name}</span>
                      <Badge variant="outline">{categoryLabel[provider.category]}</Badge>
                      <Badge variant="secondary" className={riskStyles[provider.risk]}>
                        {provider.risk} risk
                      </Badge>
                    </div>
                    <p className="mt-2 truncate text-sm text-zinc-300" title={provider.domain}>{provider.domain}</p>
                    <p className="mt-1 text-xs text-zinc-400">{provider.evidence}</p>
                  </div>
                ))}
                {thirdPartyTrust.providers.length > highlightedProviders.length && (
                  <p className="text-sm text-zinc-400">
                    Showing the most important {highlightedProviders.length} providers from a total of {thirdPartyTrust.providers.length}.
                  </p>
                )}
              </div>
            }
          />
        )}

        <div className="space-y-2">
          {thirdPartyTrust.strengths.map((strength) => (
            <StatusAlert key={strength} variant="success" icon={<ShieldCheck />}>{strength}</StatusAlert>
          ))}
          {thirdPartyTrust.issues.map((issue) => (
            <StatusAlert key={issue} variant="warning" icon={<ShieldAlert />}>{issue}</StatusAlert>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};
