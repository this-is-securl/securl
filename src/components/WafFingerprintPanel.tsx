import { Info, ShieldAlert, ShieldCheck } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SignalList } from "@/components/ui/panel-primitives";
import { WafFingerprintInfo } from "@/types/analysis";

interface WafFingerprintPanelProps {
  wafFingerprint: WafFingerprintInfo;
}

export const WafFingerprintPanel = ({ wafFingerprint }: WafFingerprintPanelProps) => {
  const reviewItems = wafFingerprint.issues;
  const hasPositiveEvidence = wafFingerprint.strengths.length > 0;
  const strengthItems = [
    ...(hasPositiveEvidence
      ? wafFingerprint.strengths
      : ["No positive WAF or edge-protection evidence was confirmed from passive signals."]),
    ...(reviewItems.length === 0 && wafFingerprint.detected
      ? ["No immediate WAF-specific watch points were identified from passive evidence."]
      : []),
    ...(reviewItems.length === 0 && !wafFingerprint.detected
      ? ["Passive evidence was limited, so absence of a branded match does not prove no WAF or edge control is present."]
      : []),
  ];

  return (
    <Card className="border-white/10 bg-white/4 shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
      <CardHeader>
        <div className="flex items-center justify-between gap-3">
          <CardTitle>WAF & Edge Fingerprint</CardTitle>
          <div className="rounded-full bg-white/10 px-3 py-1 text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-100">
            {wafFingerprint.detected ? "Detected" : "No strong match"}
          </div>
        </div>
        <p className="text-sm text-zinc-400">
          Passive edge and protection-provider inference from response headers, block-page markers, and redirect behavior.
        </p>
      </CardHeader>
      <CardContent className="space-y-6">
        <p className="text-sm leading-6 text-zinc-300">{wafFingerprint.summary}</p>

        <div className="grid gap-6 xl:grid-cols-2">
          <div className="rounded-[1.25rem] border border-white/10 bg-zinc-950/45 p-4">
            <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-400">Providers</p>
            {wafFingerprint.providers.length ? (
              <ul className="mt-3 space-y-3 text-sm text-zinc-300">
                {wafFingerprint.providers.map((provider) => (
                  <li key={`${provider.name}-${provider.evidence}`} className="rounded-[1.1rem] border border-white/10 bg-white/4 p-3">
                    <div className="flex items-center justify-between gap-3">
                      <span className="font-semibold text-white">{provider.name}</span>
                      <span className="text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-400">
                        {provider.detection} · {provider.confidence}
                      </span>
                    </div>
                    <p className="mt-2 text-xs text-zinc-400">{provider.evidence}</p>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="mt-3 text-sm text-zinc-400">No branded WAF or edge-protection provider was conclusively identified.</p>
            )}
          </div>

          <div className="rounded-[1.25rem] border border-white/10 bg-zinc-950/45 p-4">
            <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-400">Edge evidence</p>
            {wafFingerprint.edgeSignals.length ? (
              <ul className="mt-3 space-y-2 text-sm text-zinc-300">
                {wafFingerprint.edgeSignals.map((signal) => (
                  <li key={signal}>{signal}</li>
                ))}
              </ul>
            ) : (
              <p className="mt-3 text-sm text-zinc-400">No additional edge-network clues were recorded.</p>
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
