import { Bot, ShieldAlert, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { StatBox, StatusAlert, TruncatedChip } from "@/components/ui/panel-primitives";
import { getAiSurfaceClassificationSummary } from "@/lib/aiSurface";
import { AiSurfaceInfo } from "@/types/analysis";

interface AiSurfacePanelProps {
  aiSurface: AiSurfaceInfo;
}

export const AiSurfacePanel = ({ aiSurface }: AiSurfacePanelProps) => {
  const categoryLabel = {
    ai_vendor: "AI vendor",
    support_automation: "Support automation",
    assistant_ui: "Assistant UI",
  } as const;

  const confidenceStyles = {
    high: "bg-white/12 text-zinc-100",
    medium: "bg-zinc-700/40 text-zinc-300",
    low: "bg-[#4f6676]/14 text-[#d6e5ec]",
  } as const;

  const classificationSummary = getAiSurfaceClassificationSummary(aiSurface);

  return (
    <Card className="border-white/10 bg-white/4 shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Bot className="h-5 w-5" />
          AI Surface
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-5">
        <StatBox
          variant="info"
          label="Classification"
          value={<p className="text-lg font-semibold">{classificationSummary}</p>}
        />

        <div className="grid gap-4 md:grid-cols-4">
          <StatBox label="AI detected" value={<p className="text-2xl font-semibold">{aiSurface.detected ? "Yes" : "No"}</p>} />
          <StatBox label="Assistant visible" value={<p className="text-2xl font-semibold">{aiSurface.assistantVisible ? "Yes" : "No"}</p>} />
          <StatBox label="Vendors" value={<p className="text-2xl font-semibold">{aiSurface.vendors.length}</p>} />
          <StatBox label="AI paths" value={<p className="text-2xl font-semibold">{aiSurface.discoveredPaths.length}</p>} />
        </div>

        {aiSurface.vendors.length > 0 && (
          <StatBox
            label="Detected vendors"
            value={
              <div className="grid gap-3">
                {aiSurface.vendors.map((vendor) => (
                  <div key={`${vendor.name}-${vendor.category}`} className="rounded-[1.2rem] border border-white/10 bg-white/4 px-4 py-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-medium text-zinc-50">{vendor.name}</span>
                      <Badge variant="outline">{categoryLabel[vendor.category]}</Badge>
                      <Badge variant="secondary" className={confidenceStyles[vendor.confidence]}>
                        {vendor.confidence} confidence
                      </Badge>
                    </div>
                    <p className="mt-2 text-xs text-zinc-400">{vendor.evidence}</p>
                  </div>
                ))}
              </div>
            }
          />
        )}

        {aiSurface.discoveredPaths.length > 0 && (
          <StatBox
            label="AI-related paths"
            value={
              <div className="flex flex-wrap gap-2">
                {aiSurface.discoveredPaths.map((path) => <TruncatedChip key={path} value={path} />)}
              </div>
            }
          />
        )}

        {(aiSurface.privacySignals.length > 0 || aiSurface.governanceSignals.length > 0) && (
          <div className="grid gap-4 md:grid-cols-2">
            <StatBox
              label="Privacy signals"
              value={
                <div className="space-y-2">
                  {aiSurface.privacySignals.length > 0 ? (
                    aiSurface.privacySignals.map((signal) => (
                      <p key={signal} className="rounded-2xl border border-white/10 bg-white/4 px-3 py-3 text-sm text-zinc-300">
                        {signal}
                      </p>
                    ))
                  ) : (
                    <p className="text-sm text-zinc-400">No AI-related privacy guidance was identified on the fetched page.</p>
                  )}
                </div>
              }
            />
            <StatBox
              label="Governance signals"
              value={
                <div className="space-y-2">
                  {aiSurface.governanceSignals.length > 0 ? (
                    aiSurface.governanceSignals.map((signal) => (
                      <p key={signal} className="rounded-2xl border border-white/10 bg-white/4 px-3 py-3 text-sm text-zinc-300">
                        {signal}
                      </p>
                    ))
                  ) : (
                    <p className="text-sm text-zinc-400">No visible AI governance or human-review language was identified.</p>
                  )}
                </div>
              }
            />
          </div>
        )}

        <div className="space-y-2">
          {aiSurface.strengths.map((strength) => (
            <StatusAlert key={strength} variant="success" icon={<ShieldCheck />}>{strength}</StatusAlert>
          ))}
          {aiSurface.disclosures.map((disclosure) => (
            <StatusAlert key={disclosure} variant="info" icon={<ShieldCheck />}>{disclosure}</StatusAlert>
          ))}
          {aiSurface.issues.map((issue) => (
            <StatusAlert key={issue} variant="warning" icon={<ShieldAlert />}>{issue}</StatusAlert>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};
