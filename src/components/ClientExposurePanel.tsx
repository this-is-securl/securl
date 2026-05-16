import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState, StatusAlert, TruncatedChip } from "@/components/ui/panel-primitives";
import { HtmlSecurityInfo } from "@/types/analysis";
import { Cpu, ShieldAlert } from "lucide-react";

interface ClientExposurePanelProps {
  htmlSecurity: HtmlSecurityInfo;
}

export const ClientExposurePanel = ({ htmlSecurity }: ClientExposurePanelProps) => {
  if (!htmlSecurity.clientExposureSignals.length) {
    return (
      <Card className="border-white/10 bg-white/[0.04] shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Cpu className="h-5 w-5" />
            Client Config & API Exposure
          </CardTitle>
        </CardHeader>
        <CardContent>
          <EmptyState>
            No obvious client-side config leaks or public API exposure clues were detected from the fetched page.
          </EmptyState>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="border-white/10 bg-white/[0.04] shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Cpu className="h-5 w-5" />
          Client Config & API Exposure
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {htmlSecurity.clientExposureSignals.map((signal) => (
          <div key={`${signal.category}-${signal.title}`} className="rounded-[1.35rem] border border-white/10 bg-white/[0.04] p-4">
            <div className="flex flex-wrap items-center gap-2">
              <p className="font-semibold text-zinc-50">{signal.title}</p>
              <Badge variant={signal.severity === "warning" ? "destructive" : "secondary"}>
                {signal.severity}
              </Badge>
              <Badge variant="outline">{signal.category.replace(/_/g, " ")}</Badge>
            </div>
            <p className="mt-3 text-sm text-zinc-300">{signal.detail}</p>
            <div className="mt-3 flex flex-wrap gap-2">
              {signal.evidence.map((item) => (
                <TruncatedChip key={item} value={item} />
              ))}
            </div>
          </div>
        ))}

        {htmlSecurity.clientExposureSignals.some((signal) => signal.severity === "warning") ? (
          <StatusAlert variant="warning" icon={<ShieldAlert />}>
            Environment-like naming or unexpectedly explicit client configuration deserves a quick review before deeper testing.
          </StatusAlert>
        ) : null}
      </CardContent>
    </Card>
  );
};
