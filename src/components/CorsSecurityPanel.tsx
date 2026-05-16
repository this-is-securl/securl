import { ArrowLeftRight, ShieldAlert, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { StatBox, StatusAlert } from "@/components/ui/panel-primitives";
import { CorsSecurityInfo } from "@/types/analysis";

interface CorsSecurityPanelProps {
  corsSecurity: CorsSecurityInfo;
}

export const CorsSecurityPanel = ({ corsSecurity }: CorsSecurityPanelProps) => {
  return (
    <Card className="border-white/10 bg-white/[0.04] shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ArrowLeftRight className="h-5 w-5" />
          CORS & Methods
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-5">
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <StatBox label="Allowed origin" value={<p className="break-all text-sm text-zinc-200">{corsSecurity.allowedOrigin ?? "None"}</p>} />
          <StatBox label="Credentials" value={<p className="text-sm text-zinc-200">{corsSecurity.allowCredentials ?? "Not set"}</p>} />
          <StatBox label="OPTIONS status" value={<p className="text-sm text-zinc-200">{corsSecurity.optionsStatus || "No response"}</p>} />
          <StatBox label="Vary" value={<p className="break-all text-sm text-zinc-200">{corsSecurity.vary ?? "Not set"}</p>} />
        </div>

        <div className="grid gap-4 md:grid-cols-2">
          <StatBox
            label="Allowed methods"
            value={
              <div className="flex flex-wrap gap-2">
                {corsSecurity.allowMethods.length ? corsSecurity.allowMethods.map((method) => (
                  <Badge key={method} variant="outline">{method}</Badge>
                )) : <span className="text-sm text-zinc-400">None advertised</span>}
              </div>
            }
          />
          <StatBox
            label="Allowed headers"
            value={
              <div className="flex flex-wrap gap-2">
                {corsSecurity.allowHeaders.length ? corsSecurity.allowHeaders.map((header) => (
                  <Badge key={header} variant="outline">{header}</Badge>
                )) : <span className="text-sm text-zinc-400">None advertised</span>}
              </div>
            }
          />
        </div>

        <div className="space-y-2">
          {corsSecurity.strengths.map((strength) => (
            <StatusAlert key={strength} variant="success" icon={<ShieldCheck />}>{strength}</StatusAlert>
          ))}
          {corsSecurity.issues.map((issue) => (
            <StatusAlert key={issue} variant="warning" icon={<ShieldAlert />}>{issue}</StatusAlert>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};
