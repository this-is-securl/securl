import { ArrowRight, Route, ShieldAlert, ShieldCheck } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { StatusAlert } from "@/components/ui/panel-primitives";
import { getHttpStatusDetails } from "@/lib/httpStatus";
import { RedirectChainInfo, RedirectHop } from "@/types/analysis";

interface RedirectChainProps {
  redirects: RedirectHop[];
  chainAnalysis?: RedirectChainInfo;
}

export const RedirectChain = ({ redirects, chainAnalysis }: RedirectChainProps) => {
  return (
    <Card className="border-white/10 bg-white/4 shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Route className="h-5 w-5" />
          Redirect Chain
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {chainAnalysis && (
          <div className="flex flex-wrap gap-2 text-xs">
            <span className="rounded-full border border-white/10 bg-white/6 px-3 py-1 text-zinc-300">
              {chainAnalysis.totalHops} hop{chainAnalysis.totalHops !== 1 ? "s" : ""}
            </span>
            {chainAnalysis.crossesDomain && (
              <span className="rounded-full border border-amber-500/30 bg-amber-500/8 px-3 py-1 text-amber-200">Cross-domain</span>
            )}
            {chainAnalysis.hasMixedRedirect && (
              <span className="rounded-full border border-rose-500/30 bg-rose-500/8 px-3 py-1 text-rose-200">HTTPS→HTTP hop</span>
            )}
            {chainAnalysis.finalUrl && (
              <span className="max-w-full overflow-hidden break-all rounded-full border border-white/10 bg-white/4 px-3 py-1 text-zinc-400">
                Final: {chainAnalysis.finalUrl}
              </span>
            )}
          </div>
        )}

        {chainAnalysis && (chainAnalysis.issues.length > 0 || chainAnalysis.strengths.length > 0) && (
          <div className="space-y-2">
            {chainAnalysis.strengths.map((strength) => (
              <StatusAlert key={strength} variant="success" icon={<ShieldCheck />}>{strength}</StatusAlert>
            ))}
            {chainAnalysis.issues.map((issue) => (
              <StatusAlert key={issue} variant="warning" icon={<ShieldAlert />}>{issue}</StatusAlert>
            ))}
          </div>
        )}

        {redirects.map((hop, index) => {
          const status = getHttpStatusDetails(hop.statusCode);
          return (
            <div key={`${hop.url}-${index}`} className="rounded-[1.35rem] border border-white/10 bg-white/4 px-4 py-3">
              <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium text-zinc-100">{hop.url}</p>
                  <p className="text-xs text-zinc-400">{hop.secure ? "HTTPS" : "HTTP"}</p>
                </div>
                <div className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-400">
                  <span>Status {hop.statusCode} {status.label}</span>
                  {hop.location && <ArrowRight className="h-3.5 w-3.5" />}
                </div>
              </div>
              <p className="mt-2 text-xs leading-5 text-zinc-400">{status.meaning}</p>
              {hop.location && <p className="mt-3 break-all text-xs text-zinc-400">Location: {hop.location}</p>}
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
};
