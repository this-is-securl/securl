import { ArrowRight, Route } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { getHttpStatusDetails } from "@/lib/httpStatus";
import { RedirectHop } from "@/types/analysis";

interface RedirectChainProps {
  redirects: RedirectHop[];
}

export const RedirectChain = ({ redirects }: RedirectChainProps) => {
  return (
    <Card className="border-white/10 bg-white/[0.04] shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Route className="h-5 w-5" />
          Redirect Chain
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {redirects.map((hop, index) => {
          const status = getHttpStatusDetails(hop.statusCode);
          return (
            <div key={`${hop.url}-${index}`} className="rounded-[1.35rem] border border-white/10 bg-white/[0.04] px-4 py-3">
              <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium text-slate-100">{hop.url}</p>
                  <p className="text-xs text-slate-400">{hop.secure ? "HTTPS" : "HTTP"}</p>
                </div>
                <div className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-[0.2em] text-slate-400">
                  <span>Status {hop.statusCode} {status.label}</span>
                  {hop.location && <ArrowRight className="h-3.5 w-3.5" />}
                </div>
              </div>
              <p className="mt-2 text-xs leading-5 text-slate-400">{status.meaning}</p>
              {hop.location && <p className="mt-3 break-all text-xs text-slate-400">Location: {hop.location}</p>}
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
};
