import { Cookie, ShieldAlert, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { StatBox, StatusAlert } from "@/components/ui/panel-primitives";
import { CookieAnalysisInfo } from "@/types/analysis";

interface CookieAnalysisPanelProps {
  cookieAnalysis: CookieAnalysisInfo;
}

const sameSiteBadgeClass = (sameSite: "Strict" | "Lax" | "None" | "missing"): string => {
  switch (sameSite) {
    case "Strict":
      return "border-emerald-400/30 bg-emerald-400/[0.08] text-emerald-200";
    case "Lax":
      return "border-zinc-500/30 bg-zinc-500/[0.08] text-zinc-200";
    case "None":
      return "border-rose-500/30 bg-rose-500/[0.08] text-rose-200";
    case "missing":
      return "border-amber-500/30 bg-amber-500/[0.08] text-amber-200";
  }
};

export const CookieAnalysisPanel = ({ cookieAnalysis }: CookieAnalysisPanelProps) => {
  return (
    <Card className="border-white/10 bg-white/[0.04] shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Cookie className="h-5 w-5" />
          Cookie Analysis
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-5">
        <div className="grid grid-cols-2 gap-3 md:grid-cols-3 lg:grid-cols-5">
          <StatBox label="Cookies" value={<p className="text-3xl font-bold">{cookieAnalysis.cookies.length}</p>} />
          <StatBox
            label="Missing Secure"
            value={<p className="text-3xl font-bold">{cookieAnalysis.cookiesWithoutSecure}</p>}
            variant={cookieAnalysis.cookiesWithoutSecure > 0 ? "warning" : "default"}
          />
          <StatBox
            label="Missing HttpOnly"
            value={<p className="text-3xl font-bold">{cookieAnalysis.cookiesWithoutHttpOnly}</p>}
            variant={cookieAnalysis.cookiesWithoutHttpOnly > 0 ? "warning" : "default"}
          />
          <StatBox
            label="No SameSite"
            value={<p className="text-3xl font-bold">{cookieAnalysis.cookiesWithoutSameSite}</p>}
            variant={cookieAnalysis.cookiesWithoutSameSite > 0 ? "warning" : "default"}
          />
          <StatBox
            label="SameSite=None"
            value={<p className="text-3xl font-bold">{cookieAnalysis.cookiesWithSameSiteNone}</p>}
            variant={cookieAnalysis.cookiesWithSameSiteNone > 0 ? "warning" : "default"}
          />
        </div>

        {cookieAnalysis.cookies.length > 0 && (
          <StatBox
            label="Per-cookie detail"
            value={
              <div className="grid gap-3 md:grid-cols-2">
                {cookieAnalysis.cookies.map((cookie) => (
                  <div
                    key={cookie.name}
                    className="rounded-[1.15rem] border border-white/10 bg-zinc-950/45 px-4 py-3"
                  >
                    <p className="font-semibold text-zinc-50 break-all">
                      {cookie.hasHostPrefix && (
                        <span className="mr-1 text-xs font-bold text-[#d89a63]">__Host-</span>
                      )}
                      {cookie.hasSecurePrefix && !cookie.hasHostPrefix && (
                        <span className="mr-1 text-xs font-bold text-[#d89a63]">__Secure-</span>
                      )}
                      {cookie.name}
                    </p>
                    <div className="mt-2 flex flex-wrap gap-2">
                      <Badge
                        variant="outline"
                        className={cookie.hasSecure ? "border-emerald-400/30 bg-emerald-400/[0.08] text-emerald-200" : "border-rose-500/30 bg-rose-500/[0.08] text-rose-200"}
                      >
                        {cookie.hasSecure ? "Secure" : "No Secure"}
                      </Badge>
                      <Badge
                        variant="outline"
                        className={cookie.hasHttpOnly ? "border-emerald-400/30 bg-emerald-400/[0.08] text-emerald-200" : "border-rose-500/30 bg-rose-500/[0.08] text-rose-200"}
                      >
                        {cookie.hasHttpOnly ? "HttpOnly" : "No HttpOnly"}
                      </Badge>
                      <Badge
                        variant="outline"
                        className={sameSiteBadgeClass(cookie.sameSite)}
                      >
                        SameSite={cookie.sameSite}
                      </Badge>
                      {cookie.isSessionCookie && (
                        <Badge variant="outline" className="border-zinc-500/30 bg-zinc-500/[0.08] text-zinc-300">
                          Session
                        </Badge>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            }
          />
        )}

        <div className="space-y-2">
          {cookieAnalysis.strengths.map((strength) => (
            <StatusAlert key={strength} variant="success" icon={<ShieldCheck />}>{strength}</StatusAlert>
          ))}
          {cookieAnalysis.issues.map((issue) => (
            <StatusAlert key={issue} variant="warning" icon={<ShieldAlert />}>{issue}</StatusAlert>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};
