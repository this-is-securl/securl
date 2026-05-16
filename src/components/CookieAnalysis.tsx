import { Cookie, ShieldAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EmptyState, StatusAlert } from "@/components/ui/panel-primitives";
import { CookieResult } from "@/types/analysis";

interface CookieAnalysisProps {
  cookies: CookieResult[];
}

const riskStyles: Record<CookieResult["risk"], string> = {
  low: "bg-[#4f6676]/18 text-[#d9e4ea]",
  medium: "bg-[#7f1d1d]/14 text-[#99f6e4]",
  high: "bg-[#14b8a6]/16 text-[#99f6e4]",
};

export const CookieAnalysis = ({ cookies }: CookieAnalysisProps) => {
  return (
    <Card className="border-white/10 bg-white/[0.04] shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Cookie className="h-5 w-5" />
          Cookie Security
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {!cookies.length ? (
          <EmptyState>No `Set-Cookie` headers were returned on the scanned response.</EmptyState>
        ) : (
          <>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Flags</TableHead>
                  <TableHead>Scope</TableHead>
                  <TableHead>Risk</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {cookies.map((cookie) => (
                <TableRow key={cookie.name} className="align-top border-white/10 hover:bg-white/[0.02]">
                    <TableCell className="font-medium text-zinc-50">{cookie.name}</TableCell>
                    <TableCell className="space-y-2">
                      <div className="flex flex-wrap gap-2">
                        <Badge variant={cookie.secure ? "default" : "destructive"}>
                          Secure {cookie.secure ? "on" : "off"}
                        </Badge>
                        <Badge variant={cookie.httpOnly ? "default" : "destructive"}>
                          HttpOnly {cookie.httpOnly ? "on" : "off"}
                        </Badge>
                        <Badge variant={cookie.sameSite ? "outline" : "destructive"}>
                          SameSite {cookie.sameSite ?? "missing"}
                        </Badge>
                      </div>
                    </TableCell>
                    <TableCell className="text-sm text-zinc-300">
                      <div>{cookie.domain ? `Domain ${cookie.domain}` : "Host-only"}</div>
                      <div>{cookie.path ? `Path ${cookie.path}` : "Default path"}</div>
                      <div>{cookie.expires ? `Expires ${cookie.expires}` : "Session cookie"}</div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="secondary" className={riskStyles[cookie.risk]}>
                        {cookie.risk} risk
                      </Badge>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>

            <div className="space-y-2">
              {cookies.flatMap((cookie) =>
                cookie.issues.map((issue) => (
                  <StatusAlert
                    key={`${cookie.name}-${issue}`}
                    variant="critical"
                    icon={<ShieldAlert />}
                  >
                    <span className="font-medium">{cookie.name}</span>: {issue}
                  </StatusAlert>
                )),
              )}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
};
