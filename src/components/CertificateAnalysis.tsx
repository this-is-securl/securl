import { AlertTriangle, Calendar, Fingerprint, LockKeyhole, Shield } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { CertificateResult } from "@/types/analysis";

interface CertificateAnalysisProps {
  certInfo: CertificateResult;
}

export const CertificateAnalysis = ({ certInfo }: CertificateAnalysisProps) => {
  return (
    <Card className="border-white/10 bg-white/4 shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-zinc-100">
          <Shield className="h-5 w-5" />
          TLS Certificate
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {!certInfo.available ? (
          <Alert className="border-amber-500/25 bg-amber-500/8 text-amber-100 [&>svg]:text-[#d89a63]">
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription>{certInfo.issues[0]}</AlertDescription>
          </Alert>
        ) : (
          <>
            <div className="grid gap-4 md:grid-cols-2">
              <div className="rounded-[1.35rem] border border-white/10 bg-white/4 p-4">
                <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-400">Trust</p>
                <div className="mt-2 flex items-center gap-2">
                  <Badge variant={certInfo.valid ? "secondary" : "destructive"} className={certInfo.valid ? "bg-white/8 text-zinc-100" : undefined}>
                    {certInfo.valid ? "Trusted" : "Untrusted"}
                  </Badge>
                  {certInfo.protocol && <Badge variant="outline">{certInfo.protocol}</Badge>}
                </div>
                <p className="mt-3 text-sm text-zinc-300">
                  {certInfo.issuer ? `Issued by ${certInfo.issuer}` : "Issuer not available"}
                </p>
              </div>

              <div className="rounded-[1.35rem] border border-white/10 bg-white/4 p-4">
                <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-400">Expiry</p>
                <div className="mt-2 flex items-center gap-2 text-sm font-medium text-zinc-100">
                  <Calendar className="h-4 w-4" />
                  {certInfo.validTo ?? "Unknown"}
                </div>
                <p className="mt-3 text-sm text-zinc-300">
                  {certInfo.daysRemaining !== null
                    ? `${certInfo.daysRemaining} day${certInfo.daysRemaining === 1 ? "" : "s"} remaining`
                    : "Remaining lifetime unavailable"}
                </p>
              </div>
            </div>

            <div className="grid gap-3 text-sm text-zinc-300">
              <div className="flex items-start gap-2">
                <LockKeyhole className="mt-0.5 h-4 w-4 text-zinc-400" />
                <span>{certInfo.cipher ? `Cipher: ${certInfo.cipher}` : "Cipher not reported"}</span>
              </div>
              <div className="flex items-start gap-2">
                <Fingerprint className="mt-0.5 h-4 w-4 text-zinc-400" />
                <span className="break-all">
                  {certInfo.fingerprint ? `SHA-256 fingerprint: ${certInfo.fingerprint}` : "Fingerprint unavailable"}
                </span>
              </div>
              {certInfo.subject && (
                <p>
                  <span className="font-medium text-zinc-100">Subject:</span> {certInfo.subject}
                </p>
              )}
            </div>

            {certInfo.issues.map((issue) => (
              <Alert key={issue} className="border-amber-500/25 bg-amber-500/8 text-amber-100 [&>svg]:text-[#d89a63]">
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription>{issue}</AlertDescription>
              </Alert>
            ))}
          </>
        )}
      </CardContent>
    </Card>
  );
};
