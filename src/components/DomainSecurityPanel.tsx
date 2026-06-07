import { Mail, ShieldAlert, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { CodeBlock, StatBox, StatusAlert, TruncatedChip } from "@/components/ui/panel-primitives";
import { DomainSecurityInfo } from "@/types/analysis";

interface DomainSecurityPanelProps {
  domainSecurity: DomainSecurityInfo;
}

const extractBimiLogoUrl = (dns: string | null | undefined): string | null => {
  if (!dns) return null;
  const match = dns.match(/(?:^|;)\s*l=(https:\/\/[^\s;]+)/i);
  return match?.[1] ?? null;
};

const policyBadgeClass = {
  strong: "border-[#4f6676]/35 bg-[#4f6676]/12 text-[#edf3f6]",
  watch: "border-[#7f1d1d]/30 bg-[#7f1d1d]/12 text-[#f0dfcf]",
  weak: "border-amber-500/25 bg-amber-500/8 text-amber-200",
  missing: "border-white/10 bg-white/6 text-zinc-200",
} as const;

const policyLabel = {
  strong: "Strong",
  watch: "Watch",
  weak: "Weak",
  missing: "Missing",
} as const;

export const DomainSecurityPanel = ({ domainSecurity }: DomainSecurityPanelProps) => {
  const emailPolicy = domainSecurity.emailPolicy ?? {
    spf: {
      status: domainSecurity.spf ? "watch" : "missing",
      summary: domainSecurity.spf ? "SPF is present, but this older snapshot does not include parsed policy detail." : "No SPF record was detected at the zone apex.",
    },
    dmarc: {
      status: domainSecurity.dmarc ? "watch" : "missing",
      summary: domainSecurity.dmarc ? "DMARC is present, but this older snapshot does not include parsed policy detail." : "No DMARC record was detected.",
    },
  } as const;
  const spfAllMechanism = "allMechanism" in emailPolicy.spf ? emailPolicy.spf.allMechanism : null;
  const dmarcPolicy = "policy" in emailPolicy.dmarc ? emailPolicy.dmarc.policy : null;
  const dmarcSubdomainPolicy =
    "subdomainPolicy" in emailPolicy.dmarc ? emailPolicy.dmarc.subdomainPolicy : null;
  const dmarcPct = "pct" in emailPolicy.dmarc ? emailPolicy.dmarc.pct : null;
  const dmarcReporting = "reporting" in emailPolicy.dmarc ? emailPolicy.dmarc.reporting : null;

  return (
    <Card className="h-full border-white/10 bg-white/4 shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Mail className="h-5 w-5" />
          Domain & Email Security
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-5">
        <div className="grid gap-4 md:grid-cols-2">
          <StatBox
            label="SPF"
            value={
              <div className="space-y-3 text-sm leading-6 text-zinc-200">
                <div className="flex flex-wrap gap-2">
                  <Badge variant="outline" className={policyBadgeClass[emailPolicy.spf.status]}>
                    {policyLabel[emailPolicy.spf.status]}
                  </Badge>
                  {spfAllMechanism && (
                    <Badge
                      variant="outline"
                      className={
                        spfAllMechanism === "-all"
                          ? "border-emerald-400/25 bg-emerald-400/8 text-emerald-200"
                          : spfAllMechanism === "+all"
                          ? "border-rose-500/30 bg-rose-500/8 text-rose-200"
                          : "border-amber-500/30 bg-amber-500/8 text-amber-200"
                      }
                    >
                      {spfAllMechanism}
                    </Badge>
                  )}
                </div>
                <p>{emailPolicy.spf.summary}</p>
                <p className="overflow-hidden wrap-break-word text-xs text-zinc-400">{domainSecurity.spf ?? "Not found"}</p>
              </div>
            }
          />
          <StatBox
            label="DMARC"
            value={
              <div className="space-y-3 text-sm leading-6 text-zinc-200">
                <div className="flex flex-wrap gap-2">
                  <Badge variant="outline" className={policyBadgeClass[emailPolicy.dmarc.status]}>
                    {policyLabel[emailPolicy.dmarc.status]}
                  </Badge>
                  {dmarcPolicy && (
                    <Badge variant="outline" className="border-white/10 bg-white/6 text-zinc-200">
                      p={dmarcPolicy}
                    </Badge>
                  )}
                  {dmarcSubdomainPolicy && (
                    <Badge variant="outline" className="border-white/10 bg-white/6 text-zinc-200">
                      sp={dmarcSubdomainPolicy}
                    </Badge>
                  )}
                  {dmarcPct !== null && dmarcPct !== undefined && dmarcPct < 100 && (
                    <Badge variant="outline" className="border-amber-500/30 bg-amber-500/8 text-amber-200">
                      pct={dmarcPct}%
                    </Badge>
                  )}
                  {dmarcReporting ? (
                    <Badge variant="outline" className="border-emerald-400/25 bg-emerald-400/8 text-emerald-200">Reporting on</Badge>
                  ) : dmarcPolicy && (
                    <Badge variant="outline" className="border-amber-500/30 bg-amber-500/8 text-amber-200">No rua reporting</Badge>
                  )}
                </div>
                <p>{emailPolicy.dmarc.summary}</p>
                <p className="overflow-hidden wrap-break-word text-xs text-zinc-400">{domainSecurity.dmarc ?? "Not found"}</p>
              </div>
            }
          />
        </div>

        <div className="grid gap-4 md:grid-cols-2">
          <StatBox
            label="MX records"
            value={
              <div className="space-y-2 text-sm leading-6 text-zinc-200">
                {domainSecurity.mxRecords.length ? domainSecurity.mxRecords.map((record) => <p key={record} className="overflow-hidden wrap-break-word">{record}</p>) : <p>None</p>}
              </div>
            }
          />
          <StatBox
            label="CAA records"
            value={
              <div className="space-y-2 text-sm leading-6 text-zinc-200">
                {domainSecurity.caaRecords.length ? domainSecurity.caaRecords.map((record) => <p key={record} className="overflow-hidden wrap-break-word">{record}</p>) : <p>None</p>}
              </div>
            }
          />
        </div>

        <StatBox
          label="DNSSEC"
          value={
            <div className="space-y-2 text-sm leading-6 text-zinc-200">
              <p>Status: {domainSecurity.dnssec.status === "signed" ? "Signed" : domainSecurity.dnssec.status === "not_signed" ? "Not signed" : "Unknown"}</p>
              {domainSecurity.dnssec.dsRecords.length ? (
                domainSecurity.dnssec.dsRecords.map((record) => (
                  <p key={record} className="overflow-hidden wrap-break-word">{record}</p>
                ))
              ) : (
                <p>No DS records detected.</p>
              )}
            </div>
          }
        />

        <StatBox
          label="MTA-STS"
          value={
            <div className="space-y-2 text-sm leading-6 text-zinc-200">
              <p className="overflow-hidden wrap-break-word">DNS: {domainSecurity.mtaSts.dns ?? "Not found"}</p>
              {domainSecurity.mtaSts.policyUrl && <p className="overflow-hidden wrap-break-word">Policy URL: {domainSecurity.mtaSts.policyUrl}</p>}
              {domainSecurity.mtaSts.policy && (
                <CodeBlock>{domainSecurity.mtaSts.policy}</CodeBlock>
              )}
            </div>
          }
        />

        <div className="grid gap-4 md:grid-cols-2">
          <StatBox
            label="TLS-RPT"
            value={
              <div className="space-y-2 text-sm leading-6 text-zinc-200">
                <p>{domainSecurity.tlsRpt?.summary ?? "No TLS-RPT reporting record was detected."}</p>
                <p className="overflow-hidden wrap-break-word text-xs text-zinc-400">
                  {domainSecurity.tlsRpt?.dns ?? "Not found"}
                </p>
              </div>
            }
          />
          <StatBox
            label="BIMI"
            value={
              <div className="space-y-2 text-sm leading-6 text-zinc-200">
                {(() => {
                  const logoUrl = extractBimiLogoUrl(domainSecurity.bimi?.dns);
                  if (!logoUrl) return null;
                  return (
                    <img
                      src={logoUrl}
                      alt="BIMI brand logo"
                      className="mb-2 h-12 w-12 rounded-lg border border-white/10 bg-white/4 object-contain p-1"
                      onError={(e) => { (e.target as HTMLImageElement).style.display = "none"; }}
                    />
                  );
                })()}
                <p>{domainSecurity.bimi?.summary ?? "No BIMI record was detected at the default selector."}</p>
                <p className="overflow-hidden wrap-break-word text-xs text-zinc-400">
                  {domainSecurity.bimi?.dns ?? "Not found"}
                </p>
              </div>
            }
          />
        </div>

        {domainSecurity.emailDeliverabilityScore && (
          <div className="rounded-3xl border border-white/10 bg-zinc-950/45 p-5">
            <p className="text-[10px] font-bold uppercase tracking-[0.24em] text-[#e0b286]">Email deliverability score</p>
            <div className="mt-3 flex items-end gap-4">
              <p className="text-5xl font-black tracking-tighter text-white">{domainSecurity.emailDeliverabilityScore.score}</p>
              <p className="mb-1 text-lg font-black text-zinc-400">/100</p>
              <span className="mb-1 rounded-xl border border-white/10 bg-white/6 px-3 py-1 text-sm font-bold text-zinc-100">
                {domainSecurity.emailDeliverabilityScore.grade}
              </span>
            </div>
            <div className="mt-4 flex flex-wrap gap-2">
              {Object.entries(domainSecurity.emailDeliverabilityScore.breakdown)
                .filter(([, pts]) => pts > 0)
                .map(([label, pts]) => (
                  <span key={label} className="rounded-full border border-emerald-400/20 bg-emerald-400/8 px-3 py-1 text-xs text-emerald-200">
                    {label} +{pts}
                  </span>
                ))}
            </div>
          </div>
        )}

        {domainSecurity.dkim && (
          <StatBox
            label="DKIM"
            value={
              <div className="space-y-3 text-sm leading-6 text-zinc-200">
                <p>{domainSecurity.dkim.summary}</p>
                {domainSecurity.dkim.selectors.length > 0 ? (
                  <div className="flex flex-wrap gap-2">
                    {domainSecurity.dkim.selectors.map((selector) => (
                      <TruncatedChip key={selector} value={selector} />
                    ))}
                  </div>
                ) : domainSecurity.dkim.count === 0 ? (
                  <p className="text-zinc-400">No DKIM records found at common selectors.</p>
                ) : null}
              </div>
            }
          />
        )}

        {domainSecurity.spfDetail && (
          <StatBox
            label="SPF depth"
            value={
              <div className="space-y-3 text-sm leading-6 text-zinc-200">
                <div className="flex flex-wrap gap-2">
                  {domainSecurity.spfDetail.hasPlusAll && (
                    <Badge variant="outline" className="border-rose-500/30 bg-rose-500/8 text-rose-200">⚠ +all (open relay risk)</Badge>
                  )}
                  {domainSecurity.spfDetail.hasTildeAll && (
                    <Badge variant="outline" className="border-amber-500/30 bg-amber-500/8 text-amber-200">~all (softfail)</Badge>
                  )}
                  {domainSecurity.spfDetail.hasMinusAll && (
                    <Badge variant="outline" className="border-emerald-500/30 bg-emerald-500/8 text-emerald-200">-all (reject)</Badge>
                  )}
                  {domainSecurity.spfDetail.hasQuestionAll && (
                    <Badge variant="outline" className="border-amber-500/30 bg-amber-500/8 text-amber-200">?all (neutral — weak)</Badge>
                  )}
                  {domainSecurity.spfDetail.exceedsLookupLimit && (
                    <Badge variant="outline" className="border-rose-500/30 bg-rose-500/8 text-rose-200">Exceeds 10-lookup limit</Badge>
                  )}
                  {domainSecurity.spfDetail.isOverlyPermissive && (
                    <Badge variant="outline" className="border-rose-500/30 bg-rose-500/8 text-rose-200">Overly permissive</Badge>
                  )}
                </div>
                <p className="text-zinc-400">
                  include: mechanisms: {domainSecurity.spfDetail.includeCount}
                  {domainSecurity.emailPolicy && (
                    <> · DNS-querying: {domainSecurity.emailPolicy.spf.dnsLookupMechanisms}/10</>
                  )}
                </p>
              </div>
            }
          />
        )}

        <div className="flex min-w-0 flex-wrap gap-2">
          {domainSecurity.nsRecords.slice(0, 6).map((record) => (
            <Badge key={record} variant="outline" className="max-w-full overflow-hidden break-all text-left">
              {record}
            </Badge>
          ))}
        </div>

        <div className="space-y-2">
          {domainSecurity.strengths.map((strength) => (
            <StatusAlert key={strength} variant="success" icon={<ShieldCheck />}>{strength}</StatusAlert>
          ))}
          {domainSecurity.issues.map((issue) => (
            <StatusAlert key={issue} variant="warning" icon={<ShieldAlert />}>{issue}</StatusAlert>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};
