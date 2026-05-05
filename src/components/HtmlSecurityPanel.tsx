import { CodeXml, ShieldAlert, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { StatBox, StatusAlert, TruncatedChip } from "@/components/ui/panel-primitives";
import { HtmlSecurityInfo } from "@/types/analysis";

interface HtmlSecurityPanelProps {
  htmlSecurity: HtmlSecurityInfo;
}

export const HtmlSecurityPanel = ({ htmlSecurity }: HtmlSecurityPanelProps) => {
  const warningLeakSignals = htmlSecurity.passiveLeakSignals.filter((signal) => signal.severity === "warning");
  const visibleFirstPartyPaths = htmlSecurity.firstPartyPaths.slice(0, 8);
  const hiddenFirstPartyPathCount = Math.max(htmlSecurity.firstPartyPaths.length - visibleFirstPartyPaths.length, 0);
  const visibleSameSiteHosts = htmlSecurity.sameSiteHosts.slice(0, 8);
  const hiddenSameSiteHostCount = Math.max(htmlSecurity.sameSiteHosts.length - visibleSameSiteHosts.length, 0);
  const visibleTechnologies = htmlSecurity.detectedTechnologies.slice(0, 6);
  const hiddenTechnologyCount = Math.max(htmlSecurity.detectedTechnologies.length - visibleTechnologies.length, 0);
  const visibleLibraryFingerprints = htmlSecurity.libraryFingerprints.slice(0, 5);
  const hiddenLibraryFingerprintCount = Math.max(htmlSecurity.libraryFingerprints.length - visibleLibraryFingerprints.length, 0);
  const apiExposureSignals = htmlSecurity.clientExposureSignals.filter((signal) => signal.category === "api_endpoint");
  const configExposureSignals = htmlSecurity.clientExposureSignals.filter(
    (signal) => signal.category === "config" || signal.category === "environment" || signal.category === "service",
  );
  const analyticsTechnologies = htmlSecurity.detectedTechnologies.filter((technology) => technology.category === "network");
  const securityTechnologies = htmlSecurity.detectedTechnologies.filter((technology) => technology.category === "security");
  const frameworkTechnologies = htmlSecurity.detectedTechnologies.filter(
    (technology) => technology.category === "frontend" || technology.category === "hosting",
  );
  const clientCodeSignalRows = [
    {
      label: "Framework / stack",
      value: frameworkTechnologies.length
        ? frameworkTechnologies.map((technology) => technology.version ? `${technology.name} ${technology.version}` : technology.name)
        : ["No obvious framework markers surfaced from the fetched page."],
    },
    {
      label: "Analytics / client vendors",
      value: analyticsTechnologies.length || securityTechnologies.length
        ? [...analyticsTechnologies, ...securityTechnologies]
            .slice(0, 6)
            .map((technology) => technology.name)
        : ["No prominent analytics or client-side trust vendors were inferred from visible assets."],
    },
    {
      label: "API / config clues",
      value: apiExposureSignals.length || configExposureSignals.length
        ? [...apiExposureSignals, ...configExposureSignals]
            .slice(0, 6)
            .map((signal) => signal.title)
        : ["No obvious public API or client configuration clues were surfaced from markup."],
    },
    {
      label: "Version hints",
      value: visibleLibraryFingerprints.length
        ? visibleLibraryFingerprints.map((fingerprint) => `${fingerprint.packageName} ${fingerprint.version}`)
        : ["No explicit client-library version markers were detected."],
    },
  ];

  return (
    <Card className="border-white/10 bg-white/[0.04] shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <CodeXml className="h-5 w-5" />
          Passive Page Inspection
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-5">
        <StatBox
          label="Client code signals"
          value={
            <div className="grid gap-3 md:grid-cols-2">
              {clientCodeSignalRows.map((row) => (
                <div key={row.label} className="rounded-[1.15rem] border border-white/10 bg-slate-950/45 px-4 py-4">
                  <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">{row.label}</p>
                  <div className="mt-3 flex flex-wrap gap-2">
                    {row.value.map((item) => (
                      <TruncatedChip key={`${row.label}-${item}`} value={item} />
                    ))}
                  </div>
                </div>
              ))}
            </div>
          }
          note={
            htmlSecurity.detectedTechnologies.length || htmlSecurity.clientExposureSignals.length || htmlSecurity.libraryFingerprints.length ? (
              <p className="text-xs text-slate-400">
                Derived from visible client assets, markup, and versioned resource hints. These signals help with surface intelligence, not exploit proof.
              </p>
            ) : null
          }
        />

        <div className="grid gap-4 [grid-template-columns:repeat(auto-fit,minmax(9.75rem,1fr))]">
          <StatBox
            label="Page title"
            className="sm:col-span-2"
            value={<p className="line-clamp-2 text-base font-semibold leading-7">{htmlSecurity.pageTitle || "Unavailable"}</p>}
          />
          <StatBox label="Forms" value={<p className="text-2xl font-semibold">{htmlSecurity.forms.length}</p>} />
          <StatBox label="External script domains" value={<p className="text-2xl font-semibold">{htmlSecurity.externalScriptDomains.length}</p>} />
          <StatBox label="Same-site hosts" value={<p className="text-2xl font-semibold">{htmlSecurity.sameSiteHosts.length}</p>} />
          <StatBox label="Inline scripts" value={<p className="text-2xl font-semibold">{htmlSecurity.inlineScriptCount}</p>} />
          <StatBox label="Missing SRI" value={<p className="text-2xl font-semibold">{htmlSecurity.missingSriScriptUrls.length}</p>} />
          <StatBox
            label="Passive leak signals"
            value={<p className="text-2xl font-semibold">{htmlSecurity.passiveLeakSignals.length}</p>}
            note={warningLeakSignals.length ? (
              <p className="text-xs text-[#d9b488]">{warningLeakSignals.length} higher-priority review item{warningLeakSignals.length === 1 ? "" : "s"}</p>
            ) : null}
          />
          <StatBox
            label="Library risk signals"
            value={<p className="text-2xl font-semibold">{htmlSecurity.libraryRiskSignals.length}</p>}
            note={htmlSecurity.libraryFingerprints.length ? (
              <p className="text-xs text-slate-400">{htmlSecurity.libraryFingerprints.length} versioned client librar{htmlSecurity.libraryFingerprints.length === 1 ? "y" : "ies"} observed</p>
            ) : null}
          />
        </div>

        {(htmlSecurity.metaGenerator || htmlSecurity.firstPartyPaths.length > 0 || htmlSecurity.sameSiteHosts.length > 0) && (
          <div className="grid gap-4 md:grid-cols-3">
            <StatBox label="Meta generator" value={<p className="text-sm font-medium text-slate-100">{htmlSecurity.metaGenerator || "Not declared"}</p>} />
            <StatBox
              label="Discovered same-origin paths"
              value={
                <div className="flex max-h-56 min-w-0 flex-wrap gap-2 overflow-y-auto pr-1">
                  {htmlSecurity.firstPartyPaths.length ? (
                    <>
                      {visibleFirstPartyPaths.map((path) => <TruncatedChip key={path} value={path} />)}
                      {hiddenFirstPartyPathCount > 0 && (
                        <Badge variant="secondary" className="rounded-full px-3 py-1">
                          +{hiddenFirstPartyPathCount} more
                        </Badge>
                      )}
                    </>
                  ) : (
                    <span className="text-sm text-slate-400">No same-origin page links were discovered passively.</span>
                  )}
                </div>
              }
            />
            <StatBox
              label="Referenced same-site hosts"
              value={
                <div className="flex max-h-56 min-w-0 flex-wrap gap-2 overflow-y-auto pr-1">
                  {htmlSecurity.sameSiteHosts.length ? (
                    <>
                      {visibleSameSiteHosts.map((host) => <TruncatedChip key={host} value={host} />)}
                      {hiddenSameSiteHostCount > 0 && (
                        <Badge variant="secondary" className="rounded-full px-3 py-1">
                          +{hiddenSameSiteHostCount} more
                        </Badge>
                      )}
                    </>
                  ) : (
                    <span className="text-sm text-slate-400">No sibling same-site hosts were referenced by the fetched page.</span>
                  )}
                </div>
              }
            />
          </div>
        )}

        {(htmlSecurity.detectedTechnologies.length > 0 || htmlSecurity.libraryFingerprints.length > visibleLibraryFingerprints.length) && (
          <div className="grid gap-4 md:grid-cols-2">
            {htmlSecurity.detectedTechnologies.length > 0 && (
              <StatBox
                label="Detected technologies"
                value={
                  <div className="flex flex-wrap gap-2">
                    {visibleTechnologies.map((technology) => (
                      <TruncatedChip
                        key={`${technology.name}-${technology.category}`}
                        value={technology.version ? `${technology.name} ${technology.version}` : technology.name}
                      />
                    ))}
                    {hiddenTechnologyCount > 0 && (
                      <Badge variant="secondary" className="rounded-full px-3 py-1">
                        +{hiddenTechnologyCount} more
                      </Badge>
                    )}
                  </div>
                }
              />
            )}
            {htmlSecurity.libraryFingerprints.length > visibleLibraryFingerprints.length && (
              <StatBox
                label="Additional versioned libraries"
                value={
                  <div className="flex flex-wrap gap-2">
                    {visibleLibraryFingerprints.map((fingerprint) => (
                      <TruncatedChip
                        key={`${fingerprint.packageName}-${fingerprint.version}`}
                        value={`${fingerprint.packageName} ${fingerprint.version}`}
                      />
                    ))}
                    {hiddenLibraryFingerprintCount > 0 && (
                      <Badge variant="secondary" className="rounded-full px-3 py-1">
                        +{hiddenLibraryFingerprintCount} more
                      </Badge>
                    )}
                  </div>
                }
              />
            )}
          </div>
        )}

        {htmlSecurity.forms.length > 0 && (
          <StatBox
            label="Forms"
            value={
              <div className="space-y-2">
                {htmlSecurity.forms.map((form, index) => (
                  <div key={`${form.action ?? "self"}-${index}`} className="rounded-[1.15rem] border border-white/10 bg-white/[0.04] p-3 text-sm text-slate-200">
                    <p>Method: {form.method}</p>
                    <p>Action: {form.action ?? "(same page)"}</p>
                    <div className="mt-2 flex flex-wrap gap-2">
                      {form.hasPasswordField && <Badge variant="secondary">Password field</Badge>}
                      {form.insecureSubmission && <Badge variant="destructive">Insecure submit</Badge>}
                    </div>
                  </div>
                ))}
              </div>
            }
          />
        )}

        {(htmlSecurity.externalScriptDomains.length > 0 || htmlSecurity.externalStylesheetDomains.length > 0) && (
          <div className="grid gap-4 md:grid-cols-2">
            <StatBox
              label="Third-party scripts"
              value={
                <div className="flex flex-wrap gap-2">
                  {htmlSecurity.externalScriptDomains.map((domain) => <TruncatedChip key={domain} value={domain} />)}
                </div>
              }
            />
            <StatBox
              label="Third-party stylesheets"
              value={
                <div className="flex flex-wrap gap-2">
                  {htmlSecurity.externalStylesheetDomains.map((domain) => <TruncatedChip key={domain} value={domain} />)}
                </div>
              }
            />
          </div>
        )}

        {htmlSecurity.passiveLeakSignals.length > 0 && (
          <StatBox
            label="Passive leak and fingerprinting signals"
            value={
              <div className="space-y-3">
                {htmlSecurity.passiveLeakSignals.map((signal) => (
                  <div key={`${signal.category}-${signal.title}`} className="rounded-[1.15rem] border border-white/10 bg-white/[0.04] p-4 text-sm text-slate-200">
                    <div className="flex flex-wrap items-center gap-2">
                      <p className="font-semibold text-slate-50">{signal.title}</p>
                      <Badge
                        variant="secondary"
                        className={signal.severity === "warning" ? "bg-[#b56a2c]/16 text-[#f0d5bc]" : "bg-white/[0.08] text-slate-100"}
                      >
                        {signal.severity}
                      </Badge>
                    </div>
                    <p className="mt-2">{signal.detail}</p>
                    <div className="mt-3 flex flex-wrap gap-2">
                      {signal.evidence.map((item) => (
                        <TruncatedChip key={item} value={item} />
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            }
          />
        )}

        {(htmlSecurity.libraryFingerprints.length > 0 || htmlSecurity.libraryRiskSignals.length > 0) && (
          <StatBox
            label="Library version risk"
            value={
              <div className="space-y-3">
                {htmlSecurity.libraryRiskSignals.length ? (
                  htmlSecurity.libraryRiskSignals.map((signal) => (
                    <div key={`${signal.packageName}-${signal.version}`} className="rounded-[1.15rem] border border-white/10 bg-white/[0.04] p-4 text-sm text-slate-200">
                      <div className="flex flex-wrap items-center gap-2">
                        <p className="font-semibold text-slate-50">
                          {signal.packageName} {signal.version}
                        </p>
                        <Badge variant="secondary" className="bg-white/[0.08] text-slate-100">{signal.confidence} confidence</Badge>
                        <Badge variant="secondary" className="bg-[#b56a2c]/16 text-[#f0d5bc]">
                          {signal.vulnerabilities.length} advisor{signal.vulnerabilities.length === 1 ? "y" : "ies"}
                        </Badge>
                      </div>
                      <p className="mt-2 text-slate-300">{signal.evidence}</p>
                      <p className="mt-1 break-all text-xs text-slate-400">{signal.sourceUrl}</p>
                      <div className="mt-3 space-y-2">
                        {signal.vulnerabilities.map((item) => (
                          <div key={item.id} className="rounded-[1rem] border border-white/10 bg-slate-950/45 px-3 py-2">
                            <p className="font-medium text-slate-50">
                              {item.id}
                              {item.aliases.length ? ` • ${item.aliases.join(", ")}` : ""}
                            </p>
                            <p className="mt-1 text-slate-300">{item.summary}</p>
                            <p className="mt-1 text-xs uppercase tracking-[0.18em] text-slate-400">Severity: {item.severity}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="rounded-[1.15rem] border border-white/10 bg-white/[0.04] p-4 text-sm text-slate-300">
                    Explicitly versioned client libraries were detected, but no matching OSV advisories were returned.
                  </div>
                )}
              </div>
            }
          />
        )}

        <div className="space-y-2">
          {htmlSecurity.strengths.map((strength) => (
            <StatusAlert key={strength} variant="success" icon={<ShieldCheck />}>{strength}</StatusAlert>
          ))}
          {htmlSecurity.issues.map((issue) => (
            <StatusAlert key={issue} variant="warning" icon={<ShieldAlert />}>{issue}</StatusAlert>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};
