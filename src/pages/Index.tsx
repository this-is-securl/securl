import { Clock3, Layers3, ShieldCheck, Sparkles } from "lucide-react";
import { MonitoredTargetsPanel } from "@/components/MonitoredTargetsPanel";
import { UrlForm } from "@/components/UrlForm";
import { buildReportWorkspaceSections } from "@/lib/reportWorkspace";
import { useScanWorkspace } from "@/hooks/useScanWorkspace";

const Index = () => {
  const appVersionLabel = __APP_VERSION__ && __APP_VERSION__ !== "0.0.0" ? `app ${__APP_VERSION__}` : null;
  const buildDateLabel = (() => {
    const parsed = new Date(__BUILD_DATE__);
    return Number.isNaN(parsed.getTime())
      ? null
      : parsed.toLocaleString(undefined, {
          year: "numeric",
          month: "short",
          day: "2-digit",
          hour: "2-digit",
          minute: "2-digit",
        });
  })();
  const buildLabel = __BUILD_SHA__ !== "unknown" ? `build ${__BUILD_SHA__}` : buildDateLabel ? `built ${buildDateLabel}` : null;
  const coreLabel = `core ${__CORE_VERSION__}`;
  const {
    isLoading,
    scanStage,
    analysisData,
    recentScans,
    history,
    historyDiff,
    monitoredTargets,
    activeRecentScanUrl,
    activeReportSection,
    areaScores,
    monitoredViews,
    setActiveReportSection,
    handleAnalyze,
    saveCurrentAsMonitored,
    removeMonitoredTarget,
    runTargetScan,
    runDueScans,
    exportReport,
    exportMarkdown,
    exportHtml,
    exportPdf,
  } = useScanWorkspace();

  const reportSections = analysisData
    ? buildReportWorkspaceSections({
        analysisData,
        historyDiff,
        history,
        areaScores,
        exportPdf,
        exportMarkdown,
        exportHtml,
        exportReport,
      })
    : [];

  const activeSection = reportSections.find((section) => section.key === activeReportSection) ?? reportSections[0];

  return (
    <div className="min-h-screen overflow-hidden bg-[#070b14] text-slate-100">
      <div className="pointer-events-none fixed inset-0 -z-10 bg-[radial-gradient(circle_at_18%_0%,rgba(181,106,44,0.16),transparent_34%),radial-gradient(circle_at_82%_12%,rgba(122,166,182,0.12),transparent_30%),linear-gradient(180deg,#070b14_0%,#0b1220_48%,#101827_100%)]" />
      <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <section className="rounded-[2.25rem] border border-white/10 bg-white/[0.05] p-5 shadow-2xl shadow-black/30 ring-1 ring-white/[0.04] backdrop-blur-xl sm:p-7 lg:p-8">
          <div className="grid gap-8 lg:grid-cols-[1.2fr_0.8fr] lg:items-start">
            <div className="space-y-6">
              <div className="space-y-5">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="inline-flex items-center gap-2 rounded-full border border-[#b56a2c]/25 bg-[#b56a2c]/12 px-3 py-1 text-xs font-semibold uppercase tracking-[0.2em] text-[#f0d5bc]">
                    <Sparkles className="h-3.5 w-3.5" />
                    SecURL
                  </div>
                  <div className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-slate-950/35 px-3 py-1 text-[11px] font-medium tracking-[0.16em] text-slate-400">
                    <span>{coreLabel}</span>
                    {buildLabel ? (
                      <>
                        <span className="text-slate-600">/</span>
                        <span>{buildLabel}</span>
                      </>
                    ) : null}
                    {appVersionLabel ? (
                      <>
                        <span className="text-slate-600">/</span>
                        <span>{appVersionLabel}</span>
                      </>
                    ) : null}
                  </div>
                </div>
                <div className="space-y-4">
                  <h1 className="max-w-3xl text-4xl font-semibold tracking-[-0.055em] text-white sm:text-5xl lg:text-6xl">
                    Public posture, quietly interpreted.
                  </h1>
                  <p className="max-w-2xl text-base leading-7 text-slate-400 sm:text-lg">
                    SecURL is posture-first: a passive, low-noise read of headers, TLS, redirects, cookies, trust signals, and visible client code, with a fast healthcheck up front and evidence when you need to go deeper.
                  </p>
                </div>
              </div>
              <UrlForm
                onSubmit={handleAnalyze}
                isLoading={isLoading}
                initialValue="example.com"
                scanStage={scanStage}
              />
            </div>

            <div className="h-full rounded-[1.8rem] border border-white/10 bg-slate-950/35 p-5 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)] sm:p-6">
              <div className="mb-4 flex items-center justify-between gap-3">
                <p className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-400">What this scan checks</p>
                <ShieldCheck className="h-5 w-5 text-[#d89a63]" />
              </div>
              <div className="space-y-3">
                {[
                  "Headers, redirects, TLS, cookies, and browser isolation controls with confidence-labeled findings.",
                  "DNS and email posture, security.txt, HSTS preload signals, and passive page-risk analysis.",
                  "Posture-first output: quieter than broad reconnaissance, clearer than raw scanner noise.",
                ].map((item, index) => (
                  <div
                    key={item}
                    className={`rounded-[1.2rem] px-4 py-4 text-sm leading-7 text-slate-200 ${
                      index < 2 ? "border-b border-white/10" : ""
                    }`}
                  >
                    {item}
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="mt-5 rounded-[1.7rem] border border-white/10 bg-white/[0.04] p-4 sm:p-5">
            <div className="grid gap-5 xl:grid-cols-[minmax(0,0.82fr)_minmax(0,1.18fr)] xl:items-start">
              <div className={`space-y-3 ${recentScans.length > 0 ? "" : "hidden"}`}>
                <div className="flex items-center gap-2 text-sm font-semibold text-slate-200">
                  <Clock3 className="h-4 w-4 text-[#d89a63]" />
                  Recent scans
                </div>
                <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-1">
                  {recentScans.slice(0, 3).map((scan) => (
                    <button
                      key={scan.url}
                      type="button"
                      onClick={() => void handleAnalyze(scan.url, "recent")}
                      disabled={isLoading}
                      className={`rounded-[1.2rem] border px-4 py-3 text-left shadow-sm transition duration-300 ${
                        activeRecentScanUrl === scan.url
                          ? "border-[#b56a2c]/45 bg-[#b56a2c]/12 shadow-[0_18px_36px_-28px_rgba(181,106,44,0.6)]"
                          : "border-white/10 bg-slate-950/45 hover:-translate-y-0.5 hover:border-[#b56a2c]/25 hover:bg-white/[0.08]"
                      } ${isLoading ? "cursor-wait" : ""}`}
                      aria-busy={activeRecentScanUrl === scan.url}
                    >
                      <div className="flex items-center justify-between gap-3">
                        <span className="truncate text-sm font-medium text-slate-100">{scan.url}</span>
                        <div className="flex items-center gap-2">
                          {activeRecentScanUrl === scan.url ? (
                            <span className="inline-flex h-2 w-2 rounded-full bg-[#d89a63] shadow-[0_0_0_4px_rgba(181,106,44,0.16)]" />
                          ) : null}
                          <span className="text-sm font-semibold uppercase tracking-[0.14em] text-[#f0d5bc]">
                            {activeRecentScanUrl === scan.url ? scanStage?.label ?? "Scanning" : scan.grade}
                          </span>
                        </div>
                      </div>
                      <p className="mt-2 text-xs text-slate-500">{new Date(scan.scannedAt).toLocaleString()}</p>
                    </button>
                  ))}
                </div>
              </div>

              <div className={recentScans.length > 0 ? "border-t border-white/10 pt-5 xl:border-l xl:border-t-0 xl:pt-0 xl:pl-5" : ""}>
                <MonitoredTargetsPanel
                  targets={monitoredViews}
                  currentUrl={analysisData?.finalUrl ?? recentScans[0]?.url ?? null}
                  monitoredCount={monitoredTargets.length}
                  dueCount={monitoredViews.filter((target) => target.due).length}
                  embedded
                  onAddDaily={() => saveCurrentAsMonitored("daily")}
                  onAddWeekly={() => saveCurrentAsMonitored("weekly")}
                  onRunDue={runDueScans}
                  onRunTarget={(url) => void runTargetScan(url, true)}
                  onRemove={removeMonitoredTarget}
                  busy={isLoading}
                />
              </div>
            </div>
          </div>
        </section>

        {analysisData && (
          <section className="mt-6 space-y-4">
            <div className="flex items-center gap-2 px-1 text-sm font-semibold uppercase tracking-[0.18em] text-slate-500">
              <Layers3 className="h-4 w-4" />
              Report workspace
            </div>
            <div className="grid gap-4 xl:grid-cols-[18rem_minmax(0,1fr)] 2xl:grid-cols-[19.5rem_minmax(0,1fr)]">
              <aside className="xl:sticky xl:top-6 xl:self-start">
                <div className="overflow-hidden rounded-[1.75rem] border border-white/10 bg-white/[0.04] shadow-2xl shadow-black/15 ring-1 ring-white/[0.03] backdrop-blur">
                  <div className="border-b border-white/10 px-5 py-4">
                    <p className="text-xs font-semibold uppercase tracking-[0.2em] text-[#d89a63]/80">Sections</p>
                    <p className="mt-2 text-sm leading-6 text-slate-400">
                      Choose a report area to open it in the main workspace.
                    </p>
                  </div>
                  <div className="p-3">
                    <div className="space-y-2">
                      {reportSections.map((section) => {
                        const active = section.key === activeSection?.key;
                        return (
                          <button
                            key={section.key}
                            type="button"
                            onClick={() => setActiveReportSection(section.key)}
                            className={`w-full rounded-[1.1rem] border px-4 py-4 text-left transition duration-300 ${
                              active
                                ? "border-[#b56a2c]/35 bg-[#b56a2c]/12 shadow-[0_12px_28px_-22px_rgba(181,106,44,0.45)]"
                                : "border-transparent bg-transparent hover:border-white/10 hover:bg-white/[0.04] hover:translate-x-1"
                            }`}
                          >
                            <p className={`text-base font-semibold ${active ? "text-white" : "text-slate-200"}`}>
                              {section.title}
                            </p>
                            {active ? (
                              <p className="mt-2 text-sm leading-6 text-slate-400">
                                {section.summary}
                              </p>
                            ) : null}
                          </button>
                        );
                      })}
                    </div>
                  </div>
                </div>
              </aside>

              {activeSection ? (
                <div
                  key={activeSection.key}
                  className="min-w-0 overflow-hidden rounded-[1.75rem] border border-white/10 bg-white/[0.04] shadow-2xl shadow-black/15 ring-1 ring-white/[0.03] backdrop-blur animate-in fade-in-50 slide-in-from-bottom-2 duration-500"
                >
                  <div className="border-b border-white/10 px-5 py-5 sm:px-6">
                    <h2 className="text-2xl font-semibold tracking-[-0.035em] text-white">
                      {activeSection.title}
                    </h2>
                  </div>
                  <div className="bg-white/[0.02] px-4 py-6 text-slate-100 sm:px-6 lg:px-8">
                    {activeSection.content}
                  </div>
                </div>
              ) : null}
            </div>
          </section>
        )}
      </div>
    </div>
  );
};

export default Index;
