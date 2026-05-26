import { Activity, Clock3, Layers3, Sparkles } from "lucide-react";
import { GRADE_PALETTE } from "@/components/SecurityGrade";
import { toast } from "sonner";
import { AuthCard } from "@/components/AuthCard";
import { MonitoredTargetsPanel } from "@/components/MonitoredTargetsPanel";
import { UrlForm } from "@/components/UrlForm";
import { buildReportWorkspaceSections } from "@/lib/reportWorkspace";
import { ReportSectionNav } from "@/components/report/ReportSectionNav";
import { useAuthSession } from "@/hooks/useAuthSession";
import { useScanWorkspace } from "@/hooks/useScanWorkspace";
import { OutputPreview } from "@/components/landing/OutputPreview";
import { CapabilityStrip } from "@/components/landing/CapabilityStrip";

// ── Mini ring preview (hero right column, pre-scan) ──────────────────────────
const MINI_R    = 74;
const MINI_SIZE = 174;
const MINI_CIRC = parseFloat((2 * Math.PI * MINI_R).toFixed(2));
const MINI_SCORE = 81;
const MINI_OFF  = parseFloat((MINI_CIRC * (1 - MINI_SCORE / 100)).toFixed(2));
const MINI_COLOR = "#3b82f6"; // grade B — vivid blue

const HeroPreviewCard = () => (
  <div className="relative h-full overflow-hidden rounded-[1.8rem] border border-white/10 bg-zinc-950/35 p-5 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)] sm:p-6">
    {/* Grade glow */}
    <div
      className="pointer-events-none absolute inset-0"
      style={{
        background:
          "radial-gradient(ellipse 260px 200px at 50% 38%, rgba(37,99,235,0.13) 0%, transparent 70%)",
      }}
    />

    {/* Label */}
    <div className="relative mb-4 flex items-center justify-between">
      <p className="text-[10px] font-bold uppercase tracking-[0.2em] text-zinc-500">Sample result</p>
      <span className="inline-flex items-center gap-1.5 rounded-full border border-[#2563eb]/20 bg-[#2563eb]/10 px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-[0.12em] text-[#93c5fd]">
        Grade B
      </span>
    </div>

    {/* Ring */}
    <div className="relative flex flex-col items-center">
      <div className="relative" style={{ width: MINI_SIZE, height: MINI_SIZE }}>
        <div
          className="pointer-events-none absolute inset-0 rounded-full"
          style={{ boxShadow: `0 0 48px 0 rgba(37,99,235,0.22)` }}
        />
        <svg
          viewBox={`0 0 ${MINI_SIZE} ${MINI_SIZE}`}
          width={MINI_SIZE}
          height={MINI_SIZE}
          xmlns="http://www.w3.org/2000/svg"
        >
          <circle
            cx={MINI_SIZE / 2} cy={MINI_SIZE / 2} r={MINI_R}
            fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="14"
          />
          <circle
            cx={MINI_SIZE / 2} cy={MINI_SIZE / 2} r={MINI_R}
            fill="none" stroke={MINI_COLOR} strokeWidth="14"
            strokeLinecap="round"
            strokeDasharray={MINI_CIRC}
            strokeDashoffset={MINI_OFF}
            transform={`rotate(-90 ${MINI_SIZE / 2} ${MINI_SIZE / 2})`}
            filter={`drop-shadow(0 0 10px ${MINI_COLOR}99)`}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center gap-1">
          <span
            className="font-black leading-none tracking-[-0.05em]"
            style={{ fontSize: 62, color: MINI_COLOR }}
          >
            B
          </span>
          <span
            className="mt-0.5 inline-flex rounded-full px-2.5 py-0.5 text-[9px] font-bold uppercase tracking-[0.18em]"
            style={{ color: MINI_COLOR, background: `${MINI_COLOR}18`, border: `1px solid ${MINI_COLOR}30` }}
          >
            Good posture
          </span>
        </div>
      </div>

      {/* Domain */}
      <p className="mt-3 font-mono text-xs text-zinc-400">portswigger.net</p>
    </div>

    {/* Finding badges */}
    <div className="relative mt-5 flex flex-wrap justify-center gap-2">
      {[
        { label: "COOP missing",   sev: "warning" },
        { label: "DNSSEC off",     sev: "warning" },
        { label: "security.txt",   sev: "info"    },
      ].map(({ label, sev }) => (
        <span
          key={label}
          className="rounded-full border px-2.5 py-1 text-[10px] font-semibold"
          style={
            sev === "warning"
              ? { background: "rgba(217,119,6,0.10)", borderColor: "rgba(217,119,6,0.25)", color: "#fbbf24" }
              : { background: "rgba(100,116,139,0.08)", borderColor: "rgba(100,116,139,0.20)", color: "#94a3b8" }
          }
        >
          {label}
        </span>
      ))}
    </div>

    {/* Caption */}
    <p className="relative mt-4 text-center text-[11px] text-zinc-600">
      This is what your scan produces
    </p>
  </div>
);

// ── Main page ─────────────────────────────────────────────────────────────────
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
  const buildLabel =
    __BUILD_SHA__ !== "unknown"
      ? `build ${__BUILD_SHA__}`
      : buildDateLabel
        ? `built ${buildDateLabel}`
        : null;
  const coreLabel = `core ${__CORE_VERSION__}`;

  const {
    authSession,
    isAuthenticated,
    isLoading: authLoading,
    isSubmitting: authSubmitting,
    mode: authMode,
    setMode: setAuthMode,
    signIn,
    signUp,
    signOut,
  } = useAuthSession();

  const authScopeKey = authSession?.user.id ?? null;

  const {
    isLoading,
    scanStage,
    analysisData,
    currentScanId,
    recentScans,
    history,
    historyDiff,
    monitoredTargets,
    activeRecentScanUrl,
    activeReportSection,
    currentScanWasCached,
    areaScores,
    monitoredViews,
    setActiveReportSection,
    handleAnalyze,
    openRecentScan,
    saveCurrentAsMonitored,
    removeMonitoredTarget,
    runTargetScan,
    runDueScans,
    exportReport,
    exportMarkdown,
    exportPdf,
  } = useScanWorkspace({ authScopeKey });

  const reportSections = analysisData
    ? buildReportWorkspaceSections({
        analysisData,
        currentScanWasCached,
        historyDiff,
        history,
        areaScores,
        exportPdf,
        exportMarkdown,
        exportReport,
      })
    : [];

  const activeSection =
    reportSections.find((section) => section.key === activeReportSection) ?? reportSections[0];

  const hasHistory = recentScans.length > 0 || monitoredTargets.length > 0;

  return (
    <div className="min-h-screen overflow-hidden bg-[#070b14] text-zinc-100">
      <div
        className="pointer-events-none fixed inset-0 -z-10"
        style={{
          background:
            "radial-gradient(circle at 18% 0%, rgba(181,106,44,0.14), transparent 34%)," +
            "radial-gradient(circle at 82% 12%, rgba(122,166,182,0.10), transparent 30%)," +
            "linear-gradient(180deg, #070b14 0%, #0b1220 48%, #101827 100%)",
        }}
      />

      <div className="mx-auto max-w-7xl px-4 py-10 sm:px-6 sm:py-12 lg:px-8">

        {/* ── Hero card ─────────────────────────────────────────────────── */}
        <section className="rounded-[2.5rem] border border-white/[0.09] bg-white/[0.04] p-6 shadow-[0_48px_120px_-40px_rgba(0,0,0,0.7),0_1px_0_rgba(255,255,255,0.05)_inset] backdrop-blur-md sm:p-8 lg:p-10">
          <div className="grid grid-cols-1 gap-10 lg:grid-cols-[1.3fr_0.7fr] lg:items-start">

            {/* Left: headline + form */}
            <div className="space-y-6">
              <div className="space-y-5">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <a
                    href="https://securl.online"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-2 rounded-full border border-[#b56a2c]/30 bg-[#b56a2c]/[0.12] px-3 py-1 text-xs font-semibold uppercase tracking-[0.2em] text-[#f0d5bc] transition-colors hover:bg-[#b56a2c]/20"
                  >
                    <Sparkles className="h-3.5 w-3.5" />
                    SecURL
                  </a>
                  <div
                    title={[coreLabel, buildLabel, appVersionLabel].filter(Boolean).join(" / ")}
                    className="inline-flex cursor-default items-center gap-1.5 rounded-full border border-white/[0.07] bg-zinc-950/25 px-2.5 py-0.5 text-[10px] font-medium tracking-[0.12em] text-zinc-600 opacity-50 hover:opacity-100 transition-opacity"
                  >
                    <span>v{__CORE_VERSION__}</span>
                  </div>
                </div>

                <div className="space-y-5">
                  <h1 className="max-w-3xl text-3xl font-black tracking-[-0.06em] text-white sm:text-5xl lg:text-6xl">
                    See what<br className="hidden sm:block" /> attackers see.
                  </h1>
                  <p className="max-w-lg text-lg font-semibold leading-8 text-zinc-200">
                    Paste a URL. Get a letter grade, ranked findings, and a clear path to fix —
                    <span className="text-[#d89a63]"> in under 30 seconds.</span>
                  </p>
                </div>
              </div>

              <UrlForm
                onSubmit={handleAnalyze}
                isLoading={isLoading}
                initialValue=""
                scanStage={scanStage}
              />
            </div>

            {/* Right: preview card (pre-scan) or recent scan nav (post-scan) */}
            {analysisData ? (
              <div className="h-full rounded-[1.8rem] border border-white/10 bg-zinc-950/35 p-5 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)] sm:p-6">
                <div className="mb-4 flex items-center gap-2 text-sm font-semibold text-zinc-200">
                  <Clock3 className="h-4 w-4 text-[#d89a63]" />
                  Recent scans
                </div>
                <div className="flex flex-col gap-3">
                  {recentScans.slice(0, 4).map((scan) => (
                    <button
                      key={scan.id ?? scan.url}
                      type="button"
                      onClick={() => void openRecentScan(scan)}
                      disabled={isLoading}
                      className={`rounded-[1.2rem] border px-4 py-3 text-left shadow-sm transition duration-300 ${
                        activeRecentScanUrl === (scan.id ?? scan.url)
                          ? "border-[#b56a2c]/45 bg-[#b56a2c]/[0.12] shadow-[0_18px_36px_-28px_rgba(181,106,44,0.35)]"
                          : "border-white/10 bg-zinc-950/45 hover:-translate-y-0.5 hover:border-[#b56a2c]/25 hover:bg-white/[0.08]"
                      } ${isLoading ? "cursor-wait" : ""}`}
                    >
                      <div className="flex flex-col items-start gap-2 sm:flex-row sm:items-center sm:justify-between sm:gap-3">
                        <span className="truncate text-sm font-medium text-zinc-100">{scan.url}</span>
                        <span
                          className="text-sm font-bold uppercase tracking-[0.14em]"
                          style={{
                            color: activeRecentScanUrl === (scan.id ?? scan.url)
                              ? "#f0d5bc"
                              : (GRADE_PALETTE[scan.grade ?? "U"] ?? GRADE_PALETTE.U).textColor,
                          }}
                        >
                          {activeRecentScanUrl === (scan.id ?? scan.url)
                            ? scanStage?.label ?? "Opening"
                            : scan.grade}
                        </span>
                      </div>
                      <p className="mt-1 text-xs text-zinc-500">
                        {new Date(scan.scannedAt).toLocaleString()}
                      </p>
                    </button>
                  ))}
                  {recentScans.length === 0 && (
                    <p className="text-sm text-zinc-500">No recent scans yet.</p>
                  )}
                </div>
              </div>
            ) : (
              <HeroPreviewCard />
            )}
          </div>
        </section>

        {/* ── Report workspace (post-scan) ──────────────────────────────── */}
        {analysisData && (
          <section className="mt-10 space-y-6">
            <div className="flex items-center gap-2.5 px-1">
              <Layers3 className="h-4 w-4 text-[#d89a63]" />
              <span className="text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-400">
                Report workspace
              </span>
              <span className="h-px flex-1 bg-white/[0.06]" />
            </div>
            <div className="space-y-10">
              <div className="space-y-2">
                {currentScanId && (
                  <div className="flex justify-end">
                    <button
                      type="button"
                      onClick={() => {
                        navigator.clipboard.writeText(`${window.location.origin}/report/${currentScanId}`);
                        toast.success("Link copied to clipboard");
                      }}
                      className="flex items-center gap-1.5 rounded-xl border border-white/10 bg-white/[0.05] px-3 py-2 text-xs font-semibold text-zinc-400 transition hover:border-[#b56a2c]/30 hover:bg-[#b56a2c]/10 hover:text-[#d89a63]"
                      title="Copy shareable link"
                    >
                      <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.368 2.684 3 3 0 00-5.368-2.684z" />
                      </svg>
                      Share
                    </button>
                  </div>
                )}
                <ReportSectionNav
                  sections={reportSections}
                  activeKey={activeSection?.key}
                  onChange={(key) => setActiveReportSection(key)}
                />
              </div>

              {activeSection ? (
                <div
                  key={activeSection.key}
                  className="min-w-0 overflow-hidden rounded-[2rem] border border-white/[0.09] bg-white/[0.04] shadow-[0_40px_96px_-24px_rgba(0,0,0,0.75),0_1px_0_rgba(255,255,255,0.07)_inset] animate-in fade-in-50 slide-in-from-bottom-2 duration-500"
                >
                  <div className="border-b border-white/[0.08] px-4 py-6 sm:px-10 sm:py-8">
                    <div className="flex items-center gap-2.5">
                      {activeSection.icon && (
                        <activeSection.icon className="h-3.5 w-3.5 text-[#d89a63]" />
                      )}
                      {(activeSection.badge ?? activeSection.context) ? (
                        <p className="text-[10px] font-bold uppercase tracking-[0.24em] text-zinc-500">
                          {activeSection.badge ?? activeSection.context}
                        </p>
                      ) : null}
                    </div>
                    <h2 className="mt-2.5 text-xl font-black tracking-[-0.04em] text-white sm:text-[1.85rem]">
                      {activeSection.title}
                    </h2>
                    <p className="mt-2 max-w-2xl text-sm leading-relaxed text-zinc-300">
                      {activeSection.summary}
                    </p>
                  </div>
                  <div className="px-4 py-6 text-zinc-100 sm:px-10 sm:py-10">
                    {activeSection.content}
                  </div>
                </div>
              ) : null}
            </div>
          </section>
        )}

        {/* ── Landing content (pre-scan only) ───────────────────────────── */}
        {!analysisData && (
          <div className="mt-8 space-y-10">

            {/* 1 — Output preview */}
            <section>
              <div className="mb-6 text-center">
                <p className="mb-3 text-[11px] font-bold uppercase tracking-[0.22em] text-[#d89a63]">
                  What you get
                </p>
                <h2 className="text-3xl font-black tracking-[-0.04em] text-white sm:text-4xl">
                  Not a list of headers. A verdict.
                </h2>
                <p className="mx-auto mt-3 max-w-xl text-sm leading-6 text-zinc-300">
                  Every scan returns a graded posture assessment with ranked findings, consequence
                  context, and specific remediation steps — structured for action, not auditing.
                </p>
              </div>
              <OutputPreview />
            </section>

            {/* 2 — Differentiation band */}
            <section className="rounded-[1.75rem] border border-white/[0.08] bg-white/[0.03] px-4 py-8 text-center shadow-[0_1px_0_rgba(255,255,255,0.05)_inset] sm:px-8 sm:py-14">
              <p className="mb-4 text-[11px] font-bold uppercase tracking-[0.22em] text-zinc-500">
                Why SecURL
              </p>
              <h2 className="text-3xl font-black tracking-[-0.05em] text-white sm:text-4xl lg:text-[3.25rem] lg:leading-[1.1]">
                Security tools give you data.
                <br />
                <span className="text-[#d89a63]">SecURL gives you a read.</span>
              </h2>
              <p className="mx-auto mt-5 max-w-lg text-base font-medium leading-7 text-zinc-300">
                No agents. No configuration. No credentials. Just how your site looks to an informed
                external observer — graded, ranked, and ready to act on.
              </p>
              <div className="mx-auto mt-9 grid max-w-md grid-cols-2 gap-3 sm:grid-cols-3 sm:gap-6">
                {[
                  { value: "7",    label: "Posture areas"      },
                  { value: "~20s", label: "To a graded result" },
                  { value: "PDF",  label: "Export included"    },
                ].map(({ value, label }) => (
                  <div key={label} className="text-center">
                    <p className="text-3xl font-black tracking-[-0.04em] text-white">{value}</p>
                    <p className="mt-1 text-[11px] font-semibold uppercase tracking-[0.14em] text-zinc-500">
                      {label}
                    </p>
                  </div>
                ))}
              </div>
            </section>

            {/* 3 — Capability strip */}
            <section>
              <div className="mb-6">
                <p className="mb-2 text-[11px] font-bold uppercase tracking-[0.22em] text-[#d89a63]">
                  What it checks
                </p>
                <h2 className="text-3xl font-black tracking-[-0.04em] text-white sm:text-4xl">
                  Coverage across seven posture areas
                </h2>
              </div>
              <CapabilityStrip />
            </section>

            {/* 4 — Account + history section */}
            <section>
              <div className="mb-6">
                <p className="mb-2 text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-500">
                  Save your work
                </p>
                <h2 className="text-xl font-black tracking-[-0.03em] text-white">
                  Keep scans, history, and monitoring targets across sessions
                </h2>
                <p className="mt-2 max-w-xl text-sm leading-6 text-zinc-300">
                  Account mode makes everything portable — scan history, monitored targets, and
                  future mobile access all follow your account instead of being tied to one browser.
                </p>
              </div>

              <div className="grid gap-5 lg:grid-cols-[1fr_1fr]">
                {/* Left: recent scans + monitoring */}
                <div className="rounded-[1.7rem] border border-white/10 bg-white/[0.04] p-4 sm:p-5">
                  {!isAuthenticated ? (
                    <div className="mb-4 rounded-[1.25rem] border border-[#b56a2c]/25 bg-[#b56a2c]/[0.08] px-4 py-3 text-sm leading-6 text-[#f0d5bc]">
                      Signed-out mode keeps recent scans and monitoring in this browser only.
                    </div>
                  ) : (
                    <div className="mb-4 rounded-[1.25rem] border border-emerald-400/20 bg-emerald-400/[0.08] px-4 py-3 text-sm leading-6 text-emerald-200">
                      Account mode is active — scans and monitoring targets follow{" "}
                      <span className="font-semibold text-white">{authSession?.user.email}</span>.
                    </div>
                  )}

                  {hasHistory ? (
                    <div className="space-y-5">
                      {recentScans.length > 0 && (
                        <div className="space-y-3">
                          <div className="flex items-center gap-2 text-sm font-semibold text-zinc-200">
                            <Clock3 className="h-4 w-4 text-[#d89a63]" />
                            Recent scans
                          </div>
                          <div className="flex flex-col gap-2">
                            {recentScans.slice(0, 3).map((scan) => (
                              <button
                                key={scan.id ?? scan.url}
                                type="button"
                                onClick={() => void openRecentScan(scan)}
                                disabled={isLoading}
                                className={`rounded-[1.2rem] border px-4 py-3 text-left shadow-sm transition duration-300 ${
                                  activeRecentScanUrl === (scan.id ?? scan.url)
                                    ? "border-[#b56a2c]/45 bg-[#b56a2c]/[0.12]"
                                    : "border-white/10 bg-zinc-950/45 hover:border-[#b56a2c]/25 hover:bg-white/[0.08]"
                                } ${isLoading ? "cursor-wait" : ""}`}
                              >
                                <div className="flex items-center justify-between gap-3">
                                  <span className="truncate text-sm font-medium text-zinc-100">
                                    {scan.url}
                                  </span>
                                  <span
                                    className="text-sm font-bold uppercase tracking-[0.14em]"
                                    style={{ color: (GRADE_PALETTE[scan.grade ?? "U"] ?? GRADE_PALETTE.U).textColor }}
                                  >
                                    {scan.grade}
                                  </span>
                                </div>
                                <p className="mt-1 text-xs text-zinc-500">
                                  {new Date(scan.scannedAt).toLocaleString()}
                                </p>
                              </button>
                            ))}
                          </div>
                        </div>
                      )}
                      <div className={recentScans.length > 0 ? "border-t border-white/10 pt-5" : ""}>
                        <MonitoredTargetsPanel
                          targets={monitoredViews}
                          currentUrl={null}
                          monitoredCount={monitoredTargets.length}
                          dueCount={monitoredViews.filter((t) => t.due).length}
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
                  ) : (
                    <div className="flex items-start gap-3">
                      <Activity className="mt-0.5 h-4 w-4 flex-shrink-0 text-[#d89a63]" />
                      <div>
                        <p className="text-sm font-semibold text-zinc-200">Monitoring & drift tracking</p>
                        <p className="mt-1 text-xs leading-5 text-zinc-400">
                          Scan a target above, then pin it here. SecURL will track grade changes,
                          new findings, and resolved issues between scans — so regressions don't go unnoticed.
                        </p>
                      </div>
                    </div>
                  )}
                </div>

                {/* Right: auth card */}
                <AuthCard
                  authSession={authSession}
                  isLoading={authLoading}
                  isSubmitting={authSubmitting}
                  mode={authMode}
                  setMode={setAuthMode}
                  signIn={signIn}
                  signUp={signUp}
                  signOut={signOut}
                />
              </div>
            </section>

          </div>
        )}
      </div>
    </div>
  );
};

export default Index;
