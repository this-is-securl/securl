import { Activity, Clock3, Layers3, Sparkles } from "lucide-react";
import { AuthCard } from "@/components/AuthCard";
import { MonitoredTargetsPanel } from "@/components/MonitoredTargetsPanel";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { UrlForm } from "@/components/UrlForm";
import {
  buildReportWorkspaceSections,
  type ReportWorkspaceSectionKey,
} from "@/lib/reportWorkspace";
import { cn } from "@/lib/utils";
import { useAuthSession } from "@/hooks/useAuthSession";
import { useScanWorkspace } from "@/hooks/useScanWorkspace";
import { OutputPreview } from "@/components/landing/OutputPreview";
import { CapabilityStrip } from "@/components/landing/CapabilityStrip";

// ── Mini ring preview (hero right column, pre-scan) ──────────────────────────
const MINI_R    = 60;
const MINI_SIZE = 144;
const MINI_CIRC = parseFloat((2 * Math.PI * MINI_R).toFixed(2));
const MINI_SCORE = 81;
const MINI_OFF  = parseFloat((MINI_CIRC * (1 - MINI_SCORE / 100)).toFixed(2));
const MINI_COLOR = "#2563eb"; // grade B

const HeroPreviewCard = () => (
  <div className="relative h-full overflow-hidden rounded-[1.8rem] border border-white/10 bg-slate-950/35 p-5 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)] sm:p-6">
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
      <p className="text-[10px] font-bold uppercase tracking-[0.2em] text-slate-500">Sample result</p>
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
            fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="10"
          />
          <circle
            cx={MINI_SIZE / 2} cy={MINI_SIZE / 2} r={MINI_R}
            fill="none" stroke={MINI_COLOR} strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={MINI_CIRC}
            strokeDashoffset={MINI_OFF}
            transform={`rotate(-90 ${MINI_SIZE / 2} ${MINI_SIZE / 2})`}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center gap-0.5">
          <span
            className="font-black leading-none tracking-[-0.04em]"
            style={{ fontSize: 48, color: MINI_COLOR }}
          >
            B
          </span>
          <span className="text-xs font-semibold text-slate-400">81/100</span>
          <span
            className="mt-0.5 text-[9px] font-bold uppercase tracking-[0.18em]"
            style={{ color: MINI_COLOR }}
          >
            Good Posture
          </span>
        </div>
      </div>

      {/* Domain */}
      <p className="mt-3 font-mono text-xs text-slate-400">portswigger.net</p>
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
          {sev === "warning" ? "⚠ " : "ℹ "}{label}
        </span>
      ))}
    </div>

    {/* Caption */}
    <p className="relative mt-4 text-center text-[11px] text-slate-600">
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
    <div className="min-h-screen overflow-hidden bg-[#070b14] text-slate-100">
      <div className="pointer-events-none fixed inset-0 -z-10 bg-[radial-gradient(circle_at_18%_0%,rgba(181,106,44,0.16),transparent_34%),radial-gradient(circle_at_82%_12%,rgba(122,166,182,0.12),transparent_30%),linear-gradient(180deg,#070b14_0%,#0b1220_48%,#101827_100%)]" />

      <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">

        {/* ── Hero card ─────────────────────────────────────────────────── */}
        <section className="rounded-[2.25rem] border border-white/10 bg-white/[0.05] p-5 shadow-2xl shadow-black/30 ring-1 ring-white/[0.04] backdrop-blur-xl sm:p-7 lg:p-8">
          <div className="grid gap-8 lg:grid-cols-[1.25fr_0.75fr] lg:items-start">

            {/* Left: headline + form */}
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
                  <p className="max-w-xl text-base leading-7 text-slate-400 sm:text-lg">
                    Most security tools return raw data. SecURL returns a verdict — a graded read of
                    what your target looks like from the outside, with specific findings and the
                    context to act on them.
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

            {/* Right: preview card (pre-scan) or recent scan nav (post-scan) */}
            {analysisData ? (
              <div className="h-full rounded-[1.8rem] border border-white/10 bg-slate-950/35 p-5 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)] sm:p-6">
                <div className="mb-4 flex items-center gap-2 text-sm font-semibold text-slate-200">
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
                          ? "border-[#b56a2c]/45 bg-[#b56a2c]/12 shadow-[0_18px_36px_-28px_rgba(181,106,44,0.5)]"
                          : "border-white/10 bg-slate-950/45 hover:-translate-y-0.5 hover:border-[#b56a2c]/25 hover:bg-white/[0.08]"
                      } ${isLoading ? "cursor-wait" : ""}`}
                    >
                      <div className="flex items-center justify-between gap-3">
                        <span className="truncate text-sm font-medium text-slate-100">{scan.url}</span>
                        <span className="text-sm font-semibold uppercase tracking-[0.14em] text-[#f0d5bc]">
                          {activeRecentScanUrl === (scan.id ?? scan.url)
                            ? scanStage?.label ?? "Opening"
                            : scan.grade}
                        </span>
                      </div>
                      <p className="mt-1 text-xs text-slate-500">
                        {new Date(scan.scannedAt).toLocaleString()}
                      </p>
                    </button>
                  ))}
                  {recentScans.length === 0 && (
                    <p className="text-sm text-slate-500">No recent scans yet.</p>
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
          <section className="mt-6 space-y-4">
            <div className="flex items-center gap-2.5 px-1">
              <Layers3 className="h-4 w-4 text-[#d89a63]" />
              <span className="text-[11px] font-semibold uppercase tracking-[0.22em] text-slate-400">
                Report workspace
              </span>
              <span className="h-px flex-1 bg-white/[0.06]" />
            </div>
            <div className="space-y-4">
              <div className="rounded-[1.5rem] border border-white/10 bg-white/[0.04] px-4 py-4 shadow-2xl shadow-black/15 ring-1 ring-white/[0.03] backdrop-blur sm:px-5">
                <div className="flex flex-col gap-4">
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-[0.2em] text-[#d89a63]/80">
                      Sections
                    </p>
                    <p className="mt-2 text-sm leading-6 text-slate-400">
                      Move through the report without losing the main storyline.
                    </p>
                  </div>
                  <div className="lg:hidden">
                    <Select
                      value={activeSection?.key}
                      onValueChange={(value) =>
                        setActiveReportSection(value as ReportWorkspaceSectionKey)
                      }
                    >
                      <SelectTrigger className="h-auto min-h-14 rounded-2xl border-white/10 bg-slate-950/45 px-4 py-3 text-left text-sm font-medium text-slate-100 ring-offset-0 focus:ring-1 focus:ring-[#b56a2c]/40 focus:ring-offset-0">
                        {activeSection ? (
                          <div className="flex min-w-0 flex-col items-start text-left">
                            <span className="text-sm font-semibold text-white">
                              {activeSection.title}
                            </span>
                            <span className="mt-1 truncate text-xs uppercase tracking-[0.12em] text-slate-400">
                              {activeSection.context ?? activeSection.summary}
                            </span>
                          </div>
                        ) : (
                          <SelectValue placeholder="Choose a report section" />
                        )}
                      </SelectTrigger>
                      <SelectContent className="rounded-2xl border-white/10 bg-[#0f172a] text-slate-100 shadow-2xl">
                        {reportSections.map((section) => (
                          <SelectItem
                            key={section.key}
                            value={section.key}
                            className="rounded-xl py-3 pl-8 pr-3 text-sm text-slate-100 focus:bg-white/[0.08] focus:text-white"
                          >
                            <div className="flex flex-col items-start">
                              <span className="font-medium text-white">{section.title}</span>
                              <span className="mt-1 text-[11px] uppercase tracking-[0.14em] text-slate-400">
                                {section.context ?? section.summary}
                              </span>
                            </div>
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="hidden lg:block">
                    <div className="overflow-x-auto pb-1">
                      <div className="inline-flex min-w-full gap-2">
                        {reportSections.map((section) => {
                          const active = section.key === activeSection?.key;
                          return (
                            <button
                              key={section.key}
                              type="button"
                              onClick={() => setActiveReportSection(section.key)}
                              className={cn(
                                "min-w-[11rem] flex-1 rounded-[1.1rem] border px-4 py-3.5 text-left transition-all duration-200",
                                active
                                  ? "border-[#b56a2c]/40 bg-[#b56a2c]/12 shadow-[0_12px_32px_-20px_rgba(181,106,44,0.5),0_0_0_1px_rgba(181,106,44,0.12)_inset]"
                                  : "border-white/[0.08] bg-white/[0.03] hover:border-white/[0.14] hover:bg-white/[0.06]",
                              )}
                            >
                              <div className="flex items-start justify-between gap-2">
                                <span
                                  className={cn(
                                    "text-sm font-semibold leading-snug",
                                    active ? "text-white" : "text-slate-300",
                                  )}
                                >
                                  {section.title}
                                </span>
                                {active ? (
                                  <span className="mt-0.5 inline-flex h-2 w-2 shrink-0 rounded-full bg-[#d89a63] shadow-[0_0_0_4px_rgba(181,106,44,0.18)]" />
                                ) : null}
                              </div>
                              <p className="mt-1.5 line-clamp-1 text-[10px] uppercase tracking-[0.16em] text-slate-500">
                                {section.context ?? section.summary}
                              </p>
                            </button>
                          );
                        })}
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {activeSection ? (
                <div
                  key={activeSection.key}
                  className="min-w-0 overflow-hidden rounded-[1.75rem] border border-white/[0.09] bg-[linear-gradient(180deg,rgba(255,255,255,0.04)_0%,rgba(255,255,255,0.025)_100%)] shadow-[0_32px_80px_-32px_rgba(0,0,0,0.6)] ring-1 ring-white/[0.04] backdrop-blur animate-in fade-in-50 slide-in-from-bottom-2 duration-500"
                >
                  <div className="border-b border-white/[0.08] px-6 py-5 sm:px-7">
                    <p className="text-[10px] font-semibold uppercase tracking-[0.26em] text-[#d89a63]/70">
                      {activeSection.context ?? "Report section"}
                    </p>
                    <h2 className="mt-1.5 text-2xl font-bold tracking-[-0.04em] text-white sm:text-3xl">
                      {activeSection.title}
                    </h2>
                    <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">
                      {activeSection.summary}
                    </p>
                  </div>
                  <div className="px-5 py-7 text-slate-100 sm:px-7 lg:px-8">
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
                <p className="mb-3 text-[11px] font-bold uppercase tracking-[0.22em] text-[#d89a63]/70">
                  Sample output
                </p>
                <h2 className="text-2xl font-bold tracking-[-0.04em] text-white sm:text-3xl">
                  Grade, findings, and context — in under 30 seconds
                </h2>
                <p className="mx-auto mt-3 max-w-xl text-sm leading-6 text-slate-400">
                  Every scan produces a graded posture assessment with specific findings, consequence
                  context, and remediation steps — not a raw list of headers.
                </p>
              </div>
              <OutputPreview />
            </section>

            {/* 2 — Differentiation band */}
            <section className="rounded-[1.75rem] border border-white/[0.06] bg-white/[0.025] px-8 py-12 text-center sm:px-12">
              <p className="mb-4 text-[11px] font-bold uppercase tracking-[0.22em] text-slate-500">
                Why SecURL
              </p>
              <h2 className="text-2xl font-bold tracking-[-0.04em] text-white sm:text-3xl lg:text-4xl">
                Security tools give you data.
                <br />
                <span className="text-[#d89a63]">SecURL gives you a read.</span>
              </h2>
              <p className="mx-auto mt-5 max-w-lg text-base leading-7 text-slate-400">
                Passive. No agents. No configuration. No credentials required. Just a clear external
                view of how a target looks to an informed observer — with findings you can act on
                immediately.
              </p>
              <div className="mx-auto mt-9 grid max-w-md grid-cols-3 gap-6">
                {[
                  { value: "7",    label: "Posture areas"      },
                  { value: "~20s", label: "To a graded result" },
                  { value: "PDF",  label: "Export included"    },
                ].map(({ value, label }) => (
                  <div key={label} className="text-center">
                    <p className="text-3xl font-black tracking-[-0.04em] text-white">{value}</p>
                    <p className="mt-1 text-[11px] font-semibold uppercase tracking-[0.14em] text-slate-500">
                      {label}
                    </p>
                  </div>
                ))}
              </div>
            </section>

            {/* 3 — Capability strip */}
            <section>
              <div className="mb-6">
                <p className="mb-2 text-[11px] font-bold uppercase tracking-[0.22em] text-[#d89a63]/70">
                  What it checks
                </p>
                <h2 className="text-2xl font-bold tracking-[-0.04em] text-white sm:text-3xl">
                  Coverage across seven posture areas
                </h2>
              </div>
              <CapabilityStrip />
            </section>

            {/* 4 — Account + history section */}
            <section>
              <div className="mb-6">
                <p className="mb-2 text-[11px] font-bold uppercase tracking-[0.2em] text-slate-500">
                  Save your work
                </p>
                <h2 className="text-xl font-bold tracking-[-0.03em] text-white">
                  Keep scans, history, and monitoring targets across sessions
                </h2>
                <p className="mt-2 max-w-xl text-sm leading-6 text-slate-400">
                  Account mode makes everything portable — scan history, monitored targets, and
                  future mobile access all follow your account instead of being tied to one browser.
                </p>
              </div>

              <div className="grid gap-5 lg:grid-cols-[1fr_1fr]">
                {/* Left: recent scans + monitoring */}
                <div className="rounded-[1.7rem] border border-white/10 bg-white/[0.04] p-4 sm:p-5">
                  {!isAuthenticated ? (
                    <div className="mb-4 rounded-[1.25rem] border border-[#b56a2c]/25 bg-[#b56a2c]/10 px-4 py-3 text-sm leading-6 text-[#f0d5bc]">
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
                          <div className="flex items-center gap-2 text-sm font-semibold text-slate-200">
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
                                    ? "border-[#b56a2c]/45 bg-[#b56a2c]/12"
                                    : "border-white/10 bg-slate-950/45 hover:border-[#b56a2c]/25 hover:bg-white/[0.08]"
                                } ${isLoading ? "cursor-wait" : ""}`}
                              >
                                <div className="flex items-center justify-between gap-3">
                                  <span className="truncate text-sm font-medium text-slate-100">
                                    {scan.url}
                                  </span>
                                  <span className="text-sm font-semibold uppercase tracking-[0.14em] text-[#f0d5bc]">
                                    {scan.grade}
                                  </span>
                                </div>
                                <p className="mt-1 text-xs text-slate-500">
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
                    <div className="flex flex-col gap-4">
                      <div className="flex items-start gap-3">
                        <Activity className="mt-0.5 h-4 w-4 flex-shrink-0 text-[#d89a63]" />
                        <div>
                          <p className="text-sm font-semibold text-slate-200">Monitoring & drift tracking</p>
                          <p className="mt-1 text-xs leading-5 text-slate-400">
                            Save a target to monitor it over time. SecURL tracks grade changes, new
                            findings, and resolved issues between scans.
                          </p>
                        </div>
                      </div>
                      <p className="text-sm text-slate-500">
                        Run your first scan above to unlock monitoring.
                      </p>
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
