import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { getSharedScan } from "@/lib/apiClient";
import { buildReportWorkspaceSections } from "@/lib/reportWorkspace";
import { ReportSectionNav } from "@/components/report/ReportSectionNav";
import type { ReportWorkspaceSectionKey } from "@/lib/reportWorkspace";
import type { AnalysisResult } from "@/types/analysis";

export function ReportPage() {
  const { scanId } = useParams<{ scanId: string }>();
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [notFound, setNotFound] = useState(false);
  const [activeSection, setActiveSection] = useState<ReportWorkspaceSectionKey>("overview");

  useEffect(() => {
    if (!scanId) return;
    setLoading(true);
    getSharedScan(scanId).then((data) => {
      if (!data) setNotFound(true);
      else setResult(data);
      setLoading(false);
    });
  }, [scanId]);

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-[#040c08]">
        <div className="text-center">
          <div className="mx-auto mb-4 h-10 w-10 animate-spin rounded-full border-2 border-[#14b8a6] border-t-transparent" />
          <p className="text-sm text-zinc-400">Loading report…</p>
        </div>
      </div>
    );
  }

  if (notFound || !result) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center gap-4 bg-[#040c08] px-6 text-center">
        <p className="text-lg font-bold text-zinc-200">Report not found</p>
        <p className="max-w-sm text-sm text-zinc-500">
          This scan may have expired or the link is incorrect.
        </p>
        <Link
          to="/"
          className="rounded-xl bg-[#14b8a6] px-6 py-2.5 text-sm font-bold text-[#030b06] transition hover:bg-[#0f9f92]"
        >
          Run your own scan →
        </Link>
      </div>
    );
  }

  const sections = buildReportWorkspaceSections({
    analysisData: result,
    currentScanWasCached: false,
    historyDiff: null,
    history: [],
    areaScores: [],
    exportPdf: () => {},
    exportMarkdown: () => {},
    exportReport: () => {},
  });

  const currentSection = sections.find((s) => s.key === activeSection) ?? sections[0];

  return (
    <div className="min-h-screen overflow-hidden bg-[#040c08] text-zinc-100">
      <div className="pointer-events-none fixed inset-0 -z-10 bg-[radial-gradient(ellipse_90%_70%_at_18%_-5%,rgba(16,185,129,0.38),transparent_55%),radial-gradient(ellipse_50%_45%_at_88%_8%,rgba(20,184,166,0.18),transparent_52%),linear-gradient(180deg,#040c08_0%,#040c08_100%)]" />

      {/* Minimal header */}
      <header className="sticky top-0 z-40 border-b border-white/[0.06] bg-[#040c08]/80 backdrop-blur-xl">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-3 sm:px-6">
          <Link to="/" className="flex items-center gap-2 text-sm font-black tracking-[-0.03em] text-white hover:opacity-80">
            <div className="flex h-6 w-6 items-center justify-center rounded-lg text-[11px] font-black text-[#030b06]" style={{ background: "linear-gradient(135deg,#10b981,#14b8a6)" }}>S</div>
            Sec<span className="text-[#10b981]">URL</span>
          </Link>
          <span className="rounded-full border border-[#14b8a6]/25 bg-[#14b8a6]/10 px-3 py-1 text-[11px] font-bold uppercase tracking-[0.15em] text-[#2dd4bf]">
            Shared report
          </span>
          <a
            href="https://app.securl.online"
            className="rounded-xl bg-[#14b8a6] px-4 py-2 text-xs font-bold text-[#030b06] transition hover:bg-[#0f9f92]"
          >
            Scan your site →
          </a>
        </div>
      </header>

      <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <ReportSectionNav
          sections={sections}
          activeKey={currentSection?.key}
          onChange={setActiveSection}
        />
        {currentSection && (
          <div
            key={currentSection.key}
            className="mt-6 min-w-0 overflow-hidden rounded-[2rem] border border-zinc-800 bg-[#111a14] shadow-[0_40px_96px_-24px_rgba(0,0,0,0.75),0_1px_0_rgba(255,255,255,0.07)_inset] animate-in fade-in-50 slide-in-from-bottom-2 duration-500"
          >
            <div className="border-b border-zinc-800 px-4 py-6 sm:px-10 sm:py-8">
              <div className="flex items-center gap-2.5">
                {currentSection.icon && (
                  <currentSection.icon className="h-3.5 w-3.5 text-[#2dd4bf]" />
                )}
                {(currentSection.badge ?? currentSection.context) ? (
                  <p className="text-[10px] font-bold uppercase tracking-[0.24em] text-zinc-500">
                    {currentSection.badge ?? currentSection.context}
                  </p>
                ) : null}
              </div>
              <h2 className="mt-2.5 text-xl font-black tracking-[-0.04em] text-white sm:text-[1.85rem]">
                {currentSection.title}
              </h2>
              <p className="mt-2 max-w-2xl text-sm leading-relaxed text-zinc-300">
                {currentSection.summary}
              </p>
            </div>
            <div className="px-4 py-6 text-zinc-100 sm:px-10 sm:py-10">
              {currentSection.content}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
