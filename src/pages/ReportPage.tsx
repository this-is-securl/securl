import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { Sparkles } from "lucide-react";
import { getSharedScan, recordTelemetryEvent } from "@/lib/apiClient";
import { buildReportWorkspaceSections } from "@/lib/reportWorkspace";
import { getAreaScores } from "@/lib/posture";
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
      else {
        setResult(data);
        recordTelemetryEvent("shared_report_viewed", {
          target: data.url,
          scanId,
        });
      }
      setLoading(false);
    });
  }, [scanId]);

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-[#070b14]">
        <div className="text-center">
          <div className="mx-auto mb-4 h-10 w-10 animate-spin rounded-full border-2 border-[#b56a2c] border-t-transparent" />
          <p className="text-sm text-zinc-400">Loading report…</p>
        </div>
      </div>
    );
  }

  if (notFound || !result) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center gap-4 bg-[#070b14] px-6 text-center">
        <p className="text-lg font-bold text-zinc-200">Report not found</p>
        <p className="max-w-sm text-sm text-zinc-500">
          This scan may have expired or the link is incorrect.
        </p>
        <Link
          to="/"
          className="rounded-xl bg-[#b56a2c] px-6 py-2.5 text-sm font-bold text-white transition hover:bg-[#9d5a23]"
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
    areaScores: getAreaScores(result),
    exportPdf: () => {},
    exportMarkdown: () => {},
    exportReport: () => {},
  });

  const currentSection = sections.find((s) => s.key === activeSection) ?? sections[0];

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

      {/* Minimal header */}
      <header className="sticky top-0 z-40 border-b border-white/[0.06] bg-[#070b14]/80 backdrop-blur-xl">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-3 sm:px-6">
          <Link to="/" className="flex items-center gap-2 text-sm font-black tracking-[-0.03em] text-white hover:opacity-80">
            <div
              className="flex h-6 w-6 items-center justify-center rounded-lg"
              style={{ background: "linear-gradient(135deg, #b56a2c, #d89a63)" }}
            >
              <Sparkles className="h-3 w-3 text-white" />
            </div>
            Sec<span style={{ backgroundImage: "linear-gradient(135deg, #b56a2c, #d89a63)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent", backgroundClip: "text" }}>URL</span>
          </Link>
          <span className="rounded-full border border-[#b56a2c]/25 bg-[#b56a2c]/[0.10] px-3 py-1 text-[11px] font-bold uppercase tracking-[0.15em] text-[#f0d5bc]">
            Shared report
          </span>
          <a
            href="https://app.securl.online"
            className="rounded-xl bg-[#b56a2c] px-4 py-2 text-xs font-bold text-white transition hover:bg-[#9d5a23]"
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
            className="mt-6 min-w-0 overflow-hidden rounded-[2rem] border border-white/[0.09] bg-white/[0.04] shadow-[0_40px_96px_-24px_rgba(0,0,0,0.75),0_1px_0_rgba(255,255,255,0.07)_inset] animate-in fade-in-50 slide-in-from-bottom-2 duration-500"
          >
            <div className="border-b border-white/[0.08] px-4 py-6 sm:px-10 sm:py-8">
              <div className="flex items-center gap-2.5">
                {currentSection.icon && (
                  <currentSection.icon className="h-3.5 w-3.5 text-[#d89a63]" />
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
