import { toast } from "sonner";
import type { AnalysisResult, HistoryDiff } from "@/types/analysis";
import { buildHtmlReport, buildMarkdownReport } from "./reportExport";
import { downloadFile } from "./scanWorkspace";

export const exportReportJson = (analysisData: AnalysisResult | null) => {
  if (!analysisData) {
    return;
  }

  downloadFile(
    `security-report-${analysisData.host}.json`,
    JSON.stringify(analysisData, null, 2),
    "application/json;charset=utf-8",
  );
};

export const exportReportMarkdown = (analysisData: AnalysisResult | null, historyDiff: HistoryDiff | null) => {
  if (!analysisData) return;
  downloadFile(
    `security-report-${analysisData.host}.md`,
    buildMarkdownReport(analysisData, historyDiff),
    "text/markdown;charset=utf-8",
  );
};

export const exportReportPdf = (analysisData: AnalysisResult | null, historyDiff: HistoryDiff | null) => {
  if (!analysisData) return;
  const iframe = document.createElement("iframe");
  let printStarted = false;
  iframe.style.position = "fixed";
  iframe.style.right = "0";
  iframe.style.bottom = "0";
  iframe.style.width = "0";
  iframe.style.height = "0";
  iframe.style.border = "0";
  iframe.setAttribute("aria-hidden", "true");

  const cleanup = () => {
    window.setTimeout(() => {
      iframe.remove();
    }, 1000);
  };

  iframe.onload = () => {
    if (printStarted) {
      return;
    }

    const frameWindow = iframe.contentWindow;
    if (!frameWindow) {
      toast.error("Could not prepare the PDF export.");
      cleanup();
      return;
    }

    printStarted = true;
    frameWindow.focus();
    window.setTimeout(() => {
      frameWindow.print();
      cleanup();
    }, 250);
  };

  document.body.appendChild(iframe);
  const frameDocument = iframe.contentDocument;
  if (!frameDocument) {
    toast.error("Could not prepare the PDF export.");
    cleanup();
    return;
  }

  frameDocument.open();
  frameDocument.write(buildHtmlReport(analysisData, historyDiff));
  frameDocument.close();
};
