import { startTransition, useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import type { AnalysisResult } from "@/types/analysis";
import { getAreaScores } from "@/lib/posture";
import { readBrowserStorage, writeBrowserStorage } from "@/lib/browserStorage";
import { SCAN_OWNER_KEY, STORAGE_SCHEMA_VERSION } from "@/lib/scanWorkspace";
import type { ReportWorkspaceSectionKey } from "@/lib/reportWorkspace";

import { useRecentScans } from "./useRecentScans";
import { useMonitoredTargets } from "./useMonitoredTargets";
import { useScanHistory } from "./useScanHistory";
import { exportReportJson, exportReportMarkdown, exportReportHtml, exportReportPdf } from "@/lib/exportUtils";

export const useScanWorkspace = () => {
  const [isLoading, setIsLoading] = useState(false);
  const [analysisData, setAnalysisData] = useState<AnalysisResult | null>(null);
  const [activeReportSection, setActiveReportSection] = useState<ReportWorkspaceSectionKey>("overview");
  const autoScanRanRef = useRef(false);
  const analyzeUrlRef = useRef<(url: string, setAsCurrent?: boolean) => Promise<AnalysisResult>>();
  const areaScores = analysisData ? getAreaScores(analysisData) : [];

  const {
    recentScans,
    setRecentScans,
    activeRecentScanUrl,
    setActiveRecentScanUrl,
    loadRecentScans,
    addRecentScan,
  } = useRecentScans();

  const {
    monitoredTargets,
    setMonitoredTargets,
    monitoredViews,
    loadMonitoredTargets,
    saveCurrentAsMonitored,
    removeMonitoredTarget,
    syncMonitoredTarget,
  } = useMonitoredTargets();

  const {
    history,
    historyDiff,
    loadHistory,
    addHistorySnapshot,
  } = useScanHistory();

  useEffect(() => {
    let cancelled = false;

    void (async () => {
      const [storedRecentScans, storedMonitoredTargets] = await Promise.all([
        loadRecentScans(),
        loadMonitoredTargets(),
        loadHistory(),
      ]);

      if (cancelled) {
        return;
      }

      startTransition(() => {
        setRecentScans(storedRecentScans);
        setMonitoredTargets(storedMonitoredTargets);
      });
    })();

    return () => {
      cancelled = true;
    };
  }, [loadRecentScans, loadMonitoredTargets, loadHistory, setRecentScans, setMonitoredTargets]);

  const persistAnalysis = (payload: AnalysisResult, setAsCurrent = true) => {
    startTransition(() => {
      if (setAsCurrent) {
        setAnalysisData(payload);
      }
      addRecentScan(payload);
      addHistorySnapshot(payload, setAsCurrent);
      syncMonitoredTarget(payload);
    });
  };

  const readJsonResponse = async (response: Response) => {
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || "Scan failed.");
    }
    return payload;
  };

  const getScanOwnerToken = async () => {
    const existing = await readBrowserStorage<string | null>(SCAN_OWNER_KEY, null, STORAGE_SCHEMA_VERSION);
    if (existing) {
      return existing;
    }

    const generated = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    await writeBrowserStorage(SCAN_OWNER_KEY, generated, STORAGE_SCHEMA_VERSION);
    return generated;
  };

  const analyzeUrl = async (url: string, setAsCurrent = true) => {
    const scanOwnerToken = await getScanOwnerToken();
    const scanHeaders = {
      "Content-Type": "application/json",
      "X-Scan-Owner": scanOwnerToken,
    };
    const createResponse = await fetch("/api/scans", {
      method: "POST",
      headers: scanHeaders,
      body: JSON.stringify({ url }),
    });
    const createdPayload = await readJsonResponse(createResponse);
    const scanId = createdPayload.scan?.id;

    if (!scanId) {
      throw new Error("Scan did not return a tracking id.");
    }

    for (let attempt = 0; attempt < 120; attempt += 1) {
      const scanResponse = await fetch(`/api/scans/${encodeURIComponent(scanId)}`, {
        headers: {
          "X-Scan-Owner": scanOwnerToken,
        },
      });
      const scanPayload = await readJsonResponse(scanResponse);
      const scan = scanPayload.scan;

      if (scan?.status === "completed" && scan.result) {
        const payload = scan.result as AnalysisResult;
        persistAnalysis(payload, setAsCurrent);
        return payload;
      }

      if (scan?.status === "failed") {
        throw new Error(scan.error || "Scan failed.");
      }

      await new Promise((resolve) => window.setTimeout(resolve, 1000));
    }

    throw new Error("Scan is still running. Please try again shortly.");
  };

  analyzeUrlRef.current = analyzeUrl;

  const handleAnalyze = async (url: string, source: "form" | "recent" = "form") => {
    setIsLoading(true);
    if (source === "recent") {
      setActiveRecentScanUrl(url);
    }

    try {
      const result = await analyzeUrl(url, true);
      if (source === "recent") {
        toast.success(`Reloaded ${result.host}.`);
      }
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Unable to scan that site.");
    } finally {
      setActiveRecentScanUrl(null);
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (typeof window === "undefined" || autoScanRanRef.current) {
      return;
    }

    const params = new URLSearchParams(window.location.search);
    const target = params.get("target");
    if (!target) {
      return;
    }

    autoScanRanRef.current = true;
    void (async () => {
      setIsLoading(true);
      try {
        await analyzeUrlRef.current?.(target, true);
      } catch (error) {
        toast.error(error instanceof Error ? error.message : "Unable to scan that site.");
      } finally {
        setIsLoading(false);
      }
    })();
  }, []);

  const runTargetScan = async (url: string, setAsCurrent = true) => {
    setIsLoading(true);
    try {
      const result = await analyzeUrl(url, setAsCurrent);
      toast.success(`Scanned ${result.host}.`);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Unable to scan that monitored target.");
    } finally {
      setIsLoading(false);
    }
  };

  const runDueScans = async () => {
    const dueTargets = monitoredViews.filter((target) => target.due);
    if (!dueTargets.length) {
      toast.message("No monitoring targets are due right now.");
      return;
    }

    setIsLoading(true);
    let successCount = 0;
    let failureCount = 0;

    for (const target of dueTargets) {
      try {
        await analyzeUrl(target.url, false);
        successCount += 1;
      } catch {
        failureCount += 1;
      }
    }

    if (successCount && failureCount) {
      toast.warning(`Completed ${successCount} due monitoring scan${successCount === 1 ? "" : "s"} with ${failureCount} failure${failureCount === 1 ? "" : "s"}.`);
    } else if (successCount) {
      toast.success(`Completed ${successCount} due monitoring scan${successCount === 1 ? "" : "s"}.`);
    } else {
      toast.error("All due monitoring scans failed.");
    }

    setIsLoading(false);
  };

  return {
    isLoading,
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
    saveCurrentAsMonitored: (cadence: "daily" | "weekly") => saveCurrentAsMonitored(cadence, analysisData),
    removeMonitoredTarget,
    runTargetScan,
    runDueScans,
    exportReport: () => exportReportJson(analysisData),
    exportMarkdown: () => exportReportMarkdown(analysisData, historyDiff),
    exportHtml: () => exportReportHtml(analysisData, historyDiff),
    exportPdf: () => exportReportPdf(analysisData, historyDiff),
  };
};
