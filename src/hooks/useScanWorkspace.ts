import { startTransition, useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import type { AnalysisResult } from "@/types/analysis";
import { getAreaScores } from "@/lib/posture";
import type { ReportWorkspaceSectionKey } from "@/lib/reportWorkspace";
import { getInitialScanHandoff } from "@/lib/deepLinks";
import {
  analyzeTargetWithMetadata,
  ApiClientError,
  getSavedScan,
  getScanComparison,
  getScanOwnerToken,
  getScanWebIntelligence,
  recordTelemetryEvent,
} from "@/lib/apiClient";
import type { ScanWebIntelligence } from "@/types/api";
import type { RecentScan } from "@/lib/scanWorkspace";

import { useRecentScans } from "./useRecentScans";
import { useMonitoredTargets } from "./useMonitoredTargets";
import { useScanHistory } from "./useScanHistory";
import { exportReportJson, exportReportMarkdown, exportReportPdf } from "@/lib/exportUtils";

const scanLifecycleStages = [
  {
    key: "queueing",
    label: "Queueing scan",
    detail: "Opening a fresh scan resource and locking the browser-owned access token.",
  },
  {
    key: "reading",
    label: "Reading target",
    detail: "Checking transport, headers, visible page signals, and passive trust evidence.",
  },
  {
    key: "analyzing",
    label: "Analyzing evidence",
    detail: "Normalizing visible findings into category scores, priorities, and confidence-labelled risks.",
  },
  {
    key: "waiting",
    label: "Still checking target",
    detail: "Some sites take longer while DNS, TLS, page, and public-trust checks finish. Keep this tab open.",
  },
] as const;

export type ScanLifecycleStage = (typeof scanLifecycleStages)[number];

const telemetryTargetForResult = (result: AnalysisResult | null | undefined) =>
  result?.finalUrl ?? result?.normalizedUrl ?? null;

export const useScanWorkspace = ({ authScopeKey = null }: { authScopeKey?: string | null } = {}) => {
  const [isLoading, setIsLoading] = useState(false);
  const [analysisData, setAnalysisData] = useState<AnalysisResult | null>(null);
  const [activeReportSection, setActiveReportSection] = useState<ReportWorkspaceSectionKey>("overview");
  const [currentScanWasCached, setCurrentScanWasCached] = useState(false);
  const [scanIntelligence, setScanIntelligence] = useState<ScanWebIntelligence | null>(null);
  const [scanStage, setScanStage] = useState<ScanLifecycleStage | null>(null);
  const [currentScanId, setCurrentScanId] = useState<string | null>(null);
  const autoScanRanRef = useRef(false);
  const analyzeUrlRef = useRef<((url: string, setAsCurrent?: boolean) => Promise<AnalysisResult>) | null>(null);
  const stageTimeoutsRef = useRef<number[]>([]);
  const areaScores = analysisData ? getAreaScores(analysisData) : [];

  const {
    recentScans,
    setRecentScans,
    activeRecentScanUrl,
    setActiveRecentScanUrl,
    loadRecentScans,
    addRecentScan,
    clearRecentScans,
  } = useRecentScans({ accountOwned: Boolean(authScopeKey) });

  const {
    monitoredTargets,
    setMonitoredTargets,
    monitoredViews,
    loadMonitoredTargets,
    saveCurrentAsMonitored,
    removeMonitoredTarget,
    syncMonitoredTarget,
    clearMonitoredTargets,
  } = useMonitoredTargets();

  const {
    history,
    historyDiff,
    loadHistory,
    addHistorySnapshot,
    applyServerComparison,
    clearHistoryState,
  } = useScanHistory();

  useEffect(() => {
    let cancelled = false;

    setAnalysisData(null);
    setCurrentScanWasCached(false);
    setScanIntelligence(null);
    setActiveRecentScanUrl(null);
    setActiveReportSection("overview");
    clearRecentScans();
    clearMonitoredTargets();
    clearHistoryState();

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
  }, [
    authScopeKey,
    clearHistoryState,
    clearMonitoredTargets,
    clearRecentScans,
    loadHistory,
    loadMonitoredTargets,
    loadRecentScans,
    setActiveRecentScanUrl,
    setMonitoredTargets,
    setRecentScans,
  ]);

  useEffect(() => {
    stageTimeoutsRef.current.forEach((timeout) => window.clearTimeout(timeout));
    stageTimeoutsRef.current = [];

    if (!isLoading) {
      setScanStage(null);
      return;
    }

    setScanStage(scanLifecycleStages[0]);
    const stageDelaysMs = [1200, 8000, 25000];
    scanLifecycleStages.slice(1).forEach((stage, index) => {
      const timeout = window.setTimeout(() => {
        setScanStage(stage);
      }, stageDelaysMs[index]);
      stageTimeoutsRef.current.push(timeout);
    });

    return () => {
      stageTimeoutsRef.current.forEach((timeout) => window.clearTimeout(timeout));
      stageTimeoutsRef.current = [];
    };
  }, [isLoading]);

  const persistAnalysis = (payload: AnalysisResult, setAsCurrent = true, fromCache = false) => {
    startTransition(() => {
      if (setAsCurrent) {
        setAnalysisData(payload);
        setCurrentScanWasCached(fromCache);
      }
      addRecentScan(payload);
      addHistorySnapshot(payload, setAsCurrent);
    });
    void syncMonitoredTarget();
  };

  const refreshScanIntelligence = async (scanId: string, scanOwnerToken: string) => {
    try {
      const intelligence = await getScanWebIntelligence(scanId, scanOwnerToken);
      startTransition(() => {
        setScanIntelligence(intelligence);
      });
    } catch (error) {
      if (error instanceof ApiClientError && [404, 409].includes(error.status)) {
        return;
      }
      console.warn("Unable to load server-backed scan intelligence.", error);
    }
  };

  const refreshServerComparison = async (scanId: string, result: AnalysisResult) => {
    try {
      const comparison = await getScanComparison(scanId);
      startTransition(() => {
        applyServerComparison(comparison, result);
      });
    } catch (error) {
      if (error instanceof ApiClientError && [404, 409].includes(error.status)) {
        return;
      }
      console.warn("Unable to load server-backed scan comparison.", error);
    }
  };

  const analyzeUrl = async (url: string, setAsCurrent = true) => {
    setCurrentScanId(null);
    if (setAsCurrent) {
      setScanIntelligence(null);
    }
    recordTelemetryEvent("scan_started", { target: url, mode: "standard" });
    const payload = await analyzeTargetWithMetadata(url);
    setCurrentScanId(payload.scanId);
    persistAnalysis(payload.result, setAsCurrent, payload.fromCache);
    if (setAsCurrent) {
      void refreshServerComparison(payload.scanId, payload.result);
      void refreshScanIntelligence(payload.scanId, payload.scanOwnerToken);
    }
    recordTelemetryEvent("scan_completed", {
      target: telemetryTargetForResult(payload.result),
      scanId: payload.scanId,
      mode: "standard",
    });
    if (setAsCurrent) {
      recordTelemetryEvent("report_viewed", {
        target: telemetryTargetForResult(payload.result),
        scanId: payload.scanId,
      });
    }
    return payload.result;
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
      recordTelemetryEvent("scan_failed", { target: url, mode: "standard" });
      toast.error(error instanceof Error ? error.message : "Unable to scan that site.");
    } finally {
      setActiveRecentScanUrl(null);
      setIsLoading(false);
    }
  };

  const openRecentScan = async (scan: RecentScan) => {
    if (!scan.id || !authScopeKey) {
      await handleAnalyze(scan.url, "recent");
      return;
    }

    setIsLoading(true);
    setActiveRecentScanUrl(scan.id);

    try {
      const payload = await getSavedScan(scan.id);
      if (payload.scan.status !== "completed" || !payload.scan.result) {
        throw new ApiClientError("That saved scan is not ready to reopen yet.", 409, payload);
      }
      startTransition(() => {
        setAnalysisData(payload.scan.result);
        setCurrentScanWasCached(false);
        setScanIntelligence(null);
        addHistorySnapshot(payload.scan.result, true);
      });
      setCurrentScanId(scan.id);
      void refreshServerComparison(scan.id, payload.scan.result);
      void getScanOwnerToken().then((scanOwnerToken) => refreshScanIntelligence(scan.id as string, scanOwnerToken));
      recordTelemetryEvent("report_viewed", {
        target: telemetryTargetForResult(payload.scan.result),
        scanId: scan.id,
      });
      toast.success(`Reopened ${payload.scan.result.host}.`);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Unable to reopen that saved report.");
    } finally {
      setActiveRecentScanUrl(null);
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (typeof window === "undefined" || autoScanRanRef.current) {
      return;
    }

    const handoff = getInitialScanHandoff(window.location.search);
    if (!handoff) {
      return;
    }

    autoScanRanRef.current = true;
    void (async () => {
      setIsLoading(true);
      try {
        recordTelemetryEvent("handoff_started", {
          target: handoff.target,
          mode: `${handoff.source}:${handoff.campaign}`,
        });
        await analyzeUrlRef.current?.(handoff.target, true);
      } catch (error) {
        recordTelemetryEvent("scan_failed", {
          target: handoff.target,
          mode: `${handoff.source}:${handoff.campaign}`,
        });
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
      recordTelemetryEvent("scan_failed", { target: url, mode: "standard" });
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
        recordTelemetryEvent("scan_failed", { target: target.url, mode: "standard" });
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
    scanIntelligence,
    areaScores,
    monitoredViews,
    setActiveReportSection,
    handleAnalyze,
    openRecentScan,
    saveCurrentAsMonitored: async (cadence: "daily" | "weekly") => {
      await saveCurrentAsMonitored(cadence, analysisData);
      recordTelemetryEvent("monitoring_saved", {
        target: telemetryTargetForResult(analysisData),
        scanId: currentScanId,
        mode: cadence,
      });
    },
    removeMonitoredTarget,
    runTargetScan,
    runDueScans,
    exportReport: () => {
      recordTelemetryEvent("export_clicked", { target: telemetryTargetForResult(analysisData), scanId: currentScanId, format: "json" });
      exportReportJson(analysisData);
    },
    exportMarkdown: () => {
      recordTelemetryEvent("export_clicked", { target: telemetryTargetForResult(analysisData), scanId: currentScanId, format: "markdown" });
      exportReportMarkdown(analysisData, historyDiff);
    },
    exportPdf: () => {
      recordTelemetryEvent("export_clicked", { target: telemetryTargetForResult(analysisData), scanId: currentScanId, format: "pdf" });
      exportReportPdf(analysisData, historyDiff);
    },
  };
};
