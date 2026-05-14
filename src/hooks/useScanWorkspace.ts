import { startTransition, useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import type { AnalysisResult } from "@/types/analysis";
import { getAreaScores } from "@/lib/posture";
import type { ReportWorkspaceSectionKey } from "@/lib/reportWorkspace";
import { analyzeTarget, ApiClientError, getSavedScan } from "@/lib/apiClient";
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
    key: "synthesizing",
    label: "Scoring posture",
    detail: "Normalizing findings into category scores, priorities, and confidence-labelled risks.",
  },
  {
    key: "finalizing",
    label: "Finalizing report",
    detail: "Preparing the workspace, recent history, and monitoring summaries.",
  },
] as const;

export type ScanLifecycleStage = (typeof scanLifecycleStages)[number];

export const useScanWorkspace = ({ authScopeKey = null }: { authScopeKey?: string | null } = {}) => {
  const [isLoading, setIsLoading] = useState(false);
  const [analysisData, setAnalysisData] = useState<AnalysisResult | null>(null);
  const [activeReportSection, setActiveReportSection] = useState<ReportWorkspaceSectionKey>("overview");
  const [scanStage, setScanStage] = useState<ScanLifecycleStage | null>(null);
  const autoScanRanRef = useRef(false);
  const analyzeUrlRef = useRef<(url: string, setAsCurrent?: boolean) => Promise<AnalysisResult>>();
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
    clearHistoryState,
  } = useScanHistory();

  useEffect(() => {
    let cancelled = false;

    setAnalysisData(null);
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
    scanLifecycleStages.slice(1).forEach((stage, index) => {
      const timeout = window.setTimeout(() => {
        setScanStage(stage);
      }, (index + 1) * 900);
      stageTimeoutsRef.current.push(timeout);
    });

    return () => {
      stageTimeoutsRef.current.forEach((timeout) => window.clearTimeout(timeout));
      stageTimeoutsRef.current = [];
    };
  }, [isLoading]);

  const persistAnalysis = (payload: AnalysisResult, setAsCurrent = true) => {
    startTransition(() => {
      if (setAsCurrent) {
        setAnalysisData(payload);
      }
      addRecentScan(payload);
      addHistorySnapshot(payload, setAsCurrent);
    });
    void syncMonitoredTarget();
  };

  const analyzeUrl = async (url: string, setAsCurrent = true) => {
    const payload = await analyzeTarget(url);
    persistAnalysis(payload, setAsCurrent);
    return payload;
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
        addHistorySnapshot(payload.scan.result, true);
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
    saveCurrentAsMonitored: async (cadence: "daily" | "weekly") => {
      await saveCurrentAsMonitored(cadence, analysisData);
    },
    removeMonitoredTarget,
    runTargetScan,
    runDueScans,
    exportReport: () => exportReportJson(analysisData),
    exportMarkdown: () => exportReportMarkdown(analysisData, historyDiff),
    exportPdf: () => exportReportPdf(analysisData, historyDiff),
  };
};
