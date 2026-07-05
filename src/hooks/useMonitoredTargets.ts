import { useCallback, useState } from "react";
import { toast } from "sonner";
import type { AnalysisResult } from "@/types/analysis";
import type { ApiMonitoringTarget } from "@/types/api";
import {
  deleteMonitoringTarget as deleteMonitoringTargetRequest,
  getMonitoringTargets,
  saveMonitoringTarget,
} from "@/lib/apiClient";

export const useMonitoredTargets = () => {
  const [monitoredTargets, setMonitoredTargets] = useState<ApiMonitoringTarget[]>([]);

  const loadMonitoredTargets = useCallback(async () => {
    try {
      const payload = await getMonitoringTargets();
      setMonitoredTargets(payload.targets);
      return payload.targets;
    } catch (error) {
      console.warn("Unable to load monitoring targets.", error);
      setMonitoredTargets([]);
      return [];
    }
  }, []);

  const saveCurrentAsMonitored = useCallback(
    async (cadence: "daily" | "weekly", analysisData: AnalysisResult | null) => {
      if (!analysisData) {
        return;
      }

      const savedTarget = await saveMonitoringTarget(analysisData.finalUrl, cadence, analysisData.host);
      setMonitoredTargets((current) => [
        savedTarget,
        ...current.filter((target) => target.id !== savedTarget.id),
      ]);
      toast.success(`Saved ${analysisData.host} as a ${cadence} monitoring target.`);
    },
    [],
  );

  const removeMonitoredTarget = useCallback(async (targetId: string) => {
    await deleteMonitoringTargetRequest(targetId);
    setMonitoredTargets((current) => current.filter((target) => target.id !== targetId));
  }, []);

  const syncMonitoredTarget = useCallback(async () => {
    try {
      const payload = await getMonitoringTargets();
      setMonitoredTargets(payload.targets);
    } catch (error) {
      console.warn("Unable to refresh monitoring targets.", error);
    }
  }, []);

  const clearMonitoredTargets = useCallback(() => {
    setMonitoredTargets([]);
  }, []);

  return {
    monitoredTargets,
    setMonitoredTargets,
    monitoredViews: monitoredTargets,
    loadMonitoredTargets,
    saveCurrentAsMonitored,
    removeMonitoredTarget,
    syncMonitoredTarget,
    clearMonitoredTargets,
  };
};
