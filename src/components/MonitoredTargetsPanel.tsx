import { BellDot, Clock3, Play, Trash2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export interface MonitoredTargetView {
  id: string;
  url: string;
  label: string;
  cadence: "daily" | "weekly";
  addedAt: string;
  lastScannedAt: string | null;
  nextDueAt: string;
  due: boolean;
  latestScan: {
    score: number | null;
    grade: string | null;
  } | null;
  previousScan: {
    score: number | null;
    grade: string | null;
  } | null;
  scoreDelta: number | null;
}

interface MonitoredTargetsPanelProps {
  targets: MonitoredTargetView[];
  currentUrl: string | null;
  monitoredCount: number;
  dueCount: number;
  embedded?: boolean;
  onAddDaily: () => void;
  onAddWeekly: () => void;
  onRunDue: () => void;
  onRunTarget: (url: string) => void;
  onRemove: (targetId: string) => void;
  busy: boolean;
}

export const MonitoredTargetsPanel = ({
  targets,
  currentUrl,
  monitoredCount,
  dueCount,
  embedded = false,
  onAddDaily,
  onAddWeekly,
  onRunDue,
  onRunTarget,
  onRemove,
  busy,
}: MonitoredTargetsPanelProps) => {
  const panelClass = embedded
    ? "border-0 bg-transparent text-slate-100 shadow-none"
    : "border-white/10 bg-white/[0.04] text-slate-100 shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]";
  const metricTileClass = embedded
    ? "rounded-[1.2rem] border border-white/10 bg-slate-950/45 px-4 py-3 shadow-sm"
    : "rounded-2xl border border-white/10 bg-white/[0.04] px-4 py-3 shadow-sm";
  const mutedTextClass = embedded ? "text-slate-400" : "text-slate-400";
  const strongTextClass = embedded ? "text-slate-50" : "text-slate-50";
  const buttonClass = embedded
    ? "rounded-2xl border-white/10 bg-white/[0.06] text-slate-100 hover:bg-white/[0.1] hover:text-white"
    : "rounded-2xl";

  if (embedded) {
    return (
      <div className="space-y-3">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2 text-lg font-semibold text-slate-50">
              <BellDot className="h-5 w-5 text-[#d89a63]" />
              Monitoring
            </div>
            <p className="max-w-xl text-sm leading-5 text-slate-400">
              Server-backed watchlist with compact drift tracking.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2 lg:justify-end">
            <div className="inline-flex rounded-2xl border border-white/10 bg-slate-950/45 p-1">
              <Button
                variant="ghost"
                className="h-8 rounded-[0.9rem] px-3 text-xs text-slate-200 hover:bg-white/[0.08] hover:text-white"
                disabled={!currentUrl || busy}
                onClick={onAddDaily}
              >
                Save daily
              </Button>
              <Button
                variant="ghost"
                className="h-8 rounded-[0.9rem] px-3 text-xs text-slate-200 hover:bg-white/[0.08] hover:text-white"
                disabled={!currentUrl || busy}
                onClick={onAddWeekly}
              >
                Save weekly
              </Button>
            </div>
            <Button
              className="h-8 rounded-2xl bg-[#b56a2c] px-3 text-xs text-[#f8efe7] hover:bg-[#c07a3f]"
              disabled={!targets.some((target) => target.due) || busy}
              onClick={onRunDue}
            >
              Run due
            </Button>
          </div>
        </div>

        <div className="grid gap-3 md:grid-cols-[repeat(3,minmax(0,1fr))]">
          <div className="rounded-[1rem] border border-white/10 bg-slate-950/45 px-4 py-3">
            <div className="flex items-center gap-2 text-sm font-medium text-slate-400">
              <BellDot className="h-4 w-4" />
              Monitored
            </div>
            <div className="mt-2 text-2xl font-semibold text-slate-50">{monitoredCount}</div>
          </div>
          <div className="rounded-[1rem] border border-white/10 bg-slate-950/45 px-4 py-3">
            <div className="flex items-center gap-2 text-sm font-medium text-slate-400">
              <Clock3 className="h-4 w-4" />
              Due now
            </div>
            <div className="mt-2 text-2xl font-semibold text-slate-50">{dueCount}</div>
          </div>
          <div className="rounded-[1rem] border border-white/10 bg-slate-950/45 px-4 py-3">
            <p className="text-sm font-medium text-slate-400">Current site</p>
            <p className="mt-2 text-sm font-semibold text-slate-100">{currentUrl ? "Ready to add" : "No active site"}</p>
            <p className="mt-1 text-xs text-slate-500">
              {currentUrl ? "Save it to the shared monitoring list using the controls above." : "Run or reopen a scan first."}
            </p>
          </div>
        </div>

        {targets.length ? (
          <div className="grid gap-3 xl:grid-cols-2">
            {targets.map((target) => (
              <div key={target.id} className="rounded-[1rem] border border-white/10 bg-slate-950/45 p-3.5 shadow-sm">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <p className="truncate text-sm font-semibold text-slate-50">{target.label}</p>
                      <Badge
                        variant="secondary"
                        className={target.due ? "bg-[#b56a2c]/16 text-[#f0d5bc]" : "bg-white/[0.08] text-slate-100"}
                      >
                        {target.due ? "due" : "scheduled"}
                      </Badge>
                    </div>
                    <p className="mt-2 truncate text-xs text-slate-400">{target.url}</p>
                    <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-slate-400">
                      <Badge variant="outline" className="rounded-full">
                        {target.cadence}
                      </Badge>
                      <span>Next: {new Date(target.nextDueAt).toLocaleDateString()}</span>
                      {target.latestScan?.score !== null ? (
                        <span>
                          Latest: {target.latestScan?.score}%{target.latestScan?.grade ? ` (${target.latestScan.grade})` : ""}
                        </span>
                      ) : null}
                    </div>
                    {target.scoreDelta !== null ? (
                      <p className="mt-2 text-xs text-slate-400">
                        Score delta: {target.scoreDelta > 0 ? "+" : ""}{target.scoreDelta}
                      </p>
                    ) : null}
                  </div>
                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      className={`h-8 px-3 text-xs ${buttonClass}`}
                      disabled={busy}
                      onClick={() => onRunTarget(target.url)}
                    >
                      <Play className="mr-1.5 h-3.5 w-3.5" />
                      Scan now
                    </Button>
                    <Button
                      variant="outline"
                      className={`h-8 px-3 text-xs ${buttonClass}`}
                      disabled={busy}
                      onClick={() => onRemove(target.id)}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="rounded-[1rem] border border-dashed border-white/10 bg-slate-950/35 px-4 py-5 text-sm text-slate-400">
            No monitored targets yet. Save the current site as a daily or weekly watch target to start server-backed drift tracking here.
          </div>
        )}
      </div>
    );
  }

  return (
    <Card className={panelClass}>
      <CardHeader className={embedded ? "flex flex-col gap-4 px-0 pt-0 md:flex-row md:items-start md:justify-between" : "flex flex-col gap-4 md:flex-row md:items-center md:justify-between"}>
        <div className="space-y-2">
          <CardTitle className="flex items-center gap-2">
            <BellDot className="h-5 w-5" />
            Monitoring Targets
          </CardTitle>
          <p className={`max-w-2xl text-sm ${mutedTextClass}`}>
            Server-backed monitoring targets now persist across clients. Scheduled scans still only run when you trigger them from the app.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" className={buttonClass} disabled={!currentUrl || busy} onClick={onAddDaily}>
            Monitor Daily
          </Button>
          <Button variant="outline" className={buttonClass} disabled={!currentUrl || busy} onClick={onAddWeekly}>
            Monitor Weekly
          </Button>
          <Button
            className={embedded ? "rounded-2xl bg-[#b56a2c] text-[#f8efe7] hover:bg-[#c07a3f]" : "rounded-2xl"}
            disabled={!targets.some((target) => target.due) || busy}
            onClick={onRunDue}
          >
            Run Due Scans
          </Button>
        </div>
      </CardHeader>
      <CardContent className={embedded ? "space-y-4 px-0 pb-0" : "space-y-4"}>
        <div className="grid gap-4 md:grid-cols-3">
          <div className={metricTileClass}>
            <div className={`flex items-center gap-2 text-sm font-medium ${mutedTextClass}`}>
              <BellDot className="h-4 w-4" />
              Monitored
            </div>
            <div className={`mt-2 text-2xl font-semibold ${strongTextClass}`}>{monitoredCount}</div>
          </div>
          <div className={metricTileClass}>
            <div className={`flex items-center gap-2 text-sm font-medium ${mutedTextClass}`}>
              <Clock3 className="h-4 w-4" />
              Due now
            </div>
            <div className={`mt-2 text-2xl font-semibold ${strongTextClass}`}>{dueCount}</div>
          </div>
          <div className={metricTileClass}>
            <p className={`text-sm font-medium ${mutedTextClass}`}>Save current site</p>
            <div className="mt-3 flex flex-wrap gap-2">
              <Button
                variant="outline"
                className={`h-9 px-3 text-xs ${buttonClass}`}
                disabled={!currentUrl || busy}
                onClick={onAddDaily}
              >
                Daily
              </Button>
              <Button
                variant="outline"
                className={`h-9 px-3 text-xs ${buttonClass}`}
                disabled={!currentUrl || busy}
                onClick={onAddWeekly}
              >
                Weekly
              </Button>
            </div>
            {!currentUrl ? (
              <p className={`mt-3 text-xs ${mutedTextClass}`}>Run or reopen a scan first.</p>
            ) : null}
          </div>
        </div>

        {targets.length ? (
          <div className={`grid gap-3 ${embedded ? "md:grid-cols-3" : ""}`}>
            {targets.map((target) => (
              <div key={target.id} className={embedded ? "rounded-2xl border border-white/10 bg-slate-950/45 p-4 shadow-sm" : "rounded-2xl border border-white/10 bg-white/[0.04] p-4 shadow-sm"}>
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <p className={`truncate text-sm font-semibold ${strongTextClass}`}>{target.label}</p>
                      <Badge
                        variant="secondary"
                        className={target.due ? "bg-[#b56a2c]/16 text-[#f0d5bc]" : "bg-white/[0.08] text-slate-100"}
                      >
                        {target.due ? "due" : "scheduled"}
                      </Badge>
                    </div>
                    <p className={`mt-2 truncate text-xs ${mutedTextClass}`}>{target.url}</p>
                    <div className={`mt-3 flex flex-wrap items-center gap-2 text-xs ${mutedTextClass}`}>
                      <Badge variant="outline" className="rounded-full">
                        {target.cadence}
                      </Badge>
                      <span>Next: {new Date(target.nextDueAt).toLocaleDateString()}</span>
                      {target.latestScan?.score !== null ? (
                        <span>
                          Latest: {target.latestScan.score}%{target.latestScan.grade ? ` (${target.latestScan.grade})` : ""}
                        </span>
                      ) : null}
                    </div>
                    {!embedded ? (
                      <div className={`mt-3 flex flex-wrap gap-4 text-xs ${mutedTextClass}`}>
                        <span className="inline-flex items-center gap-1">
                          <Clock3 className="h-3.5 w-3.5" />
                          Last: {target.lastScannedAt ? new Date(target.lastScannedAt).toLocaleString() : "Not yet run"}
                        </span>
                        {target.scoreDelta !== null ? (
                          <span>Score delta: {target.scoreDelta > 0 ? "+" : ""}{target.scoreDelta}</span>
                        ) : null}
                      </div>
                    ) : null}
                  </div>
                </div>
                <div className="mt-3 flex gap-2">
                  <Button
                    variant="outline"
                    className={`h-9 flex-1 px-3 text-xs ${buttonClass}`}
                    disabled={busy}
                    onClick={() => onRunTarget(target.url)}
                  >
                    <Play className="mr-1.5 h-3.5 w-3.5" />
                    Run
                  </Button>
                  <Button
                    variant="outline"
                    className={`h-9 px-3 text-xs ${buttonClass}`}
                    disabled={busy}
                    onClick={() => onRemove(target.id)}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </div>
            ))}
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
};
