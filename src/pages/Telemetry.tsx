import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Clock3,
  Eye,
  Gauge,
  LockKeyhole,
  RefreshCw,
  SearchCheck,
  Users,
} from "lucide-react";
import { buildApiUrl } from "@/lib/apiClient";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

const TOKEN_STORAGE_KEY = "securl:telemetry-token";

interface MetricSummary {
  count: number;
  averageMs: number;
  p50Ms: number;
  p95Ms: number;
  maxMs: number;
}

interface TelemetrySnapshot {
  startedAt: string;
  persistence: string;
  pageLoads: number;
  visitors: {
    unique: number;
    totalPageLoads: number;
    today: {
      date: string;
      pageLoads: number;
      uniqueVisitors: number;
    };
    recentDays: Array<{
      date: string;
      pageLoads: number;
      uniqueVisitors: number;
    }>;
  };
  trafficSources: {
    pageLoads: Record<string, number>;
    today: Record<string, number>;
  };
  scans: {
    requested: number;
    completed: number;
    fullReads: number;
    limitedReads: number;
    quietMode: number;
    timedOut: number;
    limitedReadKinds: Record<string, number>;
    timing: {
      total: MetricSummary;
      core: MetricSummary;
      enrichment: MetricSummary;
    };
  };
  failures: {
    classes: Record<string, number>;
    authRejected: number;
    requesterRateLimited: number;
    targetRateLimited: number;
  };
}

const formatNumber = (value: number | undefined) => (value ?? 0).toLocaleString();
const formatMs = (value: number | undefined) => `${formatNumber(Math.round(value ?? 0))}ms`;
const formatDate = (value: string | undefined) => {
  if (!value) return "Unknown";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
};

const sortEntries = (value: Record<string, number> | undefined) =>
  Object.entries(value || {}).sort(([, left], [, right]) => right - left);

const StatCard = ({
  label,
  value,
  detail,
  icon: Icon,
  tone = "teal",
}: {
  label: string;
  value: string;
  detail: string;
  icon: typeof Activity;
  tone?: "teal" | "blue" | "amber" | "rose";
}) => {
  const tones = {
    teal: "border-teal-400/20 bg-teal-400/[0.08] text-teal-200",
    blue: "border-sky-400/20 bg-sky-400/[0.08] text-sky-200",
    amber: "border-amber-400/20 bg-amber-400/[0.08] text-amber-200",
    rose: "border-rose-400/20 bg-rose-400/[0.08] text-rose-200",
  };

  return (
    <div className="rounded-[1.5rem] border border-white/10 bg-white/[0.045] p-5 shadow-[inset_0_1px_0_rgba(255,255,255,0.05)]">
      <div className="flex items-center justify-between gap-4">
        <div className={`rounded-2xl border p-3 ${tones[tone]}`}>
          <Icon className="h-5 w-5" />
        </div>
        <p className="text-[10px] font-bold uppercase tracking-[0.22em] text-zinc-500">{label}</p>
      </div>
      <p className="mt-5 text-4xl font-black tracking-[-0.05em] text-white">{value}</p>
      <p className="mt-2 text-sm leading-6 text-zinc-400">{detail}</p>
    </div>
  );
};

const Telemetry = () => {
  const [token, setToken] = useState(() => window.sessionStorage.getItem(TOKEN_STORAGE_KEY) || "");
  const [snapshot, setSnapshot] = useState<TelemetrySnapshot | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const sources = useMemo(() => sortEntries(snapshot?.trafficSources.pageLoads), [snapshot]);
  const todaySources = useMemo(() => sortEntries(snapshot?.trafficSources.today), [snapshot]);
  const failureClasses = useMemo(() => sortEntries(snapshot?.failures.classes), [snapshot]);
  const limitedReadKinds = useMemo(() => sortEntries(snapshot?.scans.limitedReadKinds), [snapshot]);

  const fetchTelemetry = async () => {
    const trimmedToken = token.trim();
    if (!trimmedToken) {
      setError("Paste the telemetry token first.");
      return;
    }

    setIsLoading(true);
    setError(null);
    try {
      const response = await fetch(buildApiUrl("/api/telemetry"), {
        headers: {
          Authorization: `Bearer ${trimmedToken}`,
        },
      });
      const payload = await response.json().catch(() => null);
      if (!response.ok) {
        throw new Error(
          payload && typeof payload === "object" && "error" in payload && typeof payload.error === "string"
            ? payload.error
            : `Telemetry request failed with HTTP ${response.status}.`,
        );
      }
      window.sessionStorage.setItem(TOKEN_STORAGE_KEY, trimmedToken);
      setSnapshot(payload as TelemetrySnapshot);
    } catch (fetchError) {
      setError(fetchError instanceof Error ? fetchError.message : "Unable to load telemetry.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (token) {
      void fetchTelemetry();
    }
    // Run once for stored tokens only; the button handles subsequent refreshes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <main className="min-h-screen bg-[#040c08] px-4 py-8 text-zinc-100 sm:px-6 lg:px-8">
      <div className="pointer-events-none fixed inset-0 -z-10 bg-[radial-gradient(ellipse_75%_50%_at_15%_-10%,rgba(16,185,129,0.34),transparent_55%),radial-gradient(ellipse_45%_35%_at_85%_5%,rgba(14,165,233,0.16),transparent_52%),linear-gradient(180deg,#040c08_0%,#07110c_100%)]" />
      <div className="mx-auto max-w-6xl">
        <section className="rounded-[2rem] border border-emerald-700/20 bg-[#07110c]/80 p-6 shadow-[0_48px_120px_-40px_rgba(0,0,0,0.8),0_0_0_1px_rgba(16,185,129,0.10)_inset] backdrop-blur-md sm:p-8">
          <div className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <div className="inline-flex items-center gap-2 rounded-full border border-teal-400/20 bg-teal-400/10 px-3 py-1 text-xs font-bold uppercase tracking-[0.2em] text-teal-200">
                <Activity className="h-3.5 w-3.5" />
                SecURL telemetry
              </div>
              <h1 className="mt-5 text-4xl font-black tracking-[-0.05em] text-white sm:text-5xl">
                Traffic and scan pulse.
              </h1>
              <p className="mt-3 max-w-2xl text-sm leading-7 text-zinc-400">
                Internal-only readout of page loads, unique visitors, traffic sources, scans, timings, and failures from the live Railway backend.
              </p>
            </div>

            <div className="w-full rounded-[1.4rem] border border-white/10 bg-zinc-950/45 p-4 lg:max-w-md">
              <Label htmlFor="telemetry-token" className="text-xs font-bold uppercase tracking-[0.18em] text-zinc-500">
                Telemetry token
              </Label>
              <div className="mt-3 flex gap-2">
                <Input
                  id="telemetry-token"
                  type="password"
                  value={token}
                  onChange={(event) => setToken(event.target.value)}
                  placeholder="Paste token"
                  className="border-white/10 bg-black/30 text-white placeholder:text-zinc-600"
                />
                <Button
                  type="button"
                  onClick={() => void fetchTelemetry()}
                  disabled={isLoading}
                  className="bg-teal-500 text-zinc-950 hover:bg-teal-400"
                >
                  <RefreshCw className={`mr-2 h-4 w-4 ${isLoading ? "animate-spin" : ""}`} />
                  Refresh
                </Button>
              </div>
              <p className="mt-2 text-xs leading-5 text-zinc-500">
                Stored in this browser tab only. The token is not bundled into the app.
              </p>
            </div>
          </div>

          {error ? (
            <div className="mt-6 rounded-[1.25rem] border border-rose-400/25 bg-rose-400/10 px-4 py-3 text-sm text-rose-100">
              {error}
            </div>
          ) : null}
        </section>

        {snapshot ? (
          <div className="mt-6 space-y-6">
            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              <StatCard
                label="Page loads"
                value={formatNumber(snapshot.pageLoads)}
                detail={`${formatNumber(snapshot.visitors.today.pageLoads)} today since the current backend start.`}
                icon={Eye}
              />
              <StatCard
                label="Unique visitors"
                value={formatNumber(snapshot.visitors.unique)}
                detail={`${formatNumber(snapshot.visitors.today.uniqueVisitors)} unique visitors today.`}
                icon={Users}
                tone="blue"
              />
              <StatCard
                label="Scans completed"
                value={`${formatNumber(snapshot.scans.completed)}/${formatNumber(snapshot.scans.requested)}`}
                detail={`${formatNumber(snapshot.scans.fullReads)} full reads, ${formatNumber(snapshot.scans.limitedReads)} limited reads.`}
                icon={SearchCheck}
                tone="teal"
              />
              <StatCard
                label="Failures"
                value={formatNumber(
                  snapshot.failures.authRejected +
                    snapshot.failures.requesterRateLimited +
                    snapshot.failures.targetRateLimited +
                    failureClasses.reduce((sum, [, count]) => sum + count, 0),
                )}
                detail={`${formatNumber(snapshot.failures.requesterRateLimited)} requester rate limits, ${formatNumber(snapshot.failures.targetRateLimited)} target limits.`}
                icon={AlertTriangle}
                tone={failureClasses.length ? "rose" : "amber"}
              />
            </div>

            <div className="grid gap-6 lg:grid-cols-[1.05fr_0.95fr]">
              <section className="rounded-[1.7rem] border border-white/10 bg-white/[0.045] p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-[10px] font-bold uppercase tracking-[0.22em] text-zinc-500">Traffic sources</p>
                    <h2 className="mt-2 text-2xl font-black tracking-[-0.04em] text-white">Where visits came from</h2>
                  </div>
                  <BarChart3 className="h-5 w-5 text-teal-300" />
                </div>
                <div className="mt-6 space-y-3">
                  {sources.length ? sources.map(([source, count]) => {
                    const width = snapshot.pageLoads ? Math.max(6, (count / snapshot.pageLoads) * 100) : 0;
                    return (
                      <div key={source} className="rounded-2xl border border-white/10 bg-black/20 p-4">
                        <div className="flex items-center justify-between gap-4">
                          <p className="font-semibold capitalize text-zinc-100">{source.replace(/_/g, " ")}</p>
                          <p className="text-sm font-bold text-teal-200">{formatNumber(count)}</p>
                        </div>
                        <div className="mt-3 h-2 overflow-hidden rounded-full bg-white/10">
                          <div className="h-full rounded-full bg-gradient-to-r from-teal-400 to-sky-400" style={{ width: `${width}%` }} />
                        </div>
                      </div>
                    );
                  }) : (
                    <p className="rounded-2xl border border-white/10 bg-black/20 p-4 text-sm text-zinc-500">No traffic source data yet.</p>
                  )}
                </div>
              </section>

              <section className="rounded-[1.7rem] border border-white/10 bg-white/[0.045] p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-[10px] font-bold uppercase tracking-[0.22em] text-zinc-500">Scan timings</p>
                    <h2 className="mt-2 text-2xl font-black tracking-[-0.04em] text-white">How the engine is behaving</h2>
                  </div>
                  <Gauge className="h-5 w-5 text-sky-300" />
                </div>
                <div className="mt-6 grid gap-3 sm:grid-cols-3">
                  {[
                    ["Total", snapshot.scans.timing.total],
                    ["Core", snapshot.scans.timing.core],
                    ["Enrichment", snapshot.scans.timing.enrichment],
                  ].map(([label, metric]) => {
                    const typedMetric = metric as MetricSummary;
                    return (
                      <div key={label as string} className="rounded-2xl border border-white/10 bg-black/20 p-4">
                        <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-zinc-500">{label as string}</p>
                        <p className="mt-3 text-2xl font-black tracking-[-0.04em] text-white">{formatMs(typedMetric.averageMs)}</p>
                        <p className="mt-1 text-xs text-zinc-500">p95 {formatMs(typedMetric.p95Ms)}</p>
                      </div>
                    );
                  })}
                </div>
                <div className="mt-5 rounded-2xl border border-white/10 bg-black/20 p-4 text-sm leading-6 text-zinc-400">
                  <p className="flex items-center gap-2 font-semibold text-zinc-200">
                    <Clock3 className="h-4 w-4 text-teal-300" />
                    Backend started {formatDate(snapshot.startedAt)}
                  </p>
                  <p className="mt-2">
                    Telemetry storage is currently <span className="font-semibold text-white">{snapshot.persistence}</span>, so these counters reset on deploy or restart.
                  </p>
                </div>
              </section>
            </div>

            <div className="grid gap-6 lg:grid-cols-3">
              <section className="rounded-[1.7rem] border border-white/10 bg-white/[0.045] p-6">
                <p className="text-[10px] font-bold uppercase tracking-[0.22em] text-zinc-500">Today</p>
                <h2 className="mt-2 text-xl font-black tracking-[-0.03em] text-white">{snapshot.visitors.today.date}</h2>
                <div className="mt-5 space-y-2 text-sm text-zinc-300">
                  {todaySources.length ? todaySources.map(([source, count]) => (
                    <div key={source} className="flex justify-between rounded-xl bg-black/20 px-3 py-2">
                      <span className="capitalize">{source.replace(/_/g, " ")}</span>
                      <span className="font-semibold text-white">{count}</span>
                    </div>
                  )) : <p className="text-zinc-500">No visits today.</p>}
                </div>
              </section>

              <section className="rounded-[1.7rem] border border-white/10 bg-white/[0.045] p-6">
                <p className="text-[10px] font-bold uppercase tracking-[0.22em] text-zinc-500">Limited reads</p>
                <h2 className="mt-2 text-xl font-black tracking-[-0.03em] text-white">{formatNumber(snapshot.scans.limitedReads)} total</h2>
                <div className="mt-5 space-y-2 text-sm text-zinc-300">
                  {limitedReadKinds.length ? limitedReadKinds.map(([kind, count]) => (
                    <div key={kind} className="flex justify-between rounded-xl bg-black/20 px-3 py-2">
                      <span>{kind}</span>
                      <span className="font-semibold text-white">{count}</span>
                    </div>
                  )) : <p className="text-zinc-500">No limited-read buckets recorded.</p>}
                </div>
              </section>

              <section className="rounded-[1.7rem] border border-white/10 bg-white/[0.045] p-6">
                <p className="text-[10px] font-bold uppercase tracking-[0.22em] text-zinc-500">Access guard</p>
                <h2 className="mt-2 flex items-center gap-2 text-xl font-black tracking-[-0.03em] text-white">
                  <LockKeyhole className="h-5 w-5 text-teal-300" />
                  Protected
                </h2>
                <div className="mt-5 space-y-2 text-sm text-zinc-300">
                  <div className="flex justify-between rounded-xl bg-black/20 px-3 py-2">
                    <span>Auth rejected</span>
                    <span className="font-semibold text-white">{formatNumber(snapshot.failures.authRejected)}</span>
                  </div>
                  <div className="flex justify-between rounded-xl bg-black/20 px-3 py-2">
                    <span>Timed out scans</span>
                    <span className="font-semibold text-white">{formatNumber(snapshot.scans.timedOut)}</span>
                  </div>
                </div>
              </section>
            </div>
          </div>
        ) : (
          <div className="mt-6 rounded-[1.7rem] border border-dashed border-white/10 bg-white/[0.035] p-10 text-center">
            <LockKeyhole className="mx-auto h-8 w-8 text-zinc-500" />
            <h2 className="mt-4 text-xl font-black tracking-[-0.03em] text-white">Paste the telemetry token to load the dashboard.</h2>
            <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-zinc-500">
              This page is deliberately dumb and safe: no token is shipped in the frontend bundle.
            </p>
          </div>
        )}
      </div>
    </main>
  );
};

export default Telemetry;
