import { useEffect, useState } from "react";
import { AlertTriangle, ArrowRight, CheckCircle2, ExternalLink, RefreshCw, ShieldCheck } from "lucide-react";
import {
  ApiClientError,
  getSharedLinkResult,
  recheckSharedLink,
  recordSharedLinkRecheck,
  type LinkInspectionResult,
  type SharedLinkResult,
} from "@/lib/apiClient";

type LoadState = "loading" | "active" | "not_found" | "expired" | "revoked" | "error";

const verdictTone = {
  no_obvious_concern: "border-emerald-400/20 bg-emerald-400/8 text-emerald-200",
  review: "border-amber-400/20 bg-amber-400/8 text-amber-100",
  high_attention: "border-orange-400/25 bg-orange-400/10 text-orange-100",
  blocked: "border-red-400/20 bg-red-400/8 text-red-100",
} as const;

function stateFromError(error: unknown): LoadState {
  if (!(error instanceof ApiClientError)) return "error";
  const code = typeof error.payload === "object" && error.payload && "code" in error.payload
    ? String(error.payload.code)
    : "";
  if (code === "link_share_expired") return "expired";
  if (code === "link_share_revoked") return "revoked";
  if (error.status === 404) return "not_found";
  return "error";
}

export function SharedLinkPage({ publicId }: { publicId: string }) {
  const [share, setShare] = useState<SharedLinkResult | null>(null);
  const [state, setState] = useState<LoadState>("loading");
  const [checking, setChecking] = useState(false);
  const [freshResult, setFreshResult] = useState<LinkInspectionResult | null>(null);
  const [checkError, setCheckError] = useState<string | null>(null);

  useEffect(() => {
    const previousTitle = document.title;
    const robots = document.querySelector<HTMLMetaElement>('meta[name="robots"]');
    const previousRobots = robots?.content;
    const robotsMeta = robots ?? document.head.appendChild(document.createElement("meta"));
    robotsMeta.name = "robots";
    robotsMeta.content = "noindex, nofollow, noarchive";
    document.title = "Shared link check | SecURL";

    getSharedLinkResult(publicId)
      .then(({ share: loadedShare }) => {
        setShare(loadedShare);
        setState("active");
      })
      .catch((error) => setState(stateFromError(error)));

    return () => {
      document.title = previousTitle;
      if (robots) robots.content = previousRobots ?? "";
      else robotsMeta.remove();
    };
  }, [publicId]);

  const runFreshCheck = async () => {
    if (!share || checking) return;
    setChecking(true);
    setCheckError(null);
    setFreshResult(null);
    try {
      await recordSharedLinkRecheck(publicId, "started");
      const { inspection } = await recheckSharedLink(share.source.displayUrl);
      setFreshResult(inspection);
      await recordSharedLinkRecheck(publicId, "completed");
    } catch (error) {
      setCheckError(error instanceof Error ? error.message : "The fresh check could not be completed.");
    } finally {
      setChecking(false);
    }
  };

  if (state === "loading") {
    return <StatusScreen title="Loading shared result" detail="Retrieving the redacted evidence card." loading />;
  }

  if (state !== "active" || !share) {
    const copy = {
      not_found: ["Shared result not found", "The link may be incorrect or the result may no longer exist."],
      expired: ["Shared result expired", "Shared link checks expire after 30 days. Ask the sender to run a new check."],
      revoked: ["Shared result revoked", "The person who created this result has withdrawn it."],
      error: ["Shared result unavailable", "The result could not be loaded. Please try again shortly."],
    }[state] ?? ["Shared result unavailable", "The result could not be loaded."];
    return <StatusScreen title={copy[0]} detail={copy[1]} />;
  }

  const result = freshResult ?? share;
  const checkedAt = freshResult ? "Checked again just now" : `Shared ${new Date(share.createdAt).toLocaleDateString()}`;

  return (
    <div className="min-h-screen bg-[#070b14] px-5 py-10 text-zinc-100 sm:py-16">
      <main className="mx-auto max-w-3xl">
        <header className="mb-8 flex items-center justify-between gap-4">
          <a href="/" className="flex items-center gap-2 text-sm font-black tracking-tight text-white">
            <span className="flex h-8 w-8 items-center justify-center rounded-xl bg-gradient-to-br from-[#b56a2c] to-[#d89a63]">
              <ShieldCheck className="h-4 w-4" />
            </span>
            SecURL
          </a>
          <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1 text-[10px] font-bold uppercase tracking-[0.18em] text-zinc-400">
            Redacted link result
          </span>
        </header>

        <section className="overflow-hidden rounded-3xl border border-white/10 bg-white/[0.04] shadow-2xl shadow-black/30">
          <div className="border-b border-white/8 px-6 py-7 sm:px-9">
            <p className="text-xs font-bold uppercase tracking-[0.18em] text-[#d89a63]">{checkedAt}</p>
            <h1 className="mt-3 break-words text-xl font-black tracking-tight text-white sm:text-3xl">
              {share.source.hostname}
            </h1>
            <p className="mt-2 break-all text-sm text-zinc-400">{share.source.displayUrl}</p>
            <p className="mt-3 text-xs leading-5 text-zinc-500">
              Query strings, fragments, embedded credentials and token-like path values were removed before this result was stored.
            </p>
          </div>

          <div className="space-y-6 px-6 py-7 sm:px-9">
            <div className={`rounded-2xl border p-5 ${verdictTone[result.verdict.level]}`}>
              <div className="flex items-start gap-3">
                {result.verdict.level === "no_obvious_concern"
                  ? <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0" />
                  : <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0" />}
                <div>
                  <h2 className="font-bold">{result.verdict.title}</h2>
                  <p className="mt-1 text-sm leading-6 opacity-90">{result.verdict.summary}</p>
                </div>
              </div>
            </div>

            {share.destination && share.destination.hostname !== share.source.hostname && (
              <div>
                <p className="text-xs font-bold uppercase tracking-[0.16em] text-zinc-500">Resolved destination</p>
                <p className="mt-2 break-all text-sm text-zinc-200">{share.destination.displayUrl}</p>
              </div>
            )}

            {result.signals.length > 0 && (
              <div>
                <h2 className="text-sm font-bold text-white">What SecURL noticed</h2>
                <ul className="mt-3 space-y-2">
                  {result.signals.map((signal) => (
                    <li key={signal.id} className="flex gap-3 rounded-xl border border-white/7 bg-black/15 px-4 py-3 text-sm text-zinc-300">
                      <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-[#d89a63]" />
                      {signal.title ?? signal.id.replaceAll("_", " ")}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <div className="rounded-2xl border border-white/7 bg-black/15 p-4 text-xs leading-5 text-zinc-400">
              <strong className="text-zinc-200">What this does not prove:</strong> SecURL checks passive link and redirect signals. It does not execute scripts, download files, sign in, or provide a malware or safety guarantee.
            </div>

            {checkError && <p role="alert" className="text-sm text-red-300">{checkError}</p>}

            <button
              type="button"
              onClick={runFreshCheck}
              disabled={checking}
              className="flex w-full items-center justify-center gap-2 rounded-2xl bg-[#b56a2c] px-5 py-3.5 text-sm font-bold text-white transition hover:bg-[#9d5a23] disabled:cursor-wait disabled:opacity-70"
            >
              <RefreshCw className={`h-4 w-4 ${checking ? "animate-spin" : ""}`} />
              {checking ? "Running a fresh passive check" : freshResult ? "Check again" : "Run a fresh check"}
              {!checking && <ArrowRight className="h-4 w-4" />}
            </button>
          </div>
        </section>

        <div className="mt-6 flex flex-col items-center justify-between gap-3 text-xs text-zinc-500 sm:flex-row">
          <span>Expires {new Date(share.expiresAt).toLocaleDateString()}</span>
          <a href="https://securl.online/check-link/" className="inline-flex items-center gap-1.5 hover:text-zinc-300">
            Check a different link <ExternalLink className="h-3.5 w-3.5" />
          </a>
        </div>
      </main>
    </div>
  );
}

function StatusScreen({ title, detail, loading = false }: { title: string; detail: string; loading?: boolean }) {
  return (
    <div className="flex min-h-screen items-center justify-center bg-[#070b14] px-6 text-center text-zinc-100">
      <div className="max-w-md">
        {loading
          ? <RefreshCw className="mx-auto mb-5 h-8 w-8 animate-spin text-[#d89a63]" />
          : <ShieldCheck className="mx-auto mb-5 h-9 w-9 text-zinc-500" />}
        <h1 className="text-xl font-black text-white">{title}</h1>
        <p className="mt-2 text-sm leading-6 text-zinc-400">{detail}</p>
        {!loading && <a href="https://securl.online/check-link/" className="mt-6 inline-flex rounded-xl bg-[#b56a2c] px-5 py-2.5 text-sm font-bold text-white">Check a link</a>}
      </div>
    </div>
  );
}
