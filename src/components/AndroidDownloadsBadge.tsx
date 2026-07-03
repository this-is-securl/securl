import { Download, Smartphone } from "lucide-react";

const ANDROID_DOWNLOADS_URL = "https://securl.online/downloads";

export function AndroidDownloadsBadge({ className = "" }: { className?: string }) {
  return (
    <a
      href={ANDROID_DOWNLOADS_URL}
      target="_blank"
      rel="noopener noreferrer"
      aria-label="Download SecURL Android APKs"
      className={`inline-flex items-center gap-3 rounded-xl border border-emerald-300/20 bg-emerald-400/10 px-4 py-2.5 text-emerald-50 transition-all duration-200 hover:border-emerald-200/35 hover:bg-emerald-400/15 ${className}`}
    >
      <span className="relative flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-emerald-300/15 text-emerald-200">
        <Smartphone className="h-4 w-4" aria-hidden="true" />
        <Download className="absolute -bottom-1 -right-1 h-3.5 w-3.5 rounded-full bg-[#070b14] p-0.5 text-emerald-200" aria-hidden="true" />
      </span>
      <span className="flex flex-col leading-none text-left">
        <span className="text-[10px] font-medium tracking-wide text-emerald-50/70">Self-hosted</span>
        <span className="text-base font-semibold tracking-[-0.01em] text-white">Android APKs</span>
      </span>
    </a>
  );
}
