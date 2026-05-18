import { FormEvent, useState } from "react";
import { Globe, Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";

interface UrlFormProps {
  onSubmit: (url: string) => void;
  isLoading: boolean;
  initialValue?: string;
  scanStage?: {
    key: string;
    label: string;
    detail: string;
  } | null;
}

const stageOrder = ["queueing", "reading", "analyzing", "waiting"];

export const UrlForm = ({ onSubmit, isLoading, initialValue = "", scanStage = null }: UrlFormProps) => {
  const [url, setUrl] = useState(initialValue);

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault();
    const trimmed = url.trim();

    if (!trimmed) {
      toast.error("Enter a URL to scan.");
      return;
    }

    try {
      const candidate = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
      new URL(candidate);
      onSubmit(candidate);
    } catch {
      toast.error("That URL does not look valid.");
    }
  };

  return (
    <form
      onSubmit={handleSubmit}
      className="w-full rounded-[1.75rem] border border-white/10 bg-white/[0.06] p-2 shadow-2xl shadow-black/20 backdrop-blur"
    >
      <div className="flex flex-col gap-2 sm:gap-3 md:flex-row md:items-center">
        <div className="flex flex-1 items-center gap-3 rounded-[1.25rem] border border-white/10 bg-zinc-950/60 px-4 py-3">
          <Globe className="h-5 w-5 text-[#2dd4bf]" />
          <Input
            type="text"
            placeholder="github.com"
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            className="border-0 bg-transparent px-0 text-base text-zinc-50 shadow-none placeholder:text-zinc-500 focus-visible:ring-0"
          />
        </div>
        <Button
          type="submit"
          disabled={isLoading}
          className="h-12 rounded-[1.25rem] bg-[#14b8a6] px-6 text-sm font-bold text-[#f0fdfa] sm:h-14 sm:px-10 sm:text-base shadow-[0_8px_32px_-8px_rgba(20,184,166,0.6),0_0_0_1px_rgba(20,184,166,0.3)_inset] hover:bg-[#0f9f92] hover:shadow-[0_14px_40px_-8px_rgba(20,184,166,0.75),0_0_0_1px_rgba(20,184,166,0.4)_inset] active:scale-[0.98] transition-all duration-200"
        >
          <Search className="mr-2.5 h-5 w-5" />
          {isLoading ? "Scanning…" : "Run Scan"}
        </Button>
      </div>
      <p className="px-2 pt-3 text-sm text-zinc-400">
        Enter a domain or full URL. If you omit the scheme, the scanner will try HTTPS automatically.
      </p>
      {isLoading && scanStage ? (
        <div className="mt-4 rounded-[1.2rem] border border-[#14b8a6]/20 bg-zinc-950/40 px-4 py-3 shadow-[0_18px_36px_-28px_rgba(0,0,0,0.75)]">
          <div className="flex flex-col items-start gap-2 sm:flex-row sm:items-center sm:justify-between sm:gap-3">
            <div>
              <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-500">Live scan status</p>
              <p className="mt-1 text-sm font-semibold text-zinc-100">{scanStage.label}</p>
            </div>
            <div className="flex items-center gap-2">
              {stageOrder.map((stage, index) => {
                const currentIndex = stageOrder.indexOf(scanStage.key);
                const complete = index < currentIndex;
                const active = stage === scanStage.key;
                return (
                  <div
                    key={stage}
                    className={`h-2.5 w-12 rounded-full transition-all duration-500 ${
                      complete
                        ? "bg-[#2dd4bf]"
                        : active
                          ? "bg-gradient-to-r from-[#0d9488] via-[#14b8a6] to-[#2dd4bf]"
                          : "bg-white/10"
                    } ${active ? "shadow-[0_0_0_1px_rgba(216,154,99,0.22)]" : ""}`}
                  />
                );
              })}
            </div>
          </div>
          <p className="mt-3 text-sm leading-6 text-zinc-400">{scanStage.detail}</p>
        </div>
      ) : null}
    </form>
  );
};
