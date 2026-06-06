import { Radar } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { StatusAlert } from "@/components/ui/panel-primitives";
import { PublicSignalsInfo } from "@/types/analysis";

interface PublicSignalsPanelProps {
  publicSignals: PublicSignalsInfo;
}

const statusStyles = {
  preloaded: "bg-white/8 text-zinc-100",
  pending: "bg-white/8 text-zinc-100",
  eligible: "bg-[#7f1d1d]/14 text-zinc-300",
  not_preloaded: "bg-white/8 text-zinc-200",
  unknown: "bg-white/8 text-zinc-200",
} as const;

const formatStatus = (status: PublicSignalsInfo["hstsPreload"]["status"]) =>
  status
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");

export const PublicSignalsPanel = ({ publicSignals }: PublicSignalsPanelProps) => {
  return (
    <Card className="h-full border-white/10 bg-white/4 shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Radar className="h-5 w-5" />
          Public Trust Signals
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="min-w-0 rounded-[1.35rem] border border-white/10 bg-white/4 p-4">
          <div className="flex items-center justify-between gap-3">
            <p className="text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-400">HSTS preload dataset</p>
            <span className={`rounded-full px-2.5 py-1 text-xs font-semibold ${statusStyles[publicSignals.hstsPreload.status]}`}>
              {formatStatus(publicSignals.hstsPreload.status)}
            </span>
          </div>
          <p className="mt-3 overflow-hidden wrap-break-word text-sm leading-6 text-zinc-200">{publicSignals.hstsPreload.summary}</p>
          <a
            href={publicSignals.hstsPreload.sourceUrl}
            target="_blank"
            rel="noreferrer"
            className="mt-3 inline-flex text-sm font-medium text-[#e0b286] hover:text-zinc-300"
          >
            Open dataset reference
          </a>
        </div>

        <div className="space-y-2">
          {publicSignals.strengths.map((strength) => (
            <StatusAlert key={strength} variant="success">{strength}</StatusAlert>
          ))}
          {publicSignals.issues.map((issue) => (
            <StatusAlert key={issue} variant="warning">{issue}</StatusAlert>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};
