import { FolderSearch, ShieldAlert, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { StatusAlert } from "@/components/ui/panel-primitives";
import { getHttpStatusDetails } from "@/lib/httpStatus";
import { ExposureSummary } from "@/types/analysis";

interface ExposurePanelProps {
  exposure: ExposureSummary;
}

const findingStyles = {
  safe: "bg-white/8 text-zinc-100",
  interesting: "bg-[#7f1d1d]/14 text-zinc-300",
  blocked: "bg-white/8 text-zinc-100",
  exposed: "bg-zinc-700/40 text-zinc-300",
  error: "bg-zinc-700/40 text-zinc-300",
} as const;

export const ExposurePanel = ({ exposure }: ExposurePanelProps) => {
  return (
    <Card className="border-white/10 bg-white/4 shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FolderSearch className="h-5 w-5" />
          Low-Noise Exposure Checks
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-3">
          {exposure.probes.map((probe) => {
            const status = probe.statusCode ? getHttpStatusDetails(probe.statusCode) : null;
            return (
              <div key={probe.path} className="rounded-[1.25rem] border border-white/10 bg-white/4 p-4">
                <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
                  <div className="min-w-0">
                    <p className="font-semibold text-zinc-50">{probe.label}</p>
                    <p className="truncate text-sm text-zinc-400" title={probe.path}>{probe.path}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="secondary" className={findingStyles[probe.finding]}>
                      {probe.finding}
                    </Badge>
                    <span className="text-sm font-semibold text-zinc-200">
                      {probe.statusCode ? `${probe.statusCode} ${status?.label}` : "n/a"}
                    </span>
                  </div>
                </div>
                <p className="mt-3 text-sm text-zinc-300">{probe.detail}</p>
                {status ? (
                  <p className="mt-1 text-xs leading-5 text-zinc-400">
                    {status.meaning}
                  </p>
                ) : null}
              </div>
            );
          })}
        </div>

        <div className="space-y-2">
          {exposure.strengths.map((strength) => (
            <StatusAlert key={strength} variant="success" icon={<ShieldCheck />}>{strength}</StatusAlert>
          ))}
          {exposure.issues.map((issue) => (
            <StatusAlert key={issue} variant="critical" icon={<ShieldAlert />}>{issue}</StatusAlert>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};
