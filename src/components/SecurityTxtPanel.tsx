import { FileSearch, ShieldAlert, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { StatBox, StatusAlert } from "@/components/ui/panel-primitives";
import { SecurityTxtInfo } from "@/types/analysis";

interface SecurityTxtPanelProps {
  securityTxt: SecurityTxtInfo;
}

const statusStyles: Record<SecurityTxtInfo["status"], string> = {
  present_valid: "bg-zinc-700/40 text-zinc-300",
  present_expired: "bg-[#f97316]/14 text-[#fed7aa]",
  present_incomplete: "bg-[#eab308]/14 text-[#fde68a]",
  missing: "bg-[#7f1d1d]/14 text-zinc-300",
};

export const SecurityTxtPanel = ({ securityTxt }: SecurityTxtPanelProps) => {
  return (
    <Card className="border-white/10 bg-white/[0.04] shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FileSearch className="h-5 w-5" />
          security.txt
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex min-w-0 items-center gap-3">
          <Badge variant="secondary" className={statusStyles[securityTxt.status]}>
            {securityTxt.status}
          </Badge>
          {securityTxt.url ? (
            <a href={securityTxt.url} target="_blank" rel="noreferrer" className="min-w-0 truncate text-sm text-[#e0b286] underline" title={securityTxt.url}>
              {securityTxt.url}
            </a>
          ) : (
            <span className="text-sm text-zinc-400">No file discovered</span>
          )}
        </div>

        <div className="grid gap-4 md:grid-cols-2">
          <StatBox
            label="Contact"
            value={
              <div className="space-y-1 text-sm text-zinc-200">
                {securityTxt.contact.length ? securityTxt.contact.map((item) => <p key={item} className="break-words text-zinc-200">{item}</p>) : <p className="text-zinc-400">Not listed</p>}
              </div>
            }
          />
          <StatBox
            label="Expires"
            value={<p className="text-sm text-zinc-200">{securityTxt.expires ?? "Not listed"}</p>}
          />
        </div>

        {securityTxt.policy && (
          <StatBox
            label="Policy"
            value={
              <div className="space-y-1 text-sm text-zinc-200">
                <p className="break-words text-zinc-200">{securityTxt.policy}</p>
              </div>
            }
          />
        )}

        <div className="space-y-2">
          {securityTxt.issues.map((issue) => (
            <StatusAlert
              key={issue}
              variant={securityTxt.status === "present_valid" ? "warning" : "critical"}
              icon={<ShieldAlert />}
            >
              {issue}
            </StatusAlert>
          ))}
          {securityTxt.status === "present_valid" && securityTxt.issues.length === 0 && (
            <StatusAlert variant="success" icon={<ShieldCheck />}>
              Valid security.txt discovered with contact information.
            </StatusAlert>
          )}
        </div>
      </CardContent>
    </Card>
  );
};
