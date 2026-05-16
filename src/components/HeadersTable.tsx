import { AlertTriangle, CheckCircle2, Info, ShieldAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { SecurityHeaderResult } from "@/types/analysis";

interface HeadersTableProps {
  headers: SecurityHeaderResult[];
}

const statusStyles: Record<SecurityHeaderResult["status"], string> = {
  present: "border-white/10 bg-white/[0.08] text-zinc-100",
  warning: "border-[#14b8a6]/35 bg-[#14b8a6]/14 text-[#99f6e4]",
  missing: "border-[#7f1d1d]/35 bg-[#7f1d1d]/14 text-[#99f6e4]",
};

const statusIcons = {
  present: <CheckCircle2 className="h-4 w-4" />,
  warning: <AlertTriangle className="h-4 w-4" />,
  missing: <ShieldAlert className="h-4 w-4" />,
};

export const HeadersTable = ({ headers }: HeadersTableProps) => {
  return (
    <div className="space-y-4 overflow-x-auto">
      <Table>
        <TableHeader>
          <TableRow className="border-white/10 hover:bg-transparent">
            <TableHead className="w-[220px] text-zinc-400">Header</TableHead>
            <TableHead className="w-[120px] text-zinc-400">Status</TableHead>
            <TableHead className="text-zinc-400">Value</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {headers.map((header) => (
            <TableRow key={header.key} className="align-top border-white/10 hover:bg-white/[0.02]">
              <TableCell className="space-y-1">
                <div className="font-medium text-zinc-100">{header.label}</div>
                <p className="text-xs text-zinc-400">{header.description}</p>
              </TableCell>
              <TableCell>
                <Badge variant="outline" className={`gap-1 ${statusStyles[header.status]}`}>
                  {statusIcons[header.status]}
                  {header.status}
                </Badge>
              </TableCell>
              <TableCell className="space-y-2">
                <code className="block whitespace-pre-wrap break-all rounded-xl border border-white/10 bg-zinc-950/75 px-3 py-2 text-xs text-zinc-200">
                  {header.value ?? "Not returned by the origin"}
                </code>
                <p className="text-xs text-zinc-400">{header.summary}</p>
                {header.status !== "present" && (
                  <div className="flex gap-2 rounded-xl border border-[#14b8a6]/35 bg-[#14b8a6]/12 px-3 py-2 text-xs text-[#99f6e4]">
                    <Info className="mt-0.5 h-4 w-4 shrink-0" />
                    <span>{header.recommendation}</span>
                  </div>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
};
