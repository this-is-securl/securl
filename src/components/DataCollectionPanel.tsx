import { FormInput, ShieldAlert } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { StatBox, StatusAlert, TruncatedChip } from "@/components/ui/panel-primitives";
import { getDataCollectionSummary } from "@/lib/passiveSurface";
import { HtmlSecurityInfo } from "@/types/analysis";

interface DataCollectionPanelProps {
  htmlSecurity: HtmlSecurityInfo;
}

export const DataCollectionPanel = ({ htmlSecurity }: DataCollectionPanelProps) => {
  const summary = getDataCollectionSummary(htmlSecurity);

  if (!summary.totalForms) {
    return (
      <Card className="border-white/10 bg-white/[0.04] shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FormInput className="h-5 w-5" />
            Data Collection Surface
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-sm leading-6 text-zinc-300">
            No public form collection signals were detected from the fetched page.
          </p>
          <div className="grid gap-4 md:grid-cols-4">
            <StatBox label="Public forms" value={<p className="text-2xl font-semibold">0</p>} />
            <StatBox label="POST forms" value={<p className="text-2xl font-semibold">0</p>} />
            <StatBox label="External submit targets" value={<p className="text-2xl font-semibold">0</p>} />
            <StatBox label="Insecure submits" value={<p className="text-2xl font-semibold">0</p>} />
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="border-white/10 bg-white/[0.04] shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FormInput className="h-5 w-5" />
          Data Collection Surface
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-5">
        <p className="text-sm leading-6 text-zinc-300">{summary.summary}</p>

        <div className="grid gap-4 md:grid-cols-4">
          <StatBox label="Public forms" value={<p className="text-2xl font-semibold">{summary.totalForms}</p>} />
          <StatBox label="POST forms" value={<p className="text-2xl font-semibold">{summary.postForms}</p>} />
          <StatBox label="External submit targets" value={<p className="text-2xl font-semibold">{summary.externalForms.length}</p>} />
          <StatBox label="Insecure submits" value={<p className="text-2xl font-semibold">{summary.insecureForms}</p>} />
        </div>

        {summary.externalForms.length ? (
          <StatBox
            label="External submission targets"
            value={
              <div className="flex flex-wrap gap-2">
                {summary.externalForms.map((action) => (
                  <TruncatedChip key={action} value={action} />
                ))}
              </div>
            }
          />
        ) : null}

        {(summary.externalForms.length || summary.insecureForms) ? (
          <StatusAlert variant="warning" icon={<ShieldAlert />}>
            Public forms that post off-origin or without HTTPS deserve a quick trust review, especially on contact,
            support, or account-related flows.
          </StatusAlert>
        ) : null}
      </CardContent>
    </Card>
  );
};
