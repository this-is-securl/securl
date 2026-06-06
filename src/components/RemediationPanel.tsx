import { useState } from "react";
import { Copy, Wrench } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { CodeBlock, EmptyState } from "@/components/ui/panel-primitives";
import { RemediationSnippet } from "@/types/analysis";

interface RemediationPanelProps {
  remediation: RemediationSnippet[];
}

const labels: Record<RemediationSnippet["platform"], string> = {
  nginx: "Nginx",
  apache: "Apache",
  cloudflare: "Cloudflare",
  vercel: "Vercel",
  netlify: "Netlify",
};

export const RemediationPanel = ({ remediation }: RemediationPanelProps) => {
  const [selected, setSelected] = useState<RemediationSnippet["platform"]>(remediation[0]?.platform ?? "nginx");

  if (!remediation.length) {
    return (
      <Card className="border-white/10 bg-white/4 shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Wrench className="h-5 w-5" />
            Fix Snippets
          </CardTitle>
        </CardHeader>
        <CardContent>
          <EmptyState>
            No ready-made fix snippets are available for the currently visible posture issues on this target.
          </EmptyState>
        </CardContent>
      </Card>
    );
  }

  const active = remediation.find((item) => item.platform === selected) ?? remediation[0];
  if (!active) {
    return null;
  }

  const copySnippet = async () => {
    await navigator.clipboard.writeText(active.snippet);
    toast.success(`${labels[active.platform]} snippet copied`);
  };

  return (
    <Card className="border-white/10 bg-white/4 shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Wrench className="h-5 w-5" />
          Fix Snippets
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-wrap gap-2">
          {remediation.map((item) => (
            <button
              key={item.platform}
              type="button"
              onClick={() => setSelected(item.platform)}
              className={`rounded-full px-4 py-2 text-sm font-semibold transition ${
                item.platform === active.platform
                  ? "bg-[#b56a2c] text-white"
                  : "bg-white/6 text-zinc-200 hover:bg-white/10"
              }`}
            >
              {labels[item.platform]}
            </button>
          ))}
        </div>

        <div className="flex flex-col gap-3 rounded-[1.35rem] border border-white/10 bg-white/4 p-4">
          <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
            <div>
              <h3 className="text-lg font-semibold text-zinc-50">{active.title}</h3>
              <p className="mt-1 text-sm text-zinc-300">{active.description}</p>
              <p className="mt-2 text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-400">{active.filename}</p>
            </div>
            <Button variant="outline" className="rounded-2xl border-white/10 bg-white/4 text-zinc-100 hover:bg-white/8" onClick={copySnippet}>
              <Copy className="mr-2 h-4 w-4" />
              Copy
            </Button>
          </div>

          <CodeBlock>{active.snippet}</CodeBlock>
        </div>
      </CardContent>
    </Card>
  );
};
