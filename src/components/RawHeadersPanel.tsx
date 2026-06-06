import { FileJson } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { CodeBlock } from "@/components/ui/panel-primitives";

interface RawHeadersPanelProps {
  headers: Record<string, string>;
}

export const RawHeadersPanel = ({ headers }: RawHeadersPanelProps) => {
  return (
    <Card className="border-white/10 bg-white/4 shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FileJson className="h-5 w-5" />
          Raw Response Headers
        </CardTitle>
      </CardHeader>
      <CardContent>
        <CodeBlock className="whitespace-pre-wrap break-all">
          {JSON.stringify(headers, null, 2)}
        </CodeBlock>
      </CardContent>
    </Card>
  );
};
