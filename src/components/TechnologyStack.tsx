import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/panel-primitives";
import { Cloud, Code2, Globe, Network, Server, Shield } from "lucide-react";
import { TechnologyResult } from "@/types/analysis";

interface TechnologyStackProps {
  technologies: TechnologyResult[];
}

const categoryConfig = {
  server: {
    icon: <Server className="h-4 w-4" />,
    color: "bg-white/8 text-zinc-100",
  },
  frontend: {
    icon: <Code2 className="h-4 w-4" />,
    color: "bg-white/8 text-zinc-100",
  },
  security: {
    icon: <Shield className="h-4 w-4" />,
    color: "bg-zinc-700/40 text-zinc-300",
  },
  hosting: {
    icon: <Cloud className="h-4 w-4" />,
    color: "bg-[#7f1d1d]/14 text-zinc-300",
  },
  network: {
    icon: <Network className="h-4 w-4" />,
    color: "bg-[#4f6676]/18 text-[#d9e4ea]",
  },
} as const;

const categoryOrder: Array<keyof typeof categoryConfig> = ["network", "hosting", "server", "frontend", "security"];

const confidenceStyles = {
  high: "bg-white/8 text-zinc-100",
  medium: "bg-zinc-700/40 text-zinc-300",
  low: "bg-[#4f6676]/18 text-[#d9e4ea]",
} as const;

export const TechnologyStack = ({ technologies }: TechnologyStackProps) => {
  if (!technologies.length) {
    return (
      <Card className="border-white/10 bg-white/4 shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-zinc-50">
            <Globe className="h-5 w-5" />
            Detected Stack
          </CardTitle>
        </CardHeader>
        <CardContent>
          <EmptyState>
            No confident framework, platform, or client-side stack signals were detected from the fetched assets.
          </EmptyState>
        </CardContent>
      </Card>
    );
  }

  const grouped = technologies.reduce<Record<string, TechnologyResult[]>>((acc, tech) => {
    acc[tech.category] = [...(acc[tech.category] || []), tech];
    return acc;
  }, {});

  return (
    <Card className="border-white/10 bg-white/4 shadow-[0_24px_60px_-36px_rgba(0,0,0,0.65)]">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-zinc-50">
          <Globe className="h-5 w-5" />
          Detected Stack
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        {categoryOrder.filter((category) => grouped[category]?.length).map((category) => {
          const items = grouped[category] ?? [];
          const config = categoryConfig[category as keyof typeof categoryConfig];
          return (
            <div key={category} className="space-y-3">
              <div className="flex items-center gap-2 text-sm font-semibold capitalize text-zinc-300">
                {config.icon}
                {category}
              </div>
              <div className="grid gap-3">
                {items.map((tech) => (
                  <div
                    key={`${tech.category}-${tech.name}-${tech.version ?? "none"}`}
                    className="rounded-[1.25rem] border border-white/10 bg-white/4 px-4 py-3"
                  >
                    <div className="flex items-center justify-between gap-3">
                      <div className="font-medium text-zinc-50">{tech.name}</div>
                      <div className="flex flex-wrap items-center justify-end gap-2">
                        <Badge variant="secondary" className={config.color}>
                          {tech.version ?? tech.detection}
                        </Badge>
                        <Badge variant="secondary" className={confidenceStyles[tech.confidence]}>
                          {tech.confidence} confidence
                        </Badge>
                      </div>
                    </div>
                    <p className="mt-2 text-xs text-zinc-400">{tech.evidence}</p>
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
};
