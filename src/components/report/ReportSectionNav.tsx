import { cn } from "@/lib/utils";
import type { ReportWorkspaceSection, ReportWorkspaceSectionKey } from "@/lib/reportWorkspace";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
} from "@/components/ui/select";

interface ReportSectionNavProps {
  sections: ReportWorkspaceSection[];
  activeKey: ReportWorkspaceSectionKey | undefined;
  onChange: (key: ReportWorkspaceSectionKey) => void;
}

export const ReportSectionNav = ({ sections, activeKey, onChange }: ReportSectionNavProps) => {
  const activeSection = sections.find((s) => s.key === activeKey) ?? sections[0];

  return (
    <div className="w-full">
      {/* ── Mobile: Select dropdown ── */}
      <div className="lg:hidden">
        <Select
          value={activeKey}
          onValueChange={(v) => onChange(v as ReportWorkspaceSectionKey)}
        >
          <SelectTrigger className="h-auto rounded-2xl border-white/[0.1] bg-slate-950/60 px-4 py-3.5 text-left ring-offset-0 focus:ring-1 focus:ring-[#b56a2c]/40 focus:ring-offset-0 backdrop-blur">
            {activeSection ? (
              <div className="flex min-w-0 items-center gap-3">
                <activeSection.icon className="h-4 w-4 shrink-0 text-[#d89a63]" />
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-semibold text-white">{activeSection.title}</p>
                  {(activeSection.badge ?? activeSection.context) ? (
                    <p className="mt-0.5 truncate text-[11px] font-medium text-slate-400">
                      {activeSection.badge ?? activeSection.context}
                    </p>
                  ) : null}
                </div>
              </div>
            ) : (
              <span className="text-sm text-slate-400">Choose section</span>
            )}
          </SelectTrigger>
          <SelectContent className="rounded-2xl border-white/[0.1] bg-[#0d1420] text-slate-100 shadow-2xl backdrop-blur">
            {sections.map((section) => {
              const Icon = section.icon;
              return (
                <SelectItem
                  key={section.key}
                  value={section.key}
                  className="rounded-xl py-3 pl-3 pr-3 focus:bg-white/[0.08] focus:text-white"
                >
                  <div className="flex items-center gap-3">
                    <Icon
                      className={cn(
                        "h-4 w-4 shrink-0",
                        section.key === activeKey ? "text-[#d89a63]" : "text-slate-500",
                      )}
                    />
                    <div>
                      <p className="text-sm font-semibold text-white">{section.title}</p>
                      {section.badge ? (
                        <p className="mt-0.5 text-[11px] font-medium text-slate-400">{section.badge}</p>
                      ) : null}
                    </div>
                  </div>
                </SelectItem>
              );
            })}
          </SelectContent>
        </Select>
      </div>

      {/* ── Desktop: horizontal pill tab strip ── */}
      <div className="hidden lg:block">
        <div className="overflow-x-auto rounded-[1.75rem] border border-white/[0.08] bg-slate-950/50 p-1.5 shadow-[0_8px_32px_-12px_rgba(0,0,0,0.5)] backdrop-blur">
          <div className="flex min-w-max gap-1">
            {sections.map((section) => {
              const active = section.key === activeKey;
              const Icon = section.icon;
              return (
                <button
                  key={section.key}
                  type="button"
                  onClick={() => onChange(section.key)}
                  className={cn(
                    "group flex min-w-0 flex-col items-start gap-1 rounded-[1.35rem] px-4 py-3 text-left transition-all duration-200",
                    active
                      ? "bg-[#b56a2c]/18 shadow-[0_0_0_1px_rgba(181,106,44,0.3)_inset,0_8px_24px_-8px_rgba(181,106,44,0.25)]"
                      : "hover:bg-white/[0.05]",
                  )}
                >
                  <div className="flex items-center gap-2">
                    <Icon
                      className={cn(
                        "h-3.5 w-3.5 shrink-0 transition-colors",
                        active ? "text-[#d89a63]" : "text-slate-500 group-hover:text-slate-400",
                      )}
                    />
                    <span
                      className={cn(
                        "whitespace-nowrap text-sm font-semibold transition-colors",
                        active ? "text-white" : "text-slate-400 group-hover:text-slate-200",
                      )}
                    >
                      {section.title}
                    </span>
                    {section.badge ? (
                      <span
                        className={cn(
                          "rounded-full px-2 py-0.5 text-[10px] font-bold uppercase tracking-[0.08em] transition-colors",
                          active
                            ? "bg-[#b56a2c]/25 text-[#f0d5bc]"
                            : "bg-white/[0.06] text-slate-500 group-hover:text-slate-400",
                        )}
                      >
                        {section.badge}
                      </span>
                    ) : null}
                  </div>
                  <p
                    className={cn(
                      "line-clamp-1 max-w-[13rem] text-[10px] uppercase tracking-[0.14em] transition-colors",
                      active ? "text-[#d89a63]/60" : "text-slate-600 group-hover:text-slate-500",
                    )}
                  >
                    {section.summary}
                  </p>
                </button>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};
