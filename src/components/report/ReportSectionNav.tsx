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
          <SelectTrigger className="h-auto w-full rounded-[1.5rem] border-zinc-800/70 bg-[#0c1219] px-5 py-4 text-left ring-offset-0 shadow-[0_8px_24px_-12px_rgba(0,0,0,0.5)] focus:ring-1 focus:ring-[#b56a2c]/50 focus:ring-offset-0 backdrop-blur">
            {activeSection ? (
              <div className="flex min-w-0 items-center gap-3">
                <activeSection.icon className="h-5 w-5 shrink-0 text-[#d89a63]" />
                <div className="min-w-0 flex-1">
                  <p className="text-base font-bold text-white">{activeSection.title}</p>
                  {(activeSection.badge ?? activeSection.context) ? (
                    <p className="mt-0.5 truncate text-[11px] font-medium text-[#d89a63]/70">
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
        <div className="overflow-x-auto rounded-[1.75rem] border border-zinc-800/55 bg-[#090d18] p-1.5 shadow-[0_4px_16px_rgba(0,0,0,0.4)]">
          <div className="flex min-w-max gap-0.5">
            {sections.map((section) => {
              const active = section.key === activeKey;
              const Icon = section.icon;
              return (
                <button
                  key={section.key}
                  type="button"
                  onClick={() => onChange(section.key)}
                  className={cn(
                    "group flex items-center gap-2 rounded-[1.25rem] px-4 py-2.5 text-left transition-all duration-150",
                    active
                      ? "bg-[#b56a2c]/18 shadow-[0_0_0_1px_rgba(181,106,44,0.3)_inset]"
                      : "hover:bg-white/[0.04]",
                  )}
                >
                  <Icon
                    className={cn(
                      "h-3.5 w-3.5 shrink-0 transition-colors",
                      active ? "text-[#d89a63]" : "text-zinc-600 group-hover:text-zinc-400",
                    )}
                  />
                  <span
                    className={cn(
                      "whitespace-nowrap text-sm transition-colors",
                      active ? "font-bold text-white" : "font-medium text-zinc-400 group-hover:text-slate-200",
                    )}
                  >
                    {section.title}
                  </span>
                  {section.badge ? (
                    <span
                      className={cn(
                        "rounded-full px-2 py-0.5 text-[10px] font-bold tabular-nums transition-colors",
                        active
                          ? "bg-[#b56a2c]/22 text-[#f0d5bc]"
                          : "bg-white/[0.05] text-zinc-500 group-hover:text-zinc-400",
                      )}
                    >
                      {section.badge}
                    </span>
                  ) : null}
                </button>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};
