import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";

// ---------------------------------------------------------------------------
// StatBox
// A labelled metric/info cell used in grid layouts throughout the app.
// ---------------------------------------------------------------------------

type StatBoxVariant = "default" | "critical" | "warning" | "info";

const statBoxVariants: Record<StatBoxVariant, { container: string; label: string; value: string }> = {
  default: {
    container: "border-white/10 bg-white/[0.04]",
    label: "text-slate-400",
    value: "text-white",
  },
  critical: {
    container: "border-[#b56a2c]/35 bg-[#b56a2c]/12",
    label: "text-[#d89a63]",
    value: "text-[#f4dfcd]",
  },
  warning: {
    container: "border-[#9b774f]/30 bg-[#9b774f]/10",
    label: "text-[#d9b488]",
    value: "text-[#f0dfcf]",
  },
  info: {
    container: "border-white/10 bg-white/[0.04]",
    label: "text-slate-400",
    value: "text-white",
  },
};

interface StatBoxProps {
  label: string;
  value: React.ReactNode;
  note?: React.ReactNode;
  variant?: StatBoxVariant;
  className?: string;
}

export const StatBox = ({ label, value, note, variant = "default", className }: StatBoxProps) => {
  const v = statBoxVariants[variant];
  return (
    <div
      className={cn(
        "rounded-[1.35rem] border p-4 shadow-[0_12px_30px_-18px_rgba(0,0,0,0.55),0_1px_0_rgba(255,255,255,0.04)_inset]",
        v.container,
        className,
      )}
    >
      <p className={cn("text-[11px] font-bold uppercase tracking-[0.2em]", v.label)}>{label}</p>
      <div className={cn("mt-2", v.value)}>{value}</div>
      {note && <div className="mt-1 text-slate-400">{note}</div>}
    </div>
  );
};

// ---------------------------------------------------------------------------
// StatusAlert
// A coloured alert row with an optional icon — used for strengths and issues.
// ---------------------------------------------------------------------------

type StatusAlertVariant = "success" | "warning" | "critical" | "info";

const statusAlertVariants: Record<StatusAlertVariant, string> = {
  success: "border-white/10 bg-white/[0.04] text-slate-100",
  warning: "border-[#b56a2c]/35 bg-[#b56a2c]/12 text-[#f4dfcd]",
  critical: "border-[#b56a2c]/45 bg-[#3a2a20] text-[#f4dfcd]",
  info: "border-white/10 bg-white/[0.04] text-slate-100",
};

interface StatusAlertProps {
  variant: StatusAlertVariant;
  icon?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}

export const StatusAlert = ({ variant, icon, children, className }: StatusAlertProps) => (
  <div
    className={cn(
      "rounded-[1.35rem] border px-4 py-3 text-sm shadow-[0_12px_30px_-18px_rgba(0,0,0,0.55),0_1px_0_rgba(255,255,255,0.04)_inset]",
      icon ? "flex gap-3" : "",
      statusAlertVariants[variant],
      className,
    )}
  >
    {icon && <div className="mt-0.5 shrink-0 [&>svg]:h-4 [&>svg]:w-4">{icon}</div>}
    <div className="min-w-0">{children}</div>
  </div>
);

// ---------------------------------------------------------------------------
// SignalList
// Grouped evidence list for positive strengths or neutral observational reads.
// ---------------------------------------------------------------------------

type SignalListVariant = "success" | "neutral";

const signalListVariants: Record<SignalListVariant, { container: string; title: string; body: string; icon: string }> = {
  success: {
    container: "border-white/10 bg-white/[0.04]",
    title: "text-slate-400",
    body: "text-slate-200",
    icon: "text-slate-300",
  },
  neutral: {
    container: "border-white/10 bg-white/[0.04]",
    title: "text-slate-400",
    body: "text-slate-200",
    icon: "text-slate-400",
  },
};

interface SignalListProps {
  title: string;
  items: string[];
  icon: React.ReactNode;
  variant?: SignalListVariant;
}

export const SignalList = ({ title, items, icon, variant = "neutral" }: SignalListProps) => {
  const v = signalListVariants[variant];

  return (
    <div className={cn("rounded-[1.35rem] border p-4 shadow-[0_12px_30px_-18px_rgba(0,0,0,0.55)]", v.container)}>
      <p className={cn("text-[11px] font-bold uppercase tracking-[0.2em]", v.title)}>{title}</p>
      <ul className={cn("mt-3 space-y-2 text-sm", v.body)}>
        {items.map((item, index) => (
          <li key={`${item}-${index}`} className="flex gap-2">
            <span className={cn("mt-0.5 shrink-0 [&>svg]:h-4 [&>svg]:w-4", v.icon)}>{icon}</span>
            {item}
          </li>
        ))}
      </ul>
    </div>
  );
};

// ---------------------------------------------------------------------------
// EmptyState
// Dashed-border placeholder for sections with no data.
// ---------------------------------------------------------------------------

interface EmptyStateProps {
  children: React.ReactNode;
  className?: string;
}

export const EmptyState = ({ children, className }: EmptyStateProps) => (
  <div
    className={cn(
      "rounded-[1.35rem] border border-dashed border-white/10 bg-white/[0.03] px-4 py-6 text-sm text-slate-400",
      className,
    )}
  >
    {children}
  </div>
);

// ---------------------------------------------------------------------------
// CodeBlock
// Dark pre/code block for snippets and raw config output.
// ---------------------------------------------------------------------------

interface CodeBlockProps {
  children: React.ReactNode;
  className?: string;
}

export const CodeBlock = ({ children, className }: CodeBlockProps) => (
  <pre className={cn("overflow-x-auto rounded-2xl border border-white/10 bg-slate-950/85 p-4 text-xs text-slate-100", className)}>
    <code>{children}</code>
  </pre>
);

// ---------------------------------------------------------------------------
// TruncatedChip
// Safe pill for domains, paths, URLs, and evidence strings that may be long.
// ---------------------------------------------------------------------------

interface TruncatedChipProps {
  value: string;
  className?: string;
  maxWidthClassName?: string;
  variant?: React.ComponentProps<typeof Badge>["variant"];
}

export const TruncatedChip = ({
  value,
  className,
  maxWidthClassName = "max-w-[18rem]",
  variant = "outline",
}: TruncatedChipProps) => (
  <Badge
    variant={variant}
    title={value}
    className={cn("max-w-full truncate rounded-full px-3 py-1 text-left font-medium", className)}
  >
    <span className={cn("block truncate", maxWidthClassName)}>{value}</span>
  </Badge>
);
