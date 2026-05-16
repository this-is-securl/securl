import { cn } from "@/lib/utils";

interface GlassCardProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: "default" | "light" | "heavy";
}

// bg-opacity-* / border-opacity-* don't work with rgba() token values — opacity is
// baked into the rgba string, not a separate CSS channel Tailwind can override.
// Variant differences are expressed as explicit rgba overrides via inline style instead.
const variantStyles: Record<NonNullable<GlassCardProps["variant"]>, React.CSSProperties> = {
  default: {
    background: "rgba(15, 23, 42, 0.65)",
    borderColor: "rgba(148, 163, 184, 0.15)",
  },
  light: {
    background: "rgba(15, 23, 42, 0.40)",
    borderColor: "rgba(148, 163, 184, 0.10)",
  },
  heavy: {
    background: "rgba(15, 23, 42, 0.85)",
    borderColor: "rgba(148, 163, 184, 0.25)",
  },
};

export function GlassCard({
  className,
  variant = "default",
  style,
  children,
  ...props
}: GlassCardProps) {
  return (
    <div
      className={cn(
        "relative rounded-3xl border backdrop-blur-xl transition-all duration-200",
        "shadow-xl",
        // Hover: border brightens to white/20 (up from ~15%), card lifts
        "hover:shadow-2xl hover:-translate-y-0.5",
        className,
      )}
      style={{ ...variantStyles[variant], ...style }}
      {...props}
    >
      {/* Top-edge inner highlight — DOM-first so content paints over it */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 rounded-3xl bg-gradient-to-b from-white/[0.07] to-transparent"
      />
      {children}
    </div>
  );
}
