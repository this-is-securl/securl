import type { ReactNode } from "react";

interface SecurityGradeProps {
  grade: string;
  score: number;
  summary: string;
  context?: ReactNode;
  actions?: ReactNode;
  pulse?: ReactNode;
}

// Per-grade colour tokens — matches the PDF report colour system
export const GRADE_PALETTE: Record<string, { stroke: string; glow: string; textColor: string; borderColor: string }> = {
  "A+": { stroke: "#22c55e", glow: "rgba(34,197,94,0.20)",  textColor: "#86efac", borderColor: "rgba(34,197,94,0.15)"  },
  A:    { stroke: "#22c55e", glow: "rgba(34,197,94,0.20)",  textColor: "#86efac", borderColor: "rgba(34,197,94,0.15)"  },
  B:    { stroke: "#3b82f6", glow: "rgba(59,130,246,0.22)", textColor: "#93c5fd", borderColor: "rgba(59,130,246,0.18)" },
  C:    { stroke: "#f59e0b", glow: "rgba(245,158,11,0.22)", textColor: "#fcd34d", borderColor: "rgba(245,158,11,0.16)" },
  D:    { stroke: "#f97316", glow: "rgba(249,115,22,0.22)", textColor: "#fdba74", borderColor: "rgba(249,115,22,0.16)" },
  F:    { stroke: "#ef4444", glow: "rgba(239,68,68,0.24)",  textColor: "#fca5a5", borderColor: "rgba(239,68,68,0.18)"  },
  U:    { stroke: "#94a3b8", glow: "rgba(148,163,184,0.14)",textColor: "#cbd5e1", borderColor: "rgba(148,163,184,0.12)"},
};

const RING_R    = 72;
const RING_SIZE = 168;
const RING_CIRC = parseFloat((2 * Math.PI * RING_R).toFixed(2));

export const SecurityGrade = ({ grade, score, summary, context, actions, pulse }: SecurityGradeProps) => {
  const palette    = GRADE_PALETTE[grade] ?? GRADE_PALETTE.U;
  const clamped    = Math.max(0, Math.min(100, score));
  const ringOffset = parseFloat((RING_CIRC * (1 - clamped / 100)).toFixed(2));
  const gradeSize  = grade.length > 1 ? "text-5xl" : "text-6xl";

  return (
    <div
      className="w-full rounded-[2rem] bg-[linear-gradient(135deg,rgba(11,18,32,0.98),rgba(16,24,39,0.95))] px-7 py-7 shadow-[0_24px_64px_-32px_rgba(0,0,0,0.7)] backdrop-blur"
      style={{ border: `1px solid ${palette.borderColor}` }}
    >
      {context ? <div className="mb-6">{context}</div> : null}

      <div className="flex flex-col items-center gap-7 sm:flex-row sm:items-center">

        {/* ── Ring gauge ── */}
        <div className="relative shrink-0" style={{ width: RING_SIZE, height: RING_SIZE }}>
          {/* Radial glow — subtle, not a spotlight */}
          <div
            className="absolute inset-0 rounded-full"
            style={{ background: `radial-gradient(circle, ${palette.glow} 0%, transparent 70%)`, filter: "blur(16px)" }}
          />
          <svg
            viewBox={`0 0 ${RING_SIZE} ${RING_SIZE}`}
            width={RING_SIZE}
            height={RING_SIZE}
            className="relative -rotate-90"
          >
            {/* Track */}
            <circle
              cx={RING_SIZE / 2}
              cy={RING_SIZE / 2}
              r={RING_R}
              fill="none"
              stroke="rgba(255,255,255,0.07)"
              strokeWidth="10"
            />
            {/* Progress */}
            <circle
              cx={RING_SIZE / 2}
              cy={RING_SIZE / 2}
              r={RING_R}
              fill="none"
              stroke={palette.stroke}
              strokeWidth="10"
              strokeLinecap="round"
              strokeDasharray={RING_CIRC}
              strokeDashoffset={ringOffset}
            />
          </svg>
          {/* Inner labels: grade is the verdict; the number is supporting context. */}
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-0.5">
            <span
              className={`font-black leading-none tracking-[-0.05em] ${gradeSize}`}
              style={{ color: palette.textColor }}
            >
              {grade}
            </span>
          </div>
        </div>

        {/* ── Copy ── */}
        <div className="flex min-w-0 flex-1 flex-col gap-2.5">
          <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-zinc-500">
            Security posture
          </p>
          <p className="text-xs font-medium uppercase tracking-[0.18em] text-zinc-500">
            Weighted signal: {clamped}
          </p>
          <p className="text-sm leading-7 text-zinc-300">{summary}</p>
        </div>
      </div>

      {pulse ? (
        <div className="mt-5 border-t border-white/10 pt-5">{pulse}</div>
      ) : null}

      {actions ? (
        <div className="mt-5 border-t border-white/10 pt-5">
          <p className="text-[10px] font-semibold uppercase tracking-[0.26em] text-zinc-500">Export report</p>
          <div className="mt-3 flex flex-wrap gap-3">{actions}</div>
        </div>
      ) : null}
    </div>
  );
};
