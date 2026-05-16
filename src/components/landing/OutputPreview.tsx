const RING_R    = 86;
const RING_SIZE = 200;
const RING_CIRC = parseFloat((2 * Math.PI * RING_R).toFixed(2)); // 540.35
const SCORE     = 81;
const RING_OFF  = parseFloat((RING_CIRC * (1 - SCORE / 100)).toFixed(2)); // ~102.67
const GRADE_COLOR = "#2563eb"; // B → blue

const POSTURE_AREAS = [
  { label: "Edge Security",    score: 78, status: "watch"  },
  { label: "Content Security", score: 62, status: "watch"  },
  { label: "Domain & Trust",   score: 71, status: "watch"  },
  { label: "Third-Party Trust",score: 91, status: "strong" },
] as const;

const FINDINGS = [
  {
    severity: "warning",
    title: "Cross-Origin Opener Policy not enforced",
    consequence:
      "Without this control, cross-origin pages can retain a reference to this window and extract data via timing channels.",
    detail:
      "Set Cross-Origin-Opener-Policy to same-origin for stronger cross-site isolation.",
  },
  {
    severity: "warning",
    title: "DNSSEC not enabled",
    consequence:
      "Without DNSSEC, spoofed DNS responses can silently redirect users to attacker-controlled infrastructure.",
    detail: "Enable DNSSEC signing with your domain registrar or DNS provider.",
  },
  {
    severity: "info",
    title: "No security.txt published",
    consequence:
      "Without it, security researchers have no standard path to report vulnerabilities, slowing response time.",
    detail:
      "Publish a security.txt file at /.well-known/security.txt with contact and policy details.",
  },
] as const;

const barColor = (status: string) =>
  status === "strong" ? "#16a34a" : status === "watch" ? "#d97706" : "#dc2626";

const sevColor = (severity: string) =>
  severity === "warning"
    ? { bg: "rgba(217,119,6,0.12)", text: "#fbbf24", border: "rgba(217,119,6,0.25)" }
    : { bg: "rgba(100,116,139,0.10)", text: "#94a3b8", border: "rgba(100,116,139,0.20)" };

const accentBorder = (severity: string) =>
  severity === "warning" ? "#d97706" : "#64748b";

export const OutputPreview = () => (
  <div className="rounded-[1.75rem] border border-white/[0.09] bg-[linear-gradient(180deg,rgba(255,255,255,0.04)_0%,rgba(255,255,255,0.02)_100%)] p-6 shadow-[0_32px_80px_-32px_rgba(0,0,0,0.55)] ring-1 ring-white/[0.04] sm:p-8">

    {/* Header row */}
    <div className="mb-7 flex items-center justify-between">
      <div className="flex items-center gap-3">
        <div
          className="flex h-7 w-7 items-center justify-center rounded-full"
          style={{ background: "rgba(37,99,235,0.14)" }}
        >
          <div className="h-2.5 w-2.5 rounded-full" style={{ background: GRADE_COLOR }} />
        </div>
        <div>
          <p className="text-[13px] font-semibold text-zinc-200">portswigger.net</p>
          <p className="text-[11px] text-zinc-500">Example scan result</p>
        </div>
      </div>
      <span className="rounded-full border border-white/10 bg-white/[0.05] px-3 py-1 text-[10px] font-bold uppercase tracking-[0.14em] text-zinc-500">
        Sample output
      </span>
    </div>

    {/* Ring + posture bars */}
    <div className="mb-7 grid gap-8 sm:grid-cols-[auto_1fr] sm:items-center">

      {/* Ring gauge */}
      <div className="relative mx-auto flex-shrink-0" style={{ width: RING_SIZE, height: RING_SIZE }}>
        <div
          className="pointer-events-none absolute inset-0 rounded-full"
          style={{ boxShadow: `0 0 72px 0 rgba(37,99,235,0.18)` }}
        />
        <svg
          viewBox={`0 0 ${RING_SIZE} ${RING_SIZE}`}
          width={RING_SIZE}
          height={RING_SIZE}
          xmlns="http://www.w3.org/2000/svg"
        >
          <circle
            cx={RING_SIZE / 2} cy={RING_SIZE / 2} r={RING_R}
            fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="12"
          />
          <circle
            cx={RING_SIZE / 2} cy={RING_SIZE / 2} r={RING_R}
            fill="none" stroke={GRADE_COLOR} strokeWidth="12"
            strokeLinecap="round"
            strokeDasharray={RING_CIRC}
            strokeDashoffset={RING_OFF}
            transform={`rotate(-90 ${RING_SIZE / 2} ${RING_SIZE / 2})`}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center gap-0.5">
          <span
            className="font-black leading-none tracking-[-0.04em]"
            style={{ fontSize: 72, color: GRADE_COLOR }}
          >
            B
          </span>
          <span className="text-sm font-semibold text-zinc-400">{SCORE}/100</span>
          <span
            className="mt-1 text-[10px] font-bold uppercase tracking-[0.2em]"
            style={{ color: GRADE_COLOR }}
          >
            Good Posture
          </span>
        </div>
      </div>

      {/* Posture area bars */}
      <div className="flex flex-col gap-4">
        {POSTURE_AREAS.map((area) => (
          <div key={area.label}>
            <div className="mb-1.5 flex items-center justify-between">
              <span className="text-[13px] font-semibold text-zinc-300">{area.label}</span>
              <span className="text-[13px] font-bold tabular-nums text-zinc-400">{area.score}</span>
            </div>
            <div className="h-[5px] overflow-hidden rounded-full" style={{ background: "rgba(255,255,255,0.06)" }}>
              <div
                className="h-full rounded-full"
                style={{ width: `${area.score}%`, background: barColor(area.status) }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>

    {/* Finding cards */}
    <div className="grid gap-3 sm:grid-cols-3">
      {FINDINGS.map((finding) => {
        const sev = sevColor(finding.severity);
        return (
          <div
            key={finding.title}
            className="rounded-[1.1rem] border border-white/[0.07] bg-white/[0.03] p-4"
            style={{ borderLeftColor: accentBorder(finding.severity), borderLeftWidth: 3 }}
          >
            <div className="mb-3">
              <span
                className="rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-[0.08em]"
                style={{ background: sev.bg, color: sev.text, border: `1px solid ${sev.border}` }}
              >
                {finding.severity}
              </span>
            </div>
            <h4 className="mb-2 text-[13px] font-semibold leading-snug text-zinc-100">
              {finding.title}
            </h4>
            <p className="text-[12px] leading-[1.55] text-zinc-400">{finding.consequence}</p>
            <p className="mt-2 text-[11px] leading-[1.5] text-zinc-500 italic">{finding.detail}</p>
          </div>
        );
      })}
    </div>
  </div>
);
