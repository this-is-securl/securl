import { Activity, Globe, Lock, Mail, Server, ShieldCheck } from "lucide-react";
import type { LucideIcon } from "lucide-react";

interface Capability {
  icon: LucideIcon;
  title: string;
  description: string;
}

const CAPABILITIES: Capability[] = [
  {
    icon: ShieldCheck,
    title: "Browser Security",
    description:
      "HTTP headers, isolation policies, HSTS enforcement, redirect hygiene, and cookie controls.",
  },
  {
    icon: Mail,
    title: "DNS & Email",
    description:
      "SPF, DMARC, MTA-STS, DNSSEC status, and CAA record verification.",
  },
  {
    icon: Lock,
    title: "TLS & Certificates",
    description:
      "Certificate transparency coverage, chain validity, and HSTS preload status.",
  },
  {
    icon: Globe,
    title: "Third-Party Risk",
    description:
      "External scripts, trackers, and data providers identified and risk-classified.",
  },
  {
    icon: Server,
    title: "Infrastructure",
    description:
      "Passive cloud, CDN, WAF, and edge provider inference from observed signals.",
  },
  {
    icon: Activity,
    title: "Monitoring & Drift",
    description:
      "Save targets and track grade changes, new findings, and resolved issues over time.",
  },
];

export const CapabilityStrip = () => (
  <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
    {CAPABILITIES.map(({ icon: Icon, title, description }) => (
      <div
        key={title}
        className="rounded-[1.2rem] border border-white/[0.07] bg-white/[0.03] p-4 transition-colors duration-200 hover:border-white/[0.13] hover:bg-white/[0.05]"
      >
        <div className="mb-3 flex h-8 w-8 items-center justify-center rounded-[0.65rem] bg-[#b56a2c]/14">
          <Icon className="h-4 w-4 text-[#d89a63]" />
        </div>
        <p className="mb-1 text-[13px] font-semibold text-slate-100">{title}</p>
        <p className="text-[12px] leading-[1.55] text-slate-400">{description}</p>
      </div>
    ))}
  </div>
);
