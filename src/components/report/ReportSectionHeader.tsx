interface ReportSectionHeaderProps {
  eyebrow: string;
  title: string;
  description?: string;
}

export const sectionTitleClass = "text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-400";

export const ReportSectionHeader = ({
  eyebrow,
  title,
  description,
}: ReportSectionHeaderProps) => (
  <div className="max-w-3xl space-y-3">
    <p className={sectionTitleClass}>{eyebrow}</p>
    <div className="space-y-2.5">
      <h2 className="text-[2rem] font-bold leading-tight tracking-[-0.04em] text-white">{title}</h2>
      {description ? <p className="text-base leading-7 text-slate-400">{description}</p> : null}
    </div>
  </div>
);
