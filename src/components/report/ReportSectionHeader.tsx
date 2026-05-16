interface ReportSectionHeaderProps {
  eyebrow: string;
  title: string;
  description?: string;
}

export const sectionTitleClass = "text-[11px] font-bold uppercase tracking-[0.2em] text-zinc-500";

export const ReportSectionHeader = ({
  eyebrow,
  title,
  description,
}: ReportSectionHeaderProps) => (
  <div className="max-w-3xl space-y-3">
    <p className={sectionTitleClass}>{eyebrow}</p>
    <div className="space-y-2.5">
      <h2 className="text-[2.5rem] font-black leading-tight tracking-[-0.04em] text-white">{title}</h2>
      {description ? <p className="text-base leading-relaxed text-zinc-300">{description}</p> : null}
    </div>
  </div>
);
