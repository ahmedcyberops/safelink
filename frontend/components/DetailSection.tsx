interface DetailRowProps {
  label: string;
  value: string | number | boolean | null | undefined;
  mono?: boolean;
}

export const DetailRow = ({ label, value, mono }: DetailRowProps) => {
  const displayValue = value === null || value === undefined
    ? '—'
    : typeof value === 'boolean'
    ? value ? 'Yes' : 'No'
    : String(value);

  return (
    <div className="flex flex-col gap-0.5 border-b border-[hsl(var(--border))]/50 py-2.5 last:border-0 sm:flex-row sm:items-center sm:justify-between">
      <dt className="text-sm text-[hsl(var(--muted-foreground))]">{label}</dt>
      <dd className={`text-sm font-medium break-all ${mono ? 'font-mono text-xs' : ''}`}>
        {displayValue}
      </dd>
    </div>
  );
};

interface DetailSectionProps {
  title: string;
  children: React.ReactNode;
}

export const DetailSection = ({ title, children }: DetailSectionProps) => {
  return (
    <section className="glass-card p-6">
      <h3 className="mb-4 text-lg font-semibold">{title}</h3>
      <dl>{children}</dl>
    </section>
  );
};
