import type { Finding } from '@/types/scan';
import { getSeverityIcon } from '@/lib/utils';

interface FindingsListProps {
  findings: Finding[];
  title: string;
  emptyMessage?: string;
}

export const FindingsList = ({ findings, title, emptyMessage }: FindingsListProps) => {
  const warnings = findings.filter((f) => f.severity === 'warning' || f.severity === 'high');
  const positives = findings.filter((f) => f.severity === 'positive');

  return (
    <div className="glass-card p-6">
      <h3 className="mb-4 text-lg font-semibold">{title}</h3>

      {warnings.length === 0 && positives.length === 0 && (
        <p className="text-sm text-[hsl(var(--muted-foreground))]">
          {emptyMessage || 'No significant findings.'}
        </p>
      )}

      <ul className="space-y-3" aria-label={title}>
        {warnings.map((finding) => (
          <FindingItem key={finding.id} finding={finding} />
        ))}
        {positives.map((finding) => (
          <FindingItem key={finding.id} finding={finding} />
        ))}
      </ul>
    </div>
  );
};

const FindingItem = ({ finding }: { finding: Finding }) => {
  const icon = getSeverityIcon(finding.severity);
  const severityClass = {
    positive: 'text-risk-low',
    warning: 'text-risk-suspicious',
    high: 'text-risk-high',
    info: 'text-[hsl(var(--muted-foreground))]',
  }[finding.severity] || 'text-[hsl(var(--muted-foreground))]';

  return (
    <li className="flex items-start gap-3 rounded-lg border border-[hsl(var(--border))]/50 p-3">
      <span className={`mt-0.5 text-base font-bold ${severityClass}`} aria-hidden="true">
        {icon}
      </span>
      <div className="min-w-0 flex-1">
        <p className="text-sm font-medium">{finding.title}</p>
        <p className="mt-0.5 text-xs text-[hsl(var(--muted-foreground))]">{finding.description}</p>
        {finding.evidence && (
          <p className="mt-1 truncate font-mono text-xs text-[hsl(var(--muted-foreground))]/70">
            {finding.evidence}
          </p>
        )}
      </div>
    </li>
  );
};
