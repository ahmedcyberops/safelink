'use client';

import type { RiskLevel } from '@/types/scan';
import { getRiskColor, getRiskBgColor, getRiskLabel } from '@/lib/utils';

interface RiskScoreProps {
  score: number;
  level: RiskLevel | string;
}

export const RiskScore = ({ score, level }: RiskScoreProps) => {
  const circumference = 2 * Math.PI * 45;
  const offset = circumference - (score / 100) * circumference;
  const colorClass = getRiskColor(level);
  const bgClass = getRiskBgColor(level);

  const strokeColor = {
    low: '#22c55e',
    moderate: '#eab308',
    suspicious: '#f97316',
    high: '#ef4444',
  }[level as string] || '#6b7280';

  return (
    <div
      className={`flex flex-col items-center rounded-2xl border p-8 ${bgClass}`}
      role="status"
      aria-label={`Risk score ${score} out of 100, ${getRiskLabel(level)}`}
    >
      <div className="relative mb-4 h-36 w-36">
        <svg className="h-full w-full -rotate-90" viewBox="0 0 100 100" aria-hidden="true">
          <circle
            cx="50"
            cy="50"
            r="45"
            fill="none"
            stroke="currentColor"
            strokeWidth="6"
            className="text-[hsl(var(--muted))]"
          />
          <circle
            cx="50"
            cy="50"
            r="45"
            fill="none"
            stroke={strokeColor}
            strokeWidth="6"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            className="transition-all duration-1000 ease-out"
            style={{ '--score-offset': offset } as React.CSSProperties}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`text-4xl font-bold tabular-nums ${colorClass}`}>{score}</span>
          <span className="text-xs text-[hsl(var(--muted-foreground))]">/ 100</span>
        </div>
      </div>

      <span
        className={`inline-flex items-center rounded-full px-4 py-1.5 text-sm font-bold uppercase tracking-wider ${colorClass} ${bgClass}`}
      >
        {getRiskLabel(level)}
      </span>
    </div>
  );
};
