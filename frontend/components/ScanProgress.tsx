'use client';

import { useEffect, useState } from 'react';
import { Check, Loader2, Circle, AlertTriangle } from 'lucide-react';
import { formatStageName } from '@/lib/utils';

const SCAN_STAGES = [
  'url_validation',
  'domain_analysis',
  'redirect_analysis',
  'dns_analysis',
  'tls_analysis',
  'phishing_analysis',
  'reputation_check',
  'risk_scoring',
];

interface ScanProgressProps {
  url: string;
}

export const ScanProgress = ({ url }: ScanProgressProps) => {
  const [activeStage, setActiveStage] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setActiveStage((prev) => {
        if (prev >= SCAN_STAGES.length - 1) return prev;
        return prev + 1;
      });
    }, 800);
    return () => clearInterval(interval);
  }, []);

  const getStageStatus = (index: number): 'completed' | 'running' | 'pending' => {
    if (index < activeStage) return 'completed';
    if (index === activeStage) return 'running';
    return 'pending';
  };

  const StageIcon = ({ status }: { status: 'completed' | 'running' | 'pending' }) => {
    switch (status) {
      case 'completed':
        return <Check className="h-4 w-4 text-risk-low" aria-hidden="true" />;
      case 'running':
        return <Loader2 className="h-4 w-4 animate-spin text-brand-500" aria-hidden="true" />;
      default:
        return <Circle className="h-4 w-4 text-[hsl(var(--muted-foreground))]/40" aria-hidden="true" />;
    }
  };

  return (
    <div
      className="glass-card w-full max-w-lg animate-slide-up p-8"
      role="status"
      aria-live="polite"
      aria-label="Scan in progress"
    >
      <div className="mb-6 text-center">
        <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-brand-600/10">
          <Loader2 className="h-8 w-8 animate-spin text-brand-500" aria-hidden="true" />
        </div>
        <h2 className="text-xl font-semibold">Analyzing URL...</h2>
        <p className="mt-1 truncate text-sm text-[hsl(var(--muted-foreground))]">{url}</p>
      </div>

      <ul className="space-y-3" aria-label="Scan progress steps">
        {SCAN_STAGES.map((stage, index) => {
          const status = getStageStatus(index);
          return (
            <li
              key={stage}
              className={`flex items-center gap-3 rounded-lg px-3 py-2 transition-all ${
                status === 'running' ? 'bg-brand-500/10' : ''
              }`}
            >
              <StageIcon status={status} />
              <span
                className={`text-sm ${
                  status === 'pending'
                    ? 'text-[hsl(var(--muted-foreground))]/60'
                    : status === 'running'
                    ? 'font-medium text-[hsl(var(--foreground))]'
                    : 'text-[hsl(var(--muted-foreground))]'
                }`}
              >
                {formatStageName(stage)}
              </span>
            </li>
          );
        })}
      </ul>

      <p className="mt-6 flex items-center justify-center gap-2 text-xs text-[hsl(var(--muted-foreground))]">
        <AlertTriangle className="h-3.5 w-3.5" aria-hidden="true" />
        Security analysis in progress. Do not navigate away.
      </p>
    </div>
  );
};
