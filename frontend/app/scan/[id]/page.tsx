'use client';

import { useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import { ScanReport } from '@/components/ScanReport';
import { getScan } from '@/lib/api';
import type { ScanResult } from '@/types/scan';
import Link from 'next/link';
import { Loader2 } from 'lucide-react';

export default function ScanPage() {
  const params = useParams();
  const scanId = params.id as string;
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const cached = sessionStorage.getItem(`scan-${scanId}`);
    if (cached) {
      try {
        setResult(JSON.parse(cached));
        setLoading(false);
        return;
      } catch {
        sessionStorage.removeItem(`scan-${scanId}`);
      }
    }

    const fetchScan = async () => {
      try {
        const data = await getScan(scanId);
        setResult(data);
      } catch {
        setError(true);
      } finally {
        setLoading(false);
      }
    };
    fetchScan();
  }, [scanId]);

  if (loading) {
    return (
      <div className="flex min-h-[50vh] items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-brand-500" aria-label="Loading scan results" />
      </div>
    );
  }

  if (error || !result) {
    return (
      <div className="mx-auto max-w-2xl px-4 py-16 text-center">
        <h1 className="mb-4 text-2xl font-bold">Scan Not Found</h1>
        <p className="mb-6 text-[hsl(var(--muted-foreground))]">
          This scan may have expired or does not exist.
        </p>
        <Link href="/" className="btn-primary">
          Scan a URL
        </Link>
      </div>
    );
  }

  return <ScanReport result={result} />;
}
