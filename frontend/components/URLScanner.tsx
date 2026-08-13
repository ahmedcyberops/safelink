'use client';

import { useState, useCallback, type FormEvent, type KeyboardEvent } from 'react';
import { useRouter } from 'next/navigation';
import { Search, Loader2, AlertCircle } from 'lucide-react';
import { scanUrl, APIError } from '@/lib/api';
import { ScanProgress } from './ScanProgress';
import type { ScanResult } from '@/types/scan';

const EXAMPLE_URL = 'https://example.com';

export const URLScanner = () => {
  const [url, setUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const router = useRouter();

  const handleScan = useCallback(async (scanUrl_: string) => {
    if (!scanUrl_.trim()) {
      setError('Please enter a URL to scan.');
      return;
    }

    setError(null);
    setIsScanning(true);
    setScanResult(null);

    try {
      const result = await scanUrl(scanUrl_.trim());
      setScanResult(result);
      sessionStorage.setItem(`scan-${result.scan_id}`, JSON.stringify(result));
      router.push(`/scan/${result.scan_id}`);
    } catch (err) {
      if (err instanceof APIError) {
        setError(err.message);
      } else {
        setError('Unable to connect to the scanning service. Please try again.');
      }
      setIsScanning(false);
    }
  }, [router]);

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    handleScan(url);
  };

  const handleKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      handleSubmit(e as unknown as FormEvent);
    }
  };

  const handleExample = () => {
    setUrl(EXAMPLE_URL);
    setError(null);
  };

  if (isScanning && !scanResult) {
    return <ScanProgress url={url} />;
  }

  return (
    <div className="w-full max-w-2xl animate-fade-in">
      <form onSubmit={handleSubmit} className="space-y-4" aria-label="URL scanner form">
        <div className="relative">
          <label htmlFor="url-input" className="sr-only">
            URL to scan
          </label>
          <input
            id="url-input"
            type="url"
            inputMode="url"
            autoComplete="off"
            spellCheck={false}
            placeholder="Paste a suspicious URL..."
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onKeyDown={handleKeyDown}
            disabled={isScanning}
            className="input-field pr-4 text-base sm:text-lg"
            aria-describedby={error ? 'scan-error' : 'scan-hint'}
            aria-invalid={!!error}
          />
        </div>

        {error && (
          <div
            id="scan-error"
            role="alert"
            className="flex items-start gap-2 rounded-lg border border-risk-high/30 bg-risk-high/10 px-4 py-3 text-sm text-risk-high"
          >
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
            <span>{error}</span>
          </div>
        )}

        <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
          <button
            type="submit"
            disabled={isScanning || !url.trim()}
            className="btn-primary w-full gap-2 sm:w-auto sm:min-w-[160px]"
            aria-label="Scan URL for security risks"
          >
            {isScanning ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                Scanning...
              </>
            ) : (
              <>
                <Search className="h-4 w-4" aria-hidden="true" />
                Scan URL
              </>
            )}
          </button>
          <button
            type="button"
            onClick={handleExample}
            className="btn-secondary text-sm"
            aria-label="Use example URL"
          >
            Try example
          </button>
        </div>

        <p id="scan-hint" className="text-xs text-[hsl(var(--muted-foreground))]">
          Do not submit passwords, private tokens, or sensitive URLs. URLs are processed server-side and may be shared with reputation providers.
        </p>
      </form>
    </div>
  );
};
