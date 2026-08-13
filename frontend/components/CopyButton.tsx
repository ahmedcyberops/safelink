'use client';

import { useState } from 'react';
import { Copy, Check, Printer } from 'lucide-react';
import { copyToClipboard } from '@/lib/utils';

interface CopyButtonProps {
  text: string;
  label?: string;
}

export const CopyButton = ({ text, label = 'Copy' }: CopyButtonProps) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    const success = await copyToClipboard(text);
    if (success) {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <button
      type="button"
      onClick={handleCopy}
      className="btn-secondary gap-2 text-xs"
      aria-label={copied ? 'Copied' : label}
    >
      {copied ? (
        <>
          <Check className="h-3.5 w-3.5 text-risk-low" aria-hidden="true" />
          Copied
        </>
      ) : (
        <>
          <Copy className="h-3.5 w-3.5" aria-hidden="true" />
          {label}
        </>
      )}
    </button>
  );
};

export const PrintButton = () => {
  const handlePrint = () => window.print();

  return (
    <button
      type="button"
      onClick={handlePrint}
      className="btn-secondary gap-2 text-xs no-print"
      aria-label="Print report"
    >
      <Printer className="h-3.5 w-3.5" aria-hidden="true" />
      Print
    </button>
  );
};
