import type { ScanResult, ScanError } from '@/types/scan';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export class APIError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
    this.name = 'APIError';
  }
}

export const scanUrl = async (url: string): Promise<ScanResult> => {
  const response = await fetch(`${API_URL}/api/v1/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  });

  if (!response.ok) {
    const error: ScanError = await response.json().catch(() => ({
      error: 'unknown',
      code: 'unknown',
      message: 'An unexpected error occurred',
    }));
    const detail = (error as unknown as { detail?: ScanError }).detail || error;
    throw new APIError(
      response.status,
      detail.code || 'unknown',
      detail.message || 'Scan failed',
    );
  }

  return response.json();
};

export const getScan = async (scanId: string): Promise<ScanResult> => {
  const response = await fetch(`${API_URL}/api/v1/scan/${scanId}`);

  if (!response.ok) {
    const error: ScanError = await response.json().catch(() => ({
      error: 'unknown',
      code: 'unknown',
      message: 'Scan not found',
    }));
    const detail = (error as unknown as { detail?: ScanError }).detail || error;
    throw new APIError(
      response.status,
      detail.code || 'unknown',
      detail.message || 'Scan not found',
    );
  }

  return response.json();
};

export const checkHealth = async (): Promise<boolean> => {
  try {
    const response = await fetch(`${API_URL}/api/v1/health`);
    return response.ok;
  } catch {
    return false;
  }
};
