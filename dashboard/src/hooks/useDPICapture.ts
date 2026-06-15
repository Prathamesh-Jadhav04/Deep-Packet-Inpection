'use client';

import { useState, useCallback } from 'react';
import { useDPIStore } from '@/store/dpi-store';
import type { CaptureConfig, ApiResponse } from '@/types/dpi';

export function useDPICapture() {
  const { apiBase } = useDPIStore();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const startCapture = useCallback(async (config: CaptureConfig): Promise<ApiResponse> => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await fetch(`${apiBase}/api/live/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          iface: config.iface || '',
          duration: config.duration || null,
          count: config.count || 0,
          output_file: config.output_file || 'live_output.pcap',
          bpf: config.bpf || '',
        }),
      });
      const data: ApiResponse = await res.json();
      if (!data.ok) setError(data.message);
      return data;
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Network error';
      setError(msg);
      return { ok: false, message: msg };
    } finally {
      setIsLoading(false);
    }
  }, [apiBase]);

  const stopCapture = useCallback(async (): Promise<ApiResponse> => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await fetch(`${apiBase}/api/live/stop`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      const data: ApiResponse = await res.json();
      if (!data.ok) setError(data.message);
      return data;
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Network error';
      setError(msg);
      return { ok: false, message: msg };
    } finally {
      setIsLoading(false);
    }
  }, [apiBase]);

  return { startCapture, stopCapture, isLoading, error };
}
