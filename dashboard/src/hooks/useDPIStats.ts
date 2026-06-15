'use client';

import useSWR from 'swr';
import { useDPIStore } from '@/store/dpi-store';
import type { DPIStats } from '@/types/dpi';

const fetcher = async (url: string): Promise<DPIStats> => {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
};

export function useDPIStats() {
  const { apiBase, refreshRate, setConnected, setLastPollTime, setEngineStatus, setCaptureRunning } = useDPIStore();

  const { data, error, isLoading, mutate } = useSWR<DPIStats>(
    `${apiBase}/api/stats`,
    fetcher,
    {
      refreshInterval: refreshRate,
      revalidateOnFocus: false,
      dedupingInterval: Math.max(refreshRate - 100, 200),
      onSuccess: (data) => {
        setConnected(true);
        setLastPollTime(Date.now());
        setEngineStatus(data.status);
        setCaptureRunning(data.capture_running ?? false);
      },
      onError: () => {
        setConnected(false);
      },
    }
  );

  return {
    stats: data,
    error,
    isLoading,
    isConnected: !error,
    mutate,
  };
}
