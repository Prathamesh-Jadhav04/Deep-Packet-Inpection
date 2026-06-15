'use client';

import useSWR from 'swr';
import { useDPIStore } from '@/store/dpi-store';
import type { InterfacesResponse } from '@/types/dpi';

const fetcher = async (url: string): Promise<InterfacesResponse> => {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
};

export function useDPIInterfaces() {
  const { apiBase } = useDPIStore();

  const { data, error, isLoading, mutate } = useSWR<InterfacesResponse>(
    `${apiBase}/api/interfaces`,
    fetcher,
    {
      revalidateOnFocus: false,
      dedupingInterval: 10000,
    }
  );

  return {
    interfaces: data?.interfaces ?? [],
    isAvailable: data?.ok ?? false,
    error: data?.error || (error ? 'Failed to fetch interfaces' : null),
    isLoading,
    refresh: mutate,
  };
}
