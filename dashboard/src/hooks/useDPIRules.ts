'use client';

import { useState, useCallback } from 'react';
import { useDPIStore } from '@/store/dpi-store';
import type { RulesSnapshot, RuleType, RulesResponse } from '@/types/dpi';

export function useDPIRules() {
  const { apiBase } = useDPIStore();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const addRule = useCallback(async (type: RuleType, value: string): Promise<{ ok: boolean; message: string; rules?: RulesSnapshot }> => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await fetch(`${apiBase}/api/rules`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type, value }),
      });
      const data: RulesResponse = await res.json();
      if (!data.ok) {
        setError(data.message || 'Failed to add rule');
      }
      return { ok: data.ok, message: data.message || '', rules: data.rules };
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Network error';
      setError(msg);
      return { ok: false, message: msg };
    } finally {
      setIsLoading(false);
    }
  }, [apiBase]);

  const removeRule = useCallback(async (type: RuleType, value: string): Promise<{ ok: boolean; message: string; rules?: RulesSnapshot }> => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await fetch(`${apiBase}/api/rules`, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type, value }),
      });
      const data: RulesResponse = await res.json();
      if (!data.ok) {
        setError(data.message || 'Failed to remove rule');
      }
      return { ok: data.ok, message: data.message || '', rules: data.rules };
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Network error';
      setError(msg);
      return { ok: false, message: msg };
    } finally {
      setIsLoading(false);
    }
  }, [apiBase]);

  return { addRule, removeRule, isLoading, error };
}
