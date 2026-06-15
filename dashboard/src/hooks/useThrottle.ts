'use client';

import { useState, useEffect, useRef } from 'react';

export function useThrottle<T>(value: T, intervalMs: number): T {
  const [throttledValue, setThrottledValue] = useState(value);
  const lastExecuted = useRef(Date.now());

  useEffect(() => {
    const now = Date.now();
    const timeSinceLast = now - lastExecuted.current;

    if (timeSinceLast >= intervalMs) {
      lastExecuted.current = now;
      setThrottledValue(value);
    } else {
      const timerId = setTimeout(() => {
        lastExecuted.current = Date.now();
        setThrottledValue(value);
      }, intervalMs - timeSinceLast);

      return () => clearTimeout(timerId);
    }
  }, [value, intervalMs]);

  return throttledValue;
}
