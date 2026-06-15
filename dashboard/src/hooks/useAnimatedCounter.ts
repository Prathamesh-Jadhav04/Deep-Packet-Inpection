'use client';

import { useState, useEffect, useRef } from 'react';

export function useAnimatedCounter(target: number, duration: number = 500): number {
  const [current, setCurrent] = useState(target);
  const prevTarget = useRef(target);
  const animationRef = useRef<number | null>(null);

  useEffect(() => {
    if (prevTarget.current === target) return;

    const startValue = prevTarget.current;
    const startTime = performance.now();
    const diff = target - startValue;

    const animate = (currentTime: number) => {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      // Ease out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      const value = startValue + diff * eased;
      setCurrent(Math.round(value));

      if (progress < 1) {
        animationRef.current = requestAnimationFrame(animate);
      } else {
        prevTarget.current = target;
      }
    };

    animationRef.current = requestAnimationFrame(animate);

    return () => {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
    };
  }, [target, duration]);

  return current;
}
