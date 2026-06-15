'use client';

import { type ReactNode } from 'react';
import { cn } from '@/lib/utils';

interface ChartContainerProps {
  title: string;
  subtitle?: string;
  children: ReactNode;
  className?: string;
  height?: number;
  isLoading?: boolean;
}

export function ChartContainer({ title, subtitle, children, className, height = 300, isLoading }: ChartContainerProps) {
  return (
    <div className={cn('dpi-card', className)}>
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-body-sm" style={{ color: 'var(--text)', fontWeight: 500 }}>
            {title}
          </h3>
          {subtitle && (
            <p className="text-caption mt-0.5" style={{ color: 'var(--text-muted)' }}>
              {subtitle}
            </p>
          )}
        </div>
      </div>
      <div style={{ height, width: '100%', position: 'relative' }}>
        {isLoading ? (
          <div className="skeleton w-full h-full" />
        ) : (
          children
        )}
      </div>
    </div>
  );
}
