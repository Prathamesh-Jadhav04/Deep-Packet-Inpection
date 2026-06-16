'use client';

import { type ReactNode } from 'react';
import { useAnimatedCounter } from '@/hooks/useAnimatedCounter';
import { cn } from '@/lib/utils';

interface KPICardProps {
  title: string;
  value: number;
  formattedValue?: string;
  icon: ReactNode;
  accentColor?: string;
  trend?: 'up' | 'down' | 'neutral';
  subtitle?: string;
  className?: string;
}

export function KPICard({ title, value, formattedValue, icon, accentColor = 'var(--accent-blue)', trend, subtitle, className }: KPICardProps) {
  const animatedValue = useAnimatedCounter(value, 400);

  return (
    <div className={cn('dpi-card group relative overflow-hidden transition-all duration-300 hover:-translate-y-1 hover:shadow-lg hover:border-[var(--border-strong)]', className)}>
      {/* Accent glow */}
      <div
        className="absolute top-0 right-0 w-24 h-24 rounded-full opacity-10 blur-2xl transition-opacity group-hover:opacity-20"
        style={{ background: accentColor }}
      />

      <div className="relative flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <p className="text-caption-mono uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
            {title}
          </p>
          <p className="text-display-md mt-1" style={{ color: 'var(--text)' }}>
            {formattedValue || animatedValue.toLocaleString()}
          </p>
          {subtitle && (
            <p className="text-caption mt-1" style={{ color: 'var(--text-secondary)' }}>
              {subtitle}
            </p>
          )}
        </div>
        <div
          className="flex-shrink-0 w-10 h-10 rounded-full flex items-center justify-center border border-[var(--border)] bg-[var(--bg)] shadow-[var(--shadow-1)] transition-all duration-300 group-hover:scale-110 group-hover:border-[var(--border-strong)]"
          style={{ color: accentColor }}
        >
          {icon}
        </div>
      </div>

      {/* Accent color bar */}
      <div
        className="absolute bottom-0 left-0 right-0 h-[3px] opacity-70 transition-all duration-300 group-hover:h-[4px]"
        style={{ background: accentColor }}
      />
    </div>
  );
}
