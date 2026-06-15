'use client';

import { type ReactNode } from 'react';
import { cn } from '@/lib/utils';

interface EmptyStateProps {
  icon: ReactNode;
  title: string;
  description: string;
  action?: ReactNode;
  className?: string;
}

export function EmptyState({ icon, title, description, action, className }: EmptyStateProps) {
  return (
    <div className={cn('flex flex-col items-center justify-center py-16 px-6 text-center', className)}>
      <div
        className="w-16 h-16 rounded-2xl flex items-center justify-center mb-4"
        style={{ background: 'var(--panel-soft)', color: 'var(--text-muted)' }}
      >
        {icon}
      </div>
      <h3 className="text-display-sm" style={{ color: 'var(--text)' }}>
        {title}
      </h3>
      <p className="text-body-sm mt-2 max-w-md" style={{ color: 'var(--text-muted)' }}>
        {description}
      </p>
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}
