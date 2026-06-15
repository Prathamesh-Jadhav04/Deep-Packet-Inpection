'use client';

import { cn } from '@/lib/utils';

interface StatusBadgeProps {
  status: 'running' | 'idle' | 'stopped' | 'error' | 'connected' | 'disconnected';
  label?: string;
  className?: string;
}

const statusConfig = {
  running: { dot: 'status-dot-active', badge: 'dpi-badge-success', text: 'Running' },
  idle: { dot: 'status-dot-idle', badge: 'dpi-badge-info', text: 'Idle' },
  stopped: { dot: 'status-dot-stopped', badge: 'dpi-badge-warning', text: 'Stopped' },
  error: { dot: 'status-dot-error', badge: 'dpi-badge-error', text: 'Error' },
  connected: { dot: 'status-dot-active', badge: 'dpi-badge-success', text: 'Connected' },
  disconnected: { dot: 'status-dot-error', badge: 'dpi-badge-error', text: 'Disconnected' },
};

export function StatusBadge({ status, label, className }: StatusBadgeProps) {
  const config = statusConfig[status];
  return (
    <span className={cn('dpi-badge', config.badge, className)}>
      <span className={cn('status-dot', config.dot)} />
      {label || config.text}
    </span>
  );
}
