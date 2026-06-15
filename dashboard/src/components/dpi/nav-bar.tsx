'use client';

import { useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  LayoutDashboard,
  Radio,
  Shield,
  BarChart3,
  Search,
  Settings,
} from 'lucide-react';
import { useDPIStore } from '@/store/dpi-store';
import { useDPIStats } from '@/hooks/useDPIStats';
import { StatusBadge } from '@/components/dpi/status-badge';
import { cn } from '@/lib/utils';
import { TAB_NAMES } from '@/lib/dpi-constants';

const TAB_ICONS = [LayoutDashboard, Radio, Shield, BarChart3, Search, Settings];

interface NavBarProps {
  className?: string;
}

export function NavBar({ className }: NavBarProps) {
  const { activeTab, setActiveTab, isConnected } = useDPIStore();
  const { stats } = useDPIStats();

  const engineStatus = useMemo(() => {
    if (!isConnected) return 'disconnected' as const;
    if (stats?.capture_running) return 'running' as const;
    if (stats?.status === 'running') return 'running' as const;
    if (stats?.status === 'failed') return 'error' as const;
    return 'idle' as const;
  }, [isConnected, stats]);

  return (
    <header
      className={cn('sticky top-0 z-50', className)}
      style={{
        height: 'var(--nav-height)',
        background: 'var(--panel)',
        borderBottom: '1px solid var(--border)',
      }}
    >
      <div className="h-full max-w-[1400px] mx-auto px-4 md:px-6 flex items-center justify-between gap-4">
        {/* Logo */}
        <div className="flex items-center gap-3 flex-shrink-0">
          <div
            className="w-8 h-8 rounded-lg flex items-center justify-center"
            style={{
              background: 'linear-gradient(135deg, var(--gradient-develop-start), var(--gradient-develop-end))',
            }}
          >
            <Shield className="w-4 h-4 text-white" />
          </div>
          <div className="hidden sm:block">
            <h1
              className="text-body-sm font-semibold gradient-text"
              style={{ letterSpacing: '-0.5px' }}
            >
              DPI Engine.
            </h1>
          </div>
        </div>

        {/* Tab Pills */}
        <nav
          className="flex items-center gap-1 overflow-x-auto scrollbar-none px-1"
          role="tablist"
          aria-label="Dashboard tabs"
        >
          {TAB_NAMES.map((name, index) => {
            const Icon = TAB_ICONS[index];
            const isActive = activeTab === index;
            return (
              <button
                key={name}
                role="tab"
                aria-selected={isActive}
                aria-controls={`tabpanel-${index}`}
                onClick={() => setActiveTab(index)}
                className={cn(
                  'relative flex items-center gap-1.5 px-3 py-1.5 rounded-full text-body-sm whitespace-nowrap transition-all',
                  'hover:opacity-100 focus-visible:outline-2 focus-visible:outline-offset-2',
                  isActive
                    ? 'font-medium'
                    : 'opacity-60 hover:opacity-80'
                )}
                style={{
                  color: isActive ? 'var(--text)' : 'var(--text-muted)',
                }}
              >
                {isActive && (
                  <motion.div
                    layoutId="activeTab"
                    className="absolute inset-0 rounded-full"
                    style={{
                      background: 'var(--panel-soft)',
                      border: '1px solid var(--border)',
                    }}
                    transition={{ type: 'spring', bounce: 0.15, duration: 0.5 }}
                  />
                )}
                <span className="relative flex items-center gap-1.5">
                  <Icon className="w-3.5 h-3.5" />
                  <span className="hidden md:inline">{name}</span>
                </span>
              </button>
            );
          })}
        </nav>

        {/* Status + Actions */}
        <div className="flex items-center gap-3 flex-shrink-0">
          <StatusBadge status={engineStatus} />
        </div>
      </div>
    </header>
  );
}
