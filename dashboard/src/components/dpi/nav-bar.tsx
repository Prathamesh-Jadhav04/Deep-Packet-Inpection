'use client';

import { useMemo, useEffect, useRef } from 'react';
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
import { cn, playClickSound } from '@/lib/utils';
import { TAB_NAMES } from '@/lib/dpi-constants';

const TAB_ICONS = [LayoutDashboard, Radio, Shield, BarChart3, Search, Settings];

interface NavBarProps {
  className?: string;
}

export function NavBar({ className }: NavBarProps) {
  const { activeTab, setActiveTab, isConnected } = useDPIStore();
  const { stats } = useDPIStats();
  const navRef = useRef<HTMLElement>(null);

  const engineStatus = useMemo(() => {
    if (!isConnected) return 'disconnected' as const;
    if (stats?.capture_running) return 'running' as const;
    if (stats?.status === 'running') return 'running' as const;
    if (stats?.status === 'failed') return 'error' as const;
    return 'idle' as const;
  }, [isConnected, stats]);

  // Center the active tab horizontally inside the scrollable container
  useEffect(() => {
    if (navRef.current) {
      const activeChild = navRef.current.querySelector('[aria-selected="true"]');
      if (activeChild) {
        activeChild.scrollIntoView({
          behavior: 'smooth',
          block: 'nearest',
          inline: 'center',
        });
      }
    }
  }, [activeTab]);

  return (
    <header
      className={cn('sticky top-0 z-50 border-b border-[var(--border-subtle)] bg-[var(--bg)]/90 backdrop-blur-md', className)}
      style={{
        height: 'var(--nav-height)',
      }}
    >
      <div className="h-full max-w-[1400px] mx-auto px-4 md:px-6 flex items-center justify-between gap-4">
        {/* Logo */}
        <div className="flex items-center gap-3.5 flex-shrink-0">
          <div
            className="w-9 h-9 rounded-full flex items-center justify-center border border-[var(--border)] bg-[var(--panel-soft)] shadow-[var(--shadow-1)]"
          >
            <Shield className="w-4.5 h-4.5 text-[var(--accent-blue)]" />
          </div>
          <div className="hidden sm:block">
            <h1
              className="text-[20px] font-bold text-[var(--text)] tracking-[-0.8px] font-sans"
            >
              DPI Engine<span className="text-[var(--accent-blue)]">.</span>
            </h1>
          </div>
        </div>

        {/* Tab Pills */}
        <nav
          ref={navRef}
          className="flex items-center gap-2 overflow-x-auto scrollbar-none px-1 scroll-smooth max-w-full"
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
                onClick={() => {
                  setActiveTab(index);
                  playClickSound();
                }}
                className={cn(
                  'relative flex items-center gap-2 px-4 py-2 rounded-full text-[15px] whitespace-nowrap transition-all cursor-pointer',
                  'hover:opacity-100 focus-visible:outline-2 focus-visible:outline-offset-2',
                  isActive
                    ? 'font-semibold'
                    : 'opacity-60 hover:opacity-85'
                )}
                style={{
                  color: isActive ? 'var(--text)' : 'var(--text-secondary)',
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
                <span className="relative flex items-center gap-2">
                  <Icon className="w-4 h-4" />
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
