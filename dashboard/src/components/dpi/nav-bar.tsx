'use client';

import { useMemo, useEffect, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  LayoutDashboard,
  Radio,
  Shield,
  BarChart3,
  Search,
  Settings,
  Info,
  Volume2,
  VolumeX,
} from 'lucide-react';
import { useDPIStore } from '@/store/dpi-store';
import { useDPIStats } from '@/hooks/useDPIStats';
import { StatusBadge } from '@/components/dpi/status-badge';
import { cn, playClickSound } from '@/lib/utils';
import { TAB_NAMES } from '@/lib/dpi-constants';

const TAB_ICONS = [LayoutDashboard, Radio, Shield, BarChart3, Search, Settings, Info];

interface NavBarProps {
  className?: string;
}

export function NavBar({ className }: NavBarProps) {
  const { activeTab, setActiveTab, isConnected, isMuted, setMuted } = useDPIStore();
  const { stats } = useDPIStats();
  const navRef = useRef<HTMLElement>(null);
  const [scrolled, setScrolled] = useState(false);

  // Scroll listener
  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 15);
    };
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

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
      className={cn(
        'sticky top-0 z-50 w-full transition-all duration-300 flex items-center justify-center px-4',
        scrolled 
          ? 'h-[64px] bg-transparent' 
          : 'h-[56px] border-b border-[var(--border-subtle)] bg-[var(--bg)]/90 backdrop-blur-md',
        className
      )}
    >
      <div 
        className={cn(
          "w-full mx-auto px-4 md:px-6 flex items-center justify-between gap-4 transition-all duration-300",
          scrolled 
            ? "max-w-[1300px] rounded-full border border-[var(--border-strong)] bg-[var(--bg-soft)]/90 backdrop-blur-md shadow-md h-[46px]" 
            : "max-w-[1400px] h-full"
        )}
      >
        {/* Logo */}
        <div 
          onClick={() => {
            setActiveTab(0);
            playClickSound();
          }}
          className="flex items-center gap-2.5 flex-shrink-0 select-none cursor-pointer hover:opacity-80 transition-opacity"
        >
          <Shield className="w-4.5 h-4.5 text-[var(--accent-blue)]" />
          <div className="hidden sm:flex items-center gap-2">
            <span className="text-[13px] font-light tracking-[2.5px] text-[var(--text)] uppercase font-sans">
              Deep Packet
            </span>
            <span className="text-[13px] font-bold tracking-[3px] text-[var(--accent-blue)] uppercase font-sans">
              Inspection
            </span>
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
                title={name}
                onClick={() => {
                  setActiveTab(index);
                  playClickSound();
                }}
                className={cn(
                  'relative flex items-center gap-1.5 md:gap-2 px-2.5 md:px-4 py-1.5 md:py-2 rounded-full text-[12px] md:text-[14px] whitespace-nowrap transition-all cursor-pointer',
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
                <span className="relative flex items-center gap-1.5 md:gap-2">
                  <Icon className="w-3.5 h-3.5 md:w-4 md:h-4 flex-shrink-0" />
                  <span>{name}</span>
                </span>
              </button>
            );
          })}
        </nav>

        {/* Status + Actions */}
        <div className="flex items-center gap-3 flex-shrink-0">
          <button
            onClick={() => {
              const nextMuted = !isMuted;
              setMuted(nextMuted);
              if (!nextMuted) {
                // Give visual-audio feedback when unmuting
                setTimeout(() => playClickSound(0.08), 10);
              }
            }}
            className="p-2 rounded-full border border-[var(--border)] bg-[var(--panel-soft)] hover:bg-[var(--panel-hover)] text-[var(--text-secondary)] hover:text-[var(--text)] transition-all cursor-pointer flex items-center justify-center shadow-[var(--shadow-1)] hover:shadow-[var(--shadow-2)]"
            title={isMuted ? "Unmute UI sounds" : "Mute UI sounds"}
          >
            {isMuted ? <VolumeX className="w-4 h-4" /> : <Volume2 className="w-4 h-4" />}
          </button>
          <StatusBadge status={engineStatus} />
        </div>
      </div>
    </header>
  );
}
