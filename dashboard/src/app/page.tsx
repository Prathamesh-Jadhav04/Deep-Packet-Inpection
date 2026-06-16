'use client';

import { useEffect, useState } from 'react';
import { useDPIStore } from '@/store/dpi-store';
import { NavBar } from '@/components/dpi/nav-bar';
import { motion, AnimatePresence } from 'framer-motion';
import { IntroOverlay } from '@/components/dpi/intro-overlay';

// Dynamic / lazy import could also be used, but direct imports are reliable and compact
import OverviewTab from '@/tabs/overview';
import LiveCaptureTab from '@/tabs/live-capture';
import BlockingRulesTab from '@/tabs/blocking-rules';
import TrafficAnalyticsTab from '@/tabs/traffic-analytics';
import FlowInspectorTab from '@/tabs/flow-inspector';
import SettingsTab from '@/tabs/settings';
import AboutTab from '@/tabs/about';

const TAB_COMPONENTS = [
  OverviewTab,
  LiveCaptureTab,
  BlockingRulesTab,
  TrafficAnalyticsTab,
  FlowInspectorTab,
  SettingsTab,
  AboutTab,
];

export default function Home() {
  const { activeTab, apiBase, setApiBase } = useDPIStore();
  const ActiveTabComponent = TAB_COMPONENTS[activeTab] || OverviewTab;
  const [showIntro, setShowIntro] = useState(true);

  const handleIntroEnter = () => {
    setShowIntro(false);
  };

  // Automatically sync API base with the current origin to prevent port mismatches
  useEffect(() => {
    if (typeof window !== 'undefined') {
      const currentOrigin = window.location.origin;
      const isDevPort = window.location.port === '3000' || window.location.port === '3001';
      
      if (!isDevPort) {
        // If not running on Next.js dev server, we are running on the Python backend directly (local or cloud like Hugging Face)
        // If apiBase is pointing to the default localhost, or we are on Hugging Face Spaces, sync it to the hosted origin
        if (apiBase.includes('127.0.0.1:8765') || apiBase.includes('localhost:8765') || window.location.hostname.endsWith('.hf.space')) {
          if (apiBase !== currentOrigin) {
            setApiBase(currentOrigin);
          }
        }
      } else if (apiBase.includes(':3000') || apiBase.includes(':3001')) {
        setApiBase('http://127.0.0.1:8765');
      }
    }
  }, [apiBase, setApiBase]);

  return (
    <div className="min-h-screen bg-[var(--bg)] text-[var(--text)] flex flex-col font-sans transition-colors duration-200 relative">
      {/* Premium ambient backdrop */}
      <div className="ambient-bg">
        <div className="ambient-glow" />
        <div className="absolute inset-0 premium-grid premium-grid-mask" />
      </div>

      {/* Top sticky navigation bar */}
      <NavBar />

      {/* Main dashboard tab panel layout */}
      <main className="flex-1 w-full max-w-[1400px] mx-auto px-4 md:px-6 py-6 focus:outline-none relative z-10">
        <AnimatePresence mode="wait">
          <motion.div
            key={activeTab}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.2, ease: 'easeInOut' }}
            role="tabpanel"
            id={`tabpanel-${activeTab}`}
            aria-labelledby={`tab-${activeTab}`}
            className="w-full h-full min-h-[400px]"
          >
            <ActiveTabComponent />
          </motion.div>
        </AnimatePresence>
      </main>

      {/* Footer info */}
      <footer className="border-t border-[var(--border-subtle)] py-4 text-center text-[10px] text-[var(--text-muted)] font-mono">
        DPI Engine Console v2.0 • Advanced Packet Classification & Enforcer Panel
      </footer>

      {/* Onboarding Overview Modal Overlay */}
      {showIntro && <IntroOverlay onEnter={handleIntroEnter} />}
    </div>
  );
}
