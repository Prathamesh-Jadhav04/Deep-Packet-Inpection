import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type { ThemeMode } from '@/types/dpi';
import { DEFAULT_REFRESH_RATE } from '@/lib/dpi-constants';

interface DPIStore {
  // Connection
  apiBase: string;
  setApiBase: (base: string) => void;

  // Polling
  refreshRate: number;
  setRefreshRate: (rate: number) => void;

  // Connection status
  isConnected: boolean;
  setConnected: (connected: boolean) => void;
  lastPollTime: number;
  setLastPollTime: (time: number) => void;

  // Engine state
  engineStatus: string;
  setEngineStatus: (status: string) => void;
  captureRunning: boolean;
  setCaptureRunning: (running: boolean) => void;

  // UI
  activeTab: number;
  setActiveTab: (tab: number) => void;
  theme: ThemeMode;
  setTheme: (theme: ThemeMode) => void;

  // Notifications
  notifyOnHighDropRate: boolean;
  setNotifyOnHighDropRate: (notify: boolean) => void;
  notifyOnBlocked: boolean;
  setNotifyOnBlocked: (notify: boolean) => void;
  dropRateThreshold: number;
  setDropRateThreshold: (threshold: number) => void;

  // Sound
  isMuted: boolean;
  setMuted: (muted: boolean) => void;
}

export const useDPIStore = create<DPIStore>()(
  persist(
    (set) => ({
      apiBase: process.env.NEXT_PUBLIC_DPI_API_BASE || 'http://127.0.0.1:8765',
      setApiBase: (base) => set({ apiBase: base }),

      refreshRate: DEFAULT_REFRESH_RATE,
      setRefreshRate: (rate) => set({ refreshRate: rate }),

      isConnected: false,
      setConnected: (connected) => set({ isConnected: connected }),
      lastPollTime: 0,
      setLastPollTime: (time) => set({ lastPollTime: time }),

      engineStatus: 'idle',
      setEngineStatus: (status) => set({ engineStatus: status }),
      captureRunning: false,
      setCaptureRunning: (running) => set({ captureRunning: running }),

      activeTab: 0,
      setActiveTab: (tab) => set({ activeTab: tab }),
      theme: 'dark',
      setTheme: (theme) => set({ theme }),

      notifyOnHighDropRate: false,
      setNotifyOnHighDropRate: (notify) => set({ notifyOnHighDropRate: notify }),
      notifyOnBlocked: false,
      setNotifyOnBlocked: (notify) => set({ notifyOnBlocked: notify }),
      dropRateThreshold: 10,
      setDropRateThreshold: (threshold) => set({ dropRateThreshold: threshold }),

      isMuted: false,
      setMuted: (muted) => set({ isMuted: muted }),
    }),
    {
      name: 'dpi-dashboard-settings',
      partialize: (state) => ({
        refreshRate: state.refreshRate,
        theme: state.theme,
        apiBase: state.apiBase,
        notifyOnHighDropRate: state.notifyOnHighDropRate,
        notifyOnBlocked: state.notifyOnBlocked,
        dropRateThreshold: state.dropRateThreshold,
        isMuted: state.isMuted,
      }),
    }
  )
);
