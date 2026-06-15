'use client';

import { useState, useEffect } from 'react';
import { useDPIStore } from '@/store/dpi-store';
import { useDPIStats } from '@/hooks/useDPIStats';
import { StatusBadge } from '@/components/dpi/status-badge';
import { Shield, RefreshCw, Server, AlertCircle, CheckCircle2, Moon, Sun, Monitor } from 'lucide-react';
import { cn, playClickSound } from '@/lib/utils';

export default function SettingsTab() {
  const {
    apiBase,
    setApiBase,
    refreshRate,
    setRefreshRate,
    theme,
    setTheme,
    notifyOnHighDropRate,
    setNotifyOnHighDropRate,
    notifyOnBlocked,
    setNotifyOnBlocked,
    dropRateThreshold,
    setDropRateThreshold,
    isMuted,
    setMuted,
    isConnected,
  } = useDPIStore();

  const { stats, mutate } = useDPIStats();
  const [apiInput, setApiInput] = useState(apiBase);
  const [healthStatus, setHealthStatus] = useState<Record<string, 'checking' | 'ok' | 'failed'>>({
    '/api/stats': 'checking',
    '/api/interfaces': 'checking',
    '/api/rules': 'checking',
  });

  // Sync state if apiBase changes externally
  useEffect(() => {
    setApiInput(apiBase);
  }, [apiBase]);

  const checkHealth = async () => {
    const endpoints = ['/api/stats', '/api/interfaces', '/api/rules'];
    const results: Record<string, 'checking' | 'ok' | 'failed'> = {};
    
    for (const endpoint of endpoints) {
      results[endpoint] = 'checking';
      setHealthStatus({ ...results });
      try {
        const res = await fetch(`${apiInput}${endpoint}`, { signal: AbortSignal.timeout(3000) });
        results[endpoint] = res.ok ? 'ok' : 'failed';
      } catch (err) {
        results[endpoint] = 'failed';
      }
      setHealthStatus({ ...results });
    }
  };

  useEffect(() => {
    checkHealth();
  }, [apiBase]);

  const handleSaveApi = () => {
    setApiBase(apiInput);
    mutate(); // Re-fetch SWR stats with the new base URL
  };

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex items-center justify-between border-b border-[var(--border)] pb-4">
        <div>
          <h2 className="text-display-sm">System & UI Settings</h2>
          <p className="text-caption text-[var(--text-muted)] mt-1">
            Configure engine connection parameters, alerting thresholds, and UI preferences.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Connection Settings */}
        <div className="lg:col-span-2 space-y-6">
          <div className="dpi-card space-y-4">
            <div className="flex items-center gap-2 text-body-sm font-semibold text-[var(--text)]">
              <Server className="w-4 h-4 text-[var(--accent-blue)]" />
              <span>DPI Engine Connection</span>
            </div>
            
            <div className="space-y-3">
              <div className="flex flex-col gap-1.5">
                <label className="text-caption text-[var(--text-secondary)] font-medium">
                  API Server Base URL
                </label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={apiInput}
                    onChange={(e) => setApiInput(e.target.value)}
                    className="flex-1 px-3 py-1.5 rounded-md text-body-sm outline-none transition-colors border border-[var(--border)] bg-[var(--panel-soft)] text-[var(--text)] focus:border-[var(--accent-blue)]"
                    placeholder="http://127.0.0.1:8765"
                  />
                  <button
                    onClick={() => {
                      handleSaveApi();
                      playClickSound();
                    }}
                    className="btn-primary"
                  >
                    Apply
                  </button>
                </div>
                <p className="text-caption text-[var(--text-muted)]">
                  The dashboard will poll this address for packet, thread, and interface telemetry.
                </p>
              </div>

              <div className="flex flex-col gap-1.5 pt-2">
                <div className="flex items-center justify-between">
                  <label className="text-caption text-[var(--text-secondary)] font-medium">
                    Telemetry Poll Interval ({refreshRate}ms)
                  </label>
                </div>
                <input
                  type="range"
                  min="500"
                  max="5000"
                  step="500"
                  value={refreshRate}
                  onChange={(e) => setRefreshRate(parseInt(e.target.value))}
                  className="w-full h-1.5 bg-[var(--panel-soft)] rounded-lg appearance-none cursor-pointer accent-[var(--accent-blue)] border border-[var(--border)]"
                />
                <div className="flex justify-between text-[10px] text-[var(--text-muted)] font-mono">
                  <span>Fast (500ms)</span>
                  <span>Default (1000ms)</span>
                  <span>Slow (5000ms)</span>
                </div>
              </div>
            </div>
          </div>

          {/* Alarm and Notification Rules */}
          <div className="dpi-card space-y-4">
            <div className="flex items-center gap-2 text-body-sm font-semibold text-[var(--text)]">
              <Shield className="w-4 h-4 text-[var(--accent-red)]" />
              <span>Telemetry Alert Conditions</span>
            </div>

            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <span className="text-body-sm font-medium text-[var(--text)]">Notify on Packet Drops</span>
                  <p className="text-caption text-[var(--text-muted)]">
                    Trigger alert when packet drop rate exceeds target threshold.
                  </p>
                </div>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    checked={notifyOnHighDropRate}
                    onChange={(e) => {
                      setNotifyOnHighDropRate(e.target.checked);
                      playClickSound();
                    }}
                    className="sr-only peer"
                  />
                  <div className="w-9 h-5 bg-[var(--panel-soft)] peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-[var(--accent-blue)] border border-[var(--border)]"></div>
                </label>
              </div>

              {notifyOnHighDropRate && (
                <div className="flex flex-col gap-1.5 pl-4 border-l-2 border-[var(--border)] animate-fade-in">
                  <label className="text-caption text-[var(--text-secondary)]">
                    Drop Rate Threshold ({dropRateThreshold}%)
                  </label>
                  <input
                    type="range"
                    min="1"
                    max="50"
                    value={dropRateThreshold}
                    onChange={(e) => setDropRateThreshold(parseInt(e.target.value))}
                    className="w-full h-1.5 bg-[var(--panel-soft)] rounded-lg appearance-none cursor-pointer accent-[var(--accent-red)] border border-[var(--border)]"
                  />
                  <div className="flex justify-between text-[10px] text-[var(--text-muted)] font-mono">
                    <span>1%</span>
                    <span>10%</span>
                    <span>50%</span>
                  </div>
                </div>
              )}

              <div className="flex items-center justify-between pt-2 border-t border-[var(--border-subtle)]">
                <div className="space-y-0.5">
                  <span className="text-body-sm font-medium text-[var(--text)]">Notify on Block Rule Match</span>
                  <p className="text-caption text-[var(--text-muted)]">
                    Trigger browser notification when a packet matches active block filters.
                  </p>
                </div>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    checked={notifyOnBlocked}
                    onChange={(e) => {
                      setNotifyOnBlocked(e.target.checked);
                      playClickSound();
                    }}
                    className="sr-only peer"
                  />
                  <div className="w-9 h-5 bg-[var(--panel-soft)] peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-[var(--accent-blue)] border border-[var(--border)]"></div>
                </label>
              </div>
            </div>
          </div>
        </div>

        {/* Sidebar: Engine Metadata + API Health */}
        <div className="space-y-6">
          {/* Theme Switcher */}
          <div className="dpi-card space-y-4">
            <div className="text-body-sm font-semibold text-[var(--text)]">UI Palette Mode</div>
            <div className="grid grid-cols-3 gap-2">
              {[
                { name: 'dark', icon: Moon, label: 'Dark' },
                { name: 'light', icon: Sun, label: 'Light' },
                { name: 'system', icon: Monitor, label: 'System' },
              ].map((m) => {
                const Icon = m.icon;
                const active = theme === m.name;
                return (
                  <button
                    key={m.name}
                    onClick={() => {
                      setTheme(m.name as any);
                      playClickSound();
                    }}
                    className={cn(
                      "flex flex-col items-center gap-1.5 p-3 rounded-xl border text-caption font-medium transition-all cursor-pointer",
                      active
                        ? "border-[var(--border-strong)] bg-[var(--panel-soft)] text-[var(--text)] shadow-[var(--shadow-3)]"
                        : "border-[var(--border)] bg-[var(--bg)] text-[var(--text-secondary)] hover:text-[var(--text)]"
                    )}
                  >
                    <Icon className="w-4 h-4" />
                    <span>{m.label}</span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Audio Settings */}
          <div className="dpi-card space-y-4">
            <div className="text-body-sm font-semibold text-[var(--text)]">Audio Feedback</div>
            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <span className="text-body-sm font-medium text-[var(--text)]">UI Click Sounds</span>
                <p className="text-caption text-[var(--text-muted)]">
                  Play snappy mechanical ticks on clicks.
                </p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={!isMuted}
                  onChange={(e) => {
                    const newMuted = !e.target.checked;
                    setMuted(newMuted);
                    if (!newMuted) {
                      setTimeout(() => playClickSound(), 10);
                    }
                  }}
                  className="sr-only peer"
                />
                <div className="w-9 h-5 bg-[var(--panel-soft)] peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-[var(--accent-blue)] border border-[var(--border)]"></div>
              </label>
            </div>
          </div>

          {/* Engine Parameters */}
          <div className="dpi-card space-y-4">
            <div className="text-body-sm font-semibold text-[var(--text)]">DPI Engine Metadata</div>
            <div className="space-y-3 text-caption">
              <div className="flex justify-between border-b border-[var(--border-subtle)] pb-1.5">
                <span className="text-[var(--text-muted)]">Connection Status</span>
                <StatusBadge status={isConnected ? 'connected' : 'disconnected'} />
              </div>
              <div className="flex justify-between border-b border-[var(--border-subtle)] pb-1.5">
                <span className="text-[var(--text-muted)]">Engine Phase</span>
                <span className="font-mono text-[var(--text)] uppercase">{stats?.status || 'Offline'}</span>
              </div>
              <div className="flex justify-between border-b border-[var(--border-subtle)] pb-1.5">
                <span className="text-[var(--text-muted)]">Active PCAP</span>
                <span className="font-mono text-[var(--text)] max-w-[150px] truncate" title={stats?.input_file}>
                  {stats?.input_file ? stats.input_file.split(/[\\/]/).pop() : 'None'}
                </span>
              </div>
              <div className="flex justify-between border-b border-[var(--border-subtle)] pb-1.5">
                <span className="text-[var(--text-muted)]">Load Balancers</span>
                <span className="font-mono text-[var(--text)]">{stats?.lb_threads?.length ?? 0}</span>
              </div>
              <div className="flex justify-between pb-0.5">
                <span className="text-[var(--text-muted)]">Fast Paths</span>
                <span className="font-mono text-[var(--text)]">{stats?.fp_threads?.length ?? 0}</span>
              </div>
            </div>
          </div>

          {/* API Health Monitor */}
          <div className="dpi-card space-y-4">
            <div className="flex items-center justify-between">
              <div className="text-body-sm font-semibold text-[var(--text)]">REST API Health</div>
              <button
                onClick={() => {
                  checkHealth();
                  playClickSound();
                }}
                className="p-1 rounded-md hover:bg-[var(--panel-soft)] transition-colors text-[var(--text-muted)] hover:text-[var(--text)] cursor-pointer"
                title="Refresh Health"
              >
                <RefreshCw className="w-3.5 h-3.5" />
              </button>
            </div>

            <div className="space-y-3">
              {Object.entries(healthStatus).map(([endpoint, status]) => (
                <div key={endpoint} className="flex items-center justify-between text-caption border-b border-[var(--border-subtle)] pb-2 last:border-0 last:pb-0">
                  <span className="font-mono text-[var(--text-secondary)]">{endpoint}</span>
                  <span className="flex items-center gap-1.5 font-medium">
                    {status === 'checking' && (
                      <span className="flex items-center gap-1 text-[var(--text-muted)]">
                        <RefreshCw className="w-3 h-3 animate-spin" /> Checking
                      </span>
                    )}
                    {status === 'ok' && (
                      <span className="flex items-center gap-1 text-[var(--accent-green)]">
                        <CheckCircle2 className="w-3.5 h-3.5" /> Healthy
                      </span>
                    )}
                    {status === 'failed' && (
                      <span className="flex items-center gap-1 text-[var(--accent-red)]">
                        <AlertCircle className="w-3.5 h-3.5" /> Offline
                      </span>
                    )}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
