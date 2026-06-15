'use client';

import { useEffect, useState, useMemo } from 'react';
import { useDPIStats } from '@/hooks/useDPIStats';
import { KPICard } from '@/components/dpi/kpi-card';
import { ChartContainer } from '@/components/dpi/chart-container';
import { EmptyState } from '@/components/dpi/empty-state';
import { formatBytes, formatNumber, formatPps } from '@/lib/utils';
import { APP_COLORS } from '@/lib/dpi-constants';
import {
  Activity,
  ShieldAlert,
  ArrowUpRight,
  Shield,
  Layers,
  Database,
  Cpu,
  AlertTriangle,
  Flame,
  CheckCircle,
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
} from 'recharts';

interface HistoryPoint {
  time: string;
  pps: number;
  mbps: number;
}

export default function OverviewTab() {
  const { stats, isConnected, error } = useDPIStats();
  const [throughputHistory, setThroughputHistory] = useState<HistoryPoint[]>([]);
  const [prevStats, setPrevStats] = useState<{ packets: number; bytes: number; time: number } | null>(null);

  // Maintain rolling history of throughput and bandwidth
  useEffect(() => {
    if (!stats) return;

    const now = Date.now();
    let currentPps = stats.analytics?.throughput_pps ?? 0;
    let currentMbps = stats.analytics?.bandwidth_mbps ?? 0;

    // Fallback calculation if backend analytics not present
    if (!stats.analytics && prevStats) {
      const elapsed = (now - prevStats.time) / 1000;
      if (elapsed > 0.3) {
        const packetDelta = stats.total_packets - prevStats.packets;
        const byteDelta = stats.total_bytes - prevStats.bytes;
        currentPps = Math.max(0, Math.round(packetDelta / elapsed));
        currentMbps = Math.max(0, parseFloat(((byteDelta * 8) / (elapsed * 1000000)).toFixed(2)));
      }
    }

    setPrevStats({
      packets: stats.total_packets,
      bytes: stats.total_bytes,
      time: now,
    });

    const timeStr = new Date(now).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

    setThroughputHistory((prev) => {
      const next = [...prev, { time: timeStr, pps: currentPps, mbps: currentMbps }];
      if (next.length > 20) {
        return next.slice(1);
      }
      return next;
    });
  }, [stats]);

  // App Classification Donut Data
  const appChartData = useMemo(() => {
    if (!stats?.apps || stats.apps.length === 0) return [];
    // Sort by count descending, pick top 5, combine remaining into "Other"
    const sorted = [...stats.apps].sort((a, b) => b.count - a.count);
    const top = sorted.slice(0, 5);
    const remainingCount = sorted.slice(5).reduce((sum, item) => sum + item.count, 0);
    const remainingPct = sorted.slice(5).reduce((sum, item) => sum + item.pct, 0);

    if (remainingCount > 0) {
      top.push({
        name: 'Other',
        count: remainingCount,
        pct: parseFloat(remainingPct.toFixed(1)),
      });
    }
    return top;
  }, [stats?.apps]);

  // Thread Load Balancer / Worker load percentage estimation
  const threadData = useMemo(() => {
    if (!stats) return [];
    
    // lb_threads and fp_threads represent packet processing counts
    const lbs = (stats.lb_threads || []).map((t, idx) => ({
      name: `LB-${idx}`,
      packets: t.packets,
      type: 'Load Balancer' as const,
    }));
    const fps = (stats.fp_threads || []).map((t, idx) => ({
      name: `FP-${idx}`,
      packets: t.packets,
      type: 'Fast Path' as const,
    }));
    
    const all = [...lbs, ...fps];
    const maxPackets = Math.max(...all.map(t => t.packets), 1);
    
    return all.map(t => ({
      ...t,
      load: Math.round((t.packets / maxPackets) * 100),
    }));
  }, [stats?.lb_threads, stats?.fp_threads]);

  if (error || !isConnected) {
    return (
      <div className="space-y-6">
        <div className="bg-[var(--accent-red-soft)] border border-[var(--accent-red)]/30 text-[var(--accent-red)] px-4 py-3 rounded-lg flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 flex-shrink-0 animate-bounce" />
          <div>
            <h3 className="font-semibold text-body-sm">Connection Failed</h3>
            <p className="text-caption mt-0.5 opacity-80">
              Cannot establish connection to the DPI Engine REST API. Verify the engine is running and check your connection settings.
            </p>
          </div>
        </div>
        <EmptyState
          icon={<ShieldAlert className="w-8 h-8" />}
          title="DPI Engine Offline"
          description="We're waiting for the engine backend server to come online. Ensure you started it via cli.py or direct execution."
        />
      </div>
    );
  }

  if (!stats) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        {[...Array(5)].map((_, i) => (
          <div key={i} className="skeleton h-24 w-full" />
        ))}
      </div>
    );
  }

  const dropRatePct = stats.drop_rate ?? (stats.total_packets > 0 ? (stats.dropped / stats.total_packets) * 100 : 0);

  return (
    <div className="space-y-6 animate-fade-in">
      {/* KPI Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        <KPICard
          title="Total Packets"
          value={stats.total_packets}
          icon={<Activity className="w-5 h-5" />}
          accentColor="var(--accent-blue)"
          subtitle="Processed packets count"
        />
        <KPICard
          title="Traffic Volume"
          value={stats.total_bytes}
          formattedValue={formatBytes(stats.total_bytes)}
          icon={<Database className="w-5 h-5" />}
          accentColor="var(--accent-violet)"
          subtitle="Accumulated data volume"
        />
        <KPICard
          title="Forwarded"
          value={stats.forwarded}
          icon={<CheckCircle className="w-5 h-5" />}
          accentColor="var(--accent-green)"
          subtitle="Passed engine filters"
        />
        <KPICard
          title="Blocked/Dropped"
          value={stats.dropped}
          icon={<Shield className="w-5 h-5" />}
          accentColor="var(--accent-red)"
          subtitle="Matches block rules"
        />
        <KPICard
          title="Drop Rate"
          value={dropRatePct}
          formattedValue={`${dropRatePct.toFixed(2)}%`}
          icon={<ArrowUpRight className="w-5 h-5" />}
          accentColor={dropRatePct > 10 ? 'var(--accent-red)' : 'var(--accent-amber)'}
          subtitle="Dropped packet ratio"
        />
      </div>
 
      {/* System Status Hero Spotlight Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 animate-slide-up" style={{ animationDelay: '100ms' }}>
        <div className="md:col-span-2 dpi-spotlight dpi-spotlight-violet flex flex-col justify-between min-h-[170px] group">
          <div className="space-y-2 relative z-10">
            <span className="text-[11px] font-semibold text-sky-300! uppercase tracking-wider font-mono">
              Deep Packet Classification & Enforcer Panel
            </span>
            <h2 className="text-[24px] md:text-[28px] text-white! font-semibold tracking-[-0.8px] leading-tight">
              Network Traffic Intelligence Platform
            </h2>
            <p className="text-[14px] text-neutral-200! max-w-xl leading-relaxed mt-1">
              This dashboard provides real-time telemetry from active Load Balancer and Fast Path worker threads, processing network flows and enforcing active drops.
            </p>
          </div>
          
          <div className="flex flex-wrap gap-2.5 mt-4 relative z-10">
            <span className="dpi-badge bg-green-500/20! border-green-500/30! text-green-300! py-1 px-3">
              <span className="status-dot status-dot-active w-1.5 h-1.5 mr-1.5" />
              Model: Random Forest ETI
            </span>
            <span className="dpi-badge bg-sky-500/20! border-sky-500/30! text-sky-300! py-1 px-3 font-semibold">
              Npcap/Scapy Active
            </span>
          </div>
        </div>

        <div className="md:col-span-1 dpi-spotlight dpi-spotlight-magenta flex flex-col justify-between min-h-[170px] group">
          <div className="space-y-1 relative z-10">
            <span className="text-[11px] font-semibold text-pink-300! uppercase tracking-wider font-mono">
              Security Shield Status
            </span>
            <h3 className="text-[18px] text-white! font-bold tracking-[-0.4px] mt-1">
              {stats.dropped > 0 ? 'Threat Protection Enforced' : 'System Guard Online'}
            </h3>
            <p className="text-[13px] text-neutral-200! mt-1.5 leading-relaxed">
              {stats.dropped > 0 
                ? `Actively blocked ${stats.dropped.toLocaleString()} anomalous or blacklisted packets.`
                : 'No network threats or blocked packet matches detected in this session.'}
            </p>
          </div>

          <div className="mt-4 relative z-10 flex items-center justify-between text-[11px] text-neutral-300! font-mono border-t border-white/10 pt-2.5">
            <span className="text-neutral-300!">Verdict Stream</span>
            <span className="text-white! font-medium">{stats.forwarded.toLocaleString()} fwd / {stats.dropped.toLocaleString()} drp</span>
          </div>
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Real-time Bandwidth Line Chart */}
        <div className="lg:col-span-2">
          <ChartContainer
            title="Real-time Engine Throughput"
            subtitle="Live Bandwidth (Mbps) and Packets per Second (pps)"
            height={300}
          >
            {throughputHistory.length === 0 ? (
              <div className="flex h-full items-center justify-center text-caption text-[var(--text-muted)] font-mono">
                Gathering telemetry samples...
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={throughputHistory} margin={{ top: 10, right: 10, left: -10, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorMbps" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="var(--accent-blue)" stopOpacity={0.2} />
                      <stop offset="95%" stopColor="var(--accent-blue)" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="colorPps" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="var(--accent-violet)" stopOpacity={0.2} />
                      <stop offset="95%" stopColor="var(--accent-violet)" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="time" stroke="var(--border-strong)" />
                  <YAxis yAxisId="left" stroke="var(--accent-blue)" orientation="left" />
                  <YAxis yAxisId="right" stroke="var(--accent-violet)" orientation="right" />
                  <Tooltip
                    contentStyle={{
                      background: 'var(--panel)',
                      borderColor: 'var(--border)',
                      borderRadius: '8px',
                      color: 'var(--text)',
                      fontFamily: 'JetBrains Mono, monospace',
                      fontSize: '12px',
                    }}
                  />
                  <Area
                    yAxisId="left"
                    type="monotone"
                    dataKey="mbps"
                    name="Bandwidth (Mbps)"
                    stroke="var(--accent-blue)"
                    fillOpacity={1}
                    fill="url(#colorMbps)"
                    strokeWidth={2}
                  />
                  <Area
                    yAxisId="right"
                    type="monotone"
                    dataKey="pps"
                    name="Throughput (pps)"
                    stroke="var(--accent-violet)"
                    fillOpacity={1}
                    fill="url(#colorPps)"
                    strokeWidth={2}
                  />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </ChartContainer>
        </div>

        {/* Application Classification Donut */}
        <div>
          <ChartContainer
            title="App Classification breakdown"
            subtitle="Application signatures detected"
            height={300}
          >
            {appChartData.length === 0 ? (
              <div className="flex h-full items-center justify-center text-caption text-[var(--text-muted)] font-mono">
                No signatures classified yet
              </div>
            ) : (
              <div className="relative h-full flex flex-col items-center justify-center">
                <div className="w-full h-[180px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={appChartData}
                        cx="50%"
                        cy="50%"
                        innerRadius={55}
                        outerRadius={75}
                        paddingAngle={3}
                        dataKey="count"
                      >
                        {appChartData.map((entry) => (
                          <Cell
                            key={`cell-${entry.name}`}
                            fill={APP_COLORS[entry.name] || '#888888'}
                          />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{
                          background: 'var(--panel)',
                          borderColor: 'var(--border)',
                          borderRadius: '8px',
                          color: 'var(--text)',
                        }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 w-full px-4 overflow-y-auto max-h-[100px] text-caption mt-2">
                  {appChartData.map((entry) => (
                    <div key={entry.name} className="flex items-center gap-2 min-w-0">
                      <span
                        className="w-2.5 h-2.5 rounded-full flex-shrink-0"
                        style={{ backgroundColor: APP_COLORS[entry.name] || '#888888' }}
                      />
                      <span className="truncate text-[var(--text-secondary)]">{entry.name}</span>
                      <span className="font-mono text-[10px] text-[var(--text-muted)] ml-auto">
                        {entry.pct}%
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </ChartContainer>
        </div>
      </div>

      {/* Threads and Anomalies Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Thread load balancer bar charts */}
        <div className="lg:col-span-1">
          <ChartContainer
            title="Pipeline Thread Loads"
            subtitle="Worker packet queues balancer distribution"
            height={260}
          >
            {threadData.length === 0 ? (
              <div className="flex h-full items-center justify-center text-caption text-[var(--text-muted)] font-mono">
                No active threads reported
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={threadData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <XAxis dataKey="name" stroke="var(--border-strong)" />
                  <YAxis stroke="var(--border-strong)" unit="%" domain={[0, 100]} />
                  <Tooltip
                    contentStyle={{
                      background: 'var(--panel)',
                      borderColor: 'var(--border)',
                      borderRadius: '8px',
                      color: 'var(--text)',
                    }}
                  />
                  <Bar dataKey="load" name="Load Efficiency">
                    {threadData.map((entry, index) => (
                      <Cell
                        key={`cell-${index}`}
                        fill={entry.type === 'Load Balancer' ? 'var(--accent-blue)' : 'var(--accent-cyan)'}
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </ChartContainer>
        </div>

        {/* Security Alerts / Protocol Anomalies */}
        <div className="lg:col-span-2">
          <div className="dpi-card flex flex-col" style={{ height: '324px' }}>
            <div className="flex items-center justify-between border-b border-[var(--border-subtle)] pb-3 mb-3">
              <div>
                <h3 className="text-body-sm font-semibold text-[var(--text)]">Recent Protocol Anomalies</h3>
                <p className="text-caption text-[var(--text-muted)] mt-0.5">Live security events feed</p>
              </div>
              {stats.recent_anomalies && stats.recent_anomalies.length > 0 && (
                <span className="dpi-badge dpi-badge-error animate-pulse">
                  <Flame className="w-3.5 h-3.5" />
                  {stats.recent_anomalies.length} Alerts
                </span>
              )}
            </div>

            <div className="flex-1 overflow-y-auto space-y-2 pr-1.5 scrollbar-thin">
              {!stats.recent_anomalies || stats.recent_anomalies.length === 0 ? (
                <div className="h-full flex items-center justify-center flex-col text-center text-caption text-[var(--text-muted)]">
                  <CheckCircle className="w-8 h-8 text-[var(--accent-green)] mb-2 opacity-55" />
                  <span>No security anomalies or signatures detected.</span>
                </div>
              ) : (
                stats.recent_anomalies.map((anomaly, idx) => (
                  <div
                    key={idx}
                    className="p-2.5 rounded-lg border border-[var(--border)] bg-[var(--panel-soft)] flex items-start gap-2.5 text-caption transition-all hover:border-[var(--accent-red)]/50"
                  >
                    <AlertTriangle className="w-4 h-4 text-[var(--accent-red)] flex-shrink-0 mt-0.5 animate-pulse" />
                    <div className="flex-1 min-w-0">
                      <div className="flex justify-between items-baseline">
                        <span className="font-semibold text-[var(--text)] uppercase tracking-wide text-[10px]">
                          {anomaly.type}
                        </span>
                        <span className="text-[10px] text-[var(--text-muted)] font-mono">
                          {new Date(anomaly.timestamp * 1000).toLocaleTimeString()}
                        </span>
                      </div>
                      <p className="text-[var(--text-secondary)] mt-1 font-mono text-[11px] break-all">
                        {anomaly.description}
                      </p>
                      <div className="flex gap-4 mt-1.5 text-[10px] text-[var(--text-muted)] font-mono">
                        <span>Flow: {anomaly.flow}</span>
                        {anomaly.app && <span>Class: {anomaly.app}</span>}
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
