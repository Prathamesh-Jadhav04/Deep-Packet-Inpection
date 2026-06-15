'use client';

import { useMemo } from 'react';
import { useDPIStats } from '@/hooks/useDPIStats';
import { ChartContainer } from '@/components/dpi/chart-container';
import { EmptyState } from '@/components/dpi/empty-state';
import { BarChart, Bar, Cell, XAxis, YAxis, Tooltip, ResponsiveContainer, RadialBarChart, RadialBar, Legend } from 'recharts';
import { BarChart3, Globe2, Network, ShieldCheck, Terminal } from 'lucide-react';
import { formatBytes } from '@/lib/utils';
import { PROTOCOL_COLORS } from '@/lib/dpi-constants';

interface AggregatedMetric {
  name: string;
  value: number;
  displayValue?: string;
  fill?: string;
}

export default function TrafficAnalyticsTab() {
  const { stats, isConnected } = useDPIStats();

  // client-side fallback aggregation from recent_packets if analytics isn't present
  const aggregatedData = useMemo(() => {
    if (!stats) return null;

    const packets = stats.recent_packets || [];
    
    // 1. Top Talkers (IPs)
    const talkersMap: Record<string, number> = {};
    // 2. Protocols
    const protocolsMap: Record<string, number> = {};
    // 3. Port Matrix
    const portsMap: Record<string, number> = {};
    // 4. Domains SNI
    const domainsMap: Record<string, { count: number; app: string }> = {};

    // Use backend analytics if populated
    const hasBackendAnalytics = stats.analytics && Object.keys(stats.analytics.top_talkers || {}).length > 0;

    if (hasBackendAnalytics && stats.analytics) {
      Object.entries(stats.analytics.top_talkers).forEach(([ip, bytes]) => {
        talkersMap[ip] = bytes;
      });
      Object.entries(stats.analytics.protocol_distribution).forEach(([proto, count]) => {
        protocolsMap[proto] = count;
      });
      Object.entries(stats.analytics.port_matrix).forEach(([port, count]) => {
        portsMap[port] = count;
      });
    } else {
      // Fallback client-side aggregation
      packets.forEach((p) => {
        // Talkers (Aggregate bytes by Source IP)
        talkersMap[p.src] = (talkersMap[p.src] || 0) + p.size;
        
        // Protocols
        protocolsMap[p.protocol] = (protocolsMap[p.protocol] || 0) + 1;
        
        // Extract Ports from IP:Port strings if present
        const srcPort = p.src.split(':').pop();
        const dstPort = p.dst.split(':').pop();
        if (dstPort && !isNaN(Number(dstPort))) {
          portsMap[dstPort] = (portsMap[dstPort] || 0) + 1;
        }
      });
    }

    // Aggregate domains from recent packets anyway for detailed view
    packets.forEach((p) => {
      if (p.domain) {
        if (!domainsMap[p.domain]) {
          domainsMap[p.domain] = { count: 0, app: p.app };
        }
        domainsMap[p.domain].count += 1;
      }
    });

    // Format Top Talkers
    const topTalkers: AggregatedMetric[] = Object.entries(talkersMap)
      .map(([name, val]) => ({
        name,
        value: val,
        displayValue: formatBytes(val),
      }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 7);

    // Format Protocols
    const totalProtocolFrames = Object.values(protocolsMap).reduce((sum, v) => sum + v, 0);
    const protocols: AggregatedMetric[] = Object.entries(protocolsMap)
      .map(([name, val]) => ({
        name,
        value: val,
        displayValue: `${((val / (totalProtocolFrames || 1)) * 100).toFixed(1)}%`,
        fill: PROTOCOL_COLORS[name] || '#888888',
      }))
      .sort((a, b) => b.value - a.value);

    // Format Ports
    const ports: AggregatedMetric[] = Object.entries(portsMap)
      .map(([port, count]) => {
        let label = port;
        if (port === '443') label = '443 (HTTPS)';
        else if (port === '80') label = '80 (HTTP)';
        else if (port === '53') label = '53 (DNS)';
        else if (port === '853') label = '853 (DoT)';
        return {
          name: label,
          value: count,
        };
      })
      .sort((a, b) => b.value - a.value)
      .slice(0, 6);

    // Format Domains
    const domains = Object.entries(domainsMap)
      .map(([domain, info]) => ({
        domain,
        app: info.app,
        count: info.count,
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    return { topTalkers, protocols, ports, domains };
  }, [stats]);

  if (!isConnected || !stats) {
    return (
      <EmptyState
        icon={<BarChart3 className="w-8 h-8 text-[var(--text-muted)]" />}
        title="Waiting for traffic telemetry"
        description="Traffic analytics charts will populate as packets are captured and classified."
      />
    );
  }

  const data = aggregatedData;
  const hasData = data && (data.topTalkers.length > 0 || data.protocols.length > 0);

  if (!hasData) {
    return (
      <EmptyState
        icon={<Network className="w-8 h-8 text-[var(--text-muted)]" />}
        title="No traffic recorded"
        description="Run a live packet capture or replay an offline PCAP file to view network traffic analytics."
      />
    );
  }

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex items-center justify-between border-b border-[var(--border)] pb-4">
        <div>
          <h2 className="text-display-sm">Deep Traffic Analytics</h2>
          <p className="text-caption text-[var(--text-muted)] mt-1">
            Visual classification of talkers, protocol layers, destination ports, and domain headers.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Talkers (IPs by Bytes) */}
        <div>
          <ChartContainer
            title="Top Talkers (Bytes Volume)"
            subtitle="IP addresses generating the highest traffic load"
            height={280}
          >
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={data.topTalkers}
                layout="vertical"
                margin={{ top: 10, right: 30, left: 30, bottom: 5 }}
              >
                <XAxis type="number" stroke="var(--border-strong)" tickFormatter={(v) => formatBytes(v)} />
                <YAxis dataKey="name" type="category" stroke="var(--border-strong)" width={90} className="font-mono text-[10px]" />
                <Tooltip
                  formatter={(value: any) => [formatBytes(Number(value || 0)), 'Volume']}
                  contentStyle={{
                    background: 'var(--panel)',
                    borderColor: 'var(--border)',
                    borderRadius: '8px',
                    color: 'var(--text)',
                  }}
                />
                <Bar dataKey="value" name="Bytes Volume" radius={[0, 4, 4, 0]}>
                  {data.topTalkers.map((_, index) => (
                    <Cell
                      key={`cell-${index}`}
                      fill={`var(--chart-${(index % 5) + 1})`}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </ChartContainer>
        </div>

        {/* Port Matrix Distribution */}
        <div>
          <ChartContainer
            title="Destination Ports Activity"
            subtitle="Traffic frame density per destination port"
            height={280}
          >
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data.ports} margin={{ top: 15, right: 10, left: -10, bottom: 5 }}>
                <XAxis dataKey="name" stroke="var(--border-strong)" className="font-mono text-[10px]" />
                <YAxis stroke="var(--border-strong)" />
                <Tooltip
                  formatter={(value: any) => [Number(value || 0).toLocaleString(), 'Frames']}
                  contentStyle={{
                    background: 'var(--panel)',
                    borderColor: 'var(--border)',
                    borderRadius: '8px',
                    color: 'var(--text)',
                  }}
                />
                <Bar dataKey="value" name="Frames Count" fill="var(--accent-violet)" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </ChartContainer>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Protocol Dial/Radial Chart */}
        <div className="lg:col-span-1">
          <ChartContainer
            title="Layer 4 Protocols"
            subtitle="Distribution of TCP vs UDP transport streams"
            height={300}
          >
            <ResponsiveContainer width="100%" height="100%">
              <RadialBarChart
                cx="50%"
                cy="50%"
                innerRadius="30%"
                outerRadius="90%"
                barSize={15}
                data={data.protocols}
              >
                <RadialBar
                  background
                  dataKey="value"
                  cornerRadius={10}
                />
                <Legend
                  iconSize={10}
                  layout="vertical"
                  verticalAlign="middle"
                  wrapperStyle={{
                    top: '50%',
                    right: 0,
                    transform: 'translate(0, -50%)',
                    lineHeight: '24px',
                    fontSize: '11px',
                    fontFamily: 'JetBrains Mono',
                  }}
                />
              </RadialBarChart>
            </ResponsiveContainer>
          </ChartContainer>
        </div>

        {/* Classified Domains context table */}
        <div className="lg:col-span-2">
          <div className="dpi-card flex flex-col" style={{ height: '364px' }}>
            <div className="flex items-center gap-2 border-b border-[var(--border-subtle)] pb-3 mb-3">
              <Globe2 className="w-4 h-4 text-[var(--accent-blue)]" />
              <div>
                <h3 className="text-body-sm font-semibold text-[var(--text)]">Domain Contexts and SNIs</h3>
                <p className="text-caption text-[var(--text-muted)] mt-0.5">TLS Client Hellos host signatures</p>
              </div>
            </div>

            <div className="flex-1 overflow-y-auto scrollbar-thin">
              {data.domains.length === 0 ? (
                <div className="h-full flex items-center justify-center text-caption text-[var(--text-muted)] font-mono">
                  No domain records captured.
                </div>
              ) : (
                <div className="w-full overflow-x-auto scrollbar-none">
                  <table className="dpi-table">
                    <thead>
                      <tr>
                        <th>SNI / Host Context</th>
                        <th>Classified Signature</th>
                        <th className="text-right">Hits</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.domains.map((dom, idx) => (
                        <tr key={idx}>
                          <td className="font-mono text-body-sm text-[var(--text)]">{dom.domain}</td>
                          <td>
                            <span className="dpi-badge dpi-badge-info py-0 px-2 font-semibold">
                              {dom.app}
                            </span>
                          </td>
                          <td className="text-right font-mono text-body-sm text-[var(--text-secondary)]">
                            {dom.count.toLocaleString()}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
