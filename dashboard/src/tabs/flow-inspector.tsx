'use client';

import { useState, useMemo } from 'react';
import { useDPIStats } from '@/hooks/useDPIStats';
import { useDPIRules } from '@/hooks/useDPIRules';
import { DataTable, type ColumnDef } from '@/components/dpi/data-table';
import { EmptyState } from '@/components/dpi/empty-state';
import { ShieldAlert, Search, X, Shield, ShieldCheck, Clock, Network, Cpu, KeyRound } from 'lucide-react';
import { formatBytes } from '@/lib/utils';
import type { PacketEntry, PacketAction, FlowRecord } from '@/types/dpi';

export default function FlowInspectorTab() {
  const { stats, isConnected, mutate } = useDPIStats();
  const { addRule, isLoading: isRulesActionLoading } = useDPIRules();
  
  const [filterText, setFilterText] = useState('');
  const [selectedFlow, setSelectedFlow] = useState<FlowRecord | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  // Group packets into bi-directional flows
  const flowRecords = useMemo(() => {
    if (!stats || !stats.recent_packets) return [];
    
    const flowsMap: Record<string, FlowRecord> = {};

    stats.recent_packets.forEach((p) => {
      // Split IP and Port
      const lastSrcColon = p.src.lastIndexOf(':');
      const srcIp = lastSrcColon !== -1 ? p.src.substring(0, lastSrcColon) : p.src;
      const srcPort = lastSrcColon !== -1 ? parseInt(p.src.substring(lastSrcColon + 1)) || 0 : 0;

      const lastDstColon = p.dst.lastIndexOf(':');
      const dstIp = lastDstColon !== -1 ? p.dst.substring(0, lastDstColon) : p.dst;
      const dstPort = lastDstColon !== -1 ? parseInt(p.dst.substring(lastDstColon + 1)) || 0 : 0;

      // Canonical key for bi-directional flow: sort endpoints alphabetically
      const endpointA = `${srcIp}:${srcPort}`;
      const endpointB = `${dstIp}:${dstPort}`;
      const flowId = endpointA < endpointB 
        ? `${endpointA}-${endpointB}-${p.protocol}` 
        : `${endpointB}-${endpointA}-${p.protocol}`;

      const existing = flowsMap[flowId];

      if (!existing) {
        flowsMap[flowId] = {
          id: flowId,
          srcIp,
          srcPort,
          dstIp,
          dstPort,
          protocol: p.protocol,
          app: p.app,
          domain: p.domain,
          status: 'Active',
          packets: 1,
          bytes: p.size,
          firstSeen: p.time,
          lastSeen: p.time,
          action: p.action,
          ja3: p.ja3 || '',
          ja4: p.ja4 || '',
          eti: p.eti || '',
          country: p.country || 'Unknown',
        };
      } else {
        existing.packets += 1;
        existing.bytes += p.size;
        existing.lastSeen = p.time;
        
        // Elevate action to DROP if any packet in flow is dropped
        if (p.action === 'DROP') {
          existing.action = 'DROP';
        }
        // Save app signature if discovered later
        if (p.app && p.app !== 'Unknown' && existing.app === 'Unknown') {
          existing.app = p.app;
        }
        // Save domain context if discovered later
        if (p.domain && !existing.domain) {
          existing.domain = p.domain;
        }
        // Save country context if discovered later
        if (p.country && p.country !== 'Unknown' && existing.country === 'Unknown') {
          existing.country = p.country;
        }
        // Retain latest TLS fingerprints
        if (p.ja3 && !existing.ja3) existing.ja3 = p.ja3;
        if (p.ja4 && !existing.ja4) existing.ja4 = p.ja4;
        if (p.eti && !existing.eti) existing.eti = p.eti;
      }
    });

    return Object.values(flowsMap);
  }, [stats?.recent_packets]);

  // Apply search filters
  const filteredFlows = useMemo(() => {
    if (!filterText.trim()) return flowRecords;
    const query = filterText.toLowerCase();

    return flowRecords.filter(
      (f) =>
        f.srcIp.toLowerCase().includes(query) ||
        f.dstIp.toLowerCase().includes(query) ||
        String(f.srcPort).includes(query) ||
        String(f.dstPort).includes(query) ||
        f.protocol.toLowerCase().includes(query) ||
        f.app.toLowerCase().includes(query) ||
        f.domain.toLowerCase().includes(query)
    );
  }, [flowRecords, filterText]);

  // Handle blocking actions directly from the inspector panel
  const handleBlockAction = async (type: 'ip' | 'app' | 'domain', value: string) => {
    if (!value) return;
    setActionMessage(`Blocking ${type}...`);
    const res = await addRule(type, value);
    if (res.ok) {
      setActionMessage(`Successfully blocked ${type}: ${value}`);
      mutate(); // reload telemetry rules snapshot
      // If we blocked the active flow, update its client view action to DROP
      if (selectedFlow) {
        let isMatch = false;
        if (type === 'ip' && (selectedFlow.srcIp === value || selectedFlow.dstIp === value)) isMatch = true;
        if (type === 'app' && selectedFlow.app === value) isMatch = true;
        if (type === 'domain' && selectedFlow.domain.includes(value)) isMatch = true;
        
        if (isMatch) {
          setSelectedFlow({ ...selectedFlow, action: 'DROP' });
        }
      }
    } else {
      setActionMessage(`Failed: ${res.message}`);
    }
  };

  // Define Flow Columns
  const columns = useMemo<ColumnDef<FlowRecord>[]>(
    () => [
      {
        key: 'srcIp',
        header: 'Source Endpoint',
        render: (f) => `${f.srcIp}:${f.srcPort}`,
        sortable: true,
        className: 'w-[25%] font-mono text-[12px]',
      },
      {
        key: 'dstIp',
        header: 'Destination Endpoint',
        render: (f) => `${f.dstIp}:${f.dstPort}`,
        sortable: true,
        className: 'w-[25%] font-mono text-[12px]',
      },
      {
        key: 'protocol',
        header: 'Proto',
        sortable: true,
        className: 'w-[10%] font-bold text-center font-mono text-[11px]',
      },
      {
        key: 'packets',
        header: 'Frames',
        sortable: true,
        render: (f) => f.packets.toLocaleString(),
        className: 'w-[10%] text-right font-mono text-[12px]',
      },
      {
        key: 'bytes',
        header: 'Size',
        sortable: true,
        render: (f) => formatBytes(f.bytes),
        className: 'w-[12%] text-right font-mono text-[12px]',
      },
      {
        key: 'app',
        header: 'App Class',
        sortable: true,
        render: (f) => (
          <span
            className="px-1.5 py-0.5 rounded text-[11px] font-semibold"
            style={{
              backgroundColor: f.app === 'Unknown' ? 'var(--border)' : 'var(--accent-violet)',
              color: f.app === 'Unknown' ? 'var(--text-muted)' : '#fff',
            }}
          >
            {f.app}
          </span>
        ),
        className: 'w-[18%] text-center',
      },
      {
        key: 'action',
        header: 'Status',
        sortable: true,
        render: (f) => (
          <span
            className={`dpi-badge font-bold uppercase tracking-wide text-[10px] ${
              f.action === 'DROP' ? 'dpi-badge-error' : 'dpi-badge-success'
            }`}
          >
            {f.action === 'DROP' ? 'Blocked' : 'Active'}
          </span>
        ),
        className: 'w-[10%] text-center',
      },
    ],
    []
  );

  return (
    <div className="space-y-6 animate-fade-in relative">
      <div className="flex items-center justify-between border-b border-[var(--border)] pb-4">
        <div>
          <h2 className="text-display-sm">Flow Inspector Control</h2>
          <p className="text-caption text-[var(--text-muted)] mt-1">
            Aggregated 5-tuple conversations with SNI headers, TLS fingerprints, and deep packets stats.
          </p>
        </div>
      </div>

      <div className="flex flex-col lg:flex-row gap-6 items-stretch lg:items-start w-full max-w-full overflow-hidden">
        {/* Main flows table grid */}
        <div className="flex-1 w-full min-w-0 space-y-4">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
            <div className="text-caption text-[var(--text-secondary)] font-medium uppercase font-mono">
              Active Conversations ({filteredFlows.length})
            </div>
            
            {/* Search Filter input */}
            <div className="relative w-full sm:w-72">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[var(--text-muted)]" />
              <input
                type="text"
                value={filterText}
                onChange={(e) => setFilterText(e.target.value)}
                placeholder="Search IPs, ports, app, protocols..."
                className="w-full pl-8 pr-3 py-1.5 rounded-md text-caption outline-none transition-colors border border-[var(--border)] bg-[var(--panel-soft)] text-[var(--text)] focus:border-[var(--border-strong)]"
              />
            </div>
          </div>

          {!isConnected || flowRecords.length === 0 ? (
            <EmptyState
              icon={<ShieldAlert className="w-8 h-8 text-[var(--text-muted)]" />}
              title="No flows collected"
              description="Flow analytics will render once packet frames are received. Ensure capture is active."
            />
          ) : (
            <div className="w-full overflow-hidden">
              <DataTable
                data={filteredFlows}
                columns={columns}
                rowKey={(f) => f.id}
                actionField={(f) => f.action}
                onRowClick={(f) => {
                  setSelectedFlow(f);
                  setActionMessage(null);
                }}
                height="450px"
              />
            </div>
          )}
        </div>

        {/* Selected Flow Inspector drawer details (Right Column) */}
        {selectedFlow && (
          <div className="w-full lg:w-[350px] dpi-card space-y-4 border border-[var(--border-strong)] flex-shrink-0 animate-slide-up lg:sticky lg:top-20">
            <div className="flex items-center justify-between border-b border-[var(--border-subtle)] pb-3">
              <div className="flex items-center gap-1.5 text-body-sm font-semibold text-[var(--text)]">
                <Network className="w-4 h-4 text-[var(--accent-blue)]" />
                <span>Flow Conversation Details</span>
              </div>
              <button
                onClick={() => setSelectedFlow(null)}
                className="p-1 rounded-md hover:bg-[var(--panel-soft)] transition-colors text-[var(--text-muted)] hover:text-[var(--text)] cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-4 text-caption">
              {/* Enpoints */}
              <div className="bg-[var(--panel-soft)] p-3 rounded-lg border border-[var(--border)] space-y-2">
                <div className="flex justify-between">
                  <span className="text-[var(--text-muted)]">Source IP</span>
                  <span className="font-mono font-bold text-[var(--text)]">{selectedFlow.srcIp}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[var(--text-muted)]">Source Port</span>
                  <span className="font-mono font-semibold text-[var(--text-secondary)]">{selectedFlow.srcPort}</span>
                </div>
                <div className="border-t border-[var(--border-subtle)] my-1 pt-1 flex justify-between">
                  <span className="text-[var(--text-muted)]">Dest IP</span>
                  <span className="font-mono font-bold text-[var(--text)]">{selectedFlow.dstIp}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[var(--text-muted)]">Dest Port</span>
                  <span className="font-mono font-semibold text-[var(--text-secondary)]">{selectedFlow.dstPort}</span>
                </div>
              </div>

              {/* Stats */}
              <div className="space-y-2.5">
                <div className="flex justify-between">
                  <span className="text-[var(--text-muted)] flex items-center gap-1"><Clock className="w-3.5 h-3.5" /> First Seen</span>
                  <span className="font-mono">{selectedFlow.firstSeen}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[var(--text-muted)] flex items-center gap-1"><Clock className="w-3.5 h-3.5" /> Last Active</span>
                  <span className="font-mono">{selectedFlow.lastSeen}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[var(--text-muted)]">Total Volume</span>
                  <span className="font-mono font-semibold text-[var(--text)]">{formatBytes(selectedFlow.bytes)}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[var(--text-muted)]">Packets Count</span>
                  <span className="font-mono font-semibold text-[var(--text)]">{selectedFlow.packets} frames</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[var(--text-muted)]">Protocol</span>
                  <span className="font-mono font-bold uppercase text-[var(--accent-cyan)]">{selectedFlow.protocol}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[var(--text-muted)]">Destination Country</span>
                  <span className="font-mono font-semibold text-[var(--text)]">{selectedFlow.country}</span>
                </div>
              </div>

              {/* TLS Signatures if present */}
              {(selectedFlow.ja3 || selectedFlow.ja4 || selectedFlow.domain) && (
                <div className="border-t border-[var(--border-subtle)] pt-3 space-y-2">
                  <div className="flex items-center gap-1 text-[var(--text)] font-semibold">
                    <KeyRound className="w-3.5 h-3.5 text-[var(--accent-violet)]" />
                    <span>TLS Intelligence</span>
                  </div>
                  {selectedFlow.domain && (
                    <div className="flex justify-between items-baseline gap-2">
                      <span className="text-[var(--text-muted)] flex-shrink-0">SNI Domain</span>
                      <span className="font-mono font-semibold text-[var(--text)] text-right truncate max-w-[170px]" title={selectedFlow.domain}>
                        {selectedFlow.domain}
                      </span>
                    </div>
                  )}
                  {selectedFlow.ja3 && (
                    <div className="flex flex-col gap-0.5">
                      <span className="text-[var(--text-muted)]">JA3 TLS Fingerprint</span>
                      <span className="font-mono text-[10px] bg-[var(--panel-soft)] px-1.5 py-0.5 border border-[var(--border)] rounded text-[var(--text-secondary)] break-all select-all">
                        {selectedFlow.ja3}
                      </span>
                    </div>
                  )}
                  {selectedFlow.ja4 && (
                    <div className="flex flex-col gap-0.5">
                      <span className="text-[var(--text-muted)]">JA4 TLS Fingerprint</span>
                      <span className="font-mono text-[10px] bg-[var(--panel-soft)] px-1.5 py-0.5 border border-[var(--border)] rounded text-[var(--text-secondary)] break-all select-all">
                        {selectedFlow.ja4}
                      </span>
                    </div>
                  )}
                </div>
              )}

              {/* ETI Security scores if present */}
              {selectedFlow.eti && (
                <div className="border-t border-[var(--border-subtle)] pt-3 space-y-1">
                  <div className="flex items-center gap-1 text-[var(--text)] font-semibold">
                    <Cpu className="w-3.5 h-3.5 text-[var(--accent-red)]" />
                    <span>ETI Classifier Engine</span>
                  </div>
                  <div className="flex justify-between items-center bg-[var(--panel-soft)] border border-[var(--border)] p-2 rounded-lg">
                    <span className="text-[var(--text-secondary)]">Behavioral Signature</span>
                    <span className="font-mono font-bold text-[var(--accent-red)]">{selectedFlow.eti}</span>
                  </div>
                </div>
              )}

              {/* Blocking Action Controls */}
              <div className="border-t border-[var(--border-subtle)] pt-3 space-y-2">
                <div className="font-semibold text-[var(--text)] flex items-center gap-1.5">
                  <Shield className="w-3.5 h-3.5 text-[var(--accent-red)]" />
                  <span>Rule Enforcement</span>
                </div>
                
                {selectedFlow.action === 'DROP' ? (
                  <div className="bg-[var(--accent-red-soft)] border border-[var(--accent-red)]/20 p-2.5 rounded-lg flex items-center gap-2 text-[var(--accent-red)] font-semibold">
                    <Shield className="w-4 h-4" />
                    <span>Flow drops actively enforced.</span>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 gap-1.5">
                    <button
                      onClick={() => handleBlockAction('ip', selectedFlow.srcIp)}
                      disabled={isRulesActionLoading}
                      className="py-1.5 rounded border border-[var(--border)] hover:border-[var(--accent-red)]/50 hover:bg-[var(--accent-red-soft)]/10 text-left px-2.5 transition-all text-[var(--text-secondary)] hover:text-[var(--accent-red)] cursor-pointer"
                    >
                      Block Source IP ({selectedFlow.srcIp})
                    </button>
                    {selectedFlow.app && selectedFlow.app !== 'Unknown' && (
                      <button
                        onClick={() => handleBlockAction('app', selectedFlow.app)}
                        disabled={isRulesActionLoading}
                        className="py-1.5 rounded border border-[var(--border)] hover:border-[var(--accent-red)]/50 hover:bg-[var(--accent-red-soft)]/10 text-left px-2.5 transition-all text-[var(--text-secondary)] hover:text-[var(--accent-red)] cursor-pointer"
                      >
                        Block Application Signature ({selectedFlow.app})
                      </button>
                    )}
                    {selectedFlow.domain && (
                      <button
                        onClick={() => handleBlockAction('domain', selectedFlow.domain)}
                        disabled={isRulesActionLoading}
                        className="py-1.5 rounded border border-[var(--border)] hover:border-[var(--accent-red)]/50 hover:bg-[var(--accent-red-soft)]/10 text-left px-2.5 transition-all text-[var(--text-secondary)] hover:text-[var(--accent-red)] cursor-pointer"
                      >
                        Block SNI Domain Substring ({selectedFlow.domain})
                      </button>
                    )}
                  </div>
                )}

                {actionMessage && (
                  <div className="p-2 rounded bg-[var(--panel-soft)] text-center text-[10px] text-[var(--accent-amber)] font-mono border border-[var(--border)] animate-pulse">
                    {actionMessage}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
