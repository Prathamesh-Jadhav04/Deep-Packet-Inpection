'use client';

import { useState, useEffect, useMemo, useCallback } from 'react';
import { useDPICapture } from '@/hooks/useDPICapture';
import { useDPIInterfaces } from '@/hooks/useDPIInterfaces';
import { useDPIStats } from '@/hooks/useDPIStats';
import { DataTable, type ColumnDef } from '@/components/dpi/data-table';
import { StatusBadge } from '@/components/dpi/status-badge';
import { GradientSpotlightCard } from '@/components/dpi/gradient-spotlight-card';
import { Radio, Play, Square, Settings2, ShieldAlert, ArrowDownWideNarrow, Search, FileDown } from 'lucide-react';
import { cn, formatBytes, formatDuration } from '@/lib/utils';
import type { PacketEntry } from '@/types/dpi';

export default function LiveCaptureTab() {
  const { interfaces, isAvailable: isIfaceAvailable, error: ifaceError, refresh: refreshIfaces } = useDPIInterfaces();
  const { startCapture, stopCapture, isLoading: isCaptureActionLoading, error: captureError } = useDPICapture();
  const { stats, isConnected, mutate } = useDPIStats();

  const [selectedIface, setSelectedIface] = useState('');
  const [bpfFilter, setBpfFilter] = useState('');
  const [packetLimit, setPacketLimit] = useState(0);
  const [durationLimit, setDurationLimit] = useState(0);
  const [outputFile, setOutputFile] = useState('live_output.pcap');
  const [showConfig, setShowConfig] = useState(false);
  const [filterQuery, setFilterQuery] = useState('');

  // Is capture currently running on backend?
  const isCapturing = useMemo(() => stats?.capture_running ?? false, [stats?.capture_running]);

  const handleStartCapture = async () => {
    if (isCaptureActionLoading) return;
    const res = await startCapture({
      iface: selectedIface,
      bpf: bpfFilter,
      count: packetLimit,
      duration: durationLimit || undefined,
      output_file: outputFile,
    });
    if (res.ok) {
      mutate(); // immediate SWR update
    }
  };

  const handleStopCapture = async () => {
    const res = await stopCapture();
    if (res.ok) {
      mutate(); // immediate SWR update
    }
  };

  // Filter packet feed based on search query
  const filteredPackets = useMemo(() => {
    const packets = stats?.recent_packets || [];
    if (!filterQuery.trim()) return packets;
    
    const query = filterQuery.toLowerCase();
    return packets.filter((p) => {
      return (
        p.src.toLowerCase().includes(query) ||
        p.dst.toLowerCase().includes(query) ||
        p.protocol.toLowerCase().includes(query) ||
        p.app.toLowerCase().includes(query) ||
        p.domain.toLowerCase().includes(query) ||
        p.action.toLowerCase().includes(query)
      );
    });
  }, [stats?.recent_packets, filterQuery]);

  // Export current packets in table view as CSV
  const handleExportCSV = () => {
    if (filteredPackets.length === 0) return;
    const headers = 'ID,Timestamp,Src IP,Dst IP,Proto,Length,App Class,Domain Name,Action\r\n';
    const rows = filteredPackets
      .map(
        (p) =>
          `${p.id},"${p.time}","${p.src}","${p.dst}","${p.protocol}",${p.size},"${p.app}","${p.domain}","${p.action}"`
      )
      .join('\r\n');
    
    const blob = new Blob([headers + rows], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `dpi_capture_packets_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Define table columns
  const columns = useMemo<ColumnDef<PacketEntry>[]>(
    () => [
      {
        key: 'id',
        header: 'Frame ID',
        sortable: true,
        className: 'w-[10%] font-mono text-[11px]',
      },
      {
        key: 'time',
        header: 'Timestamp',
        sortable: true,
        className: 'w-[15%] font-mono text-[11px]',
      },
      {
        key: 'src',
        header: 'Source Address',
        sortable: true,
        className: 'w-[20%] font-mono text-[12px] font-medium',
      },
      {
        key: 'dst',
        header: 'Destination Address',
        sortable: true,
        className: 'w-[20%] font-mono text-[12px] font-medium',
      },
      {
        key: 'protocol',
        header: 'Proto',
        sortable: true,
        className: 'w-[8%] font-mono text-[11px] font-bold text-center',
      },
      {
        key: 'size',
        header: 'Len (B)',
        sortable: true,
        render: (p) => p.size.toLocaleString(),
        className: 'w-[8%] text-right font-mono text-[12px]',
      },
      {
        key: 'app',
        header: 'App Class',
        sortable: true,
        render: (p) => (
          <span
            className="px-1.5 py-0.5 rounded text-[11px] font-semibold"
            style={{
              backgroundColor:
                p.app === 'Unknown' ? 'var(--border)' : 'var(--accent-blue)',
              color: p.app === 'Unknown' ? 'var(--text-muted)' : '#fff',
            }}
          >
            {p.app}
          </span>
        ),
        className: 'w-[12%] text-center',
      },
      {
        key: 'domain',
        header: 'SNI/Domain Context',
        sortable: true,
        render: (p) => p.domain || <span className="text-[var(--text-muted)] italic">-</span>,
        className: 'w-[18%] font-mono text-[11px]',
      },
      {
        key: 'action',
        header: 'Verdict',
        sortable: true,
        render: (p) => (
          <span
            className={`dpi-badge font-bold uppercase tracking-wide text-[10px] ${
              p.action === 'DROP' ? 'dpi-badge-error' : 'dpi-badge-success'
            }`}
          >
            {p.action}
          </span>
        ),
        className: 'w-[10%] text-center',
      },
    ],
    []
  );

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Atmosphere tile (pure UI decoration) */}
      <div className="relative overflow-hidden">
        <div className="absolute -top-10 -right-16 w-[420px] h-[220px] opacity-70 blur-[22px]">
          <GradientSpotlightCard variant="violet" />
        </div>

        <div className="relative flex flex-col sm:flex-row sm:items-center justify-between border-b border-[var(--border)] pb-4 gap-4">
          <div>
            <h2 className="text-display-sm flex items-center gap-2">
              <Radio className="w-5 h-5 text-[var(--accent-blue)] animate-pulse" />
              <span>Live Packet Capture Controls</span>
            </h2>
            <p className="text-caption text-[var(--text-muted)] mt-1">
              Intercept network frames from local interfaces and classify traffic flows in real-time.
            </p>
          </div>
          <div className="flex items-center gap-3">
            <StatusBadge status={isCapturing ? 'running' : 'idle'} label={isCapturing ? 'Capturing' : 'Idle'} />
          </div>
        </div>
      </div>

      {captureError && (
        <div className="bg-[var(--accent-red-soft)] border border-[var(--accent-red)]/30 text-[var(--accent-red)] px-4 py-3 rounded-lg flex items-center gap-3 animate-fade-in">
          <ShieldAlert className="w-5 h-5 flex-shrink-0 animate-bounce" />
          <div className="text-caption">
            <span className="font-semibold">Capture Action Failed:</span> {captureError}
          </div>
        </div>
      )}

      {/* Control Dashboard Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        <div className="lg:col-span-3 space-y-4">
          <div className="dpi-card space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div className="flex items-center gap-3 flex-1 min-w-[200px]">
                <div className="flex flex-col gap-1 w-full">
                  <label className="text-caption text-[var(--text-muted)]">Interface Selection</label>
                  <select
                    disabled={isCapturing}
                    value={selectedIface}
                    onChange={(e) => setSelectedIface(e.target.value)}
                    className="w-full h-9 px-3 rounded-md text-body-sm outline-none transition-colors border border-[var(--border)] bg-[var(--panel-soft)] text-[var(--text)] focus:border-[var(--border-strong)] disabled:opacity-50"
                  >
                    <option value="">Scapy Default (Auto-detect)</option>
                    {interfaces.map((i) => (
                      <option key={i.name} value={i.name}>
                        {i.name}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              {/* Start Stop Button Row */}
              <div className="flex items-end gap-2.5 pt-4 sm:pt-0">
                {!isCapturing ? (
                  <button
                    onClick={handleStartCapture}
                    disabled={isCaptureActionLoading || !isConnected}
                    className="btn-primary flex-shrink-0"
                  >
                    <Play className="w-3.5 h-3.5 fill-current" />
                    <span>Start Capture</span>
                  </button>
                ) : (
                  <button
                    onClick={handleStopCapture}
                    disabled={isCaptureActionLoading}
                    className="btn-primary bg-[var(--accent-red)]! text-white! hover:bg-red-600! flex-shrink-0"
                  >
                    <Square className="w-3.5 h-3.5 fill-current" />
                    <span>Stop Capture</span>
                  </button>
                )}

                <button
                  onClick={() => setShowConfig(!showConfig)}
                  className={cn(
                    "btn-secondary rounded-full w-10 h-10 p-0 flex items-center justify-center flex-shrink-0",
                    showConfig && "border-[var(--accent-blue)]! text-[var(--accent-blue)]!"
                  )}
                  title="Configure Capture Options"
                >
                  <Settings2 className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Advanced configurations collapsible */}
            {showConfig && (
              <div className="pt-4 border-t border-[var(--border)] grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 animate-fade-in">
                <div className="flex flex-col gap-1.5">
                  <label className="text-caption text-[var(--text-secondary)] font-medium">
                    BPF Filter (e.g. tcp port 80)
                  </label>
                  <input
                    type="text"
                    disabled={isCapturing}
                    value={bpfFilter}
                    onChange={(e) => setBpfFilter(e.target.value)}
                    placeholder="None"
                    className="h-9 px-3 rounded-md text-body-sm outline-none transition-colors border border-[var(--border)] bg-[var(--panel-soft)] text-[var(--text)] focus:border-[var(--border-strong)] disabled:opacity-50"
                  />
                </div>
                <div className="flex flex-col gap-1.5">
                  <label className="text-caption text-[var(--text-secondary)] font-medium">
                    Limit Frame Count (0=Unlimited)
                  </label>
                  <input
                    type="number"
                    disabled={isCapturing}
                    value={packetLimit}
                    onChange={(e) => setPacketLimit(parseInt(e.target.value) || 0)}
                    className="h-9 px-3 rounded-md text-body-sm outline-none transition-colors border border-[var(--border)] bg-[var(--panel-soft)] text-[var(--text)] focus:border-[var(--border-strong)] disabled:opacity-50"
                  />
                </div>
                <div className="flex flex-col gap-1.5">
                  <label className="text-caption text-[var(--text-secondary)] font-medium">
                    Limit Capture Duration (s, 0=None)
                  </label>
                  <input
                    type="number"
                    disabled={isCapturing}
                    value={durationLimit}
                    onChange={(e) => setDurationLimit(parseInt(e.target.value) || 0)}
                    className="h-9 px-3 rounded-md text-body-sm outline-none transition-colors border border-[var(--border)] bg-[var(--panel-soft)] text-[var(--text)] focus:border-[var(--border-strong)] disabled:opacity-50"
                  />
                </div>
                <div className="flex flex-col gap-1.5">
                  <label className="text-caption text-[var(--text-secondary)] font-medium">
                    Output PCAP Filename
                  </label>
                  <input
                    type="text"
                    disabled={isCapturing}
                    value={outputFile}
                    onChange={(e) => setOutputFile(e.target.value)}
                    className="h-9 px-3 rounded-md text-body-sm outline-none transition-colors border border-[var(--border)] bg-[var(--panel-soft)] text-[var(--text)] focus:border-[var(--border-strong)] disabled:opacity-50"
                  />
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Captured mini-stats side panel */}
        <div className="lg:col-span-1">
          <div className="dpi-card h-full flex flex-col justify-center gap-3">
            <div className="text-caption text-[var(--text-muted)] uppercase font-mono tracking-wider font-semibold">
              Live Session Metrics
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-0.5">
                <div className="text-caption text-[var(--text-muted)]">Frames Intercepted</div>
                <div className="text-display-sm font-mono text-[var(--text)]">
                  {stats?.total_packets?.toLocaleString() ?? 0}
                </div>
              </div>
              <div className="space-y-0.5">
                <div className="text-caption text-[var(--text-muted)]">Data Volume</div>
                <div className="text-display-sm font-mono text-[var(--text)]">
                  {formatBytes(stats?.total_bytes ?? 0)}
                </div>
              </div>
              <div className="space-y-0.5">
                <div className="text-caption text-[var(--text-muted)]">Elapsed Capture</div>
                <div className="text-display-sm font-mono text-[var(--text)]">
                  {formatDuration(stats?.elapsed ?? 0)}
                </div>
              </div>
              <div className="space-y-0.5">
                <div className="text-caption text-[var(--text-muted)]">Drop Rate</div>
                <div className="text-display-sm font-mono text-[var(--accent-red)]">
                  {(stats?.drop_rate ?? 0).toFixed(1)}%
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Virtualized live packet feed */}
      <div className="space-y-3">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="text-body-sm font-semibold text-[var(--text)] flex items-center gap-1.5">
            <ArrowDownWideNarrow className="w-4 h-4 text-[var(--accent-blue)]" />
            <span>Captured Frame Stream ({filteredPackets.length})</span>
          </div>

          <div className="flex gap-2 w-full sm:w-auto">
            {/* Search filter bar */}
            <div className="relative flex-1 sm:w-64">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[var(--text-muted)]" />
              <input
                type="text"
                value={filterQuery}
                onChange={(e) => setFilterQuery(e.target.value)}
                placeholder="Search Src, Dst, Protocol, App..."
                className="w-full pl-8 pr-3 py-1.5 rounded-md text-caption outline-none transition-colors border border-[var(--border)] bg-[var(--panel-soft)] text-[var(--text)] focus:border-[var(--border-strong)]"
              />
            </div>

            <button
              onClick={handleExportCSV}
              disabled={filteredPackets.length === 0}
              className="flex items-center gap-1 px-3 py-1.5 rounded-md text-caption font-medium border border-[var(--border)] bg-[var(--panel-soft)] hover:bg-[var(--panel-hover)] text-[var(--text-secondary)] transition-colors cursor-pointer disabled:opacity-50"
            >
              <FileDown className="w-3.5 h-3.5" />
              <span className="hidden md:inline">Export CSV</span>
            </button>
          </div>
        </div>

        <DataTable
          data={filteredPackets}
          columns={columns}
          rowKey={(p) => p.id}
          actionField={(p) => p.action}
          height="450px"
        />
      </div>
    </div>
  );
}
