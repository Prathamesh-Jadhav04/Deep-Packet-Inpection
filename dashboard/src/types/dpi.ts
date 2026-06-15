// All types for the DPI Engine Dashboard API

export type EngineStatus = 'idle' | 'running' | 'finished' | 'failed';
export type PacketAction = 'FORWARD' | 'DROP';
export type RuleType = 'ip' | 'app' | 'domain';
export type ThemeMode = 'dark' | 'light' | 'system';

export interface AppCount {
  name: string;
  count: number;
  pct: number;
}

export interface DomainEntry {
  domain: string;
  app: string;
}

export interface ThreadInfo {
  name: string;
  packets: number;
}

export interface PacketEntry {
  id: number;
  time: string;
  src: string;
  dst: string;
  protocol: string;
  app: string;
  domain: string;
  action: PacketAction;
  size: number;
  fp: number;
  ja3: string;
  ja4: string;
  eti: string;
}

export interface RulesSnapshot {
  ips: string[];
  apps: string[];
  domains: string[];
}

export interface AnomalyEntry {
  timestamp: number;
  type: string;
  description: string;
  flow: string;
  app: string;
}

export interface AnalyticsData {
  bandwidth_mbps: number;
  throughput_pps: number;
  top_talkers: Record<string, number>;
  protocol_distribution: Record<string, number>;
  port_matrix: Record<string, number>;
}

export interface DPIStats {
  status: EngineStatus;
  input_file: string;
  output_file: string;
  elapsed: number;
  total_packets: number;
  total_bytes: number;
  forwarded: number;
  dropped: number;
  drop_rate: number;
  tcp_packets: number;
  udp_packets: number;
  apps: AppCount[];
  domains: DomainEntry[];
  lb_threads: ThreadInfo[];
  fp_threads: ThreadInfo[];
  recent_packets: PacketEntry[];
  capture_running?: boolean;
  rules?: RulesSnapshot;
  last_error?: string;
  anomaly_counts?: Record<string, number>;
  recent_anomalies?: AnomalyEntry[];
  analytics?: AnalyticsData;
}

export interface InterfaceInfo {
  name: string;
}

export interface InterfacesResponse {
  ok: boolean;
  interfaces: InterfaceInfo[];
  error: string;
}

export interface RulesResponse {
  ok: boolean;
  rules: RulesSnapshot;
  message?: string;
}

export interface CaptureConfig {
  iface?: string;
  duration?: number;
  count?: number;
  output_file?: string;
  bpf?: string;
}

export interface ApiResponse {
  ok: boolean;
  message: string;
}

// Client-side aggregated flow from recent_packets
export interface FlowRecord {
  id: string; // hash of 5-tuple
  srcIp: string;
  srcPort: number;
  dstIp: string;
  dstPort: number;
  protocol: string;
  app: string;
  domain: string;
  status: 'Active' | 'Closed';
  packets: number;
  bytes: number;
  firstSeen: string;
  lastSeen: string;
  action: PacketAction;
  ja3: string;
  ja4: string;
  eti: string;
}

// Time-series data point for charts
export interface TimeSeriesPoint {
  timestamp: number;
  value: number;
}

export interface AppTimeSeriesPoint {
  timestamp: number;
  [appName: string]: number;
}
