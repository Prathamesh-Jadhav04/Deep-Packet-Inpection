import { type ClassValue, clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

export function formatNumber(num: number): string {
  if (num >= 1_000_000) return `${(num / 1_000_000).toFixed(1)}M`;
  if (num >= 1_000) return `${(num / 1_000).toFixed(1)}K`;
  return num.toLocaleString();
}

export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.floor(seconds % 60)}s`;
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return `${h}h ${m}m`;
}

export function formatPps(pps: number): string {
  if (pps >= 1_000_000) return `${(pps / 1_000_000).toFixed(1)}M pps`;
  if (pps >= 1_000) return `${(pps / 1_000).toFixed(1)}K pps`;
  return `${Math.round(pps)} pps`;
}

export function formatMbps(bytes: number, seconds: number): string {
  if (seconds <= 0) return '0 Mbps';
  const mbps = (bytes * 8) / (seconds * 1_000_000);
  return `${mbps.toFixed(2)} Mbps`;
}

export function parseIpPort(ipPort: string): { ip: string; port: number } {
  const lastColon = ipPort.lastIndexOf(':');
  return {
    ip: ipPort.substring(0, lastColon),
    port: parseInt(ipPort.substring(lastColon + 1), 10),
  };
}

export function generateFlowId(src: string, dst: string, protocol: string): string {
  return `${src}-${dst}-${protocol}`;
}
