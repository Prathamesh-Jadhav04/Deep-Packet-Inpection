export const API_BASE = process.env.NEXT_PUBLIC_DPI_API_BASE || 'http://127.0.0.1:8765';

export const ENDPOINTS = {
  stats: '/api/stats',
  interfaces: '/api/interfaces',
  rules: '/api/rules',
  liveStart: '/api/live/start',
  liveStop: '/api/live/stop',
} as const;

export const DEFAULT_REFRESH_RATE = 1000;
export const MIN_REFRESH_RATE = 500;
export const MAX_REFRESH_RATE = 5000;

export const APP_TYPES = [
  'Unknown', 'HTTP', 'HTTPS', 'DNS', 'TLS', 'QUIC',
  'Google', 'Facebook', 'YouTube', 'Twitter/X', 'Instagram',
  'Netflix', 'Amazon', 'Microsoft', 'Apple', 'WhatsApp',
  'Telegram', 'TikTok', 'Spotify', 'Zoom', 'Discord',
  'GitHub', 'Cloudflare',
] as const;

export const APP_COLORS: Record<string, string> = {
  Google: '#4285F4',
  YouTube: '#FF0000',
  Facebook: '#1877F2',
  'Twitter/X': '#1DA1F2',
  Instagram: '#E4405F',
  Netflix: '#E50914',
  Amazon: '#FF9900',
  Microsoft: '#00A4EF',
  Apple: '#A2AAAD',
  WhatsApp: '#25D366',
  Telegram: '#0088CC',
  TikTok: '#69C9D0',
  Spotify: '#1DB954',
  Zoom: '#2D8CFF',
  Discord: '#5865F2',
  GitHub: '#6e5494',
  Cloudflare: '#F38020',
  HTTP: '#0070f3',
  HTTPS: '#007cf0',
  DNS: '#50e3c2',
  TLS: '#7928ca',
  QUIC: '#ff0080',
  Unknown: '#888888',
};

export const PROTOCOL_COLORS: Record<string, string> = {
  TCP: '#0070f3',
  UDP: '#7928ca',
  DNS: '#50e3c2',
  QUIC: '#ff0080',
};

export const TAB_NAMES = [
  'Overview',
  'Live Capture',
  'Blocking Rules',
  'Traffic Analytics',
  'Flow Inspector',
  'Settings',
  'About',
] as const;

export const TAB_ICONS = [
  'LayoutDashboard',
  'Radio',
  'Shield',
  'BarChart3',
  'Search',
  'Settings',
  'Info',
] as const;
