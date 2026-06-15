import { type ClassValue, clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { useDPIStore } from '@/store/dpi-store';

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

let audioCtx: any = null;

export function playClickSound(volume = 0.08) {
  try {
    if (typeof window === 'undefined') return;
    
    // Check global mute state
    if (useDPIStore.getState().isMuted) return;

    const AudioContextClass = window.AudioContext || (window as any).webkitAudioContext;
    if (!AudioContextClass) return;
    
    if (!audioCtx) {
      audioCtx = new AudioContextClass();
    }
    
    if (audioCtx.state === 'suspended') {
      audioCtx.resume();
    }
    
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    
    osc.connect(gain);
    gain.connect(audioCtx.destination);
    
    // Snappy mechanical click synthesis
    osc.type = 'sine';
    osc.frequency.setValueAtTime(1500, audioCtx.currentTime);
    osc.frequency.exponentialRampToValueAtTime(800, audioCtx.currentTime + 0.04);
    
    gain.gain.setValueAtTime(volume, audioCtx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.0001, audioCtx.currentTime + 0.04);
    
    osc.start(audioCtx.currentTime);
    osc.stop(audioCtx.currentTime + 0.04);
  } catch (e) {
    // Fail silently
  }
}

export function playBurstSound() {
  try {
    if (typeof window === 'undefined') return;
    if (useDPIStore.getState().isMuted) return;

    const AudioContextClass = window.AudioContext || (window as any).webkitAudioContext;
    if (!AudioContextClass) return;
    
    if (!audioCtx) {
      audioCtx = new AudioContextClass();
    }
    
    if (audioCtx.state === 'suspended') {
      audioCtx.resume();
    }
    
    const now = audioCtx.currentTime;
    
    // 1. Sub Bass Sweep (sine) - provides physical feel
    const subOsc = audioCtx.createOscillator();
    const subGain = audioCtx.createGain();
    subOsc.type = 'sine';
    subOsc.frequency.setValueAtTime(250, now);
    subOsc.frequency.exponentialRampToValueAtTime(35, now + 0.4);
    subGain.gain.setValueAtTime(0.35, now);
    subGain.gain.exponentialRampToValueAtTime(0.0001, now + 0.5);
    subOsc.connect(subGain);
    subGain.connect(audioCtx.destination);
    subOsc.start(now);
    subOsc.stop(now + 0.5);

    // 2. Mid Impact (triangle) - provides crunchy core
    const midOsc = audioCtx.createOscillator();
    const midGain = audioCtx.createGain();
    midOsc.type = 'triangle';
    midOsc.frequency.setValueAtTime(600, now);
    midOsc.frequency.exponentialRampToValueAtTime(70, now + 0.3);
    midGain.gain.setValueAtTime(0.2, now);
    midGain.gain.exponentialRampToValueAtTime(0.0001, now + 0.35);
    midOsc.connect(midGain);
    midGain.connect(audioCtx.destination);
    midOsc.start(now);
    midOsc.stop(now + 0.35);

    // 3. White Noise Debris/Burst - provides structural blast crackle
    const bufferSize = audioCtx.sampleRate * 1.2; // 1.2s duration
    const buffer = audioCtx.createBuffer(1, bufferSize, audioCtx.sampleRate);
    const data = buffer.getChannelData(0);
    for (let i = 0; i < bufferSize; i++) {
      data[i] = Math.random() * 2 - 1;
    }
    
    const noiseNode = audioCtx.createBufferSource();
    noiseNode.buffer = buffer;
    
    // Filter to sweep noise down (sounds like collapsing pressure)
    const filter = audioCtx.createBiquadFilter();
    filter.type = 'bandpass';
    filter.frequency.setValueAtTime(1200, now);
    filter.frequency.exponentialRampToValueAtTime(130, now + 0.85);
    filter.Q.setValueAtTime(1.8, now);
    
    const noiseGain = audioCtx.createGain();
    noiseGain.gain.setValueAtTime(0.25, now);
    noiseGain.gain.exponentialRampToValueAtTime(0.00001, now + 1.2);
    
    noiseNode.connect(filter);
    filter.connect(noiseGain);
    noiseGain.connect(audioCtx.destination);
    
    noiseNode.start(now);
    noiseNode.stop(now + 1.2);
  } catch (e) {
    // Fail silently
  }
}
