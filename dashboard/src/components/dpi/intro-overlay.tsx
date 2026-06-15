'use client';

import { useState, useRef, useEffect } from 'react';
import { 
  Shield, 
  Cpu, 
  Network, 
  Layers, 
  Terminal, 
  Info, 
  ShieldAlert, 
  Volume2, 
  Play, 
  CheckCircle,
  HelpCircle,
  AlertTriangle,
  BookOpen
} from 'lucide-react';
import { playClickSound, playBurstSound, cn } from '@/lib/utils';

interface IntroOverlayProps {
  onEnter: () => void;
}

type IntroTab = 'overview' | 'features' | 'advanced' | 'limitations';

interface Particle {
  x: number;
  y: number;
  vx: number;
  vy: number;
  size: number;
  color: string;
  alpha: number;
  decay: number;
  gravity: number;
}

export function IntroOverlay({ onEnter }: IntroOverlayProps) {
  const [activeTab, setActiveTab] = useState<IntroTab>('overview');
  const [isBursting, setIsBursting] = useState(false);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const animationFrameId = useRef<number | null>(null);
  const particles = useRef<Particle[]>([]);
  const revealRadius = useRef(0);
  const maxRevealRadius = useRef(0);

  const handleTabChange = (tab: IntroTab) => {
    setActiveTab(tab);
    playClickSound();
  };

  // Resize canvas to full screen
  useEffect(() => {
    const handleResize = () => {
      if (canvasRef.current) {
        canvasRef.current.width = window.innerWidth;
        canvasRef.current.height = window.innerHeight;
      }
    };
    window.addEventListener('resize', handleResize);
    handleResize();
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  const handleEnterClick = () => {
    if (isBursting) return;
    setIsBursting(true);
    
    // Play the synthesized cyber-burst sound
    playBurstSound();

    const canvas = canvasRef.current;
    const button = buttonRef.current;
    if (!canvas || !button) {
      onEnter();
      return;
    }

    const ctx = canvas.getContext('2d');
    if (!ctx) {
      onEnter();
      return;
    }

    // Get button position
    const rect = button.getBoundingClientRect();
    const btnCenterX = rect.left + rect.width / 2;
    const btnCenterY = rect.top + rect.height / 2;

    // Calculate maximum reveal radius to cover the entire screen from the button center
    const corners = [
      { x: 0, y: 0 },
      { x: window.innerWidth, y: 0 },
      { x: 0, y: window.innerHeight },
      { x: window.innerWidth, y: window.innerHeight }
    ];
    let maxDist = 0;
    corners.forEach(c => {
      const dist = Math.sqrt(Math.pow(c.x - btnCenterX, 2) + Math.pow(c.y - btnCenterY, 2));
      if (dist > maxDist) maxDist = dist;
    });
    maxRevealRadius.current = maxDist + 100; // Extra buffer

    // Generate particles
    const colors = [
      '#3b82f6', // blue
      '#a855f7', // violet
      '#f43f5e', // red
      '#06b6d4', // cyan
      '#ffffff'  // white
    ];

    for (let i = 0; i < 75; i++) {
      const angle = Math.random() * Math.PI * 2;
      const speed = 2 + Math.random() * 12;
      particles.current.push({
        x: btnCenterX,
        y: btnCenterY,
        vx: Math.cos(angle) * speed,
        vy: Math.sin(angle) * speed - (1 + Math.random() * 2), // slight upward bias
        size: 1.5 + Math.random() * 4,
        color: colors[Math.floor(Math.random() * colors.length)],
        alpha: 1,
        decay: 0.012 + Math.random() * 0.02,
        gravity: 0.12 + Math.random() * 0.08
      });
    }

    // Particle/Reveal animation loop
    let startTime: number | null = null;
    const animate = (timestamp: number) => {
      if (!startTime) startTime = timestamp;
      const elapsed = timestamp - startTime;

      ctx.clearRect(0, 0, canvas.width, canvas.height);

      // Update and draw particles
      particles.current.forEach((p, idx) => {
        p.x += p.vx;
        p.y += p.vy;
        p.vy += p.gravity; // apply gravity
        p.vx *= 0.98;      // air resistance
        p.vy *= 0.98;
        p.alpha -= p.decay;
        p.size *= 0.98;

        if (p.alpha > 0 && p.size > 0.1) {
          ctx.save();
          
          // Soft outer glow circle (highly efficient double-pass glow)
          ctx.beginPath();
          ctx.arc(p.x, p.y, p.size * 2.5, 0, Math.PI * 2);
          ctx.fillStyle = p.color;
          ctx.globalAlpha = p.alpha * 0.22;
          ctx.fill();

          // Bright inner core
          ctx.beginPath();
          ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
          ctx.fillStyle = p.color;
          ctx.globalAlpha = p.alpha;
          ctx.fill();
          
          ctx.restore();
        }
      });

      // Draw shockwave rings
      if (elapsed < 600) {
        ctx.save();
        ctx.beginPath();
        const shockRadius = (elapsed / 600) * 250;
        ctx.arc(btnCenterX, btnCenterY, shockRadius, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(59, 130, 246, ${1 - elapsed / 600})`;
        ctx.lineWidth = 3;
        ctx.stroke();
        ctx.restore();
      }

      animationFrameId.current = requestAnimationFrame(animate);
    };

    animationFrameId.current = requestAnimationFrame(animate);

    // Fade out overlay and unmount after 800ms transition completes
    setTimeout(() => {
      if (animationFrameId.current) {
        cancelAnimationFrame(animationFrameId.current);
      }
      onEnter();
    }, 800);
  };

  // Cleanup animations on unmount
  useEffect(() => {
    return () => {
      if (animationFrameId.current) {
        cancelAnimationFrame(animationFrameId.current);
      }
    };
  }, []);

  return (
    <div className={cn(
      "fixed inset-0 z-50 flex items-center justify-center overflow-hidden p-4 select-none transition-all duration-[800ms] ease-out",
      isBursting ? "opacity-0 pointer-events-none scale-[1.02] blur-xs" : "opacity-100 bg-[#0a0a0a]"
    )}>
      {/* Background canvas for the explosion and reveal wipe */}
      <canvas 
        ref={canvasRef} 
        className="absolute inset-0 pointer-events-none z-20"
      />

      <div className={cn(
        "relative z-10 w-full max-w-[850px] max-h-[95vh] md:max-h-none bg-[var(--panel)] border border-[var(--border-strong)] rounded-2xl shadow-2xl flex flex-col md:flex-row overflow-hidden transition-all duration-700",
        isBursting && "scale-95 opacity-0 pointer-events-none blur-md"
      )}>
        
        {/* Left Side: App Intro Banner */}
        <div className="w-full md:w-[280px] bg-linear-to-b from-[var(--bg-soft)] to-[var(--panel-soft)] border-b md:border-b-0 md:border-r border-[var(--border)] p-5 md:p-6 flex md:flex-col justify-between flex-shrink-0 items-center md:items-start gap-4">
          <div className="flex md:flex-col items-center md:items-start gap-3 flex-1 md:flex-none">
            <div className="w-10 h-10 md:w-12 md:h-12 rounded-xl flex items-center justify-center bg-[var(--accent-blue-soft)] border border-[var(--accent-blue)]/20 shadow-[0_0_15px_var(--accent-blue-soft)] flex-shrink-0">
              <Shield className="w-5 h-5 md:w-6 md:h-6 text-[var(--accent-blue)] animate-pulse" />
            </div>
            <div className="space-y-0.5 text-left">
              <h1 className="text-[18px] md:text-[20px] font-bold tracking-tight text-[var(--text)]">DPI Engine</h1>
              <p className="text-[9px] md:text-caption text-[var(--text-muted)] font-mono uppercase tracking-wider">
                Verdict Shield v2.0
              </p>
            </div>
          </div>
          <p className="hidden md:block text-[12px] text-[var(--text-secondary)] leading-relaxed">
            Unlock a granular window into loopback socket streams, classifying web flows with machine learning models and implementing hardware-level packet drop verdicts.
          </p>
          <div className="hidden md:flex pt-6 border-t border-[var(--border-subtle)] text-[10px] text-[var(--text-muted)] font-mono items-center gap-1.5 w-full">
            <Info className="w-3.5 h-3.5 text-[var(--accent-blue)] flex-shrink-0" />
            <span>Developer Sandbox Environment</span>
          </div>
        </div>

        {/* Right Side: Interactive Walkthrough and Enter Button */}
        <div className="flex-1 flex flex-col justify-between p-5 md:p-6 h-[400px] sm:h-[450px] md:h-[500px]">
          {/* Header Subtabs */}
          <div className="flex border-b border-[var(--border-subtle)] gap-4 pb-0.5 overflow-x-auto scrollbar-none">
            {(['overview', 'features', 'advanced', 'limitations'] as const).map((tab) => (
              <button
                key={tab}
                onClick={() => handleTabChange(tab)}
                className={cn(
                  "pb-2 text-caption font-semibold border-b-2 transition-all cursor-pointer whitespace-nowrap text-[12px] md:text-caption",
                  activeTab === tab
                    ? "border-[var(--accent-blue)] text-[var(--text)]"
                    : "border-transparent text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
                )}
              >
                {tab === 'overview' && 'Overview'}
                {tab === 'features' && 'Feature Guide'}
                {tab === 'advanced' && 'Advanced Specs'}
                {tab === 'limitations' && 'Limitations'}
              </button>
            ))}
          </div>

          {/* Scrollable Content Area */}
          <div className="flex-1 overflow-y-auto scrollbar-thin my-4 pr-1.5 space-y-4">
            
            {activeTab === 'overview' && (
              <div className="space-y-3.5 animate-fade-in text-[13px]">
                <div className="flex items-start gap-2.5">
                  <BookOpen className="w-4 h-4 text-[var(--accent-blue)] flex-shrink-0 mt-0.5" />
                  <div className="space-y-1">
                    <span className="font-semibold text-[var(--text)]">Core Purpose</span>
                    <p className="text-[var(--text-secondary)] leading-relaxed">
                      Designed as an inspection portal for network operators. It establishes kernel-level bridges to sniff raw interface adapters, reconstructing frames into stateful bidirectional flow streams.
                    </p>
                  </div>
                </div>

                <div className="flex items-start gap-2.5">
                  <CheckCircle className="w-4 h-4 text-[var(--accent-green)] flex-shrink-0 mt-0.5" />
                  <div className="space-y-1">
                    <span className="font-semibold text-[var(--text)]">Telemetry Feedback Loop</span>
                    <p className="text-[var(--text-secondary)] leading-relaxed">
                      Packets are analyzed, scored via a classifier model, and checked against drop rules. If a drop matches, execution fires drop instructions, reflecting in dashboard charts immediately.
                    </p>
                  </div>
                </div>

                <div className="bg-[var(--panel-soft)] p-3 rounded-lg border border-[var(--border)] text-[12px] text-[var(--text-secondary)] mt-2">
                  <span className="font-semibold text-[var(--text)] block mb-1">How it Operates:</span>
                  1. Sniffs raw Ethernet/Loopback adapters.<br />
                  2. Feeds statistics to Random Forest classification matrices.<br />
                  3. Drops packets fitting block rules, updating UI verdict metrics.
                </div>
              </div>
            )}

            {activeTab === 'features' && (
              <div className="space-y-3.5 animate-fade-in text-[13px]">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div className="p-2.5 rounded-lg border border-[var(--border)] bg-[var(--panel-soft)] space-y-1">
                    <span className="font-semibold text-[var(--text)] block text-[12px]">1. Overview Page</span>
                    <p className="text-[11px] text-[var(--text-secondary)] leading-normal">
                      Provides rolling bandwidth charts (Mbps), packets-per-second, and thread load distributions.
                    </p>
                  </div>
                  <div className="p-2.5 rounded-lg border border-[var(--border)] bg-[var(--panel-soft)] space-y-1">
                    <span className="font-semibold text-[var(--text)] block text-[12px]">2. Live Capture</span>
                    <p className="text-[11px] text-[var(--text-secondary)] leading-normal">
                      Hooks to interfaces (WiFi/Ethernet) to write log tables and stream raw hex outputs.
                    </p>
                  </div>
                  <div className="p-2.5 rounded-lg border border-[var(--border)] bg-[var(--panel-soft)] space-y-1">
                    <span className="font-semibold text-[var(--text)] block text-[12px]">3. Blocking Rules</span>
                    <p className="text-[11px] text-[var(--text-secondary)] leading-normal">
                      Blacklist enforcer panel. Block traffic by specific IP, Domain SNI patterns, or Application tags.
                    </p>
                  </div>
                  <div className="p-2.5 rounded-lg border border-[var(--border)] bg-[var(--panel-soft)] space-y-1">
                    <span className="font-semibold text-[var(--text)] block text-[12px]">4. Traffic Analytics</span>
                    <p className="text-[11px] text-[var(--text-secondary)] leading-normal">
                      Presents Top Talkers traffic bandwidth, Radial Layer 4 transport divisions, and SNI domain logs.
                    </p>
                  </div>
                </div>

                <div className="p-2.5 rounded-lg border border-[var(--border)] bg-[var(--panel-soft)] space-y-1">
                  <span className="font-semibold text-[var(--text)] block text-[12px]">5. Flow Inspector</span>
                  <p className="text-[11px] text-[var(--text-secondary)] leading-normal">
                    Inspects aggregated 5-tuple conversations containing first/last active timestamps, TLS client hello JA3/JA4 fingerprints, and deep payload hex streams.
                  </p>
                </div>
              </div>
            )}

            {activeTab === 'advanced' && (
              <div className="space-y-3.5 animate-fade-in text-[13px]">
                <div className="flex items-start gap-2.5">
                  <Cpu className="w-4 h-4 text-[var(--accent-violet)] flex-shrink-0 mt-0.5" />
                  <div className="space-y-1">
                    <span className="font-semibold text-[var(--text)]">Machine Learning Classification</span>
                    <p className="text-[var(--text-secondary)] leading-relaxed text-[12px]">
                      Features an embedded **Random Forest Classifier** that evaluates packet sizes, variations, and inter-arrival timing signatures to output app tags (Google, Netflix, YouTube) without parsing encrypted payload bodies.
                    </p>
                  </div>
                </div>

                <div className="flex items-start gap-2.5">
                  <Layers className="w-4 h-4 text-[var(--accent-cyan)] flex-shrink-0 mt-0.5" />
                  <div className="space-y-1">
                    <span className="font-semibold text-[var(--text)]">Multi-Threaded Ring Buffer</span>
                    <p className="text-[var(--text-secondary)] leading-relaxed text-[12px]">
                      Implements a circular producer-consumer ring buffer layout. Decouples raw interface sniffer interrupts from heavier statistical parsing threads, reducing queue bottlenecks.
                    </p>
                  </div>
                </div>

                <div className="flex items-start gap-2.5">
                  <Terminal className="w-4 h-4 text-[var(--accent-blue)] flex-shrink-0 mt-0.5" />
                  <div className="space-y-1">
                    <span className="font-semibold text-[var(--text)]">Stateful Protocol Inspections</span>
                    <p className="text-[var(--text-secondary)] leading-relaxed text-[12px]">
                      Validates TCP flags for anomalies (such as Null and Xmas port scans) and evaluates payload data randomness using Shannon entropy to block DNS tunneling and hidden exfiltration vectors.
                    </p>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'limitations' && (
              <div className="space-y-3.5 animate-fade-in text-[13px]">
                <div className="flex items-start gap-2.5">
                  <CheckCircle className="w-4 h-4 text-[var(--accent-blue)] flex-shrink-0 mt-0.5" />
                  <div className="space-y-1">
                    <span className="font-semibold text-[var(--text)]">Dynamic CPU Safety Shield</span>
                    <p className="text-[var(--text-secondary)] leading-relaxed">
                      To protect system processor cores from heavy capture loops, the backend sniffer applies micro-sleep filters and logs simulated load metrics under stress. This sandbox allows seamless verification without overloading your system.
                    </p>
                  </div>
                </div>

                <div className="flex items-start gap-2.5">
                  <CheckCircle className="w-4 h-4 text-[var(--accent-blue)] flex-shrink-0 mt-0.5" />
                  <div className="space-y-1">
                    <span className="font-semibold text-[var(--text)]">Local Sniffing Boundaries</span>
                    <p className="text-[var(--text-secondary)] leading-relaxed">
                      Captures are bounded strictly to selected local interfaces (Ethernet, Wi-Fi, Loopback). This provides a completely self-contained network sandbox, safeguarding personal privacy.
                    </p>
                  </div>
                </div>

                <div className="flex items-start gap-2.5">
                  <CheckCircle className="w-4 h-4 text-[var(--accent-blue)] flex-shrink-0 mt-0.5" />
                  <div className="space-y-1">
                    <span className="font-semibold text-[var(--text)]">Promiscuous Mode Permissioning</span>
                    <p className="text-[var(--text-secondary)] leading-relaxed">
                      Interacting with raw packet captures requires running the CLI server with administrative privileges (sudo/root) to hook the socket driver correctly.
                    </p>
                  </div>
                </div>
              </div>
            )}

          </div>

          {/* Footer Enter Button */}
          <div className="border-t border-[var(--border-subtle)] pt-4 flex flex-col sm:flex-row items-center justify-between gap-3">
            <span className="text-[10px] md:text-[11px] text-[var(--text-muted)] font-mono">
              Ready to initialize console?
            </span>
            
            <button
              ref={buttonRef}
              onClick={handleEnterClick}
              disabled={isBursting}
              className={cn(
                "relative overflow-hidden cursor-pointer select-none font-semibold text-body-sm px-5 py-2 md:px-6 md:py-2.5 rounded-full border border-[var(--accent-blue)] bg-[var(--accent-blue-soft)] text-[var(--text)] shadow-[0_0_15px_var(--accent-blue-soft)] transition-all duration-300 hover:scale-105 active:scale-95 flex items-center justify-center gap-2 w-full sm:w-auto",
                isBursting && "scale-75 opacity-0 pointer-events-none blur-sm"
              )}
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Initialize Console</span>
            </button>
          </div>
        </div>

      </div>
    </div>
  );
}
