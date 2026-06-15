'use client';

import { useState, useRef, useEffect } from 'react';
import { 
  Shield, 
  Play, 
  AlertTriangle,
  Zap,
  Workflow,
  BookOpen,
  Activity,
  Info
} from 'lucide-react';
import { playClickSound, playBurstSound, cn } from '@/lib/utils';

interface IntroOverlayProps {
  onEnter: () => void;
}

type IntroTab = 'overview' | 'architecture' | 'benchmarks';

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

const PIPELINE_NODES = [
  { label: 'Packets', desc: 'Raw Ethernet/Loopback interface frames', badge: 'Ingress', color: 'var(--accent-blue)' },
  { label: 'eBPF Fast Path', desc: 'Kernel-level BPF expressions filter', badge: 'Kernel', color: 'var(--accent-cyan)' },
  { label: 'DPI Engine', desc: 'Stateful protocol dissection & flag scan', badge: 'Parser', color: 'var(--accent-violet)' },
  { label: 'ETI Classifier', desc: 'Random Forest AI application signature profiling', badge: 'AI Classifier', color: 'var(--accent-violet)' },
  { label: 'Policy Engine V2', desc: 'Threat intelligence & dynamic enforcer rules check', badge: 'Core Policy', color: 'var(--accent-amber)' },
  { label: 'Alert / Block / Log', desc: 'MITRE ATT&CK tagged threat logs & drop verdicts', badge: 'Verdict', color: 'var(--accent-red)' }
];

export function IntroOverlay({ onEnter }: IntroOverlayProps) {
  const [activeTab, setActiveTab] = useState<IntroTab>('overview');
  const [isBursting, setIsBursting] = useState(false);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const animationFrameId = useRef<number | null>(null);
  const particles = useRef<Particle[]>([]);

  const handleTabChange = (tab: IntroTab) => {
    setActiveTab(tab);
    playClickSound();
  };

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
    
    // Play sound
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

    const rect = button.getBoundingClientRect();
    const btnCenterX = rect.left + rect.width / 2;
    const btnCenterY = rect.top + rect.height / 2;

    const colors = ['#3b82f6', '#a855f7', '#f43f5e', '#06b6d4', '#ffffff'];

    for (let i = 0; i < 75; i++) {
      const angle = Math.random() * Math.PI * 2;
      const speed = 2 + Math.random() * 12;
      particles.current.push({
        x: btnCenterX,
        y: btnCenterY,
        vx: Math.cos(angle) * speed,
        vy: Math.sin(angle) * speed - (1 + Math.random() * 2),
        size: 1.5 + Math.random() * 4,
        color: colors[Math.floor(Math.random() * colors.length)],
        alpha: 1,
        decay: 0.012 + Math.random() * 0.02,
        gravity: 0.12 + Math.random() * 0.08
      });
    }

    let startTime: number | null = null;
    const animate = (timestamp: number) => {
      if (!startTime) startTime = timestamp;
      const elapsed = timestamp - startTime;

      ctx.clearRect(0, 0, canvas.width, canvas.height);

      particles.current.forEach((p) => {
        p.x += p.vx;
        p.y += p.vy;
        p.vy += p.gravity;
        p.vx *= 0.98;
        p.vy *= 0.98;
        p.alpha -= p.decay;
        p.size *= 0.98;

        if (p.alpha > 0 && p.size > 0.1) {
          ctx.save();
          ctx.beginPath();
          ctx.arc(p.x, p.y, p.size * 2.5, 0, Math.PI * 2);
          ctx.fillStyle = p.color;
          ctx.globalAlpha = p.alpha * 0.22;
          ctx.fill();

          ctx.beginPath();
          ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
          ctx.fillStyle = p.color;
          ctx.globalAlpha = p.alpha;
          ctx.fill();
          ctx.restore();
        }
      });

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

    setTimeout(() => {
      if (animationFrameId.current) {
        cancelAnimationFrame(animationFrameId.current);
      }
      onEnter();
    }, 800);
  };

  return (
    <div className={cn(
      "fixed inset-0 z-50 flex items-center justify-center overflow-hidden p-4 select-none transition-all duration-[800ms] ease-out",
      isBursting ? "opacity-0 pointer-events-none scale-[1.02] blur-xs bg-transparent" : "opacity-100 bg-[var(--bg)]"
    )}>
      <canvas ref={canvasRef} className="absolute inset-0 pointer-events-none z-20" />

      {/* Unified Card utilizing internal UI theme */}
      <div className={cn(
        "relative z-10 w-full max-w-[760px] max-h-[95vh] md:max-h-none dpi-card flex flex-col justify-between overflow-hidden shadow-2xl transition-all duration-700",
        isBursting && "scale-95 opacity-0 pointer-events-none blur-md"
      )}>
        
        {/* Console Header */}
        <div className="flex items-center justify-between border-b border-[var(--border)] pb-4 mb-4 flex-shrink-0">
          <div className="flex items-center gap-3">
            <div className="relative flex items-center justify-center flex-shrink-0">
              <span className="absolute w-8 h-8 rounded-full bg-[var(--accent-blue)]/10 animate-pulse" />
              <div className="relative w-8 h-8 rounded-lg flex items-center justify-center bg-[var(--panel-soft)] border border-[var(--border-strong)] shadow-sm z-10">
                <Shield className="w-4.5 h-4.5 text-[var(--accent-blue)]" />
              </div>
            </div>
            <div className="text-left">
              <h1 className="text-[14px] md:text-[15px] font-bold tracking-[2px] text-[var(--text)] uppercase font-sans">
                Deep Packet Inspection Console
              </h1>
              <p className="text-[9px] text-[var(--text-muted)] font-mono uppercase tracking-[1.5px] font-semibold mt-0.5">
                Verdict Shield Platform v2.0 • Operator Deck
              </p>
            </div>
          </div>
          <span className="hidden sm:inline-block text-[9px] font-mono px-2 py-0.5 rounded border border-[var(--border-strong)] bg-[var(--panel-soft)] text-[var(--text-muted)]">
            SECURE ENVIRONMENT
          </span>
        </div>

        {/* Minimal Underlined Navigation Tabs */}
        <div className="flex border-b border-[var(--border)] gap-6 mb-4 select-none flex-shrink-0">
          {(['overview', 'architecture', 'benchmarks'] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => handleTabChange(tab)}
              className={cn(
                "pb-2.5 text-caption font-semibold border-b-2 transition-all cursor-pointer whitespace-nowrap text-[12.5px] relative",
                activeTab === tab
                  ? "border-[var(--accent-blue)] text-[var(--text)]"
                  : "border-transparent text-[var(--text-secondary)] hover:text-[var(--text)] opacity-60 hover:opacity-100"
              )}
            >
              {tab === 'overview' && 'System Overview'}
              {tab === 'architecture' && 'Pipeline & Stack'}
              {tab === 'benchmarks' && 'Metrics & Limits'}
            </button>
          ))}
        </div>

        {/* Console Content Area */}
        <div className="h-[280px] sm:h-[300px] md:h-[320px] overflow-y-auto scrollbar-thin pr-1.5 my-1 space-y-4">
          
          {activeTab === 'overview' && (
            <div className="space-y-4 animate-fade-in text-[13px]">
              {/* One-liner Hook */}
              <div className="p-3.5 rounded-lg border-l-[3px] border-[var(--accent-blue)] bg-[var(--panel-soft)] text-left relative overflow-hidden">
                <div className="absolute top-0 right-0 w-24 h-24 bg-[var(--accent-blue)]/5 rounded-full blur-xl -mr-6 -mt-6 pointer-events-none" />
                <p className="text-[13px] font-medium tracking-tight text-[var(--text)] leading-relaxed italic opacity-95">
                  "A kernel-aware, ML-augmented network security platform that classifies encrypted traffic without decryption."
                </p>
              </div>

              {/* Differentiators list */}
              <div className="space-y-3">
                <h3 className="text-[10px] font-bold text-[var(--accent-blue)] uppercase font-mono tracking-wider">
                  Core capabilities (vs Wireshark / Suricata)
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div className="flex items-start gap-2.5">
                    <div className="w-4 h-4 rounded-full bg-[var(--panel-soft)] border border-[var(--border)] flex items-center justify-center flex-shrink-0 mt-0.5">
                      <Zap className="w-2.5 h-2.5 text-[var(--accent-blue)]" />
                    </div>
                    <p className="text-[var(--text-secondary)] leading-normal text-[12px]">
                      <strong>Behavioral C2 Analysis:</strong> Identifies encrypted command & control botnet traffic dynamically without decryption.
                    </p>
                  </div>
                  <div className="flex items-start gap-2.5">
                    <div className="w-4 h-4 rounded-full bg-[var(--panel-soft)] border border-[var(--border)] flex items-center justify-center flex-shrink-0 mt-0.5">
                      <Zap className="w-2.5 h-2.5 text-[var(--accent-blue)]" />
                    </div>
                    <p className="text-[var(--text-secondary)] leading-normal text-[12px]">
                      <strong>JA3/JA4 Fingerprints:</strong> Inspects TLS handshake profiles using Salesforce & Cloudflare style GREASE filters.
                    </p>
                  </div>
                  <div className="flex items-start gap-2.5">
                    <div className="w-4 h-4 rounded-full bg-[var(--panel-soft)] border border-[var(--border)] flex items-center justify-center flex-shrink-0 mt-0.5">
                      <Zap className="w-2.5 h-2.5 text-[var(--accent-blue)]" />
                    </div>
                    <p className="text-[var(--text-secondary)] leading-normal text-[12px]">
                      <strong>MITRE ATT&CK Tagging:</strong> Feeds alerts mapped to threat matrices (T1071 C2, T1046 Scan, T1498 DDoS).
                    </p>
                  </div>
                  <div className="flex items-start gap-2.5">
                    <div className="w-4 h-4 rounded-full bg-[var(--panel-soft)] border border-[var(--border)] flex items-center justify-center flex-shrink-0 mt-0.5">
                      <Zap className="w-2.5 h-2.5 text-[var(--accent-blue)]" />
                    </div>
                    <p className="text-[var(--text-secondary)] leading-normal text-[12px]">
                      <strong>RFC 7011 IPFIX Stream:</strong> Exports standard flow data directly into Splunk, Elastic, or QRadar.
                    </p>
                  </div>
                </div>
              </div>

              {/* Inspired By references */}
              <div className="pt-3 border-t border-[var(--border)] flex items-center justify-between text-[10px] text-[var(--text-muted)] font-mono">
                <span>Inspired by:</span>
                <span className="font-semibold text-[var(--text-secondary)]">
                  Zeek · Suricata · Cloudflare Gateway · Cisco ETA
                </span>
              </div>
            </div>
          )}

          {activeTab === 'architecture' && (
            <div className="space-y-4 animate-fade-in text-[13px]">
              {/* High-fidelity visual pipeline timeline list */}
              <div className="space-y-2.5">
                <h3 className="text-[10px] font-bold text-[var(--accent-cyan)] uppercase font-mono tracking-wider">
                  Pipeline Execution Steps
                </h3>
                
                <div className="space-y-0">
                  {PIPELINE_NODES.map((node, idx) => (
                    <div key={idx} className="flex flex-col">
                      <div className="flex items-center gap-3">
                        <div 
                          className="w-7 h-7 rounded-lg flex items-center justify-center font-mono font-bold text-[11px] border flex-shrink-0 z-10"
                          style={{ 
                            borderColor: `${node.color}33`, 
                            backgroundColor: `${node.color}11`, 
                            color: node.color 
                          }}
                        >
                          {idx + 1}
                        </div>
                        
                        <div className="flex-1 min-w-0 p-2.5 rounded-lg border border-[var(--border)] bg-[var(--panel-soft)] flex items-center justify-between gap-4 hover:border-[var(--border-strong)] transition-all">
                          <div className="min-w-0">
                            <span className="font-semibold text-[var(--text)] text-[12px] block truncate">{node.label}</span>
                            <span className="text-[11px] text-[var(--text-muted)] block truncate">{node.desc}</span>
                          </div>
                          <span 
                            className="px-2 py-0.5 rounded text-[9px] font-mono font-bold uppercase tracking-wider border flex-shrink-0"
                            style={{
                              borderColor: `${node.color}33`,
                              backgroundColor: `${node.color}11`,
                              color: node.color
                            }}
                          >
                            {node.badge}
                          </span>
                        </div>
                      </div>
                      {idx < PIPELINE_NODES.length - 1 && (
                        <div className="w-7 flex justify-center py-1 flex-shrink-0">
                          <div className="w-0.5 h-4 border-l-2 border-dotted border-[var(--border-strong)] opacity-40" />
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* Technology Stack chips */}
              <div className="space-y-2.5">
                <h3 className="text-[10px] font-bold text-[var(--accent-cyan)] uppercase font-mono tracking-wider">
                  Engine tech stack
                </h3>
                <div className="flex flex-wrap gap-2 select-none">
                  {[
                    'Python', 'eBPF/XDP', 'FastAPI', 'Redis', 
                    'ONNX Runtime', 'MaxMind GeoIP', 'OpenTelemetry', 
                    'Next.js', 'Docker', 'Scapy'
                  ].map((tech) => (
                    <span 
                      key={tech} 
                      className="px-2.5 py-1 text-[11px] font-mono font-semibold rounded border border-[var(--border)] bg-[var(--panel-soft)] text-[var(--text-secondary)] shadow-sm hover:border-[var(--border-strong)] hover:text-[var(--text)] transition-all duration-350 cursor-default"
                    >
                      {tech}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          )}

          {activeTab === 'benchmarks' && (
            <div className="space-y-4 animate-fade-in text-[13px]">
              {/* Benchmark Numbers Bento Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 select-none">
                <div className="p-3 rounded-lg border border-[var(--border)] bg-[var(--panel-soft)] text-center space-y-0.5">
                  <span className="text-[9px] text-[var(--text-muted)] block uppercase tracking-wider font-mono">Throughput</span>
                  <span className="text-[15px] font-mono font-bold text-[var(--text)]">4,800+ pps</span>
                </div>
                <div className="p-3 rounded-lg border border-[var(--border)] bg-[var(--panel-soft)] text-center space-y-0.5">
                  <span className="text-[9px] text-[var(--text-muted)] block uppercase tracking-wider font-mono">ETI Inference</span>
                  <span className="text-[15px] font-mono font-bold text-[var(--text)]">&lt;10ms</span>
                </div>
                <div className="p-3 rounded-lg border border-[var(--border)] bg-[var(--panel-soft)] text-center space-y-0.5">
                  <span className="text-[9px] text-[var(--text-muted)] block uppercase tracking-wider font-mono">TLS Tracking</span>
                  <span className="text-[15px] font-mono font-bold text-[var(--text)]">100% flows</span>
                </div>
                <div className="p-3 rounded-lg border border-[var(--border)] bg-[var(--panel-soft)] text-center space-y-0.5">
                  <span className="text-[9px] text-[var(--text-muted)] block uppercase tracking-wider font-mono">Threat Maps</span>
                  <span className="text-[15px] font-mono font-bold text-[var(--text)]">6 Techniques</span>
                </div>
              </div>

              {/* Limitations & Known Tradeoffs */}
              <div className="p-3.5 rounded-lg border border-[var(--border)] bg-[var(--panel-soft)] space-y-2.5">
                <h3 className="text-[10px] font-bold text-[var(--accent-red)] uppercase font-mono tracking-wider flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 text-[var(--accent-red)]" />
                  <span>Limitations & Tradeoffs</span>
                </h3>
                <div className="space-y-2 text-[11.5px] leading-relaxed">
                  <div className="flex items-start gap-2">
                    <span className="text-[var(--accent-red)] font-bold font-mono">→</span>
                    <p className="text-[var(--text-secondary)]">
                      <strong>eBPF Platform bounds:</strong> BPF fast path hooks are Linux-only. Windows deployment operates under Scapy loop fallback mode.
                    </p>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="text-[var(--accent-red)] font-bold font-mono">→</span>
                    <p className="text-[var(--text-secondary)]">
                      <strong>Model Training Bias:</strong> ETI Random Forest is trained on synthetic traces. CICIDS dataset integration is currently W.I.P.
                    </p>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="text-[var(--accent-red)] font-bold font-mono">→</span>
                    <p className="text-[var(--text-secondary)]">
                      <strong>HPACK Decoder Range:</strong> Decodes static header indexes only. Live dynamic session state updates are unsupported.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}

        </div>

        {/* Footer & Shimmer Enter Button */}
        <div className="border-t border-[var(--border)] pt-4 flex flex-col sm:flex-row items-center justify-between gap-3 mt-2 flex-shrink-0">
          <div className="flex items-center gap-1.5 text-[10px] text-[var(--text-muted)] font-mono">
            <Info className="w-3.5 h-3.5 text-[var(--accent-blue)]" />
            <span>Authorized Operators Only • Npcap driver required</span>
          </div>
          
          <button
            ref={buttonRef}
            onClick={handleEnterClick}
            disabled={isBursting}
            className={cn(
              "btn-primary flex-shrink-0 cursor-pointer w-full sm:w-auto relative overflow-hidden transition-all duration-300 hover:opacity-90 active:scale-95 flex items-center justify-center gap-2",
              isBursting && "scale-75 opacity-0 pointer-events-none blur-sm"
            )}
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>Initialize Console</span>
          </button>
        </div>

      </div>
    </div>
  );
}
