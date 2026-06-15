'use client';

import { useState } from 'react';
import { 
  Shield, 
  Cpu, 
  Network, 
  Layers, 
  Terminal, 
  Award, 
  HelpCircle, 
  GitBranch, 
  Mail, 
  ExternalLink, 
  Code2, 
  Workflow, 
  Scale, 
  ShieldCheck, 
  User, 
  Zap, 
  SlidersHorizontal 
} from 'lucide-react';
import { playClickSound, cn } from '@/lib/utils';

type SubTab = 'specs' | 'architecture' | 'stack' | 'legal';

export default function AboutTab() {
  const [activeSubTab, setActiveSubTab] = useState<SubTab>('specs');

  const handleSubTabChange = (tab: SubTab) => {
    setActiveSubTab(tab);
    playClickSound();
  };

  const PIPELINE_STEPS = [
    {
      step: '01',
      title: 'Frame Interception',
      source: 'Npcap / Scapy Kernel Wrapper',
      desc: 'Binds directly to selected network interface in promiscuous mode. Reads raw Layer 2/3 frames and filters packets at kernel space using compiled Berkeley Packet Filter (BPF) expressions.',
      icon: Terminal,
      color: 'var(--accent-blue)',
    },
    {
      step: '02',
      title: 'Flow Hashing & Load Balancing',
      source: 'Ring Buffer & LB Thread',
      desc: 'Intercepted frames are pushed into a high-performance circular ring buffer. A dedicated Load Balancer thread computes a symmetric 5-tuple flow hash to route packets to designated worker queues while preserving strict frame ordering.',
      icon: Layers,
      color: 'var(--accent-cyan)',
    },
    {
      step: '03',
      title: 'Stateful Protocol Inspection',
      source: 'State Machine & Entropy Shield',
      desc: 'Validates TCP handshake states (checking flags for Null, Xmas, or Out-Of-Order anomalies), computes Shannon entropy on DNS queries to detect tunneling, and inspects HTTP headers for smuggling discrepancies.',
      icon: Shield,
      color: 'var(--accent-red)',
    },
    {
      step: '04',
      title: 'Explainable AI Classification',
      source: 'Random Forest Classify Core',
      desc: 'Aggregates packet size variance, payload distributions, and inter-arrival intervals. Feeds these parameters to an embedded Random Forest classifier, producing a probability-weighted application class verdict.',
      icon: Cpu,
      color: 'var(--accent-violet)',
    },
    {
      step: '05',
      title: 'Live Telemetry Serialization',
      source: 'Next.js UI & REST Broadcast',
      desc: 'Final verdicts, throughput rates, and block metrics are aggregated in memory. A lightweight multi-threaded Python web server serves the data, which is pulled in real-time by the Next.js UI using optimized SWR sockets.',
      icon: Network,
      color: 'var(--accent-pink)',
    },
  ];

  return (
    <div className="space-y-8 animate-fade-in pb-12">
      {/* Top Header */}
      <div className="flex items-center justify-between border-b border-[var(--border)] pb-4">
        <div>
          <h2 className="text-display-sm">Deep Packet Inspection Console</h2>
          <p className="text-caption text-[var(--text-muted)] mt-1">
            System capabilities, pipeline architecture, and creator details.
          </p>
        </div>
      </div>

      {/* Hero Section & Developer Profile */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Project Intro */}
        <div className="lg:col-span-2 dpi-card bg-linear-to-br from-[var(--bg-soft)] to-[var(--bg)] border border-[var(--border-strong)] flex flex-col sm:flex-row gap-6 items-center p-6 justify-center">
          <div className="w-16 h-16 rounded-2xl flex items-center justify-center bg-[var(--accent-blue-soft)] border border-[var(--accent-blue)]/20 shadow-[0_0_20px_var(--accent-blue-soft)] flex-shrink-0 animate-pulse">
            <Shield className="w-8 h-8 text-[var(--accent-blue)]" />
          </div>
          <div className="space-y-2 text-center sm:text-left">
            <h3 className="text-display-sm font-semibold tracking-[-0.6px] flex items-center justify-center sm:justify-start gap-2">
              DPI Engine Platform
              <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full border border-[var(--border)] bg-[var(--panel-soft)] text-[var(--text-muted)]">
                v2.0.0
              </span>
            </h3>
            <p className="text-body-md text-[var(--text-secondary)] leading-relaxed">
              A state-of-the-art multi-threaded network security console. Built on a zero-copy packet interception model, it orchestrates a high-performance pipeline of load-balancing, stateful protocol tracking, and machine learning classifiers to audit network streams under sub-millisecond latencies.
            </p>
          </div>
        </div>

        {/* Developer Card (Connect & Collaborate) */}
        <div className="lg:col-span-1 dpi-card border border-[var(--accent-blue)]/30 bg-[var(--panel-soft)]/50 flex flex-col justify-between p-6">
          <div className="space-y-3">
            <div className="flex items-center gap-2.5 text-[var(--accent-blue)] font-bold tracking-wide uppercase text-[11px] font-mono">
              <User className="w-4 h-4" />
              <span>Designed & Engineered By</span>
            </div>
            <div>
              <h4 className="text-[18px] font-bold text-[var(--text)] tracking-[-0.3px]">Prathamesh Jadhav</h4>
              <p className="text-caption text-[var(--text-secondary)] mt-0.5 font-medium">Security Software & Networks Engineer</p>
            </div>
            <p className="text-caption text-[var(--text-muted)] leading-normal">
              Specialized in network intelligence, microsecond threading pipelines, and statistical traffic classification.
            </p>
          </div>

          <div className="grid grid-cols-2 gap-2 mt-4 pt-3 border-t border-[var(--border-subtle)]">
            <a
              href="https://github.com/Prathamesh-Jadhav04"
              target="_blank"
              rel="noopener noreferrer"
              onClick={() => playClickSound()}
              className="flex items-center justify-center gap-1.5 px-3 py-1.8 rounded-lg text-caption font-semibold border border-[var(--border)] bg-[var(--panel)] hover:bg-[var(--panel-hover)] text-[var(--text-secondary)] hover:text-[var(--text)] transition-colors cursor-pointer"
            >
              <GitBranch className="w-3.5 h-3.5" />
              <span>GitHub</span>
              <ExternalLink className="w-2.5 h-2.5 opacity-60" />
            </a>
            <a
              href="mailto:Prathamesh.jadhav.office@gmail.com"
              onClick={() => playClickSound()}
              className="flex items-center justify-center gap-1.5 px-3 py-1.8 rounded-lg text-caption font-semibold border border-[var(--border)] bg-[var(--panel)] hover:bg-[var(--panel-hover)] text-[var(--text-secondary)] hover:text-[var(--text)] transition-colors cursor-pointer"
            >
              <Mail className="w-3.5 h-3.5" />
              <span>Email</span>
              <ExternalLink className="w-2.5 h-2.5 opacity-60" />
            </a>
          </div>
        </div>

      </div>

      {/* Sub Tab Navigation */}
      <div className="flex border-b border-[var(--border)] gap-6 select-none overflow-x-auto scrollbar-none pb-0.5">
        {(['specs', 'architecture', 'stack', 'legal'] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => handleSubTabChange(tab)}
            className={cn(
              'pb-3 text-body-sm font-semibold tracking-[-0.2px] border-b-2 transition-all cursor-pointer whitespace-nowrap',
              activeSubTab === tab
                ? 'border-[var(--accent-blue)] text-[var(--text)]'
                : 'border-transparent text-[var(--text-muted)] hover:text-[var(--text-secondary)]'
            )}
          >
            {tab === 'specs' && 'System Capabilities'}
            {tab === 'architecture' && 'Pipeline Architecture'}
            {tab === 'stack' && 'Technology Stack'}
            {tab === 'legal' && 'Legal & Compliance'}
          </button>
        ))}
      </div>

      {/* Interactive Sub-tab Panels */}
      <div className="min-h-[350px]">
        {activeSubTab === 'specs' && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 animate-fade-in">
            {/* AI Classification */}
            <div className="dpi-card space-y-3.5 hover:border-[var(--accent-violet)]/30 transition-all">
              <div className="flex items-center gap-2.5 text-body-sm font-semibold text-[var(--text)]">
                <Cpu className="w-4 h-4 text-[var(--accent-violet)]" />
                <span>AI Application Classifier</span>
              </div>
              <p className="text-caption text-[var(--text-secondary)] leading-relaxed">
                Uses an embedded <strong>Random Forest Classifier</strong> trained to audit statistical profiles. It dynamically classifies applications (Google, Netflix, YouTube, etc.) with real-time confidence tracking.
              </p>
              <ul className="text-caption text-[var(--text-muted)] space-y-1.5 list-disc pl-4 font-sans">
                <li>Feature-weighted signature profiles.</li>
                <li>TLS Client Hello SNI & Host Header extraction.</li>
                <li>DNS resolution matching for unidentified IPs.</li>
              </ul>
            </div>

            {/* Stateful Security Shield */}
            <div className="dpi-card space-y-3.5 hover:border-[var(--accent-red)]/30 transition-all">
              <div className="flex items-center gap-2.5 text-body-sm font-semibold text-[var(--text)]">
                <ShieldCheck className="w-4 h-4 text-[var(--accent-red)]" />
                <span>Stateful Protocol Shield</span>
              </div>
              <p className="text-caption text-[var(--text-secondary)] leading-relaxed">
                Inspects Layer 4 protocols using a fast state machine. Detects flag anomalies (Null, Xmas, Syn-flood) and calculates Shannon entropy metrics to flag hidden DNS tunneling streams.
              </p>
              <ul className="text-caption text-[var(--text-muted)] space-y-1.5 list-disc pl-4 font-sans">
                <li>Real-time flag combinations scan.</li>
                <li>Entropy analysis for outbound payloads.</li>
                <li>HTTP smuggling and length mismatch flags.</li>
              </ul>
            </div>

            {/* 5-Tuple Flow Aggregator */}
            <div className="dpi-card space-y-3.5 hover:border-[var(--accent-cyan)]/30 transition-all">
              <div className="flex items-center gap-2.5 text-body-sm font-semibold text-[var(--text)]">
                <Network className="w-4 h-4 text-[var(--accent-cyan)]" />
                <span>5-Tuple Flow Aggregator</span>
              </div>
              <p className="text-caption text-[var(--text-secondary)] leading-relaxed">
                Combines asynchronous packets into bidirectional flow streams using source/destination IPs, ports, and protocols. Tracks telemetry data, throughput rates, and sizes.
              </p>
              <ul className="text-caption text-[var(--text-muted)] space-y-1.5 list-disc pl-4 font-sans">
                <li>TLS JA3/JA4 fingerprint matching.</li>
                <li>Dynamic bandwidth utilization scoring.</li>
                <li>Out-of-order packet sequence reconstruction.</li>
              </ul>
            </div>

            {/* Enforcer Rules Engine */}
            <div className="dpi-card space-y-3.5 hover:border-[var(--accent-amber)]/30 transition-all">
              <div className="flex items-center gap-2.5 text-body-sm font-semibold text-[var(--text)]">
                <Terminal className="w-4 h-4 text-[var(--accent-amber)]" />
                <span>Enforcer Rules Engine</span>
              </div>
              <p className="text-caption text-[var(--text-secondary)] leading-relaxed">
                Maintains a synchronized blacklist. Any traffic matching an active rule is intercepted at the kernel buffer space and assigned an immediate drop verdict.
              </p>
              <ul className="text-caption text-[var(--text-muted)] space-y-1.5 list-disc pl-4 font-sans">
                <li>Drop by specific IP address.</li>
                <li>Drop by classified application signature.</li>
                <li>Drop by SNI/Domain host substring matches.</li>
              </ul>
            </div>

            {/* Zero-Copy Ring Buffer */}
            <div className="dpi-card space-y-3.5 hover:border-[var(--accent-blue)]/30 transition-all">
              <div className="flex items-center gap-2.5 text-body-sm font-semibold text-[var(--text)]">
                <Zap className="w-4 h-4 text-[var(--accent-blue)]" />
                <span>Zero-Copy Ring Buffer (Advanced)</span>
              </div>
              <p className="text-caption text-[var(--text-secondary)] leading-relaxed">
                Employs a custom circular ring buffer design to bridge kernel-to-user space transmission. This minimizes memory allocation bottlenecks during high-density capture bursts.
              </p>
              <ul className="text-caption text-[var(--text-muted)] space-y-1.5 list-disc pl-4 font-sans">
                <li>Single-producer multi-consumer rings.</li>
                <li>Lock-free sequence pointer updates.</li>
                <li>Sub-microsecond frame enqueue latency.</li>
              </ul>
            </div>

            {/* Dynamic Worker Load Balancing */}
            <div className="dpi-card space-y-3.5 hover:border-[var(--accent-pink)]/30 transition-all">
              <div className="flex items-center gap-2.5 text-body-sm font-semibold text-[var(--text)]">
                <SlidersHorizontal className="w-4 h-4 text-[var(--accent-pink)]" />
                <span>PID-Driven Worker Balancer (Advanced)</span>
              </div>
              <p className="text-caption text-[var(--text-secondary)] leading-relaxed">
                Monitors thread pipeline queues using a PID loop. Adjusts flow hash routing weights dynamically when processing cores suffer bottleneck delays or packet-drop spikes.
              </p>
              <ul className="text-caption text-[var(--text-muted)] space-y-1.5 list-disc pl-4 font-sans">
                <li>Worker load distribution audits.</li>
                <li>Auto-scaling worker assignment threshold.</li>
                <li>Fast Path fallback trigger during queue saturations.</li>
              </ul>
            </div>
          </div>
        )}

        {activeSubTab === 'architecture' && (
          <div className="space-y-6 animate-fade-in">
            {/* Visual Pipeline Layout */}
            <div className="flex flex-col lg:flex-row items-stretch gap-4">
              {PIPELINE_STEPS.map((step, idx) => (
                <div key={idx} className="flex-1 dpi-card relative flex flex-col justify-between p-5 border border-[var(--border)] hover:border-[var(--border-strong)] transition-all">
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-[28px] font-mono font-bold tracking-tight opacity-10" style={{ color: step.color }}>
                        {step.step}
                      </span>
                      <step.icon className="w-5 h-5 opacity-70" style={{ color: step.color }} />
                    </div>
                    <div>
                      <h4 className="text-body-sm font-bold text-[var(--text)]">{step.title}</h4>
                      <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-[var(--text-muted)] block mt-0.5">
                        {step.source}
                      </span>
                    </div>
                    <p className="text-caption text-[var(--text-secondary)] leading-normal mt-2">
                      {step.desc}
                    </p>
                  </div>
                </div>
              ))}
            </div>

            {/* Pipeline Depth Description */}
            <div className="dpi-card space-y-4">
              <div className="flex items-center gap-2 text-body-sm font-semibold text-[var(--text)]">
                <Workflow className="w-4 h-4 text-[var(--accent-blue)]" />
                <span>Deep Pipeline Execution Blueprint</span>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-caption text-[var(--text-secondary)] leading-relaxed">
                <p>
                  At its core, the platform operates a separated thread pool topology to isolate IO capture bottlenecks from heavy statistical computations. The <strong>Reader Thread</strong> locks to the hardware interface via compiled BPF filters, moving packets into the lock-free circular ring buffer. This isolates network reception from downstream queue blockages.
                </p>
                <p>
                  A secondary <strong>Load Balancer (LB) thread</strong> acts as the traffic scheduler. Using symmetric XOR hashing on IP and port coordinates, it ensures that all packets forming a bi-directional flow conversation land in the exact same worker queue. This architecture permits worker threads to evaluate stateful TCP anomalies and train application classification matrices concurrently without inter-thread locking overhead.
                </p>
              </div>
            </div>
          </div>
        )}

        {activeSubTab === 'stack' && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 animate-fade-in">
            {/* Frontend Stack */}
            <div className="dpi-card space-y-4">
              <div className="flex items-center gap-2 text-body-sm font-semibold text-[var(--text)]">
                <Code2 className="w-4.5 h-4.5 text-[var(--accent-blue)]" />
                <span>Frontend Dashboard Engine</span>
              </div>
              <p className="text-caption text-[var(--text-secondary)]">
                Engineered as a lightweight, single-page dashboard designed for dense data layouts, low rendering-overhead, and high-frequency UI updates.
              </p>
              <div className="grid grid-cols-2 gap-3.5 pt-2">
                <div className="space-y-1">
                  <span className="text-[11px] font-semibold text-[var(--text-muted)] uppercase font-mono block">Framework & Language</span>
                  <span className="text-caption text-[var(--text-secondary)] font-semibold block">Next.js 16 (App Router)</span>
                  <span className="text-caption text-[var(--text-secondary)] font-semibold block">TypeScript 5.0</span>
                </div>
                <div className="space-y-1">
                  <span className="text-[11px] font-semibold text-[var(--text-muted)] uppercase font-mono block">Layout & Styles</span>
                  <span className="text-caption text-[var(--text-secondary)] font-semibold block">Tailwind CSS v4</span>
                  <span className="text-caption text-[var(--text-secondary)] font-semibold block">Framer Motion</span>
                </div>
                <div className="space-y-1">
                  <span className="text-[11px] font-semibold text-[var(--text-muted)] uppercase font-mono block">Charts & Telemetry</span>
                  <span className="text-caption text-[var(--text-secondary)] font-semibold block">Recharts Visualizations</span>
                  <span className="text-caption text-[var(--text-secondary)] font-semibold block">SWR State Hydration</span>
                </div>
                <div className="space-y-1">
                  <span className="text-[11px] font-semibold text-[var(--text-muted)] uppercase font-mono block">State Management</span>
                  <span className="text-caption text-[var(--text-secondary)] font-semibold block">Zustand Store</span>
                  <span className="text-caption text-[var(--text-secondary)] font-semibold block">HTML5 Web Audio API</span>
                </div>
              </div>
            </div>

            {/* Backend Stack */}
            <div className="dpi-card space-y-4">
              <div className="flex items-center gap-2 text-body-sm font-semibold text-[var(--text)]">
                <Award className="w-4.5 h-4.5 text-[var(--accent-violet)]" />
                <span>Backend Processing Core</span>
              </div>
              <p className="text-caption text-[var(--text-secondary)]">
                Powered by a multi-threaded Python engine acting as the telemetry aggregator, packet dissector, and machine learning scoring engine.
              </p>
              <div className="grid grid-cols-2 gap-3.5 pt-2">
                <div className="space-y-1">
                  <span className="text-[11px] font-semibold text-[var(--text-muted)] uppercase font-mono block">Core Engine</span>
                  <span className="text-caption text-[var(--text-secondary)] font-semibold block">Python Multi-Threading</span>
                  <span className="text-caption text-[var(--text-secondary)] font-semibold block">Scapy Packet Assembler</span>
                </div>
                <div className="space-y-1">
                  <span className="text-[11px] font-semibold text-[var(--text-muted)] uppercase font-mono block">Driver Wrappers</span>
                  <span className="text-caption text-[var(--text-secondary)] font-semibold block">Npcap Packet Interceptor</span>
                  <span className="text-caption text-[var(--text-secondary)] font-semibold block">Kernel-Level Socket Sniffers</span>
                </div>
                <div className="space-y-1">
                  <span className="text-[11px] font-semibold text-[var(--text-muted)] uppercase font-mono block">AI Classifier Core</span>
                  <span className="text-caption text-[var(--text-secondary)] font-semibold block">Scikit-Learn Classifier</span>
                  <span className="text-caption text-[var(--text-secondary)] font-semibold block">Random Forest Weights Matrix</span>
                </div>
                <div className="space-y-1">
                  <span className="text-[11px] font-semibold text-[var(--text-muted)] uppercase font-mono block">API Telemetry Link</span>
                  <span className="text-caption text-[var(--text-secondary)] font-semibold block">Threaded HTTP Web Server</span>
                  <span className="text-caption text-[var(--text-secondary)] font-semibold block">JSON Data Serializers</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeSubTab === 'legal' && (
          <div className="dpi-card space-y-5 animate-fade-in">
            <div className="flex items-center gap-2 text-body-sm font-semibold text-[var(--text)]">
              <Scale className="w-4.5 h-4.5 text-[var(--accent-red)]" />
              <span>Legal Guidelines & Compliance Policies</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-caption text-[var(--text-secondary)] leading-relaxed">
              <div className="space-y-3">
                <h5 className="font-bold text-[var(--text)]">1. Authorized Interception</h5>
                <p>
                  This Deep Packet Inspection application is intended solely for local network diagnostic troubleshooting, educational analysis, and security verification. Users must possess explicit authorization to bind to network interfaces in promiscuous mode or intercept raw frames on the targeted infrastructure.
                </p>
                <h5 className="font-bold text-[var(--text)]">2. Driver Licensing Requirement</h5>
                <p>
                  Raw packet sniffer drivers (such as Npcap under Windows environments or libpcap under UNIX environments) operate under independent software licenses. Ensure compliance with their respective licensing terms before binding this DPI console to active hardware.
                </p>
              </div>

              <div className="space-y-3">
                <h5 className="font-bold text-[var(--text)]">3. Data Privacy & Minimization</h5>
                <p>
                  To adhere to network security principles and privacy regulations (such as GDPR), the application limits persistent data storage. Packet payloads are evaluated on-the-fly in temporary CPU memory pools. Historical records are scoped to rolling circular buffers and are immediately deleted upon terminating the application session.
                </p>
                <h5 className="font-bold text-[var(--text)]">4. Liability Disclaimer</h5>
                <p>
                  The author and developers of this console assume no liability and are not responsible for any misuse, packet drop outages in production environments, network interface driver corruption, or unauthorized data capture attempts conducted with this diagnostic utility.
                </p>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Operations Notice */}
      <div className="dpi-panel flex items-start gap-3 text-caption text-[var(--text-secondary)]">
        <HelpCircle className="w-4.5 h-4.5 text-[var(--accent-blue)] flex-shrink-0 mt-0.5" />
        <div className="space-y-1">
          <span className="font-semibold text-[var(--text)]">Verification Tutorial</span>
          <p>
            To audit the enforcer block mechanics: navigate to the <strong>Blocking Rules</strong> tab, write a new block rule targeting a domain (e.g. <code>facebook.com</code>) or signature, and trigger the capture loop in the <strong>Live Capture</strong> tab. Flows matching the criteria will instantly flag red with a <code>DROP</code> status, and live dropped counters will increment.
          </p>
        </div>
      </div>
    </div>
  );
}
