# DPI Engine — Developer Guide (`CLAUDE.md`)

This document provides a comprehensive guide to the Deep Packet Inspection (DPI) Engine and Network Traffic Intelligence Platform. It outlines the system architecture, file structure, code style conventions, build/run workflows, and internal mechanisms like RFC 793 TCP reset injection and dynamic IP harvesting.

---

## 1. Project Overview

The DPI Engine is a production-grade, multi-threaded packet analysis and threat intelligence platform. Built as a high-performance Python port of a C++ DPI engine, it passively intercepts Ethernet frames (via Scapy and Npcap), decodes network protocols up to layer 7, detects anomalies, classifies applications using machine learning, and dynamically enforces traffic blocking rules.

```
                  +----------------------------------------------+
                  |               Network Adapter                |
                  +----------------------+-----------------------+
                                         |
                                         | (Passive Sniffing / Npcap)
                                         v
                  +----------------------+-----------------------+
                  |         DPI Engine Pipeline (pipeline.py)    |
                  |                                              |
                  |   +--------------------------------------+   |
                  |   |        Raw Ingestion & Parser        |   |
                  |   +------------------+-------------------+   |
                  |                      |                       |
                  |                      v (Hash dispatching)    |
                  |   +------------------+-------------------+   |
                  |   |    Load Balancer Threads (LB0, LB1)  |   |
                  |   +------------------+-------------------+   |
                  |                      |                       |
                  |                      v (Thread-safe queues)  |
                  |   +------------------+-------------------+   |
                  |   |      FastPath Workers (FP0..FP3)     |   |
                  |   |      - Stateful TCP Trackers         |   |
                  |   |      - Protocol Parsers (TLS, HTTP)  |   |
                  |   |      - Anomaly Detectors             |   |
                  |   |      - ML App Classifiers            |   |
                  |   |      - Active Blocking & Reset       |   |
                  |   +------------------+-------------------+   |
                  |                      |                       |
                  |                      +----------------+      |
                  +---------------------------------------|------+
                                                          |
                                      +-------------------+------------------+
                                      |                                      |
                                      v (Forwarded)                          v (Dropped & RST)
                        +-------------+------------+           +-------------+------------+
                        |  Output Queue (output)   |           |    TCP Reset Generator   |
                        +-------------+------------+           |    - RFC 793 Compliance  |
                                      |                        |    - Dynamic MAC Swap    |
                                      v                        |    - Sniffed interface   |
                        +-------------+------------+           +-------------+------------+
                        |      pcap File Writer      |                       |
                        +--------------------------+                       v
                                                              +--------------+------------+
                                                              |      Spoofed Reset/ICMP   |
                                                              +---------------------------+
```

---

## 2. Codebase Directory Map

### 2.1. Python Backend
*   [cli.py](file:///D:/Deep%20Packet%20Inpection/cli.py): CLI interface tool (`.\dpi`). Wraps dashboard start/stop, status checks, offline replays, rule updates, and security alerts.
*   [dpi_engine.py](file:///D:/Deep%20Packet%20Inpection/dpi_engine.py): Main Python entry point script. Parses CLI options and delegates to the pipeline or dashboard.
*   [dpi_engine/common.py](file:///D:/Deep%20Packet%20Inpection/dpi_engine/common.py): Core data models (`Packet`, `RawPacket`, `FiveTuple`), shared `Rules` manager (locking, IP/App/Domain rules), and global `Stats` database.
*   [dpi_engine/pipeline.py](file:///D:/Deep%20Packet%20Inpection/dpi_engine/pipeline.py): Multi-threaded execution pipeline. Contains `DPIEngine`, `LoadBalancer`, `FastPath`, and active `_inject_tcp_reset` / `_inject_icmp_unreachable` packet spoofers.
*   [dpi_engine/parsers.py](file:///D:/Deep%20Packet%20Inpection/dpi_engine/parsers.py): Zero-dependency binary parsers for Ethernet, IPv4/IPv6, TCP, UDP, TLS Client Hello (SNI, extension list), HTTP/1.x Host, HTTP/2 frames, QUIC initial packets, and DNS queries/answers.
*   [dpi_engine/anomaly.py](file:///D:/Deep%20Packet%20Inpection/dpi_engine/anomaly.py): Stateful network security alert monitors including TCP SYN Flood trackers, DNS Tunneling counters, and HTTP Request Smuggling heuristic check state machines.
*   [dpi_engine/analytics.py](file:///D:/Deep%20Packet%20Inpection/dpi_engine/analytics.py): Rolling throughput rates (PPS, Mbps), port-to-port communication matrices, and IP top talkers aggregators.
*   [dpi_engine/classifiers.py](file:///D:/Deep%20Packet%20Inpection/dpi_engine/classifiers.py): Encapsulated Machine Learning classifier loading `models/eti_rf_model.pkl` to compute ETI threat scores.
*   [dpi_engine/ui.py](file:///D:/Deep%20Packet%20Inpection/dpi_engine/ui.py): Embedded HTTP Server (built on `BaseHTTPRequestHandler`) that handles stats endpoints, rules configurations, live capture triggers, CORS preflight headers, and custom Windows MIME-type overrides for serving static Next.js UI files.

### 2.2. Next.js Frontend
*   [dashboard/src/app/page.tsx](file:///D:/Deep%20Packet%20Inpection/dashboard/src/app/page.tsx): Main dashboard shell. Handles SWR client origin sync and Framer Motion tab transitions.
*   [dashboard/src/store/dpi-store.ts](file:///D:/Deep%20Packet%20Inpection/dashboard/src/store/dpi-store.ts): Global Zustand state machine for theme toggles, API base port mapping, notification thresholds, and capture states.
*   [dashboard/src/tabs/overview.tsx](file:///D:/Deep%20Packet%20Inpection/dashboard/src/tabs/overview.tsx): CPU / worker thread metric load charts, rolling traffic area graphs, and ETI anomaly warnings.
*   [dashboard/src/tabs/live-capture.tsx](file:///D:/Deep%20Packet%20Inpection/dashboard/src/tabs/live-capture.tsx): Dynamic virtualized list table displaying real-time packet metadata (IPs, App classifications, JA3/JA4 fingerprints) with drop/forward actions.
*   [dashboard/src/tabs/blocking-rules.tsx](file:///D:/Deep%20Packet%20Inpection/dashboard/src/tabs/blocking-rules.tsx): Rule manager panel. Contains automatic IP/App/Domain category validators and JSON rule configuration exporters.

---

## 3. Core Technical Implementations

### 3.1. RFC 793 Compliant TCP Reset Injection
Since passive sniffing cannot physically drop packets on the wire (the packets have already left the NIC), the engine enforces blocking rules by injecting spoofed TCP Reset (`RST`) packets to both the client and server.

To guarantee that the reset packets are accepted, the injector follows strict rules:
1.  **Direction-Aware Parameter Swapping**: The injector parses the packet port numbers to determine the flow direction:
    *   If destination port is `80`/`443`, the packet is **Client-to-Server**. The client MAC is `packet.data[6:12]` (source) and server MAC is `packet.data[0:6]` (destination).
    *   If source port is `80`/`443`, the packet is **Server-to-Client**. The client MAC is `packet.data[0:6]` (destination) and server MAC is `packet.data[6:12]` (source).
2.  **RFC 793 Sequence Calculations**:
    *   If the incoming packet has the **ACK flag set** (standard data packet/Client Hello): We transmit a spoofed `RST` frame.
        *   RST to Client: `flags="R"`, `seq = incoming_ack`.
        *   RST to Server: `flags="R"`, `seq = incoming_seq + incoming_payload_length`.
    *   If the incoming packet does **NOT have the ACK flag set** (TCP `SYN` packet): We transmit a spoofed `RST-ACK` frame to validate the sequence window.
        *   RST-ACK to Client: `flags="RA"`, `seq = 0`, `ack = incoming_seq + 1`.
        *   RST-ACK to Server: `flags="RA"`, `seq = incoming_seq`, `ack = 0`.
3.  **Interface Propagation**: The raw packet listener stores the name of the network adapter on which the packet was sniffed (`packet.iface`). The injector passes this interface name to Scapy's `sendp(..., iface=iface)`. This ensures that resets are injected on the exact same active network adapter, rather than default loopback or offline adapters.

### 3.2. Dynamic IP Harvesting on Domain Match
To defeat connections utilizing Encrypted Client Hello (ECH) or cached browser dns lookups:
1.  When a Client Hello or HTTP Host matches a domain rule (e.g. `github.com`), the engine extracts the SNI.
2.  Upon a match, the engine immediately calls `self.rules.block_ip(server_ip)` to blacklist the server's IP address.
3.  Any subsequent packets (including TCP `SYN` packets from retry attempts) are matched at the IP layer and dropped/reset immediately, completely terminating access.

---

## 4. Compilation & Build Workflows

### 4.1. Prerequisites
Ensure you have Python 3.8+ and Node.js 18+ installed. 
On Windows, **Npcap** must be installed (configured in WinPcap-compatible mode).

### 4.2. Running the Python Backend
```bash
# Verify type checking and compile python scripts
python -m py_compile dpi_engine/common.py dpi_engine/pipeline.py

# Run standalone HTTP dashboard controller (port 8765)
python dpi_engine.py --dashboard --dashboard-port 8765

# Or use the wrapper CLI
.\dpi dashboard
```

### 4.3. Building the Next.js Frontend
```bash
# Navigate to dashboard directory
cd dashboard

# Install node dependencies
npm install

# Compile TypeScript and export static build to /dashboard/out
npm run build
```

---

## 5. Development Conventions

1.  **Thread Safety**: Always modify `self._blocked_ips`, `self._blocked_apps`, and `self._blocked_domains` within a `with self._lock:` block. The `Rules` class utilizes a re-entrant lock to prevent race conditions between incoming fast path threads and UI API configurations.
2.  **MIME-Type Overrides**: When updating UI routes in [ui.py](file:///D:/Deep%20Packet%20Inpection/dpi_engine/ui.py), ensure file extensions (`.js`, `.css`, `.svg`, `.html`) bypass Python's standard `mimetypes` library by using explicit string overrides. This prevents Windows Registry corruption bugs from causing the browser to reject static assets.
3.  **No Placeholders**: Avoid writing dummy data or mocks. Write fully production-ready, typed implementations. All frontend components should have strict TS types matching [types/dpi.ts](file:///D:/Deep%20Packet%20Inpection/dashboard/src/types/dpi.ts).
