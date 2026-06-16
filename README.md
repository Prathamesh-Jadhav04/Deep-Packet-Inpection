---
title: Deep Packet Inspection
emoji: 🛡️
colorFrom: blue
colorTo: green
sdk: docker
app_port: 7860
---

<div align="center">

# DPI Engine

**A high-performance, multi-threaded Deep Packet Inspection (DPI) and network traffic intelligence platform written in Python.**

Parses traffic at every layer from Ethernet to application protocols, fingerprints encrypted clients without decryption, runs a stateful Intrusion Detection System (IDS), and features a command-line interface (CLI) along with a Next.js web dashboard.

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](#license)
[![Status](https://img.shields.io/badge/status-active%20development-orange.svg)](#known-limitations)

</div>

---

## 1. Project Overview & Motivation

DPI Engine is designed as a lightweight, zero-config network security auditing and flow inspection platform. It ingests traffic from raw network interfaces or offline PCAP dumps and routes it through a pipelined, multi-threaded architecture. By combining classic protocol parsing with modern behavioral machine learning, it identifies application names and flags malicious or anomalous activity inside encrypted sessions (such as HTTPS or QUIC) without resorting to SSL/TLS decryption.

In production environments, security gateways rely on tools like Zeek, Suricata, Snort, or Cloudflare Gateway. This project implements similar logic (handshake parsing, ETI features extraction, signature checking, active connection teardowns) in a modular, highly readable Python codebase. It is ideal for cybersecurity labs, traffic debugging, threat hunting, and educational demonstrations of active network defense.

```
                  [ Ingress Network Interface / PCAP File ]
                                      │
                                      ▼
                        [ Reader / Packet Parser Stage ]
                                      │
                                      ▼
                [ Load Balancer Thread (5-Tuple Hash Routing) ]
                                      │
                    ┌─────────────────┼─────────────────┐
                    ▼                 ▼                 ▼
             [ FastPath 0 ]    [ FastPath 1 ]    [ FastPath N ] (Worker Threads)
             ┌────────────┐    ┌────────────┐    ┌────────────┐
             │ Parse L7   │    │ Parse L7   │    │ Parse L7   │
             │ JA3/JA4    │    │ JA3/JA4    │    │ JA3/JA4    │
             │ IDS Alerts │    │ IDS Alerts │    │ IDS Alerts │
             │ ETI Preds  │    │ ETI Preds  │    │ ETI Preds  │
             └─────┬──────┘    └─────┬──────┘    └─────┬──────┘
                   │                 │                 │
                   └─────────────────┼─────────────────┘
                                     ▼
                   [ Active Rules & Threat Intel Check ]
                                     │
                    ┌────────────────┴────────────────┐
                    │                                 │
            (Match: Block)                   (Match: Forward)
                    ▼                                 ▼
         [ Drop Packet + Inject ]           [ Queue Output Packets ]
         [ TCP RST / ICMP Spoofs ]                    │
                                                      ▼
                                            [ Output PCAP Writer ]
                                            [ & Dashboard REST API ]
```

---

## 2. Core Capabilities

### 2.1 Deep Protocol Parsing
The engine decodes network packet byte structures iteratively from the link layer upward:
- **Layer 2 (Link)**: Ethernet MAC address resolution and EtherType extraction.
- **Layer 3 (Network)**: IPv4 and IPv6 header decoding, including parsing and skipping of IPv6 extension header chains (Routing, Fragmentation, ESP, AH).
- **Layer 4 (Transport)**: TCP sequence, acknowledgment tracking, flag extraction (SYN, ACK, RST, FIN, PSH, URG), and UDP port mappings.
- **TLS SNI Extraction**: Decodes TLS record layers (handshakes) to extract the Server Name Indication (SNI) extension.
- **HTTP/1.x**: Decodes plain text payloads to extract `Host` headers.
- **HTTP/2 Frame Parsing**: Decodes `HEADERS` and `CONTINUATION` frames. Features a custom HPACK decoder containing a static index table and a custom Huffman tree traversal algorithm for header value extraction.
- **QUIC / HTTP3 Decapsulation**: Detects QUIC Initial packets, decodes variable-length integers (varints), parses CRYPTO frames, and extracts the inner TLS Client Hello.
- **DNS Decodes**: Extracts query hostnames and dynamically harvests resolved IPv4 (A) and IPv6 (AAAA) records from DNS responses.
- **DoT & DoH Detection**: Recognizes DNS-over-TLS (port 853) and flags DNS-over-HTTPS by matching known DoH providers or parsing HTTP/2 request paths.

### 2.2 Encrypted Traffic Intelligence (ETI)
ETI enables the engine to classify network flows as `BENIGN`, `SUSPICIOUS`, or `MALICIOUS` without decrypting payloads. For every flow, the engine extracts a 17-dimensional behavioral feature vector:
1. **Normalized Payload Size Histogram** (10 bins tracking sizes from $\le 100$ bytes to $>1600$ bytes)
2. **Mean Payload Size** and **Payload Size Variance**
3. **Mean Packet Inter-Arrival Time (IAT)** and **IAT Variance** (used to detect malware beaconing)
4. **Coefficient of Variation of IAT**
5. **Flow Burst Count** and **Average Burst Size**

Inference runs through an ONNX runtime model if available. If the ONNX module is missing, it falls back to a pickled RandomForest model (loaded via `joblib`), and falls back further to rule-based heuristics if no model files are present.

### 2.3 Client Fingerprinting (JA3 / JA4)
The engine generates JA3 and JA4 fingerprints from TLS Client Hello handshakes (including QUIC Initial packets):
- **JA3**: Concatenates TLS version, cipher list, extensions list, elliptic curve groups, and elliptic curve formats, returning the MD5 hash.
- **JA4**: Builds a 3-part fingerprint `SegmentA_SegmentB_SegmentC`. Segment A contains protocol type, TLS version, SNI status, ciphers/extensions counts, and ALPN. Segment B and C contain hashes of sorted cipher suites and extensions.
- Both fingerprinters filter out GREASE values per RFC 8701 to ensure fingerprint consistency.

### 2.4 Stateful Intrusion Detection System (IDS)
The stateful IDS inspects packets for protocol-specific anomalies and maps alerts to MITRE ATT&CK technique IDs:
- **TCP Anomalies**: Detects SYN floods, invalid flag combinations (such as null flags, SYN+FIN, or Xmas scans), and out-of-order handshakes (data sent before connection is established).
- **DNS Anomalies**: Flags subdomains exceeding 50 characters, high Shannon entropy, query rates exceeding 50 queries/sec (DNS tunneling), and conflicting TXID answers (cache poisoning).
- **HTTP Anomalies**: Detects HTTP request smuggling, invalid chunked body framing, non-RFC method verbs, and header overflows ($>16\text{ KB}$).

### 2.5 Active Blocking & Rules Engine
Blocking is applied in real time by source IP, application enum, or domain substring. When a block matches, the engine drops the packet and actively injects spoofed teardown packets into the network interface:
- **TCP connections**: Injects TCP RST packets spoofed from both the client and server to terminate the connection.
- **UDP/QUIC sessions**: Injects spoofed ICMP Port Unreachable (or ICMPv6 Destination Unreachable) packets back to the client.

### 2.6 Bidirectional Routing & Flow Tracking
To handle bidirectional traffic correctly across multiple parallel worker threads, the engine uses:
- **Consistent Endpoint Sorting Hashing**: Compares and sorts endpoint IPs and ports before hashing in `five_tuple_hash`. This routes both directions of a flow (client $\to$ server and server $\to$ client) to the same LoadBalancer and FastPath worker queues.
- **Unified Bidirectional Flow Map**: Searches the flow table for both the forward tuple and the reverse tuple. When a new flow is registered, it is mapped under both keys, resolving to the same `FlowEntry` instance. This preserves the direction context (`is_upload` tracking) and enables correct calculation of bidirectional features like upload/download byte ratios and stateful anomaly correlation.

### 2.7 Threat Intelligence Feed Ingestion
DPI Engine implements dynamic threat intelligence ingestion using public reputation blocklists:
- **Supported Feeds**: Automatically fetches and parses abuse.ch Feodo Tracker (C2 IPs), OpenPhish (phishing domains), Spamhaus DROP (malicious IP blocks), and URLhaus (malware distribution domains).
- **Background Updates**: Launches feed fetching in a background daemon thread on startup so it does not block the engine's initialization.
- **REST & CLI Controls**: Supports manual updating via `POST /api/threat-intel/update` or the CLI command `python cli.py threat-intel update`.
- **Redis Bloom Filter**: Integrates with a local Redis instance using RedisBloom filters (`BF.ADD` / `BF.EXISTS`) for O(1) space-efficient lookups, falling back to Python sets if Redis is offline.

### 2.8 Real Performance Benchmarks
We measured the engine's performance under offline PCAP replay and real-time inference (stored in `scratch/benchmark_results.json`):
- **Packet Throughput**: **1,598 pps** (measured using `live_output.pcap`).
- **ETI Classifier Inference Latency**: **5.5ms** (using the Random Forest model).
- **In-Memory Footprint**: Multi-threaded packet classification with minimal context-switch overhead.

---

## 3. Architecture & Codebase Map

The project is structured into modular Python files and a Next.js dashboard:

```
dpi_engine/
├── common.py        # Core enums, packet models, PCAP I/O, thread-safe Rules & Stats
├── parsers.py        # Binary protocol parsers, HPACK, Huffman, and JA3/JA4 generation
├── classifiers.py    # ETI feature extraction & ONNX / RandomForest inference
├── anomaly.py         # Stateful IDS: TCP/DNS/HTTP anomaly detectors & MITRE mapping
├── analytics.py       # Flow-level and global throughput metrics
├── pipeline.py        # LoadBalancer, FastPath workers, DPIEngine, active blocking
├── threat_intel.py    # Redis Bloom Filter & local fallback threat lookups
├── geoip.py           # MaxMind GeoLite2 country resolution
└── ui.py               # Dashboard HTTP server & REST APIs

cli.py                 # Click-based CLI, talks to the dashboard's REST API
dpi_engine.py           # Direct backend runner (argparse-based, no dashboard required)
dashboard/              # Next.js React frontend
scratch/                 # Training scripts, test PCAP generators, analysis utilities
```

---

## 4. Getting Started

### 4.1 System Prerequisites
- **Python**: Version 3.9 or higher.
- **Network Access**: Administrator or root privileges are required to run live captures and inject spoofed packet blocks.
- **Npcap (Windows)**: Install Npcap and ensure "WinPcap API-compatible mode" is enabled.
- **libpcap (Linux)**: Install development libraries via package manager (e.g., `apt-get install libpcap-dev`).

### 4.2 Installation
Clone the repository and install the Python dependencies:
```bash
pip install -r requirements.txt
```

### 4.3 Running the Engine via CLI
Use the Click-based command-line tool `cli.py` (or execute `dpi.bat` on Windows):
```bash
# Start the web dashboard backend and control center
python cli.py dashboard --host 127.0.0.1 --port 8765

# Replay an offline PCAP file with block filters
python cli.py replay test_dpi.pcap --output filtered.pcap --block-domain "facebook.com"

# Check the live statistics and throughput metrics
python cli.py status

# List recent security alerts and protocol anomalies
python cli.py alerts

# Trigger threat intelligence feeds updates manually
python cli.py threat-intel update
```

### 4.4 Running Directly (Direct Ingest Engine)
Run the direct backend script `dpi_engine.py` (which uses standard `argparse` instead of Click):
```bash
# Process a local PCAP file and block a source IP
python dpi_engine.py input.pcap output.pcap --block-ip 192.168.1.100

# Capture live traffic on interface 'eth0' for 60 seconds
python dpi_engine.py --live capture.pcap --iface eth0 --duration 60
```

### 4.5 Setting Up the Next.js Dashboard Frontend
Navigate to the dashboard directory, install dependencies, and start the development server:
```bash
cd dashboard
npm install
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) to view the live dashboard interface.

---

## 5. Technical Limitations & Trade-offs

Real-world deployments involve specific tradeoffs. Understanding these limitations is critical for operating the platform effectively:

- **Bidirectional Flow Routing**: Packets are routed to worker threads by sorting the source/destination IPs and ports before hashing. This ensures both directions of a flow (client $\to$ server and server $\to$ client) land on the same worker thread, allowing stateful anomaly checking to successfully correlate bidirectional packets.
- **No TCP Stream Reassembly**: Packets are processed individually. The engine does not perform TCP sequence reordering or reassembly. Handshakes split across multiple packets or packets arriving out-of-order will fail L7 protocol parsing.
- **Static HPACK Table Range**: The HTTP/2 HPACK decoder only decodes static table indexes (1–8 and 58). Dynamic table updates and eviction are not supported.
- **eBPF Bypass**: The capture loop runs in userspace via Scapy/PCAP, not as a kernel hook (like eBPF or XDP). This limits the maximum packet processing rate.
- **Threat Feed Fetching**: Dynamic threat intelligence feed ingestion is implemented. The engine automatically fetches and parses blocklists from abuse.ch Feodo Tracker, OpenPhish, Spamhaus DROP, and URLhaus. Feed updates run in a background daemon thread upon startup, and can also be triggered manually via a POST request to `/api/threat-intel/update` or the CLI command `dpi threat-intel update`.
- **Active Blocking loopback limitations**: On Windows, spoofed TCP RST and ICMP Port Unreachable packets targeting local loopback are dropped by the OS network stack, bypassing client-side blocking when running on the same host.

---

## 6. Project Roadmap

- [x] Implement bi-directional flow matching to route both directions of a flow to the same worker thread.
- [ ] Add TCP stream reassembly to handle segmented payloads.
- [x] Implement scheduled threat feed updates from public blocklists.
- [ ] Train ETI models on real labeled datasets (such as CICIDS2017 or UNSW-NB15).
- [ ] Export Prometheus metrics.
- [ ] Add Docker Compose configurations for full-stack local deployment.

---

## 7. License

This project is licensed under the MIT License. See `LICENSE` for details.
