# DPI Engine — Execution Guide

This guide describes how to run, configure, and test the upgraded Deep Packet Inspection (DPI) and Network Traffic Intelligence Platform.

---

## 1. Prerequisites & Environment Setup

Before running the engine, ensure your Python environment is set up.

```bash
# Verify Python version (requires Python 3.8+)
python --version

# Install required dependencies
pip install scapy scikit-learn numpy joblib
```

> [!IMPORTANT]
> **Windows Users**: 
> To capture live network packets, you must install **Npcap** (ensure you check the box to **"Install Npcap with WinPcap API-compatible Mode"** during installation).

---

## 2. Step-by-Step Execution Commands

### Step 2.1. Train the ETI Machine Learning Model
Train the Random Forest classifier on the 17 ETI behavioral features (packet size histograms, inter-arrival times, byte ratios, and burst details) before starting the DPI engine:

```bash
python scratch/train_eti_model.py
```
*   **Output**: Saves the serialized classifier to `models/eti_rf_model.pkl`. The engine will load this model automatically at startup. If this file is missing, the engine will gracefully fall back to its statistical heuristic engine.

---

### Step 2.2. Generate a Test PCAP File
Create a test network trace containing simulated IPv4, IPv6, TCP, UDP, TLS Client Hello (with SNIs like `youtube.com` and `discord.com`), DNS queries, and HTTP/1.x headers:

```bash
python dpi_engine.py --generate-test-pcap test_dpi.pcap
```

---

### Step 2.3. Analyze PCAP Offline
Run the multi-threaded DPI pipeline to analyze packets in a PCAP file, apply blocking rules, classify traffic, and output the filtered packets to a new file:

```bash
# Standard analysis
python dpi_engine.py test_dpi.pcap output.pcap

# Analysis with active blocking rules
python dpi_engine.py test_dpi.pcap output.pcap --block-app YouTube --block-domain discord.com --block-ip 192.168.1.100

# Customize pipeline threads (e.g., 4 load balancers, 4 worker threads per LB)
python dpi_engine.py test_dpi.pcap output.pcap --lbs 4 --fps 4
```

---

### Step 2.4. Run the Web Dashboard Control Center
Monitor decisions, application breakdowns, JA3/JA4 TLS fingerprints, and ETI threat scores in real-time.

#### Option A: Offline Replay Dashboard
Start the dashboard alongside an offline PCAP replay run:
```bash
python dpi_engine.py test_dpi.pcap output.pcap --dashboard
```

#### Option B: Standalone Dashboard Control Center
Launch the dashboard in standalone controller mode. This allows you to choose an interface, configure blocking rules, and start/stop live capture dynamically from the web interface:
```bash
python dpi_engine.py --dashboard --dashboard-port 8765
```
*   **URL**: Open [http://127.0.0.1:8765](http://127.0.0.1:8765) in your web browser.

---

### Step 2.5. Run Live Packet Capture (CLI Mode)
To capture live packets on a network interface directly from the command line:

```bash
# List available network interfaces
python dpi_engine.py --list-ifaces

# Capture live traffic on a specific interface and save to output.pcap
python dpi_engine.py --live live_output.pcap --iface "Ethernet"

# Capture with a duration limit (seconds) and packet count limit
python dpi_engine.py --live live_output.pcap --iface "Ethernet" --duration 30 --count 1000 --bpf "tcp port 443"
```

---

### Step 2.6. Verify Flow Analytics & Protocol Anomaly Detection
Run the anomaly verification test to generate a custom PCAP containing simulated threat vectors (TCP SYN flood, DNS tunneling, HTTP request smuggling) and process it using the engine:

```bash
# Generate anomaly test PCAP
python scratch/test_anomalies.py

# Run DPI analysis to detect anomalies and apply blocking actions
python dpi_engine.py test_anomalies.pcap output_anomalies.pcap
```
*   **Verification**: The engine will detect the anomalies, log them to the statistics database, mark the anomalous flows as blocked, and drop the remaining packets belonging to those flows (e.g. dropping 7 packets). When running the web dashboard alongside it, these alerts will pulse in red in the **Recent Protocol Anomalies** panel, and the flow throughput stats will display in the **Top Talkers** panel.

---

## 3. Configuration & CLI Options reference

Run the help command to see the full list of supported arguments and flags:

```bash
python dpi_engine.py --help
```

### Key Parameters:
*   `--generate-test-pcap <path>`: Generates a test PCAP file with simulated traffic.
*   `--list-ifaces`: Lists all network interfaces available to Scapy.
*   `--live`: Enables live capture mode.
*   `--iface <name>`: Specifies the network interface name for live capture.
*   `--duration <seconds>`: Live capture timeout.
*   `--count <number>`: Live capture packet count limit.
*   `--bpf <filter>`: Sets a custom BPF filter (e.g., `udp port 53`).
*   `--dashboard`: Starts the HTTP dashboard monitor.
*   `--dashboard-port <port>`: Sets the dashboard bind port (default: `8765`).
*   `--block-ip <IP>`: Discards packets originating from this source IP.
*   `--block-app <Name>`: Discards packets matching classified applications (e.g. `Spotify`, `TikTok`).
*   `--block-domain <Substring>`: Discards packets matching a domain substring (e.g. `facebook`).
*   `--lbs <count>`: Sets the number of load balancer threads (default: `2`).
*   `--fps <count>`: Sets the number of fast path threads per load balancer (default: `2`).

---

## 4. Simplified CLI Tool (`dpi`)

We have introduced a simplified and extremely user-friendly command-line wrapper `dpi` (via `cli.py` and `dpi.bat` for Windows). This eliminates complex flag chains.

### 4.1. Available Commands:
- `.\dpi dashboard` / `python cli.py dashboard`: Launches the Web Dashboard Control Center.
- `.\dpi start` / `python cli.py start`: Initiates a live packet capture session on the running dashboard. Options: `--iface`, `--output`, `--duration`, `--count`, `--bpf`.
- `.\dpi stop` / `python cli.py stop`: Stops the active live capture session.
- `.\dpi status` / `python cli.py status`: Shows current status, statistics, and rolling 10-second throughput.
- `.\dpi replay <pcap_file>` / `python cli.py replay <pcap_file>`: Replays and inspects a sample PCAP file offline. Options: `--output`, `--block-ip`, `--block-app`, `--block-domain`.
- `.\dpi export` / `python cli.py export`: Exports session stats or packet decision logs. Options: `--file`, `--type`.
- `.\dpi rules <list|add|remove>` / `python cli.py rules <list|add|remove>`: Manages blocking rules.
- `.\dpi alerts` / `python cli.py alerts`: Lists recent protocol anomalies and security alerts.

### 4.2. Example Quick-Start Workflow:
```bash
# 1. Start the control center dashboard (binds to http://127.0.0.1:8765)
.\dpi dashboard

# 2. In another terminal, add a blocking rule for YouTube
.\dpi rules add app YouTube

# 3. Check the current status of the engine
.\dpi status

# 4. View active alerts (e.g. if any DNS Tunneling or SYN Floods are detected)
.\dpi alerts
```
