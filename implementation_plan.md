# DPI Engine — Phase 1 & Phase 2 Implementation Plan

This plan outlines the architecture, data structures, and step-by-step implementation for upgrading the [DPI Engine](file:///D:/Deep%20Packet%20Inpection/dpi_engine.py) to support **Phase 1 (Advanced DPI)** and **Phase 2 (Encrypted Traffic Intelligence - ETI)**.

---

## 1. Phase 1 — Advanced DPI Features

### 1.1. IPv6 Support
To support IPv6 traffic seamlessly, we must update the ingestion and parsing pipeline to recognize IPv6 headers and support 128-bit addresses in the flow table.

#### 1.1.1. Ingestion Changes
- Add `EtherType.IPV6 = 0x86dd` to the parser.
- In `PacketParser.parse()`, check for `parsed.ether_type == EtherType.IPV6` and invoke a new `_parse_ipv6()` method.
- **IPv6 Header Structure** (40 bytes):
  - Version (4 bits): Must be `6`.
  - Next Header (8 bits): Identifies the transport protocol (TCP/UDP) or extension header.
  - Source IP (16 bytes) and Destination IP (16 bytes): Decoded to standard representation using `socket.inet_ntop(socket.AF_INET6, ...)`.
- **Extension Headers Loop**: IPv6 can chain extension headers (e.g., Hop-by-Hop options `0`, Routing `43`, Fragment `44`, Destination Options `60`). The parser will follow the chain by reading the Next Header and Header Length bytes until it reaches TCP (`6`), UDP (`17`), or no next header (`59`).

#### 1.1.2. Flow Table Upgrades
- Modify [FiveTuple](file:///D:/Deep%20Packet%20Inpection/dpi_engine.py#L267) to store IP addresses as strings (e.g. `'192.168.1.100'` or `'2001:db8::1'`). This natively handles IPv4 and IPv6.
- Update `five_tuple_hash()` to convert IP strings to standard integers (32-bit for IPv4, 128-bit for IPv6) before running the XOR-shift hashing, preserving the lock-less routing logic:
  ```python
  def ip_to_int(ip_str: str) -> int:
      if ":" in ip_str:
          return int.from_bytes(socket.inet_pton(socket.AF_INET6, ip_str), 'big')
      return int.from_bytes(socket.inet_pton(socket.AF_INET, ip_str), 'big')
  ```
- Simplify `FiveTuple.to_string()` to return direct strings without requiring `ip_to_string_little`.

#### 1.1.3. Upgraded FlowEntry Dataclass
Below is the updated `FlowEntry` definition integrating both Phase 1 and Phase 2 fields. It instantiates the behavioral extractor on initialization using `__post_init__`.

```python
@dataclass
class FlowEntry:
    tuple: FiveTuple
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""
    packets: int = 0
    bytes: int = 0
    blocked: bool = False
    classified: bool = False

    # --- Phase 1: Handshake Fingerprinting ---
    ja3_string: str = ""       # Format: version,ciphers,extensions,groups,formats
    ja3_hash: str = ""         # MD5 hash of ja3_string
    ja4_string: str = ""       # Format: A_B_C segments

    # --- Phase 2: Encrypted Traffic Intelligence (ETI) ---
    eti_extractor: "ETIFeatureExtractor" = field(default=None, init=False)
    eti_classification: str = "BENIGN"   # BENIGN, SUSPICIOUS, or MALICIOUS
    eti_confidence: float = 1.0          # Confidence score [0.0, 1.0]
    
    # --- Timing Tracking ---
    first_seen: float = 0.0
    last_seen: float = 0.0

    def __post_init__(self) -> None:
        # Initialize timestamps
        import time
        now = time.time()
        self.first_seen = now
        self.last_seen = now
        
        # Instantiate the ETI behavioral feature extractor for this flow
        self.eti_extractor = ETIFeatureExtractor(self.tuple)
```

---

## 2. Phase 1.2 — JA3 & JA4 Fingerprinting
TLS Client Hello fingerprinting identifies clients without decryption by examining handshake negotiation details.

```
                    ┌─────────────────────────┐
                    │    TLS Client Hello     │
                    └────────────┬────────────┘
                                 │
                   ┌─────────────┴─────────────┐
                   ▼                           ▼
            ┌─────────────┐             ┌─────────────┐
            │  JA3 Hash   │             │  JA4 Hash   │
            └──────┬──────┘             └──────┬──────┘
                   │                           │
                   ▼                           ▼
            MD5 of comma-       Segmented SHA-256 of:
            separated decimal   - A: Transport, SNI, ALPN
            values.             - B: Sorted Ciphers
                                - C: Sorted Extensions + Sig Algs
```

#### TLS Parsing Upgrades
We will extend [SNIExtractor](file:///D:/Deep%20Packet%20Inpection/dpi_engine.py#L582) to extract all fields required for fingerprinting from the TLS Client Hello:
- **Version**: Handshake protocol version (typically `0x0303` for TLS 1.2+). We will also scan extensions for the `supported_versions` extension (`0x002b`) to identify the real version (e.g., `0x0304` for TLS 1.3).
- **Cipher Suites**: List of 16-bit integers.
- **Extensions**: List of 16-bit extension types.
- **Supported Groups (Elliptic Curves)**: List of 16-bit integers from the `supported_groups` extension (`0x000a`).
- **Elliptic Curve Point Formats**: List of 8-bit values from the `ec_point_formats` extension (`0x000b`).
- **ALPN**: List of application layer protocol strings from the `alpn` extension (`0x0010`).
- **Signature Algorithms**: List of 16-bit signature algorithms from the `signature_algorithms` extension (`0x000d`).

#### GREASE Filtering
GREASE values (RFC 8701) must be removed from all lists before fingerprinting. A 16-bit value `val` is GREASE if:
`val & 0x0f0f == 0x0a0a and (val & 0xff) == (val >> 8)`

#### Fingerprint Generators
1. **JA3**:
   - Format: `TLSVersion,Ciphers,Extensions,SupportedGroups,PointFormats` (decimal, joined by hyphens, then comma-separated).
   - Output: The raw string and its MD5 hash.
2. **JA4**:
   - Segment A (10 chars): `{protocol}{version}{sni}{cipher_count}{ext_count}{alpn_first}`
     - `protocol`: `t` (TCP/TLS) or `q` (QUIC).
     - `version`: `13` (TLS 1.3), `12` (TLS 1.2), etc., or `00`.
     - `sni`: `d` (domain SNI), `i` (IP SNI), or `n` (no SNI).
     - `cipher_count`: Number of ciphers (max 99, 2-digit zero-padded).
     - `ext_count`: Number of extensions (max 99, 2-digit zero-padded).
     - `alpn_first`: First 2 characters of first ALPN (e.g., `h2`), or `00` if none.
   - Segment B (12 chars): SHA-256 of sorted hex ciphers (comma-separated, lowercase), truncated to 12 chars.
   - Segment C (12 chars): SHA-256 of sorted hex extensions (excluding SNI/ALPN) concatenated with an underscore `_` and the unsorted signature algorithms (if present), truncated to 12 chars. If extensions and sig-algs are both empty, output `000000000000`.

---

## 3. Phase 1.3 — HTTP/2 Parsing
HTTP/2 runs as binary framing over TCP (port 443 / 80).
- **Frame Header** (9 bytes):
  - Length (24 bits)
  - Type (8 bits)
  - Flags (8 bits)
  - Stream ID (31 bits)
- **Frame Types to Parse**:
  - `0x01` (HEADERS): Contains HPACK-compressed headers.
  - `0x04` (SETTINGS): Identifies HTTP/2 protocol options.
- **HPACK Decoder**:
  We will implement a lightweight, self-contained HPACK decoder:
  - Supports Indexed Header Fields (`1xxxxxxx`) referencing the Static Table (e.g., index `1` is `:authority`, index `58` is `user-agent`).
  - Supports Huffman-encoded string fields (bit `7` of string length byte is `1`), utilizing a precomputed decoding table for the standard HTTP/2 Huffman tree.
  - Extracts: `:authority` (Host), `:path` (URI), and `user-agent`.

---

## 4. Phase 1.4 — QUIC & HTTP/3 Inspection
QUIC traffic runs over UDP (port 443).
- **Initial Packet Identification**:
  - Long header flag (high bit set: `0x80`).
  - Packet Type: Initial (`0x00` in bits 4-5 of the first byte, i.e., `0xc0` mask).
  - Version: `0x00000001` (QUIC v1) or `0xff00001d` (QUIC Draft-29).
- **Parsing In-Kernel/User-Space**:
  - Extract Destination Connection ID (DCID) and Source Connection ID (SCID).
  - Parse the Token and Length fields to locate the payload.
  - Scan the payload for **CRYPTO Frames** (type `0x06`).
  - Extract the Crypto Data payload, which contains the raw TLS Client Hello.
  - Pass the TLS Client Hello payload to our `SNIExtractor` and `JA3`/`JA4` generators.

---

## 5. Phase 2 — Encrypted Traffic Intelligence (ETI)

ETI classifies traffic security posture (e.g., detecting exfiltration or beaconing) by analyzing behavioral attributes of encrypted flows without decryption.

```
                    ┌─────────────────────────┐
                    │    Raw Network Flow     │
                    └────────────┬────────────┘
                                 │
                   ┌─────────────┴─────────────┐
                   ▼                           ▼
            Behavioral Features         TLS Record Layer
            - IAT Mean, Variance        - Record Lengths
            - Packet size histogram     - Record Count
            - Byte ratios, bursts
                   │                           │
                   └─────────────┬─────────────┘
                                 │
                                 ▼
                     ┌───────────────────────┐
                     │ ETIFeatureExtractor   │
                     └───────────┬───────────┘
                                 │
                   ┌─────────────┴─────────────┐
                   ▼                           ▼
            ┌──────────────┐            ┌──────────────┐
            │ RandomForest │            │  Heuristic   │
            │  Classifier  │            │   Fallback   │
            └──────┬───────┘            └──────┬───────┘
                   │                           │
                   └─────────────┬─────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │  Classification Output  │
                    │   - BENIGN (conf)       │
                    │   - SUSPICIOUS (conf)   │
                    │   - MALICIOUS (conf)    │
                    └─────────────────────────┘
```

### 5.1. Feature Extraction Per Flow
We will define an `ETIFeatureExtractor` attached to each `FlowEntry`. It will record:
1. **Packet Sizes (Payload)**:
   - Maintains a 10-bucket histogram of payload sizes (ranges: `0-100`, `101-200`, `201-400`, `401-600`, `601-800`, `801-1000`, `1001-1200`, `1201-1400`, `1401-1600`, `>1600`).
   - Running mean and variance of payload sizes.
2. **Timing Patterns**:
   - Calculates Inter-Arrival Times (IAT) in milliseconds.
   - Computes running mean and variance of IAT.
   - Computes Coefficient of Variation (CV = `iat_std_dev / iat_mean`) to flag low-variance beaconing.
3. **Direction Ratio**:
   - Tracks `client_bytes` and `server_bytes` based on packet direction relative to the flow initiator.
   - Calculates the byte ratio: `client_bytes / (client_bytes + server_bytes + 1)`.
4. **Burst Analysis**:
   - Identifies a burst as a series of consecutive packets in one direction.
   - Computes `burst_count` and `avg_burst_size`.
5. **TLS Record Layer**:
   - Parsed from the TCP payload (if TLS): extracts record count and record length distribution.

### 5.2. ETI Machine Learning Model
We will write an `ETIClassifier` module that wraps a Scikit-Learn `RandomForestClassifier`:
- **Training**: We will provide a training script in the `scratch/` directory that reads a CSV dataset (e.g. UNSW-NB15 flow features) or parses PCAP files, fits a `RandomForestClassifier` on the 17 ETI features, and serializes the model to `eti_rf_model.pkl` using `joblib`.
- **Inference**: The `ETIClassifier` will load `eti_rf_model.pkl` at startup. For active flows, it will classify the extracted features.
- **Robust Fallback**: If `eti_rf_model.pkl` is not found, the classifier will execute a **Heuristic Fallback Engine** to score threat indicators:
  - *Beaconing*: Low IAT variance (CV < 0.15) over 10+ packets -> `SUSPICIOUS`
  - *Data Exfiltration*: Byte ratio > 0.85 and total bytes > 5MB -> `SUSPICIOUS`
  - *Covert Tunneling*: Small uniform payload sizes (variance < 20, mean < 80) and DNS protocol -> `MALICIOUS`
  - Otherwise -> `BENIGN`

---

## 6. Integration & Code Architecture

### 6.1. File Structure Changes
```
D:\Deep Packet Inpection\
│   dpi_engine.py          # Updated with IPv6 parser, HTTP/2 & QUIC extractors
│   README.md              # Documentation updates
│
├───models/
│       eti_rf_model.pkl   # Serialized Random Forest model
│
└───scratch/
        train_eti_model.py # Training script for ETI classifier
```

### 6.2. Flow Pipeline Integration
On every packet processed in `FastPath._process()`:
1. Parse IPv4/IPv6 packet headers.
2. Retrieve or create `FlowEntry`.
3. Feed raw payload to JA3/JA4 fingerprinting and HTTP/2 or QUIC parsers.
4. Pass packet data (timing, size, direction) to `FlowEntry.eti_extractor.add_packet()`.
5. Every 50 packets (or upon flow expiration/termination), run `ETIClassifier.classify(flow.eti_extractor.get_features())` and update `flow.eti_classification` and `flow.eti_confidence`.
6. Update rules checking: block flow if `eti_classification == "MALICIOUS"`.

---

## 7. UI & Dashboard Upgrades

We will update `DASHBOARD_HTML` in `dpi_engine.py` to display the new telemetry:
- Add **JA3 / JA4 Fingerprint** columns to the Live Traffic table.
- Display **IPv6 address** support in tables and statistics.
- Show **ETI Classifications** (`BENIGN`, `SUSPICIOUS`, `MALICIOUS`) with color-coded badges and confidence scores.
- Add an **Encrypted Analytics Widget** displaying a breakdown of TLS fingerprints and detected anomalies.

---

## 8. Modular Code Restructuring (Phase 2.5)

To prevent `dpi_engine.py` from growing into an unmanageable single file, we will partition the codebase into the following module structure under a new package directory `dpi_engine/`:

- `dpi_engine/__init__.py`: Package entry point.
- `dpi_engine/common.py`: Shared constants, enumerations, datastructures (`AppType`, `EtherType`, `Protocol`, `TCPFlags`, `FiveTuple`, `Stats`, `Rules`, `TSQueue`).
- `dpi_engine/parsers.py`: Protocol parsing logic (`PacketParser`, `SNIExtractor`, `HTTPHostExtractor`, `DNSExtractor`, `QUICSNIExtractor`, `TLSClientHelloParser`, `HuffmanDecoder`, `HTTP2Parser`, `QUICParser`).
- `dpi_engine/classifiers.py`: Machine Learning classification (`ETIFeatureExtractor`, `ETIClassifier`).
- `dpi_engine/analytics.py`: Flow metrics and global aggregates calculation (Phase 3).
- `dpi_engine/anomaly.py`: Stateful TCP, HTTP, and DNS anomaly state machines (Phase 4).
- `dpi_engine/pipeline.py`: Load balancing, multi-threaded pipelines (`FlowEntry`, `FastPath`, `LoadBalancer`, `DPIEngine`, `PCAPWriter`).
- `dpi_engine/ui.py`: Dashboard HTTP server and web API (`DashboardController`, `DashboardServer`, `DASHBOARD_HTML`).

A thin bootstrap script `dpi_engine.py` will remain at the root level to preserve backward compatibility for all CLI interfaces.

---

## 9. Phase 3 — Flow Analytics Engine

The Flow Analytics Engine computes micro-level connection performance metrics and macro-level aggregate network trends.

### 9.1. Micro-Level Flow Metrics
We will track the following metrics on the `FlowEntry` object:
- `start_time` / `last_seen`: Floating-point Unix timestamps of the first and last packet.
- `duration`: Calculated as `last_seen - start_time` (minimum 0.001 seconds to avoid division by zero).
- `client_packets` / `server_packets`: Packet count in each direction relative to the flow initiator.
- `client_bytes` / `server_bytes`: Payload bytes in each direction.
- `packet_rate`: Total packets divided by duration (packets per second).
- `throughput`: Total bytes divided by duration (bytes per second).

These statistics will be updated dynamically on every packet processed in the `FastPath` worker.

### 9.2. Macro-Level Global Aggregates
A new global tracking structure (or extensions in `Stats`) will aggregate:
- **Global Throughput**: Rolling bytes/sec and packets/sec calculated using sliding 10-second window buckets.
- **Protocol Distribution**: Breakdown of flows, packets, and bytes per protocol type (HTTP, HTTPS, HTTP/2, QUIC, DNS, Unknown).
- **Top Talkers**: The top 10 active flows sorted by total bytes.

### 9.3. Web Dashboard Charting
We will update the HTML/JS dashboard:
- Integrate **Chart.js** from a CDN (`https://cdn.jsdelivr.net/npm/chart.js`).
- Render a live **Throughput Line Chart** showing rolling bps (bits/sec) and pps.
- Render a **Protocol Distribution Pie/Doughnut Chart**.
- Render a **Top Talkers Horizontal Bar Chart**.

---

## 10. Phase 4 — Stateful Protocol Anomaly Detection

Stateful Protocol Anomaly Detection monitors packet streams to detect TCP flood attacks, HTTP request smuggling, DNS tunneling, and cache poisoning.

### 10.1. TCP Stateful Anomaly Detector
A `TCPStateMachine` will be created for each TCP flow:
- **States**: `CLOSED` -> `SYN_SENT` / `SYN_RCVD` -> `ESTABLISHED` -> `FIN_WAIT` / `CLOSE_WAIT` -> `CLOSED`.
- **Anomalies**:
  - **TCP SYN Flood**: If client sends more than 20 SYN packets without completing the 3-way handshake (receiving a SYN-ACK and sending an ACK).
  - **Out-of-Order Handshake**: Data packets, FIN, or RST packets received before the flow enters `ESTABLISHED` state.
  - **Invalid Flags combination**: Flag combinations such as SYN+FIN, SYN+RST, or null/all flags set (Xmas scan).

### 10.2. DNS Anomaly Detector
A `DNSAnomalyDetector` will inspect UDP port 53 packets:
- **Anomalies**:
  - **DNS Tunneling**: Identifies potential covert channels by flagging subdomains that:
    - Exceed 50 characters in length.
    - Exhibit high entropy (Shannon entropy > 4.5 bits) indicative of base64/hex encoding.
    - Exceed query rates of 50 queries/sec from a single source.
  - **DNS Cache Poisoning / Spoofing**:
    - Flags multiple responses for the same transaction ID (TXID) with conflicting answers.
    - Flags response packets with a TXID that does not match any active query pending in the flow list.

### 10.3. HTTP Anomaly Detector
An `HTTPAnomalyDetector` will inspect HTTP/1.x and HTTP/2 payloads:
- **Anomalies**:
  - **HTTP Request Smuggling**: Flags requests containing both `Content-Length` and `Transfer-Encoding: chunked` headers, or an invalid chunk length format.
  - **HTTP Method Anomaly**: Flags requests containing non-RFC methods (e.g., anything other than GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH, CONNECT).
  - **Header Overflow**: Flags request header size exceeding 16KB.

### 10.4. Integration & Rules Action
- Any detected anomaly will create an anomaly event recorded in `FlowEntry.anomalies` list: `{"timestamp": float, "type": str, "description": str}`.
- Global statistics will keep counts of anomalies by type.
- The web interface will show an **Anomaly Alert log** containing recent alerts and badging on individual flows.
- If configured (e.g. via rules or command line), flows with critical anomalies (such as SYN Flood or Smuggling) will be immediately marked as `blocked = True` and dropped.
