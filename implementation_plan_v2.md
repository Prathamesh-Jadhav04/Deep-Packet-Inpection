# Plan: Safe Implementation of Missing Features in Deep Packet Inspection Engine

We will implement the remaining 6 features in a highly modular and safe way, ensuring the engine never crashes if optional dependencies (Redis, ONNX Runtime, GeoIP, OpenTelemetry) are missing.

---

## 1. DNS Enhancements: DoT & DoH Detection
- **DoT (DNS over TLS):**
  - Detect traffic on port `853` (TCP/UDP).
  - Parse the TLS Client Hello on port 853 to extract SNI and classify `AppType` as `AppType.DNS` with subtype `DoT`.
- **DoH (DNS over HTTPS):**
  - In `pipeline.py` or HTTP/2 HPACK parsing, check if:
    - The host/SNI matches common DoH endpoints (e.g., `cloudflare-dns.com`, `dns.google`, `dns.quad9.net`).
    - The HTTP/1.x or HTTP/2 headers contain `Content-Type: application/dns-message`.
    - The path matches `/dns-query`.
  - Classify the flow's `app_type` as `AppType.DNS` with subtype `DoH`.

## 2. IDS Features: MITRE ATT&CK Technique IDs
- **Alert Enrichment:**
  - Update `dpi_engine/anomaly.py` to add a `mitre_id` and `technique_name` to every generated anomaly alert.
- **Mapping:**
  - *TCP SYN Flood:* `T1498` (Network Service Denial: Direct Network Flood)
  - *HTTP Request Smuggling:* `T1210` (Exploitation of Remote Service)
  - *DNS Tunneling:* `T1071.004` (Application Layer Protocol: DNS)
  - *Header Overflow:* `T1190` (Exploit Public-Facing Application)

## 3. Threat Intelligence: Redis / In-Memory Bloom Filter
- **Modular Lookup:**
  - Create `dpi_engine/threat_intel.py`.
  - Check for a running Redis connection. If available, use Redis Bloom Filter commands (`BF.EXISTS`).
  - **Fallback:** If Redis is unavailable, fall back to a high-performance in-memory Python `set` or a pure-Python hash-based bloom filter.
- **Free Feeds:**
  - List free sources (Abuse.ch, Feodo, OpenPhish, Spamhaus) in comments and fetch/populate threat lists from them.

## 4. AI Anomaly Detection: ONNX Inference
- **ONNX Inference:**
  - In `classifiers.py`, check if `onnxruntime` is installed and if `models/eti_model.onnx` is present.
  - If yes, use ONNX Runtime to perform ETI classification inference (runs in ~10ms).
  - **Fallback:** Gracefully fall back to standard `joblib` loading of `eti_rf_model.pkl` or heuristics.
- **ONNX Export Script:**
  - Add an export script in `scratch/export_onnx.py` that converts the RandomForest model to ONNX format.

## 5. GeoIP Intelligence: MaxMind GeoLite2
- **GeoIP Lookup:**
  - Integrate a GeoIP reader in `dpi_engine/common.py`.
  - Read `models/GeoLite2-Country.mmdb` (if present) to resolve country names for destination IPs.
  - **Fallback:** If database is missing, default to `"Local/Unknown"` without throwing errors.

## 6. Observability: OpenTelemetry & eBPF Counters
- **OTel Tracing:**
  - Add proper OpenTelemetry spans in `dpi_engine/pipeline.py` around `process_packet()` and `classify()`.
  - Fall back gracefully if `opentelemetry` packages are not installed, making the dependency optional.
- **eBPF Drop Count (Linux-only, Planned):**
  - Document eBPF integration honestly in the project documentation (README/Guide) as a Linux-only architecture roadmap, showing how an XDP/TC eBPF program would count dropped packets in kernel-space and expose them to user-space via a BPF map. No mock eBPF code will be written in the Python engine.
/