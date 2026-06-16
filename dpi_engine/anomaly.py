from __future__ import annotations

import collections
import math
import struct
from typing import Any, Dict, List, Optional, Tuple

def get_mitre_mapping(anomaly_type: str) -> Dict[str, str]:
    mapping = {
        "Invalid Flags combination": ("T1046", "Active Scanning"),
        "Out-of-Order Handshake": ("T1024", "Protocol Impersonation"),
        "TCP SYN Flood": ("T1498.001", "Network Service Denial: Direct Network Flood"),
        "DNS Tunneling": ("T1071.004", "Application Layer Protocol: DNS"),
        "DNS Cache Poisoning / Spoofing": ("T1557", "Adversary-in-the-Middle"),
        "Header Overflow": ("T1190", "Exploit Public-Facing Application"),
        "HTTP Method Anomaly": ("T1071.001", "Application Layer Protocol: Web Protocols"),
        "HTTP Request Smuggling": ("T1210", "Exploitation of Remote Service")
    }
    mitre_id, technique = mapping.get(anomaly_type, ("T1071", "Application Layer Protocol"))
    return {
        "mitre_id": mitre_id,
        "mitre_technique": technique
    }


class TCPFlags:
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20


class TCPStateMachine:
    """
    Tracks TCP flags and state transitions:
    CLOSED -> SYN_SENT/SYN_RCVD -> ESTABLISHED -> FIN_WAIT/CLOSE_WAIT -> CLOSED
    """
    def __init__(self) -> None:
        self.state = "CLOSED"
        self.syn_count = 0
        self.client_ip = None
        self.client_port = None
        self.syn_flood_flagged = False

    def update(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        flags: int,
        payload_len: int,
        timestamp: float
    ) -> List[Dict[str, Any]]:
        anomalies: List[Dict[str, Any]] = []

        # Initialize client IP/port on the first packet of the flow
        if self.client_ip is None:
            self.client_ip = src_ip
            self.client_port = src_port

        is_client = (src_ip == self.client_ip and src_port == self.client_port)

        # Extract flags
        syn = bool(flags & TCPFlags.SYN)
        ack = bool(flags & TCPFlags.ACK)
        fin = bool(flags & TCPFlags.FIN)
        rst = bool(flags & TCPFlags.RST)
        psh = bool(flags & TCPFlags.PSH)
        urg = bool(flags & TCPFlags.URG)

        # 1. Check for Invalid Flags combination
        invalid_flags = False
        flag_desc = []
        if flags == 0:
            invalid_flags = True
            flag_desc.append("null flags")
        if syn and fin:
            invalid_flags = True
            flag_desc.append("SYN+FIN")
        if syn and rst:
            invalid_flags = True
            flag_desc.append("SYN+RST")
        # Xmas Scan: FIN+PSH+URG set, or all flags set
        if (flags & 0x29) == 0x29 or (flags & 0x3F) == 0x3F:
            invalid_flags = True
            flag_desc.append("Xmas scan")

        if invalid_flags:
            anomalies.append({
                "timestamp": timestamp,
                "type": "Invalid Flags combination",
                "description": f"Invalid TCP flag combination: {', '.join(flag_desc)} (flags={hex(flags)})"
            })

        # 2. Check for Out-of-Order Handshake
        # Data/FIN/RST before connection enters ESTABLISHED
        if self.state in ("CLOSED", "SYN_SENT", "SYN_RCVD"):
            # A valid handshake packet is a SYN (SYN-only or SYN-ACK) or a pure ACK (no data, not FIN/RST)
            is_handshake = (syn and not ack) or (syn and ack) or (not syn and ack and payload_len == 0 and not fin and not rst)
            if not is_handshake:
                if payload_len > 0 or fin or rst:
                    pkt_type = "Data" if payload_len > 0 else "FIN" if fin else "RST"
                    anomalies.append({
                        "timestamp": timestamp,
                        "type": "Out-of-Order Handshake",
                        "description": f"Received {pkt_type} packet before handshake completed (state: {self.state})"
                    })

        # 3. Check for TCP SYN Flood
        if is_client and syn:
            if self.state in ("CLOSED", "SYN_SENT", "SYN_RCVD"):
                self.syn_count += 1
                if self.syn_count > 20 and not self.syn_flood_flagged:
                    self.syn_flood_flagged = True
                    anomalies.append({
                        "timestamp": timestamp,
                        "type": "TCP SYN Flood",
                        "description": f"Client sent {self.syn_count} SYN packets without completing handshake"
                    })

        # Perform State Transitions
        if self.state == "CLOSED":
            if syn and not ack and is_client:
                self.state = "SYN_SENT"
            elif syn and ack and not is_client:
                self.state = "SYN_RCVD"
        elif self.state == "SYN_SENT":
            if not is_client and syn and ack:
                self.state = "SYN_RCVD"
            elif not is_client and syn and not ack:  # Simultaneous open
                self.state = "SYN_RCVD"
        elif self.state == "SYN_RCVD":
            if is_client and ack and not syn and not fin and not rst:
                self.state = "ESTABLISHED"
        elif self.state == "ESTABLISHED":
            if fin:
                if is_client:
                    self.state = "FIN_WAIT"
                else:
                    self.state = "CLOSE_WAIT"
            elif rst:
                self.state = "CLOSED"
        elif self.state in ("FIN_WAIT", "CLOSE_WAIT"):
            if fin or rst:
                self.state = "CLOSED"

        for a in anomalies:
            a.update(get_mitre_mapping(a["type"]))
        return anomalies


class DNSAnomalyDetector:
    """
    Inspects UDP port 53 packets. Detects:
    - DNS Tunneling: Subdomains > 50 characters, Shannon entropy > 4.5 bits, or high query frequency (> 50 queries/sec).
    - DNS Cache Poisoning / Spoofing: Multiple conflicting responses for same TXID, or response without matching query.
    """
    def __init__(self) -> None:
        # Rate limiting: source_ip -> deque of timestamps
        self.query_rates = collections.defaultdict(collections.deque)
        # Pending queries: (txid, client_ip, server_ip, client_port, server_port) -> (timestamp, domain)
        self.pending_queries = {}
        # Received responses: (txid, client_ip, server_ip, client_port, server_port) -> list of answers (RDATA bytes)
        self.received_responses = {}
        # Rate limit reporting lock/timestamp: source_ip -> float
        self.last_rate_limit_report = {}

    def _cleanup_expired(self, current_time: float) -> None:
        """Removes pending queries and responses older than 10 seconds."""
        expired_keys = [
            key for key, (ts, _) in self.pending_queries.items()
            if current_time - ts > 10.0
        ]
        for key in expired_keys:
            self.pending_queries.pop(key, None)
            self.received_responses.pop(key, None)

    def process_packet(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        payload: bytes,
        timestamp: float
    ) -> List[Dict[str, Any]]:
        anomalies: List[Dict[str, Any]] = []
        if len(payload) < 12:
            return anomalies

        self._cleanup_expired(timestamp)

        try:
            txid, flags, qdcount, ancount, nscount, arcount = struct.unpack('>HHHHHH', payload[:12])
        except Exception:
            return anomalies

        qr = bool(flags & 0x8000)  # Query (0) / Response (1)

        if not qr:
            # --- DNS QUERY ---
            try:
                domain, _ = self._parse_dns_name(payload, 12)
            except Exception:
                domain = None

            if domain:
                labels = domain.split('.')
                subdomain_part = ".".join(labels[:-2]) if len(labels) > 2 else domain

                is_tunneling = False
                desc_reasons = []

                # a) Subdomain > 50 characters
                if len(subdomain_part) > 50:
                    is_tunneling = True
                    desc_reasons.append(f"subdomain length exceeds 50 chars ({len(subdomain_part)})")

                # b) Shannon entropy > 4.5 bits
                entropy = self._calculate_entropy(subdomain_part)
                if entropy > 4.5:
                    is_tunneling = True
                    desc_reasons.append(f"high Shannon entropy ({entropy:.2f} bits)")

                if is_tunneling:
                    anomalies.append({
                        "timestamp": timestamp,
                        "type": "DNS Tunneling",
                        "description": f"Potential DNS Tunneling detected for query '{domain}': {', '.join(desc_reasons)}"
                    })

            # c) Query rate > 50 queries/sec
            rates = self.query_rates[src_ip]
            while rates and rates[0] < timestamp - 1.0:
                rates.popleft()
            rates.append(timestamp)

            if len(rates) > 50:
                last_report = self.last_rate_limit_report.get(src_ip, 0.0)
                if timestamp - last_report > 1.0:
                    self.last_rate_limit_report[src_ip] = timestamp
                    anomalies.append({
                        "timestamp": timestamp,
                        "type": "DNS Tunneling",
                        "description": f"Query rate exceeds 50 queries/sec from {src_ip} (current: {len(rates)} queries/sec)"
                    })

            # Save query for matching response
            query_key = (txid, src_ip, dst_ip, src_port, dst_port)
            self.pending_queries[query_key] = (timestamp, domain or "")

        else:
            # --- DNS RESPONSE ---
            # Matching key: (txid, client_ip, server_ip, client_port, server_port)
            query_key = (txid, dst_ip, src_ip, dst_port, src_port)

            try:
                answers = self._parse_dns_answers(payload, qdcount, ancount)
            except Exception:
                answers = []

            # a) Response without matching query
            if query_key not in self.pending_queries:
                anomalies.append({
                    "timestamp": timestamp,
                    "type": "DNS Cache Poisoning / Spoofing",
                    "description": f"DNS response received without matching query (TXID: {txid})"
                })
            else:
                # b) Conflicting answers for the same TXID
                if query_key in self.received_responses:
                    prev_answers = self.received_responses[query_key]
                    if prev_answers != answers:
                        anomalies.append({
                            "timestamp": timestamp,
                            "type": "DNS Cache Poisoning / Spoofing",
                            "description": f"Multiple conflicting responses for same TXID: {txid}"
                        })
                else:
                    self.received_responses[query_key] = answers

        for a in anomalies:
            a.update(get_mitre_mapping(a["type"]))
        return anomalies

    def _calculate_entropy(self, s: str) -> float:
        if not s:
            return 0.0
        total_len = len(s)
        counts = {}
        for char in s:
            counts[char] = counts.get(char, 0) + 1
        entropy = 0.0
        for count in counts.values():
            p = count / total_len
            entropy -= p * math.log2(p)
        return entropy

    def _parse_dns_name(self, payload: bytes, offset: int) -> Tuple[str, int]:
        labels = []
        visited = set()
        curr = offset
        length = len(payload)
        original_next_offset = None

        while curr < length:
            b = payload[curr]
            if b == 0:
                curr += 1
                if original_next_offset is None:
                    original_next_offset = curr
                break
            elif (b & 0xC0) == 0xC0:
                if curr + 1 >= length:
                    break
                pointer = ((b & 0x3F) << 8) | payload[curr + 1]
                if original_next_offset is None:
                    original_next_offset = curr + 2
                if pointer in visited:
                    break
                visited.add(pointer)
                curr = pointer
            else:
                label_len = b
                curr += 1
                if curr + label_len > length:
                    break
                try:
                    label = payload[curr : curr + label_len].decode('ascii', errors='ignore')
                except Exception:
                    label = ""
                labels.append(label)
                curr += label_len

        domain = '.'.join(labels)
        return domain, original_next_offset if original_next_offset is not None else curr

    def _parse_dns_answers(self, payload: bytes, qdcount: int, ancount: int) -> List[bytes]:
        answers = []
        offset = 12
        length = len(payload)

        # Skip questions
        for _ in range(qdcount):
            if offset >= length:
                break
            _, offset = self._parse_dns_name(payload, offset)
            offset += 4  # Type (2) + Class (2)

        # Parse answers
        for _ in range(ancount):
            if offset >= length:
                break
            _, offset = self._parse_dns_name(payload, offset)
            if offset + 10 > length:
                break
            rtype, rclass, ttl, rdlength = struct.unpack('>HHIH', payload[offset : offset + 10])
            offset += 10
            if offset + rdlength > length:
                break
            rdata = payload[offset : offset + rdlength]
            offset += rdlength
            answers.append(rdata)

        return answers


class HTTPAnomalyDetector:
    """
    Inspects TCP port 80/443 payloads. Detects:
    - HTTP Request Smuggling: Conflicting Content-Length and Transfer-Encoding headers, or invalid chunked framing.
    - HTTP Method Anomaly: Non-RFC method verb.
    - Header Overflow: Request header size > 16KB.
    """
    def __init__(self) -> None:
        self.buffer = b""
        self.headers_parsed = False
        self.is_chunked = False
        self.body_offset = 0
        self.last_ts = 0.0
        self.header_overflow_flagged = False
        self.is_http_confirmed = False
        self.is_http_disabled = False
        self.is_http2 = False

    def process_packet(self, payload: bytes, timestamp: float) -> List[Dict[str, Any]]:
        self.last_ts = timestamp
        anomalies: List[Dict[str, Any]] = []
        if not payload:
            return anomalies

        if self.is_http_disabled:
            return anomalies

        self.buffer += payload

        # Confirm if HTTP (either HTTP/1.x or HTTP/2)
        if not self.is_http_confirmed and len(self.buffer) >= 4:
            if self.buffer.startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"):
                self.is_http2 = True
                self.is_http_confirmed = True
                self.body_offset = 24
            elif all(32 <= b <= 126 for b in self.buffer[:4]):
                self.is_http_confirmed = True
            else:
                self.is_http_disabled = True
                return anomalies

        if self.is_http2:
            # Parse HTTP/2 frames
            while self.body_offset + 9 <= len(self.buffer):
                flen = (self.buffer[self.body_offset] << 16) | (self.buffer[self.body_offset+1] << 8) | self.buffer[self.body_offset+2]
                ftype = self.buffer[self.body_offset+3]
                fflags = self.buffer[self.body_offset+4]
                if self.body_offset + 9 + flen > len(self.buffer):
                    break

                frame_payload = self.buffer[self.body_offset + 9 : self.body_offset + 9 + flen]

                # Check for Header Overflow
                if ftype == 0x01:  # HEADERS
                    if flen > 16384:
                        anomalies.append({
                            "timestamp": timestamp,
                            "type": "Header Overflow",
                            "description": f"HTTP/2 HEADERS frame size exceeds 16KB ({flen} bytes)"
                        })

                    # Extract HPACK block fragment
                    h_offset = 0
                    pad_len = 0
                    if fflags & 0x08:  # PADDED
                        if h_offset < len(frame_payload):
                            pad_len = frame_payload[h_offset]
                            h_offset += 1
                    if fflags & 0x20:  # PRIORITY
                        h_offset += 5

                    if h_offset + pad_len <= len(frame_payload):
                        hpack_fragment = frame_payload[h_offset : len(frame_payload) - pad_len]
                        self._check_hpack_anomalies(hpack_fragment, timestamp, anomalies)

                self.body_offset += 9 + flen
        else:
            # Parse HTTP/1.x requests
            if not self.headers_parsed:
                header_end = self.buffer.find(b'\r\n\r\n')
                delimiter_len = 4
                if header_end == -1:
                    header_end = self.buffer.find(b'\n\n')
                    delimiter_len = 2

                if header_end == -1:
                    # Headers not fully received yet. Check for Header Overflow
                    if len(self.buffer) > 16384:
                        if not self.header_overflow_flagged:
                            self.header_overflow_flagged = True
                            anomalies.append({
                                "timestamp": timestamp,
                                "type": "Header Overflow",
                                "description": f"Request header size exceeds 16KB (current: {len(self.buffer)} bytes)"
                            })
                else:
                    if header_end > 16384:
                        if not self.header_overflow_flagged:
                            self.header_overflow_flagged = True
                            anomalies.append({
                                "timestamp": timestamp,
                                "type": "Header Overflow",
                                "description": f"Request header size exceeds 16KB ({header_end} bytes)"
                            })

                    header_data = self.buffer[:header_end]
                    self._parse_headers(header_data, anomalies)
                    self.headers_parsed = True
                    self.body_offset = header_end + delimiter_len

            if self.headers_parsed and self.is_chunked:
                self._parse_chunked_body(anomalies)

        for a in anomalies:
            a.update(get_mitre_mapping(a["type"]))
        return anomalies

    def _parse_headers(self, header_data: bytes, anomalies: List[Dict[str, Any]]) -> None:
        lines = header_data.split(b'\r\n')
        if not lines or not lines[0]:
            return

        request_line = lines[0]
        parts = request_line.split()
        if len(parts) >= 1:
            method = parts[0].decode('ascii', errors='ignore')
            if not method.startswith("HTTP/"):
                rfc_methods = {"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH", "CONNECT"}
                if method not in rfc_methods:
                    anomalies.append({
                        "timestamp": self.last_ts,
                        "type": "HTTP Method Anomaly",
                        "description": f"Non-RFC method verb: '{method}'"
                    })

        headers = {}
        for line in lines[1:]:
            if not line:
                continue
            colon = line.find(b':')
            if colon != -1:
                key = line[:colon].strip().lower().decode('ascii', errors='ignore')
                val = line[colon+1:].strip().decode('ascii', errors='ignore')
                headers[key] = val

        if "content-length" in headers and "transfer-encoding" in headers:
            te_val = headers["transfer-encoding"].lower()
            if "chunked" in te_val:
                anomalies.append({
                    "timestamp": self.last_ts,
                    "type": "HTTP Request Smuggling",
                    "description": "Conflicting Content-Length and Transfer-Encoding headers"
                })
                self.is_chunked = True
        elif "transfer-encoding" in headers:
            te_val = headers["transfer-encoding"].lower()
            if "chunked" in te_val:
                self.is_chunked = True

    def _parse_chunked_body(self, anomalies: List[Dict[str, Any]]) -> None:
        while self.body_offset < len(self.buffer):
            crlf = self.buffer.find(b'\r\n', self.body_offset)
            if crlf == -1:
                break

            size_line = self.buffer[self.body_offset : crlf]
            size_part = size_line.split(b';')[0].strip()

            try:
                chunk_size = int(size_part, 16)
            except ValueError:
                anomalies.append({
                    "timestamp": self.last_ts,
                    "type": "HTTP Request Smuggling",
                    "description": f"Invalid chunk length format: '{size_part.decode('ascii', errors='ignore')}'"
                })
                self.body_offset = len(self.buffer)
                break

            data_start = crlf + 2

            if chunk_size == 0:
                if data_start + 2 <= len(self.buffer):
                    if self.buffer[data_start : data_start + 2] == b'\r\n':
                        self.buffer = self.buffer[data_start + 2 :]
                        self.body_offset = 0
                        self.headers_parsed = False
                        self.is_chunked = False
                    else:
                        anomalies.append({
                            "timestamp": self.last_ts,
                            "type": "HTTP Request Smuggling",
                            "description": "Invalid chunked framing: missing terminating CRLF for final chunk"
                        })
                        self.body_offset = len(self.buffer)
                break

            if data_start + chunk_size + 2 > len(self.buffer):
                break

            trail_offset = data_start + chunk_size
            if self.buffer[trail_offset : trail_offset + 2] != b'\r\n':
                anomalies.append({
                    "timestamp": self.last_ts,
                    "type": "HTTP Request Smuggling",
                    "description": "Invalid chunked framing: missing CRLF at end of chunk data"
                })
                self.body_offset = len(self.buffer)
                break

            self.body_offset = trail_offset + 2

    def _parse_hpack_int(self, data: bytes, offset: int, prefix_mask: int) -> Tuple[int, int]:
        if offset >= len(data):
            return 0, offset
        b = data[offset]
        val = b & prefix_mask
        offset += 1
        if val < prefix_mask:
            return val, offset
        shift = 0
        while offset < len(data):
            b = data[offset]
            offset += 1
            val += (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
        return val, offset

    def _check_hpack_anomalies(self, data: bytes, timestamp: float, anomalies: List[Dict[str, Any]]) -> None:
        idx = 0
        try:
            from dpi_engine.parsers import hpack_huffman_decoder
        except ImportError:
            hpack_huffman_decoder = None

        while idx < len(data):
            b = data[idx]
            if b & 0x80:
                idx += 1
            elif (b & 0xC0) == 0x40:
                is_method = (b & 0x3F) == 2
                idx += 1
                if (b & 0x3F) == 0:
                    name_len, idx = self._parse_hpack_int(data, idx, 0x7F)
                    idx += name_len
                if idx < len(data):
                    is_huff = bool(data[idx] & 0x80)
                    val_len, idx = self._parse_hpack_int(data, idx, 0x7F)
                    if idx + val_len <= len(data):
                        val_bytes = data[idx : idx + val_len]
                        if is_method:
                            method = ""
                            if is_huff and hpack_huffman_decoder:
                                try:
                                    method = hpack_huffman_decoder.decode(val_bytes)
                                except Exception:
                                    pass
                            else:
                                method = val_bytes.decode('ascii', errors='ignore')
                            if method:
                                rfc_methods = {"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH", "CONNECT"}
                                if method not in rfc_methods:
                                    anomalies.append({
                                        "timestamp": timestamp,
                                        "type": "HTTP Method Anomaly",
                                        "description": f"Non-RFC method verb in HTTP/2: '{method}'"
                                    })
                        idx += val_len
            elif (b & 0xF0) == 0 or (b & 0xF0) == 0x10:
                is_method = (b & 0x0F) == 2
                idx += 1
                if (b & 0x0F) == 0:
                    name_len, idx = self._parse_hpack_int(data, idx, 0x7F)
                    idx += name_len
                if idx < len(data):
                    is_huff = bool(data[idx] & 0x80)
                    val_len, idx = self._parse_hpack_int(data, idx, 0x7F)
                    if idx + val_len <= len(data):
                        val_bytes = data[idx : idx + val_len]
                        if is_method:
                            method = ""
                            if is_huff and hpack_huffman_decoder:
                                try:
                                    method = hpack_huffman_decoder.decode(val_bytes)
                                except Exception:
                                    pass
                            else:
                                method = val_bytes.decode('ascii', errors='ignore')
                            if method:
                                rfc_methods = {"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH", "CONNECT"}
                                if method not in rfc_methods:
                                    anomalies.append({
                                        "timestamp": timestamp,
                                        "type": "HTTP Method Anomaly",
                                        "description": f"Non-RFC method verb in HTTP/2: '{method}'"
                                    })
                        idx += val_len
            else:
                idx += 1
