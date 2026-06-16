from __future__ import annotations

import threading
import time
from collections import deque
from typing import Dict, List, Optional, Tuple, Any, TYPE_CHECKING

from dpi_engine.common import (
    FiveTuple,
    AppType,
    Protocol,
    Packet,
    app_type_to_string,
)

if TYPE_CHECKING:
    from dpi_engine.pipeline import FlowEntry


class FlowAnalytics:
    """
    Tracks micro-level connection performance metrics for a single flow.
    """
    def __init__(self, flow_tuple: FiveTuple) -> None:
        self.flow_tuple = flow_tuple
        self.start_time: float = 0.0
        self.last_seen: float = 0.0
        self.client_packets: int = 0
        self.server_packets: int = 0
        self.client_bytes: int = 0
        self.server_bytes: int = 0

    @property
    def first_seen(self) -> float:
        return self.start_time

    @first_seen.setter
    def first_seen(self, value: float) -> None:
        self.start_time = value

    @property
    def duration(self) -> float:
        """
        Calculated as last_seen - start_time (minimum 0.001 seconds to avoid division by zero).
        """
        if self.start_time == 0.0:
            return 0.0
        return max(0.001, self.last_seen - self.start_time)

    @property
    def total_packets(self) -> int:
        return self.client_packets + self.server_packets

    @property
    def total_bytes(self) -> int:
        return self.client_bytes + self.server_bytes

    @property
    def packet_rate(self) -> float:
        """
        Total packets divided by duration (packets per second).
        """
        dur = self.duration
        if dur == 0.0:
            return 0.0
        return self.total_packets / dur

    @property
    def throughput(self) -> float:
        """
        Total bytes divided by duration (bytes per second).
        """
        dur = self.duration
        if dur == 0.0:
            return 0.0
        return self.total_bytes / dur

    def update(self, packet: Packet) -> None:
        """
        Updates the flow statistics with a new packet.
        """
        ts = packet.ts_sec + packet.ts_usec / 1000000.0
        if self.start_time == 0.0:
            self.start_time = ts
        self.last_seen = ts

        # Determine packet direction relative to the flow initiator
        is_client = (packet.tuple == self.flow_tuple)
        
        # Increment packets and bytes (payload bytes)
        payload_len = packet.payload_length if packet.payload_length is not None else 0
        if is_client:
            self.client_packets += 1
            self.client_bytes += payload_len
        else:
            self.server_packets += 1
            self.server_bytes += payload_len

    def to_dict(self) -> Dict[str, Any]:
        """
        Returns a dictionary representation suitable for serialization.
        """
        return {
            "start_time": self.start_time,
            "last_seen": self.last_seen,
            "duration": self.duration,
            "client_packets": self.client_packets,
            "server_packets": self.server_packets,
            "client_bytes": self.client_bytes,
            "server_bytes": self.server_bytes,
            "packet_rate": self.packet_rate,
            "throughput": self.throughput,
        }


class SlidingWindowStats:
    """
    Tracks metrics over a rolling time window using bucketed aggregates for high performance.
    """
    def __init__(self, window_size: float = 10.0, bucket_size: float = 0.1) -> None:
        self.window_size = window_size
        self.bucket_size = bucket_size
        self.buckets: deque[List[float]] = deque()  # list of [bucket_start_time, bytes, packets]
        self.lock = threading.Lock()

    def add(self, timestamp: float, bytes_count: int, packet_count: int = 1) -> None:
        bucket_time = int(timestamp / self.bucket_size) * self.bucket_size
        with self.lock:
            if self.buckets and abs(self.buckets[-1][0] - bucket_time) < 1e-6:
                self.buckets[-1][1] += bytes_count
                self.buckets[-1][2] += packet_count
            else:
                self.buckets.append([bucket_time, float(bytes_count), float(packet_count)])
            
            # Prune old buckets
            cutoff = timestamp - self.window_size
            while self.buckets and self.buckets[0][0] < cutoff:
                self.buckets.popleft()

    def get_throughput(self, current_time: float) -> Tuple[float, float]:
        """
        Returns rolling average (bps, pps) over the window up to current_time.
        """
        with self.lock:
            cutoff = current_time - self.window_size
            while self.buckets and self.buckets[0][0] < cutoff:
                self.buckets.popleft()

            if not self.buckets:
                return 0.0, 0.0

            total_bytes = sum(b[1] for b in self.buckets)
            total_packets = sum(b[2] for b in self.buckets)

            # Calculate actual time elapsed in the window
            first_bucket_time = self.buckets[0][0]
            elapsed = max(0.001, current_time - first_bucket_time)
            actual_window = min(self.window_size, elapsed)

            bps = (total_bytes * 8.0) / actual_window
            pps = total_packets / actual_window
            return bps, pps


def get_flow_protocol(flow: FlowEntry, packet: Packet) -> str:
    """
    Classifies a flow's protocol as HTTP, HTTPS, HTTP/2, QUIC, DNS, or Unknown,
    and caches the result on the flow object.
    """
    current = getattr(flow, "_protocol_type", "Unknown")
    if current not in ("Unknown", "HTTPS"):
        return current

    proto = "Unknown"
    # 1. DNS (Port 53)
    if flow.tuple.dst_port == 53 or flow.tuple.src_port == 53 or flow.app_type == AppType.DNS:
        proto = "DNS"
    # 2. QUIC (UDP Port 443)
    elif flow.tuple.protocol == 17:  # UDP
        if flow.tuple.dst_port == 443 or flow.tuple.src_port == 443 or flow.app_type == AppType.QUIC:
            proto = "QUIC"
    # 3. TCP Protocols
    elif flow.tuple.protocol == 6:
        # Check HTTP/2 indicators
        # Indicator A: JA4 ALPN is 'h2'
        if flow.ja4_string and len(flow.ja4_string) >= 10 and flow.ja4_string[8:10] == "h2":
            proto = "HTTP/2"
        else:
            payload = packet.data[packet.payload_offset : packet.payload_offset + packet.payload_length]
            # Indicator B: Connection Preface
            if payload.startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"):
                proto = "HTTP/2"
            else:
                # Indicator C: HTTP/2 headers parsing test
                is_h2 = False
                if payload and (flow.tuple.dst_port == 443 or flow.tuple.dst_port == 80 or flow.tuple.src_port == 443 or flow.tuple.src_port == 80):
                    try:
                        from dpi_engine.parsers import HTTP2Parser, hpack_huffman_decoder
                        h2_parser = HTTP2Parser(hpack_huffman_decoder)
                        headers = h2_parser.extract_headers(payload)
                        if headers:
                            is_h2 = True
                    except Exception:
                        pass
                
                if is_h2:
                    proto = "HTTP/2"
                # Check HTTP (Port 80)
                elif flow.tuple.dst_port == 80 or flow.tuple.src_port == 80 or flow.app_type == AppType.HTTP:
                    proto = "HTTP"
                # Check HTTPS (Port 443 or JA3/JA4 present)
                elif flow.tuple.dst_port == 443 or flow.tuple.src_port == 443 or flow.app_type in (AppType.HTTPS, AppType.TLS) or flow.ja3_hash:
                    proto = "HTTPS"
                else:
                    # Fallback check for plain text HTTP methods
                    is_http = False
                    if payload:
                        first_word = payload.split(b' ', 1)[0]
                        if first_word in (b"GET", b"POST", b"PUT", b"DELETE", b"OPTIONS", b"HEAD", b"PATCH", b"CONNECT") or payload.startswith(b"HTTP/1."):
                            is_http = True
                    if is_http:
                        proto = "HTTP"

    flow._protocol_type = proto
    return proto


class GlobalAnalytics:
    """
    Tracks macro-level aggregates for the entire DPI platform.
    """
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.throughput_window = SlidingWindowStats(window_size=10.0, bucket_size=0.1)
        self.flows: Dict[FiveTuple, FlowEntry] = {}
        self.last_ts: float = 0.0

    def update(self, flow: FlowEntry, packet: Packet) -> None:
        """
        Records packet data and updates flow tracking in the global aggregate metrics.
        """
        ts = packet.ts_sec + packet.ts_usec / 1000000.0
        
        # Update sliding window (bps tracks raw packet bytes)
        self.throughput_window.add(ts, len(packet.data), 1)

        with self.lock:
            if ts > self.last_ts:
                self.last_ts = ts
            self.flows[flow.tuple] = flow
            
            # Update/cache the protocol type
            get_flow_protocol(flow, packet)

    def get_rolling_throughput(self) -> Dict[str, float]:
        """
        Returns rolling 10-second throughput in bps (bits/sec) and pps (packets/sec).
        """
        ref_time = self.last_ts if self.last_ts > 0 else time.time()
        bps, pps = self.throughput_window.get_throughput(ref_time)
        return {
            "bps": bps,
            "pps": pps,
        }

    def get_protocol_distribution(self) -> Dict[str, Dict[str, int]]:
        """
        Returns a breakdown of flows, packets, and bytes per protocol type.
        """
        distribution = {
            proto: {"flows": 0, "packets": 0, "bytes": 0}
            for proto in ["HTTP", "HTTPS", "HTTP/2", "QUIC", "DNS", "Unknown"]
        }
        with self.lock:
            for flow in self.flows.values():
                proto = getattr(flow, "_protocol_type", "Unknown")
                if proto not in distribution:
                    proto = "Unknown"
                distribution[proto]["flows"] += 1
                distribution[proto]["packets"] += flow.packets
                distribution[proto]["bytes"] += flow.bytes
        return distribution

    def get_top_talkers(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Returns the top active flows sorted by total bytes.
        """
        with self.lock:
            sorted_flows = sorted(
                self.flows.values(),
                key=lambda f: f.bytes,
                reverse=True
            )
            
            top_talkers = []
            for flow in sorted_flows[:limit]:
                proto = getattr(flow, "_protocol_type", "Unknown")
                duration = max(0.001, flow.last_seen - flow.first_seen) if flow.first_seen > 0 else 0.001
                throughput = flow.bytes / duration
                
                top_talkers.append({
                    "tuple": flow.tuple.to_string(),
                    "src_ip": flow.tuple.src_ip,
                    "dst_ip": flow.tuple.dst_ip,
                    "src_port": flow.tuple.src_port,
                    "dst_port": flow.tuple.dst_port,
                    "protocol": "TCP" if flow.tuple.protocol == 6 else "UDP" if flow.tuple.protocol == 17 else str(flow.tuple.protocol),
                    "app": app_type_to_string(flow.app_type),
                    "sni": flow.sni,
                    "packets": flow.packets,
                    "bytes": flow.bytes,
                    "duration": duration,
                    "throughput": throughput,
                    "proto_name": proto,
                })
            return top_talkers

    def dashboard_snapshot(self) -> Dict[str, Any]:
        """
        Returns a complete snapshot of global aggregates, suitable for JSON serialization.
        """
        throughput = self.get_rolling_throughput()
        return {
            "rolling_bps": throughput["bps"],
            "rolling_pps": throughput["pps"],
            "protocol_distribution": self.get_protocol_distribution(),
            "top_talkers": self.get_top_talkers(),
        }
