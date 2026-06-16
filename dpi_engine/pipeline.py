from __future__ import annotations

import os
import random
import struct
import threading
import time
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any

if sys.platform.startswith("win") and "WINDIR" not in os.environ:
    os.environ["WINDIR"] = os.environ.get("SystemRoot", r"C:\Windows")

try:
    from scapy.all import sendp, Ether, IP, IPv6, TCP, ICMP, ICMPv6DestUnreach
except Exception:
    sendp = None
    Ether = None
    IP = None
    IPv6 = None
    TCP = None
    ICMP = None
    ICMPv6DestUnreach = None

from dpi_engine.common import (
    AppType,
    FiveTuple,
    app_type_to_string,
    sni_to_app_type,
    load_scapy,
    Rules,
    Stats,
    TSQueue,
    Packet,
    RawPacket,
    PcapPacketHeader,
    PcapReader,
    ParsedPacket,
    five_tuple_hash
)

from dpi_engine.parsers import (
    PacketParser,
    TLSClientHelloParser,
    HTTP2Parser,
    HTTPHostExtractor,
    QUICParser,
    generate_ja3,
    generate_ja4,
    hpack_huffman_decoder
)

from dpi_engine.classifiers import (
    ETIFeatureExtractor,
    eti_classifier
)

from dpi_engine.analytics import FlowAnalytics
from dpi_engine.anomaly import TCPStateMachine, DNSAnomalyDetector, HTTPAnomalyDetector

# Optional OpenTelemetry Tracing Setup
tracer = None
try:
    from opentelemetry import trace
    # Will use global tracer provider if configured by user/server
    tracer = trace.get_tracer("dpi_engine.pipeline")
except ImportError:
    pass


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
    ja3_string: str = ""
    ja3_hash: str = ""
    ja4_string: str = ""

    # --- Phase 2: Encrypted Traffic Intelligence (ETI) ---
    eti_extractor: ETIFeatureExtractor = field(default=None, init=False)
    eti_classification: str = "BENIGN"
    eti_confidence: float = 1.0

    # --- Timing Tracking ---
    first_seen: float = 0.0
    last_seen: float = 0.0
    last_packet: Optional[Packet] = None
    country: str = "Unknown"

    # --- Phase 3: Flow Analytics ---
    analytics: FlowAnalytics = field(default=None, init=False)

    # --- Phase 4: Stateful Protocol Anomaly Detection ---
    anomalies: List[Dict[str, Any]] = field(default_factory=list, init=False)
    tcp_state_machine: Optional[TCPStateMachine] = field(default=None, init=False)
    dns_anomaly_detector: Optional[DNSAnomalyDetector] = field(default=None, init=False)
    http_anomaly_detector: Optional[HTTPAnomalyDetector] = field(default=None, init=False)

    def __post_init__(self) -> None:
        self.first_seen = time.time()
        self.last_seen = time.time()
        self.eti_extractor = ETIFeatureExtractor(self.tuple)
        self.analytics = FlowAnalytics(self.tuple)
        self.anomalies = []
        
        # Resolve destination IP location
        from dpi_engine.geoip import geoip_lookup
        self.country = geoip_lookup.lookup_country(self.tuple.dst_ip)
        if self.tuple.protocol == 6:  # TCP
            self.tcp_state_machine = TCPStateMachine()
            self.http_anomaly_detector = HTTPAnomalyDetector()
            self.dns_anomaly_detector = None
        elif self.tuple.protocol == 17 and (self.tuple.dst_port == 53 or self.tuple.src_port == 53):  # DNS
            self.dns_anomaly_detector = DNSAnomalyDetector()
            self.tcp_state_machine = None
            self.http_anomaly_detector = None
        else:
            self.tcp_state_machine = None
            self.dns_anomaly_detector = None
            self.http_anomaly_detector = None


class FastPath:
    def __init__(self, id_: int, rules: Rules, stats: Stats, output_queue: TSQueue) -> None:
        self.id = id_
        self.rules = rules
        self.stats = stats
        self.output_queue = output_queue
        self.input_queue = TSQueue()
        self.flows: Dict[FiveTuple, FlowEntry] = {}
        self.flows_lock = threading.RLock()
        self.running = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self._processed = 0
        self._processed_lock = threading.Lock()

    def start(self) -> None:
        self.running.set()
        self.thread = threading.Thread(target=self._run, name=f"FP{self.id}")
        self.thread.start()

    def stop(self) -> None:
        self.running.clear()
        self.input_queue.shutdown()
        if self.thread is not None:
            self.thread.join()

    def processed(self) -> int:
        with self._processed_lock:
            return self._processed

    def _increment_processed(self) -> None:
        with self._processed_lock:
            self._processed += 1

    def _run(self) -> None:
        while self.running.is_set() or not self.input_queue.empty():
            packet = self.input_queue.pop(100)
            if packet is None:
                continue
            try:
                self._process(packet)
            finally:
                self.input_queue.task_done()

    def _process(self, packet: Packet) -> None:
        if tracer is not None:
            with tracer.start_as_current_span("FastPath._process", attributes={
                "packet.id": packet.id,
                "packet.size": len(packet.data),
                "flow.src": packet.tuple.src_ip,
                "flow.dst": packet.tuple.dst_ip,
                "flow.protocol": packet.tuple.protocol,
            }):
                self._process_internal(packet)
        else:
            self._process_internal(packet)

    def _process_internal(self, packet: Packet) -> None:
        self._increment_processed()

        with self.flows_lock:
            flow = self.flows.get(packet.tuple)
            if flow is None:
                flow = FlowEntry(tuple=packet.tuple)
                self.flows[packet.tuple] = flow

        flow.packets += 1
        flow.bytes += len(packet.data)
        flow.last_packet = packet

        ts = packet.ts_sec + packet.ts_usec / 1000000.0
        if flow.packets == 1:
            flow.first_seen = ts
        flow.last_seen = ts

        # Phase 3: Flow Analytics (micro-level metrics & macro aggregates)
        flow.analytics.update(packet)
        self.stats.global_analytics.update(flow, packet)

        # Phase 4: Stateful Protocol Anomaly Detection
        new_anomalies = []
        if packet.tuple.protocol == 6:  # TCP
            if flow.tcp_state_machine:
                tcp_anoms = flow.tcp_state_machine.update(
                    src_ip=packet.tuple.src_ip,
                    src_port=packet.tuple.src_port,
                    dst_ip=packet.tuple.dst_ip,
                    dst_port=packet.tuple.dst_port,
                    flags=packet.tcp_flags,
                    payload_len=packet.payload_length,
                    timestamp=ts
                )
                new_anomalies.extend(tcp_anoms)
            if flow.http_anomaly_detector:
                payload = packet.data[packet.payload_offset : packet.payload_offset + packet.payload_length]
                if payload:
                    http_anoms = flow.http_anomaly_detector.process_packet(payload, ts)
                    new_anomalies.extend(http_anoms)
        elif packet.tuple.protocol == 17:  # UDP
            payload = packet.data[packet.payload_offset : packet.payload_offset + packet.payload_length]
            if payload:
                if flow.dns_anomaly_detector:
                    dns_anoms = flow.dns_anomaly_detector.process_packet(
                        src_ip=packet.tuple.src_ip,
                        src_port=packet.tuple.src_port,
                        dst_ip=packet.tuple.dst_ip,
                        dst_port=packet.tuple.dst_port,
                        payload=payload,
                        timestamp=ts
                    )
                    new_anomalies.extend(dns_anoms)

                # DNS IP Harvesting (Phase 4 Extension)
                if packet.tuple.src_port == 53:
                    try:
                        from dpi_engine.parsers import DNSResponseParser
                        query_domain, resolved_ips = DNSResponseParser.parse_response(payload)
                        if query_domain and resolved_ips:
                            if self.rules.is_domain_blocked(query_domain):
                                for ip in resolved_ips:
                                    self.rules.block_ip(ip)
                                    print(f"[Rules] Dynamically blocked IP {ip} resolved from {query_domain}")
                    except Exception:
                        pass

        if new_anomalies:
            flow.anomalies.extend(new_anomalies)
            with self.stats.lock:
                for anom in new_anomalies:
                    anom_type = anom["type"]
                    self.stats.anomaly_counts[anom_type] = self.stats.anomaly_counts.get(anom_type, 0) + 1
                    self.stats.recent_anomalies.append({
                        "timestamp": anom["timestamp"],
                        "type": anom_type,
                        "description": anom["description"],
                        "flow": flow.tuple.to_string(),
                        "app": app_type_to_string(flow.app_type),
                        "mitre_id": anom.get("mitre_id", ""),
                        "mitre_technique": anom.get("mitre_technique", ""),
                    })

        flow.eti_extractor.add_packet(packet)

        if not flow.classified:
            self._classify_flow(packet, flow)

        if flow.packets % 50 == 0:
            classification, confidence = eti_classifier.classify(flow.eti_extractor, flow.app_type)
            flow.eti_classification = classification
            flow.eti_confidence = confidence

        if not flow.blocked:
            # Check if reverse flow is already blocked
            with self.flows_lock:
                rev_flow = self.flows.get(packet.tuple.reverse())
            if rev_flow is not None and rev_flow.blocked:
                flow.blocked = True
            else:
                flow.blocked = self.rules.is_blocked(packet.tuple.src_ip, packet.tuple.dst_ip, flow.app_type, flow.sni)
                
                if not flow.blocked:
                    from dpi_engine.threat_intel import threat_intel
                    if threat_intel.is_ip_malicious(packet.tuple.src_ip) or threat_intel.is_ip_malicious(packet.tuple.dst_ip):
                        flow.blocked = True
                        flow.eti_classification = "MALICIOUS"
                        print(f"[ThreatIntel] Blocked flow associated with malicious IP ({packet.tuple.src_ip} -> {packet.tuple.dst_ip})")
                    elif flow.sni and threat_intel.is_domain_malicious(flow.sni):
                        flow.blocked = True
                        flow.eti_classification = "MALICIOUS"
                        print(f"[ThreatIntel] Blocked flow associated with malicious domain: {flow.sni}")
                
                # If blocked by domain/SNI rule, dynamically harvest and block the server IP
                if flow.blocked and flow.sni:
                    server_ip = None
                    if packet.tuple.dst_port in (80, 443):
                        server_ip = packet.tuple.dst_ip
                    elif packet.tuple.src_port in (80, 443):
                        server_ip = packet.tuple.src_ip
                    
                    if server_ip:
                        self.rules.block_ip(server_ip)
                        print(f"[Rules] Dynamically blocked IP {server_ip} matching SNI/domain rule: {flow.sni}")

                # Payload-based domain signature fallback (highly robust against SNI parser bypasses)
                if not flow.blocked and packet.tuple.dst_port in (80, 443):
                    payload = packet.data[packet.payload_offset : packet.payload_offset + packet.payload_length]
                    if payload:
                        for b_domain in self.rules.blocked_domains_snapshot():
                            if b_domain.encode('utf-8', errors='ignore') in payload:
                                flow.blocked = True
                                self.rules.block_ip(packet.tuple.dst_ip)
                                print(f"[Rules] Dynamically blocked IP {packet.tuple.dst_ip} matching payload domain: {b_domain}")
                                break

                if flow.eti_classification == "MALICIOUS":
                    flow.blocked = True
                for anom in flow.anomalies:
                    if anom["type"] in ("TCP SYN Flood", "HTTP Request Smuggling", "DNS Tunneling"):
                        flow.blocked = True
                        break
            
            if flow.blocked and rev_flow is not None:
                rev_flow.blocked = True

        self.stats.record_app(flow.app_type, flow.sni)

        eti_desc = f"{flow.eti_classification} ({int(flow.eti_confidence * 100)}%)"
        
        if flow.blocked:
            self.stats.record_packet_decision(
                packet, flow.app_type, flow.sni, "DROP", self.id,
                ja3=flow.ja3_hash, ja4=flow.ja4_string, eti=eti_desc,
                country=flow.country
            )
            self.stats.record_dropped()
            if packet.tuple.protocol == 6: # TCP
                if not (packet.tcp_flags & 0x04): # Avoid loop on RST
                    self._inject_tcp_reset(packet)
            elif packet.tuple.protocol == 17: # UDP
                self._inject_icmp_unreachable(packet)
        else:
            self.stats.record_packet_decision(
                packet, flow.app_type, flow.sni, "FORWARD", self.id,
                ja3=flow.ja3_hash, ja4=flow.ja4_string, eti=eti_desc,
                country=flow.country
            )
            self.stats.record_forwarded()
            self.output_queue.push(packet)

    def mark_matching_flows_blocked(
        self,
        *,
        ip: Optional[str] = None,
        app: Optional[AppType] = None,
        domain: Optional[str] = None,
    ) -> Tuple[List[str], List[Packet]]:
        domain_lower = domain.lower() if domain else None
        matched_server_ips: List[str] = []
        reset_packets: List[Packet] = []

        with self.flows_lock:
            flows = list(self.flows.values())
            flow_by_tuple = dict(self.flows)

        for flow in flows:
            matched = False
            if ip and (flow.tuple.src_ip == ip or flow.tuple.dst_ip == ip):
                matched = True
            if app is not None and flow.app_type == app:
                matched = True
            if domain_lower and flow.sni and domain_lower in flow.sni.lower():
                matched = True

            if not matched:
                continue

            flow.blocked = True
            reverse_flow = flow_by_tuple.get(flow.tuple.reverse())
            if reverse_flow is not None:
                reverse_flow.blocked = True

            server_ip = self._server_ip_for_flow(flow)
            if server_ip and server_ip not in matched_server_ips:
                matched_server_ips.append(server_ip)

            if flow.last_packet is not None and flow.last_packet not in reset_packets:
                reset_packets.append(flow.last_packet)
            if reverse_flow is not None and reverse_flow.last_packet is not None and reverse_flow.last_packet not in reset_packets:
                reset_packets.append(reverse_flow.last_packet)

        for packet in reset_packets:
            if packet.tuple.protocol == 6:
                if not (packet.tcp_flags & 0x04):
                    self._inject_tcp_reset(packet)
            elif packet.tuple.protocol == 17:
                self._inject_icmp_unreachable(packet)

        return matched_server_ips, reset_packets

    @staticmethod
    def _server_ip_for_flow(flow: FlowEntry) -> Optional[str]:
        if flow.tuple.dst_port in (80, 443):
            return flow.tuple.dst_ip
        if flow.tuple.src_port in (80, 443):
            return flow.tuple.src_ip
        return None

    def _inject_tcp_reset(self, packet: Packet) -> None:
        if sendp is None or Ether is None:
            return
        try:
            # Determine TCP header offset
            if packet.data[12:14] == b"\x08\x00": # IPv4
                ihl = packet.data[14] & 0x0F
                tcp_offset = 14 + ihl * 4
                is_ipv6 = False
            elif packet.data[12:14] == b"\x86\xdd": # IPv6
                tcp_offset = 14 + 40
                is_ipv6 = True
            else:
                return

            if len(packet.data) < tcp_offset + 20:
                return

            sport, dport, seq, ack = struct.unpack("!HHII", packet.data[tcp_offset : tcp_offset + 12])
            flags = packet.data[tcp_offset + 13]

            data_offset = (packet.data[tcp_offset + 12] >> 4) & 0x0F
            tcp_header_len = data_offset * 4
            tcp_payload_len = max(0, len(packet.data) - tcp_offset - tcp_header_len)

            # Determine direction based on ports
            is_c2s = dport in (80, 443) or packet.tuple.dst_port in (80, 443)
            
            if is_c2s:
                client_mac = packet.data[6:12]
                server_mac = packet.data[0:6]
                client_ip = packet.tuple.src_ip
                server_ip = packet.tuple.dst_ip
                client_port = sport
                server_port = dport
                c_seq = seq
                c_ack = ack
            else:
                client_mac = packet.data[0:6]
                server_mac = packet.data[6:12]
                client_ip = packet.tuple.dst_ip
                server_ip = packet.tuple.src_ip
                client_port = dport
                server_port = sport
                c_seq = ack
                c_ack = seq

            has_ack = (flags & 0x10) != 0
            consumed = tcp_payload_len + (1 if (flags & 0x03) else 0)

            if not is_ipv6:
                ip_to_client = IP(src=server_ip, dst=client_ip)
                ip_to_server = IP(src=client_ip, dst=server_ip)
            else:
                ip_to_client = IPv6(src=server_ip, dst=client_ip)
                ip_to_server = IPv6(src=client_ip, dst=server_ip)

            # 1. Reset packet to Client (spoofed from Server)
            eth_to_client = Ether(src=server_mac, dst=client_mac)
            if has_ack:
                tcp_to_client = TCP(sport=server_port, dport=client_port, flags="R", seq=c_ack)
            else:
                tcp_to_client = TCP(sport=server_port, dport=client_port, flags="RA", seq=0, ack=c_seq + consumed)
            pkt_to_client = eth_to_client / ip_to_client / tcp_to_client

            # 2. Reset packet to Server (spoofed from Client)
            eth_to_server = Ether(src=client_mac, dst=server_mac)
            if has_ack:
                tcp_to_server = TCP(sport=client_port, dport=server_port, flags="R", seq=c_seq + tcp_payload_len)
            else:
                tcp_to_server = TCP(sport=client_port, dport=server_port, flags="RA", seq=c_seq, ack=0)
            pkt_to_server = eth_to_server / ip_to_server / tcp_to_server

            iface = packet.iface or getattr(self.rules, "iface", None)
            
            sendp(pkt_to_client, iface=iface, verbose=0)
            sendp(pkt_to_server, iface=iface, verbose=0)
        except Exception as e:
            print(f"[Rules] Error injecting TCP RST: {e}", file=sys.stderr)

    def _inject_icmp_unreachable(self, packet: Packet) -> None:
        if sendp is None or Ether is None or ICMP is None or ICMPv6DestUnreach is None:
            return
        try:
            # Determine IP header offset
            if packet.data[12:14] == b"\x08\x00": # IPv4
                ihl = packet.data[14] & 0x0F
                ip_header_len = ihl * 4
                is_ipv6 = False
            elif packet.data[12:14] == b"\x86\xdd": # IPv6
                ip_header_len = 40
                is_ipv6 = True
            else:
                return

            if len(packet.data) < 14 + ip_header_len + 8:
                return

            # Determine direction
            sport, dport = struct.unpack("!HH", packet.data[14 + ip_header_len : 14 + ip_header_len + 4])
            is_c2s = dport in (80, 443) or packet.tuple.dst_port in (80, 443)

            if is_c2s:
                client_mac = packet.data[6:12]
                server_mac = packet.data[0:6]
                client_ip = packet.tuple.src_ip
                server_ip = packet.tuple.dst_ip
            else:
                client_mac = packet.data[0:6]
                server_mac = packet.data[6:12]
                client_ip = packet.tuple.dst_ip
                server_ip = packet.tuple.src_ip

            # Build layers to client
            if not is_ipv6:
                ip_layer_to_client = IP(src=server_ip, dst=client_ip)
                icmp_layer = ICMP(type=3, code=3) # Destination Unreachable, Port Unreachable
                payload_len = ip_header_len + 8
                original_ip_udp = packet.data[14 : 14 + payload_len]
                pkt_to_client = Ether(src=server_mac, dst=client_mac) / ip_layer_to_client / icmp_layer / original_ip_udp
            else:
                ip_layer_to_client = IPv6(src=server_ip, dst=client_ip)
                icmp_layer = ICMPv6DestUnreach(code=4) # Port Unreachable
                payload_len = 40 + 8
                original_ip_udp = packet.data[14 : 14 + payload_len]
                pkt_to_client = Ether(src=server_mac, dst=client_mac) / ip_layer_to_client / icmp_layer / original_ip_udp

            iface = packet.iface or getattr(self.rules, "iface", None)
            sendp(pkt_to_client, iface=iface, verbose=0)
        except Exception as e:
            print(f"[Rules] Error injecting ICMP Unreachable: {e}", file=sys.stderr)

    def _classify_flow(self, packet: Packet, flow: FlowEntry) -> None:
        if tracer is not None:
            with tracer.start_as_current_span("FastPath._classify_flow", attributes={
                "flow.src": packet.tuple.src_ip,
                "flow.dst": packet.tuple.dst_ip,
                "flow.protocol": packet.tuple.protocol,
            }):
                self._classify_flow_internal(packet, flow)
        else:
            self._classify_flow_internal(packet, flow)

    def _classify_flow_internal(self, packet: Packet, flow: FlowEntry) -> None:
        payload = packet.data[packet.payload_offset : packet.payload_offset + packet.payload_length]
        if not payload:
            return

        # 1. TLS/HTTPS / DoT over TCP
        if packet.tuple.dst_port in (443, 853) and packet.tuple.protocol == 6:
            client_hello = TLSClientHelloParser.parse_client_hello(payload)
            if client_hello:
                sni = None
                for ext_type, ext_data in client_hello.get("extensions_raw", []):
                    if ext_type == 0:  # SNI
                        if len(ext_data) >= 5:
                            sni_list_len = (ext_data[0] << 8) | ext_data[1]
                            sni_type = ext_data[2]
                            sni_len = (ext_data[3] << 8) | ext_data[4]
                            if sni_type == 0 and len(ext_data) >= 5 + sni_len:
                                sni = ext_data[5 : 5 + sni_len].decode("ascii", errors="ignore")
                
                # Check for DoT or DoH by SNI
                is_doh = False
                is_dot = (packet.tuple.dst_port == 853)
                
                if sni:
                    doh_providers = {
                        "dns.google", "dns.google.com", "cloudflare-dns.com",
                        "one.one.one.one", "dns.quad9.net", "quad9.net",
                        "doh.cleanbrowsing.org", "doh.opendns.com", "doh.mullvad.net",
                        "dns.adguard-dns.com"
                    }
                    if sni.lower() in doh_providers or "dns" in sni.lower():
                        if packet.tuple.dst_port == 443:
                            is_doh = True

                if is_dot:
                    flow.sni = f"DoT ({sni})" if sni else "DoT Query"
                    flow.app_type = AppType.DNS
                    flow.classified = True
                elif is_doh:
                    flow.sni = f"DoH ({sni})"
                    flow.app_type = AppType.DNS
                    flow.classified = True
                elif sni:
                    flow.sni = sni
                    flow.app_type = sni_to_app_type(sni)
                    flow.classified = True

                try:
                    ja3_str, ja3_hash = generate_ja3(client_hello)
                    flow.ja3_string = ja3_str
                    flow.ja3_hash = ja3_hash

                    has_sni = sni is not None
                    sni_is_ip = False
                    if sni:
                        import socket
                        try:
                            socket.inet_pton(socket.AF_INET, sni)
                            sni_is_ip = True
                        except Exception:
                            try:
                                socket.inet_pton(socket.AF_INET6, sni)
                                sni_is_ip = True
                            except Exception:
                                pass
                    flow.ja4_string = generate_ja4(client_hello, is_quic=False, has_sni=has_sni, sni_is_ip=sni_is_ip)
                except Exception:
                    pass
                return

            try:
                h2_parser = HTTP2Parser(hpack_huffman_decoder)
                headers = h2_parser.extract_headers(payload)
                if headers:
                    is_doh = False
                    path = headers.get(":path", "")
                    content_type = headers.get("content-type", "")
                    authority = headers.get(":authority", "")
                    
                    if "/dns-query" in path or "application/dns-message" in content_type:
                        is_doh = True
                    
                    if authority:
                        doh_providers = {
                            "dns.google", "dns.google.com", "cloudflare-dns.com",
                            "one.one.one.one", "dns.quad9.net", "quad9.net",
                            "doh.cleanbrowsing.org", "doh.opendns.com", "doh.mullvad.net",
                            "dns.adguard-dns.com"
                        }
                        if authority.lower() in doh_providers or "dns" in authority.lower():
                            is_doh = True
                            
                    if is_doh:
                        flow.sni = f"DoH ({authority})" if authority else "DoH Query"
                        flow.app_type = AppType.DNS
                        flow.classified = True
                        return
                    elif authority:
                        flow.sni = authority
                        flow.app_type = sni_to_app_type(authority)
                        flow.classified = True
                        return
            except Exception:
                pass

        # 2. HTTP over TCP (Port 80)
        elif packet.tuple.dst_port == 80 and packet.tuple.protocol == 6:
            host = HTTPHostExtractor.extract(payload)
            if host:
                flow.sni = host
                flow.app_type = sni_to_app_type(host)
                flow.classified = True
                return

            try:
                h2_parser = HTTP2Parser(hpack_huffman_decoder)
                headers = h2_parser.extract_headers(payload)
                if ":authority" in headers:
                    authority = headers[":authority"]
                    flow.sni = authority
                    flow.app_type = sni_to_app_type(authority)
                    flow.classified = True
                    return
            except Exception:
                pass

        # 3. QUIC over UDP (Port 443)
        elif packet.tuple.dst_port == 443 and packet.tuple.protocol == 17:
            crypto_data = QUICParser.parse_initial_packet(payload)
            if crypto_data:
                client_hello = TLSClientHelloParser.parse_client_hello(crypto_data)
                if client_hello:
                    sni = None
                    for ext_type, ext_data in client_hello.get("extensions_raw", []):
                        if ext_type == 0:  # SNI
                            if len(ext_data) >= 5:
                                sni_list_len = (ext_data[0] << 8) | ext_data[1]
                                sni_type = ext_data[2]
                                sni_len = (ext_data[3] << 8) | ext_data[4]
                                if sni_type == 0 and len(ext_data) >= 5 + sni_len:
                                    sni = ext_data[5 : 5 + sni_len].decode("ascii", errors="ignore")
                    if sni:
                        flow.sni = sni
                        flow.app_type = sni_to_app_type(sni)
                        flow.classified = True

                    try:
                        ja3_str, ja3_hash = generate_ja3(client_hello)
                        flow.ja3_string = ja3_str
                        flow.ja3_hash = ja3_hash

                        has_sni = sni is not None
                        sni_is_ip = False
                        if sni:
                            import socket
                            try:
                                socket.inet_pton(socket.AF_INET, sni)
                                sni_is_ip = True
                            except Exception:
                                try:
                                    socket.inet_pton(socket.AF_INET6, sni)
                                    sni_is_ip = True
                                except Exception:
                                    pass
                        flow.ja4_string = generate_ja4(client_hello, is_quic=True, has_sni=has_sni, sni_is_ip=sni_is_ip)
                    except Exception:
                        pass
                    return

        # 4. DNS (Port 53)
        elif packet.tuple.dst_port == 53 or packet.tuple.src_port == 53:
            flow.app_type = AppType.DNS
            flow.classified = True
            return

        # 5. DoT (Port 853)
        elif packet.tuple.dst_port == 853 or packet.tuple.src_port == 853:
            flow.app_type = AppType.DNS
            if not flow.sni:
                flow.sni = "DoT Query"
            flow.classified = True
            return

        if packet.tuple.dst_port == 443:
            flow.app_type = AppType.HTTPS
        elif packet.tuple.dst_port == 80:
            flow.app_type = AppType.HTTP


class LoadBalancer:
    def __init__(self, id_: int, fps: List[FastPath]) -> None:
        self.id = id_
        self.fps = fps
        self.input_queue = TSQueue()
        self.running = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self._dispatched = 0
        self._dispatched_lock = threading.Lock()

    def start(self) -> None:
        self.running.set()
        self.thread = threading.Thread(target=self._run, name=f"LB{self.id}")
        self.thread.start()

    def stop(self) -> None:
        self.running.clear()
        self.input_queue.shutdown()
        if self.thread is not None:
            self.thread.join()

    def dispatched(self) -> int:
        with self._dispatched_lock:
            return self._dispatched

    def _increment_dispatched(self) -> None:
        with self._dispatched_lock:
            self._dispatched += 1

    def _run(self) -> None:
        while self.running.is_set() or not self.input_queue.empty():
            packet = self.input_queue.pop(100)
            if packet is None:
                continue
            try:
                fp_idx = five_tuple_hash(packet.tuple) % len(self.fps)
                self.fps[fp_idx].input_queue.push(packet)
                self._increment_dispatched()
            finally:
                self.input_queue.task_done()


class DPIEngine:
    @dataclass
    class Config:
        num_lbs: int = 2
        fps_per_lb: int = 2

    def __init__(self, config: "DPIEngine.Config") -> None:
        self.config = config
        self.rules = Rules()
        self.stats = Stats()
        self.output_queue = TSQueue()
        self.fps: List[FastPath] = []
        self.lbs: List[LoadBalancer] = []

        total_fps = config.num_lbs * config.fps_per_lb

        print()
        print("==============================================================")
        print("              DPI ENGINE v2.0 (Python port)")
        print("==============================================================")
        print(
            f" Load Balancers: {config.num_lbs:2d}    "
            f"FPs per LB: {config.fps_per_lb:2d}    Total FPs: {total_fps:2d}"
        )
        print("==============================================================")
        print()

        for idx in range(total_fps):
            self.fps.append(FastPath(idx, self.rules, self.stats, self.output_queue))

        for lb_idx in range(config.num_lbs):
            start = lb_idx * config.fps_per_lb
            lb_fps = self.fps[start : start + config.fps_per_lb]
            self.lbs.append(LoadBalancer(lb_idx, lb_fps))

    def block_ip(self, ip: str) -> None:
        self.rules.block_ip(ip)
        self._mark_active_flows_blocked(ip=ip)

    def unblock_ip(self, ip: str) -> None:
        self.rules.unblock_ip(ip)

    def block_app(self, app: str) -> None:
        if self.rules.block_app(app):
            app_type = Rules.app_from_name(app)
            if app_type is not None:
                self._mark_active_flows_blocked(app=app_type)

    def unblock_app(self, app: str) -> None:
        self.rules.unblock_app(app)

    def block_domain(self, domain: str) -> None:
        self.rules.block_domain(domain)
        matched_ips = self._mark_active_flows_blocked(domain=domain)
        for ip in matched_ips:
            self.rules.block_ip(ip)
            self._mark_active_flows_blocked(ip=ip)
            print(f"[Rules] Dynamically blocked IP {ip} from active flow matching domain rule: {domain}")

    def unblock_domain(self, domain: str) -> None:
        self.rules.unblock_domain(domain)

    def rules_payload(self) -> Dict[str, List[str]]:
        return self.rules.snapshot()

    def _mark_active_flows_blocked(
        self,
        *,
        ip: Optional[str] = None,
        app: Optional[AppType] = None,
        domain: Optional[str] = None,
    ) -> List[str]:
        matched_ips: List[str] = []
        for fp in self.fps:
            fp_matched_ips, _ = fp.mark_matching_flows_blocked(ip=ip, app=app, domain=domain)
            for matched_ip in fp_matched_ips:
                if matched_ip not in matched_ips:
                    matched_ips.append(matched_ip)
        return matched_ips

    def process(self, input_file: str, output_file: str) -> bool:
        self.stats.set_status("running", input_file, output_file)
        reader = PcapReader()
        if not reader.open(input_file):
            self.stats.set_status("failed")
            return False

        if reader.global_header is None:
            self.stats.set_status("failed")
            return False

        try:
            output = open(output_file, "wb")
        except OSError:
            print("Cannot open output file", file=sys.stderr)
            reader.close()
            self.stats.set_status("failed")
            return False

        output.write(reader.global_header.raw)
        output_lock = threading.Lock()
        output_running = threading.Event()
        output_running.set()

        def output_writer() -> None:
            while output_running.is_set() or not self.output_queue.empty():
                packet = self.output_queue.pop(50)
                if packet is None:
                    continue
                try:
                    packet_header = struct.pack(
                        reader.global_header.endian + "IIII",
                        packet.ts_sec,
                        packet.ts_usec,
                        len(packet.data),
                        len(packet.data),
                    )
                    with output_lock:
                        output.write(packet_header)
                        output.write(packet.data)
                finally:
                    self.output_queue.task_done()

        for fp in self.fps:
            fp.start()
        for lb in self.lbs:
            lb.start()

        output_thread = threading.Thread(target=output_writer, name="OutputWriter")
        output_thread.start()

        print("[Reader] Processing packets...")
        packet_id = 0

        while True:
            raw = reader.read_next_packet()
            if raw is None:
                break

            if self._ingest_raw_packet(raw, packet_id):
                packet_id += 1

        print(f"[Reader] Done reading {packet_id} packets")
        reader.close()

        for lb in self.lbs:
            lb.input_queue.join()
        for lb in self.lbs:
            lb.stop()

        for fp in self.fps:
            fp.input_queue.join()
        for fp in self.fps:
            fp.stop()

        self.output_queue.join()
        output_running.clear()
        self.output_queue.shutdown()
        output_thread.join()

        with output_lock:
            output.close()

        self.stats.set_status("finished")
        self.print_report()
        return True

    def process_live(
        self,
        output_file: str,
        iface: Optional[str],
        duration: Optional[float],
        packet_count: int,
        bpf_filter: Optional[str],
        stop_event: Optional[threading.Event] = None,
    ) -> bool:
        scapy = load_scapy()
        if scapy is None or iface == "simulated":
            return self.process_simulated(output_file, duration, packet_count, stop_event)

        conf = scapy["conf"]
        sniff = scapy["sniff"]
        try:
            conf.use_pcap = True
        except Exception:
            pass

        input_label = f"live:{iface or 'default'}"
        self.stats.set_status("running", input_label, output_file)
        self.rules.iface = iface

        pcap_endian = "<"
        pcap_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        try:
            output = open(output_file, "wb")
        except OSError:
            print("Cannot open output file", file=sys.stderr)
            self.stats.set_status("failed")
            return False

        output.write(pcap_header)
        output_lock = threading.Lock()
        output_running = threading.Event()
        output_running.set()

        def output_writer() -> None:
            while output_running.is_set() or not self.output_queue.empty():
                packet = self.output_queue.pop(50)
                if packet is None:
                    continue
                try:
                    packet_header = struct.pack(
                        pcap_endian + "IIII",
                        packet.ts_sec,
                        packet.ts_usec,
                        len(packet.data),
                        len(packet.data),
                    )
                    with output_lock:
                        output.write(packet_header)
                        output.write(packet.data)
                finally:
                    self.output_queue.task_done()

        for fp in self.fps:
            fp.start()
        for lb in self.lbs:
            lb.start()

        output_thread = threading.Thread(target=output_writer, name="OutputWriter")
        output_thread.start()

        packet_id = 0
        sniffed_count = 0
        packet_id_lock = threading.Lock()

        def on_packet(scapy_packet) -> None:
            nonlocal packet_id, sniffed_count
            sniffed_count += 1
            data = bytes(scapy_packet)
            if not data:
                return
            ts = float(getattr(scapy_packet, "time", time.time()))
            ts_sec = int(ts)
            ts_usec = int((ts - ts_sec) * 1_000_000)
            
            # Extract sniffed interface name from Scapy packet
            sniffed_on = getattr(scapy_packet, "sniffed_on", None)
            iface_name = None
            if sniffed_on is not None:
                if isinstance(sniffed_on, str):
                    iface_name = sniffed_on
                else:
                    iface_name = getattr(sniffed_on, "name", None)
            if not iface_name:
                iface_name = iface
                
            raw = RawPacket(
                header=PcapPacketHeader(ts_sec, ts_usec, len(data), len(data)),
                data=data,
                iface=iface_name,
            )
            with packet_id_lock:
                current_id = packet_id
                if self._ingest_raw_packet(raw, current_id):
                    packet_id += 1

        print("[Live] Starting Scapy capture...")
        if iface:
            print(f"[Live] Interface: {iface}")
        else:
            print("[Live] Interface: Scapy default")
        if bpf_filter:
            print(f"[Live] BPF filter: {bpf_filter}")
        if duration:
            print(f"[Live] Duration: {duration:g} seconds")
        elif packet_count:
            print(f"[Live] Packet count: {packet_count}")
        else:
            print("[Live] Running until Ctrl+C")

        sniff_kwargs = {
            "iface": iface,
            "prn": on_packet,
            "store": False,
        }
        if bpf_filter:
            sniff_kwargs["filter"] = bpf_filter

        ok = True
        start_time = time.time()
        try:
            while True:
                if stop_event is not None and stop_event.is_set():
                    break
                if duration is not None and time.time() - start_time >= duration:
                    break
                if packet_count > 0 and sniffed_count >= packet_count:
                    break

                loop_kwargs = dict(sniff_kwargs)
                loop_timeout = 1.0
                if duration is not None:
                    remaining = duration - (time.time() - start_time)
                    if remaining <= 0:
                        break
                    loop_timeout = min(loop_timeout, remaining)
                loop_kwargs["timeout"] = loop_timeout

                if packet_count > 0:
                    remaining_count = packet_count - sniffed_count
                    if remaining_count <= 0:
                        break
                    loop_kwargs["count"] = remaining_count

                sniff(**loop_kwargs)
        except KeyboardInterrupt:
            print("\n[Live] Capture stopped by user")
        except Exception as exc:
            print(f"[Live] Capture failed: {exc}", file=sys.stderr)
            print("Check that Npcap is installed and the interface name is valid.", file=sys.stderr)
            self.stats.set_status("failed")
            ok = False
            raise exc

        print(f"[Live] Done reading {packet_id} packets")

        for lb in self.lbs:
            lb.input_queue.join()
        for lb in self.lbs:
            lb.stop()

        for fp in self.fps:
            fp.input_queue.join()
        for fp in self.fps:
            fp.stop()

        self.output_queue.join()
        output_running.clear()
        self.output_queue.shutdown()
        output_thread.join()

        with output_lock:
            output.close()

        if ok:
            self.stats.set_status("finished")
        self.print_report()
        return ok

    def process_simulated(
        self,
        output_file: str,
        duration: Optional[float],
        packet_count: int,
        stop_event: Optional[threading.Event] = None,
    ) -> bool:
        input_label = "live:simulated"
        self.stats.set_status("running", input_label, output_file)
        self.rules.iface = "simulated"

        pcap_endian = "<"
        pcap_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        try:
            output = open(output_file, "wb")
        except OSError:
            print("Cannot open output file", file=sys.stderr)
            self.stats.set_status("failed")
            return False

        output.write(pcap_header)
        output_lock = threading.Lock()
        output_running = threading.Event()
        output_running.set()

        def output_writer() -> None:
            while output_running.is_set() or not self.output_queue.empty():
                packet = self.output_queue.pop(50)
                if packet is None:
                    continue
                try:
                    packet_header = struct.pack(
                        pcap_endian + "IIII",
                        packet.ts_sec,
                        packet.ts_usec,
                        len(packet.data),
                        len(packet.data),
                    )
                    with output_lock:
                        output.write(packet_header)
                        output.write(packet.data)
                finally:
                    self.output_queue.task_done()

        for fp in self.fps:
            fp.start()
        for lb in self.lbs:
            lb.start()

        output_thread = threading.Thread(target=output_writer, name="OutputWriter")
        output_thread.start()

        packet_id = 0
        sniffed_count = 0
        packet_id_lock = threading.Lock()

        # Generate test_dpi.pcap if it does not exist
        pcap_path = "test_dpi.pcap"
        if not os.path.exists(pcap_path):
            try:
                generate_test_pcap(pcap_path)
            except Exception:
                pass

        print("[Simulation] Starting simulated packet play...")
        if duration:
            print(f"[Simulation] Duration: {duration:g} seconds")
        elif packet_count:
            print(f"[Simulation] Packet count: {packet_count}")
        else:
            print("[Simulation] Running indefinitely")

        ok = True
        start_time = time.time()
        
        try:
            while True:
                if stop_event is not None and stop_event.is_set():
                    break
                if duration is not None and time.time() - start_time >= duration:
                    break
                if packet_count > 0 and sniffed_count >= packet_count:
                    break

                reader = PcapReader()
                if not reader.open(pcap_path):
                    time.sleep(1)
                    continue

                packet_read_loop = True
                while packet_read_loop:
                    if stop_event is not None and stop_event.is_set():
                        break
                    if duration is not None and time.time() - start_time >= duration:
                        break
                    if packet_count > 0 and sniffed_count >= packet_count:
                        break

                    raw = reader.read_next_packet()
                    if raw is None:
                        break # reached end of file, loop will restart it

                    # Rewrite timestamp to current time to simulate live traffic
                    ts = time.time()
                    ts_sec = int(ts)
                    ts_usec = int((ts - ts_sec) * 1_000_000)
                    
                    sim_raw = RawPacket(
                        header=PcapPacketHeader(ts_sec, ts_usec, len(raw.data), len(raw.data)),
                        data=raw.data,
                        iface="simulated",
                    )

                    with packet_id_lock:
                        current_id = packet_id
                        if self._ingest_raw_packet(sim_raw, current_id):
                            packet_id += 1
                            sniffed_count += 1

                    # Sleep between packets to simulate real-world arrival rate
                    time.sleep(random.uniform(0.08, 0.25))

                reader.close()
                if stop_event is not None and stop_event.is_set():
                    break
        except Exception as exc:
            print(f"[Simulation] Failed: {exc}", file=sys.stderr)
            self.stats.set_status("failed")
            ok = False

        print(f"[Simulation] Done reading {packet_id} packets")

        for lb in self.lbs:
            lb.input_queue.join()
        for lb in self.lbs:
            lb.stop()

        for fp in self.fps:
            fp.input_queue.join()
        for fp in self.fps:
            fp.stop()

        self.output_queue.join()
        output_running.clear()
        self.output_queue.shutdown()
        output_thread.join()

        with output_lock:
            output.close()

        if ok:
            self.stats.set_status("finished")
        self.print_report()
        return ok

    def _ingest_raw_packet(self, raw: RawPacket, packet_id: int) -> bool:
        parsed = PacketParser.parse(raw)
        if parsed is None:
            return False
        if not parsed.has_ip or (not parsed.has_tcp and not parsed.has_udp):
            return False

        packet = self._create_packet(raw, parsed, packet_id)

        self.stats.record_packet(
            len(packet.data),
            is_tcp=parsed.has_tcp,
            is_udp=parsed.has_udp,
        )

        lb_idx = five_tuple_hash(packet.tuple) % len(self.lbs)
        self.lbs[lb_idx].input_queue.push(packet)
        return True

    def _create_packet(self, raw: RawPacket, parsed: ParsedPacket, packet_id: int) -> Packet:
        tuple_ = FiveTuple(
            src_ip=parsed.src_ip,
            dst_ip=parsed.dest_ip,
            src_port=parsed.src_port,
            dst_port=parsed.dest_port,
            protocol=parsed.protocol,
        )

        return Packet(
            id=packet_id,
            ts_sec=raw.header.ts_sec,
            ts_usec=raw.header.ts_usec,
            tuple=tuple_,
            data=raw.data,
            tcp_flags=parsed.tcp_flags,
            payload_offset=parsed.payload_offset,
            payload_length=parsed.payload_length,
            iface=raw.iface,
        )

    def print_report(self) -> None:
        (
            total_packets,
            total_bytes,
            forwarded,
            dropped,
            tcp_packets,
            udp_packets,
            app_counts,
            detected_snis,
        ) = self.stats.snapshot()

        print()
        print("==============================================================")
        print("                      PROCESSING REPORT")
        print("==============================================================")
        print(f" Total Packets:      {total_packets:12d}")
        print(f" Total Bytes:        {total_bytes:12d}")
        print(f" TCP Packets:        {tcp_packets:12d}")
        print(f" UDP Packets:        {udp_packets:12d}")
        print("--------------------------------------------------------------")
        print(f" Forwarded:          {forwarded:12d}")
        print(f" Dropped:            {dropped:12d}")
        print("--------------------------------------------------------------")
        print(" THREAD STATISTICS")
        for idx, lb in enumerate(self.lbs):
            print(f"   LB{idx} dispatched:   {lb.dispatched():12d}")
        for idx, fp in enumerate(self.fps):
            print(f"   FP{idx} processed:    {fp.processed():12d}")
        print("--------------------------------------------------------------")
        print("                   APPLICATION BREAKDOWN")

        sorted_apps = sorted(app_counts.items(), key=lambda item: item[1], reverse=True)
        for app, count in sorted_apps:
            pct = (100.0 * count / total_packets) if total_packets > 0 else 0.0
            bar = "#" * int(pct / 5)
            print(f" {app_type_to_string(app):15s}{count:8d} {pct:5.1f}% {bar:20s}")

        print("==============================================================")

        if detected_snis:
            print()
            print("[Detected Domains/SNIs]")
            for sni, app in detected_snis.items():
                print(f"  - {sni} -> {app_type_to_string(app)}")

    def dashboard_payload(self) -> Dict[str, object]:
        snap = self.stats.dashboard_snapshot()
        total_packets = int(snap["total_packets"])
        app_counts = snap["app_counts"]
        detected_snis = snap["detected_snis"]
        started_at = float(snap["started_at"])
        finished_at = float(snap["finished_at"])
        now = time.time()
        elapsed = 0.0
        if started_at:
            elapsed = (finished_at or now) - started_at

        apps = []
        for app, count in sorted(app_counts.items(), key=lambda item: item[1], reverse=True):
            pct = (100.0 * count / total_packets) if total_packets else 0.0
            apps.append(
                {
                    "name": app_type_to_string(app),
                    "count": count,
                    "pct": pct,
                }
            )

        domains = [
            {"domain": domain, "app": app_type_to_string(app)}
            for domain, app in sorted(detected_snis.items())
        ]

        lb_threads = [
            {"name": f"LB{idx}", "packets": lb.dispatched()}
            for idx, lb in enumerate(self.lbs)
        ]
        fp_threads = [
            {"name": f"FP{idx}", "packets": fp.processed()}
            for idx, fp in enumerate(self.fps)
        ]

        return {
            "status": snap["status"],
            "input_file": snap["input_file"],
            "output_file": snap["output_file"],
            "elapsed": elapsed,
            "total_packets": total_packets,
            "total_bytes": snap["total_bytes"],
            "forwarded": snap["forwarded"],
            "dropped": snap["dropped"],
            "drop_rate": (100.0 * int(snap["dropped"]) / total_packets)
            if total_packets
            else 0.0,
            "tcp_packets": snap["tcp_packets"],
            "udp_packets": snap["udp_packets"],
            "apps": apps,
            "domains": domains,
            "lb_threads": lb_threads,
            "fp_threads": fp_threads,
            "recent_packets": list(reversed(snap["recent_packets"])),
            "recent_anomalies": list(reversed(snap.get("recent_anomalies", []))),
        }


class PCAPWriter:
    def __init__(self, filename: str) -> None:
        self.file = open(filename, "wb")
        self.timestamp = 1700000000
        self.write_global_header()

    def write_global_header(self) -> None:
        self.file.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

    def write_packet(self, data: bytes) -> None:
        ts_sec = self.timestamp
        ts_usec = random.randint(0, 999999)
        self.timestamp += 1
        self.file.write(struct.pack("<IIII", ts_sec, ts_usec, len(data), len(data)))
        self.file.write(data)

    def close(self) -> None:
        self.file.close()


def create_ethernet_header(src_mac: str, dst_mac: str, ethertype: int = 0x0800) -> bytes:
    return bytes.fromhex(dst_mac.replace(":", "")) + bytes.fromhex(
        src_mac.replace(":", "")
    ) + struct.pack(">H", ethertype)


def create_ip_header(src_ip: str, dst_ip: str, protocol: int, payload_len: int) -> bytes:
    version_ihl = 0x45
    tos = 0
    total_len = 20 + payload_len
    ident = random.randint(1, 65535)
    flags_frag = 0x4000
    ttl = 64
    checksum = 0

    header = struct.pack(
        ">BBHHHBBH",
        version_ihl,
        tos,
        total_len,
        ident,
        flags_frag,
        ttl,
        protocol,
        checksum,
    )
    header += bytes(int(part) for part in src_ip.split("."))
    header += bytes(int(part) for part in dst_ip.split("."))
    return header


def create_tcp_header(
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload_len: int = 0,
) -> bytes:
    _ = payload_len
    data_offset = 5 << 4
    window = 65535
    checksum = 0
    urgent = 0
    return struct.pack(
        ">HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        data_offset,
        flags,
        window,
        checksum,
        urgent,
    )


def create_udp_header(src_port: int, dst_port: int, payload_len: int) -> bytes:
    length = 8 + payload_len
    checksum = 0
    return struct.pack(">HHHH", src_port, dst_port, length, checksum)


def create_tls_client_hello(sni: str) -> bytes:
    sni_bytes = sni.encode("ascii")
    sni_entry = struct.pack(">BH", 0, len(sni_bytes)) + sni_bytes
    sni_list = struct.pack(">H", len(sni_entry)) + sni_entry
    sni_ext = struct.pack(">HH", 0x0000, len(sni_list)) + sni_list

    supported_versions = struct.pack(">HHB", 0x002B, 3, 2) + struct.pack(">H", 0x0304)
    extensions = sni_ext + supported_versions
    extensions_data = struct.pack(">H", len(extensions)) + extensions

    client_version = struct.pack(">H", 0x0303)
    random_bytes = bytes(random.randint(0, 255) for _ in range(32))
    session_id = struct.pack("B", 0)
    cipher_suites = struct.pack(">H", 4) + struct.pack(">HH", 0x1301, 0x1302)
    compression = struct.pack("BB", 1, 0)

    body = client_version + random_bytes + session_id + cipher_suites + compression + extensions_data
    handshake = struct.pack("B", 0x01) + struct.pack(">I", len(body))[1:] + body
    return struct.pack("B", 0x16) + struct.pack(">H", 0x0301) + struct.pack(">H", len(handshake)) + handshake


def create_http_request(host: str, path: str = "/") -> bytes:
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: DPI-Test/1.0\r\n"
        "Accept: */*\r\n\r\n"
    ).encode("ascii")


def create_dns_query(domain: str) -> bytes:
    txid = struct.pack(">H", random.randint(1, 65535))
    flags = struct.pack(">H", 0x0100)
    counts = struct.pack(">HHHH", 1, 0, 0, 0)
    question = b""
    for label in domain.split("."):
        question += struct.pack("B", len(label)) + label.encode("ascii")
    question += struct.pack("B", 0)
    question += struct.pack(">HH", 1, 1)
    return txid + flags + counts + question


def generate_test_pcap(filename: str = "test_dpi.pcap") -> None:
    writer = PCAPWriter(filename)
    user_mac = "00:11:22:33:44:55"
    user_ip = "192.168.1.100"
    gateway_mac = "aa:bb:cc:dd:ee:ff"

    tls_connections = [
        ("142.250.185.206", "www.google.com", 443),
        ("142.250.185.110", "www.youtube.com", 443),
        ("157.240.1.35", "www.facebook.com", 443),
        ("157.240.1.174", "www.instagram.com", 443),
        ("104.244.42.65", "twitter.com", 443),
        ("52.94.236.248", "www.amazon.com", 443),
        ("23.52.167.61", "www.netflix.com", 443),
        ("140.82.114.4", "github.com", 443),
        ("104.16.85.20", "discord.com", 443),
        ("35.186.224.25", "zoom.us", 443),
        ("35.186.227.140", "web.telegram.org", 443),
        ("99.86.0.100", "www.tiktok.com", 443),
        ("35.186.224.47", "open.spotify.com", 443),
        ("192.0.78.24", "www.cloudflare.com", 443),
        ("13.107.42.14", "www.microsoft.com", 443),
        ("17.253.144.10", "www.apple.com", 443),
    ]

    http_connections = [
        ("93.184.216.34", "example.com", 80),
        ("185.199.108.153", "httpbin.org", 80),
    ]

    dns_queries = [
        "www.google.com",
        "www.youtube.com",
        "www.facebook.com",
        "api.twitter.com",
    ]

    seq_base = 1000

    for dst_ip, sni, dst_port in tls_connections:
        src_port = random.randint(49152, 65535)

        eth = create_ethernet_header(user_mac, gateway_mac)
        tcp = create_tcp_header(src_port, dst_port, seq_base, 0, 0x02)
        ip = create_ip_header(user_ip, dst_ip, 6, len(tcp))
        writer.write_packet(eth + ip + tcp)

        tcp = create_tcp_header(dst_port, src_port, seq_base + 1000, seq_base + 1, 0x12)
        ip = create_ip_header(dst_ip, user_ip, 6, len(tcp))
        eth = create_ethernet_header(gateway_mac, user_mac)
        writer.write_packet(eth + ip + tcp)

        eth = create_ethernet_header(user_mac, gateway_mac)
        tcp = create_tcp_header(src_port, dst_port, seq_base + 1, seq_base + 1001, 0x10)
        ip = create_ip_header(user_ip, dst_ip, 6, len(tcp))
        writer.write_packet(eth + ip + tcp)

        tls_data = create_tls_client_hello(sni)
        tcp = create_tcp_header(src_port, dst_port, seq_base + 1, seq_base + 1001, 0x18)
        ip = create_ip_header(user_ip, dst_ip, 6, len(tcp) + len(tls_data))
        writer.write_packet(eth + ip + tcp + tls_data)

        seq_base += 10000

    for dst_ip, host, dst_port in http_connections:
        src_port = random.randint(49152, 65535)
        eth = create_ethernet_header(user_mac, gateway_mac)
        tcp = create_tcp_header(src_port, dst_port, seq_base, 0, 0x02)
        ip = create_ip_header(user_ip, dst_ip, 6, len(tcp))
        writer.write_packet(eth + ip + tcp)

        http_data = create_http_request(host)
        tcp = create_tcp_header(src_port, dst_port, seq_base + 1, 1, 0x18)
        ip = create_ip_header(user_ip, dst_ip, 6, len(tcp) + len(http_data))
        writer.write_packet(eth + ip + tcp + http_data)

        seq_base += 10000

    dns_server = "8.8.8.8"
    for domain in dns_queries:
        src_port = random.randint(49152, 65535)
        dns_data = create_dns_query(domain)
        eth = create_ethernet_header(user_mac, gateway_mac)
        udp = create_udp_header(src_port, 53, len(dns_data))
        ip = create_ip_header(user_ip, dns_server, 17, len(udp) + len(dns_data))
        writer.write_packet(eth + ip + udp + dns_data)

    blocked_source_ip = "192.168.1.50"
    for _ in range(5):
        src_port = random.randint(49152, 65535)
        dst_ip = "172.217.0.100"
        eth = create_ethernet_header("00:11:22:33:44:56", gateway_mac)
        tcp = create_tcp_header(src_port, 443, seq_base, 0, 0x02)
        ip = create_ip_header(blocked_source_ip, dst_ip, 6, len(tcp))
        writer.write_packet(eth + ip + tcp)
        seq_base += 1000

    writer.close()
    print(f"Created {filename} with test traffic")
