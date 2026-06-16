from __future__ import annotations

import enum
import os
import queue
import socket
import struct
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any


class AppType(enum.IntEnum):
    UNKNOWN = 0
    HTTP = 1
    HTTPS = 2
    DNS = 3
    TLS = 4
    QUIC = 5
    GOOGLE = 6
    FACEBOOK = 7
    YOUTUBE = 8
    TWITTER = 9
    INSTAGRAM = 10
    NETFLIX = 11
    AMAZON = 12
    MICROSOFT = 13
    APPLE = 14
    WHATSAPP = 15
    TELEGRAM = 16
    TIKTOK = 17
    SPOTIFY = 18
    ZOOM = 19
    DISCORD = 20
    GITHUB = 21
    CLOUDFLARE = 22
    APP_COUNT = 23


def app_type_to_string(app: AppType) -> str:
    names = {
        AppType.UNKNOWN: "Unknown",
        AppType.HTTP: "HTTP",
        AppType.HTTPS: "HTTPS",
        AppType.DNS: "DNS",
        AppType.TLS: "TLS",
        AppType.QUIC: "QUIC",
        AppType.GOOGLE: "Google",
        AppType.FACEBOOK: "Facebook",
        AppType.YOUTUBE: "YouTube",
        AppType.TWITTER: "Twitter/X",
        AppType.INSTAGRAM: "Instagram",
        AppType.NETFLIX: "Netflix",
        AppType.AMAZON: "Amazon",
        AppType.MICROSOFT: "Microsoft",
        AppType.APPLE: "Apple",
        AppType.WHATSAPP: "WhatsApp",
        AppType.TELEGRAM: "Telegram",
        AppType.TIKTOK: "TikTok",
        AppType.SPOTIFY: "Spotify",
        AppType.ZOOM: "Zoom",
        AppType.DISCORD: "Discord",
        AppType.GITHUB: "GitHub",
        AppType.CLOUDFLARE: "Cloudflare",
    }
    return names.get(app, "Unknown")


def sni_to_app_type(sni: str) -> AppType:
    if not sni:
        return AppType.UNKNOWN

    lower_sni = sni.lower()

    # SNI-to-app classification order.
    if (
        "google" in lower_sni
        or "gstatic" in lower_sni
        or "googleapis" in lower_sni
        or "ggpht" in lower_sni
        or "gvt1" in lower_sni
    ):
        return AppType.GOOGLE

    if (
        "youtube" in lower_sni
        or "ytimg" in lower_sni
        or "youtu.be" in lower_sni
        or "yt3.ggpht" in lower_sni
    ):
        return AppType.YOUTUBE

    if (
        "facebook" in lower_sni
        or "fbcdn" in lower_sni
        or "fb.com" in lower_sni
        or "fbsbx" in lower_sni
        or "meta.com" in lower_sni
    ):
        return AppType.FACEBOOK

    if "instagram" in lower_sni or "cdninstagram" in lower_sni:
        return AppType.INSTAGRAM

    if "whatsapp" in lower_sni or "wa.me" in lower_sni:
        return AppType.WHATSAPP

    if (
        "twitter" in lower_sni
        or "twimg" in lower_sni
        or "x.com" in lower_sni
        or "t.co" in lower_sni
    ):
        return AppType.TWITTER

    if "netflix" in lower_sni or "nflxvideo" in lower_sni or "nflximg" in lower_sni:
        return AppType.NETFLIX

    if (
        "amazon" in lower_sni
        or "amazonaws" in lower_sni
        or "cloudfront" in lower_sni
        or "aws" in lower_sni
    ):
        return AppType.AMAZON

    if (
        "microsoft" in lower_sni
        or "msn.com" in lower_sni
        or "office" in lower_sni
        or "azure" in lower_sni
        or "live.com" in lower_sni
        or "outlook" in lower_sni
        or "bing" in lower_sni
    ):
        return AppType.MICROSOFT

    if (
        "apple" in lower_sni
        or "icloud" in lower_sni
        or "mzstatic" in lower_sni
        or "itunes" in lower_sni
    ):
        return AppType.APPLE

    if "telegram" in lower_sni or "t.me" in lower_sni:
        return AppType.TELEGRAM

    if (
        "tiktok" in lower_sni
        or "tiktokcdn" in lower_sni
        or "musical.ly" in lower_sni
        or "bytedance" in lower_sni
    ):
        return AppType.TIKTOK

    if "spotify" in lower_sni or "scdn.co" in lower_sni:
        return AppType.SPOTIFY

    if "zoom" in lower_sni:
        return AppType.ZOOM

    if "discord" in lower_sni or "discordapp" in lower_sni:
        return AppType.DISCORD

    if "github" in lower_sni or "githubusercontent" in lower_sni:
        return AppType.GITHUB

    if "cloudflare" in lower_sni or "cf-" in lower_sni:
        return AppType.CLOUDFLARE

    return AppType.HTTPS


def parse_ip_little(ip: str) -> int:
    result = 0
    octet = 0
    shift = 0
    for char in ip:
        if char == ".":
            result |= octet << shift
            shift += 8
            octet = 0
        elif "0" <= char <= "9":
            octet = octet * 10 + (ord(char) - ord("0"))
    result |= octet << shift
    return result & 0xFFFFFFFF


def ip_to_string_little(ip: int) -> str:
    return ".".join(str((ip >> shift) & 0xFF) for shift in (0, 8, 16, 24))


def load_scapy():
    if sys.platform.startswith("win") and "WINDIR" not in os.environ:
        os.environ["WINDIR"] = os.environ.get("SystemRoot", r"C:\Windows")

    try:
        from scapy.all import conf, get_if_list, sniff
    except ImportError:
        print("Scapy is not installed.", file=sys.stderr)
        print("Install it with: python -m pip install scapy", file=sys.stderr)
        print("On Windows, install Npcap first and enable WinPcap API-compatible mode.", file=sys.stderr)
        return None
    except Exception as exc:
        print(f"Could not initialize Scapy: {exc}", file=sys.stderr)
        print("Check that Npcap is installed and available to Scapy.", file=sys.stderr)
        return None
    return {
        "conf": conf,
        "get_if_list": get_if_list,
        "sniff": sniff,
    }


def list_scapy_interfaces() -> bool:
    scapy = load_scapy()
    if scapy is None:
        return False

    conf = scapy["conf"]
    get_if_list = scapy["get_if_list"]
    try:
        conf.use_pcap = True
    except Exception:
        pass

    print("Available Scapy interfaces:")
    try:
        ifaces = list(get_if_list())
    except Exception as exc:
        print(f"Could not list interfaces: {exc}", file=sys.stderr)
        return False

    for idx, iface in enumerate(ifaces, start=1):
        print(f"  {idx}. {iface}")
    return True


def ip_to_int(ip_str: str) -> int:
    if ":" in ip_str:
        try:
            return int.from_bytes(socket.inet_pton(socket.AF_INET6, ip_str), 'big')
        except Exception:
            return 0
    else:
        try:
            return int.from_bytes(socket.inet_pton(socket.AF_INET, ip_str), 'big')
        except Exception:
            return 0


@dataclass(frozen=True)
class FiveTuple:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int

    def reverse(self) -> "FiveTuple":
        return FiveTuple(
            self.dst_ip,
            self.src_ip,
            self.dst_port,
            self.src_port,
            self.protocol,
        )

    def to_string(self) -> str:
        proto = "TCP" if self.protocol == 6 else "UDP" if self.protocol == 17 else "?"
        return f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} ({proto})"


def five_tuple_hash(tuple_: FiveTuple) -> int:
    ip1 = ip_to_int(tuple_.src_ip)
    ip2 = ip_to_int(tuple_.dst_ip)
    port1 = tuple_.src_port
    port2 = tuple_.dst_port

    if ip1 < ip2 or (ip1 == ip2 and port1 < port2):
        first_ip, second_ip = ip1, ip2
        first_port, second_port = port1, port2
    else:
        first_ip, second_ip = ip2, ip1
        first_port, second_port = port2, port1

    h = 0
    for value in (
        first_ip,
        second_ip,
        first_port,
        second_port,
        tuple_.protocol,
    ):
        h ^= (value + 0x9E3779B9 + ((h << 6) & 0xFFFFFFFFFFFFFFFF) + (h >> 2))
        h &= 0xFFFFFFFFFFFFFFFF
    return h



@dataclass
class PcapGlobalHeader:
    magic_number: int
    version_major: int
    version_minor: int
    thiszone: int
    sigfigs: int
    snaplen: int
    network: int
    endian: str
    raw: bytes


@dataclass
class PcapPacketHeader:
    ts_sec: int
    ts_usec: int
    incl_len: int
    orig_len: int


@dataclass
class RawPacket:
    header: PcapPacketHeader
    data: bytes
    iface: Optional[str] = None


class PcapReader:
    PCAP_MAGIC_NATIVE = 0xA1B2C3D4
    PCAP_MAGIC_SWAPPED = 0xD4C3B2A1

    def __init__(self) -> None:
        self.file = None
        self.global_header: Optional[PcapGlobalHeader] = None

    def open(self, filename: str) -> bool:
        self.close()
        try:
            self.file = open(filename, "rb")
        except OSError:
            print(f"Error: Could not open file: {filename}", file=sys.stderr)
            return False

        raw = self.file.read(24)
        if len(raw) != 24:
            print("Error: Could not read PCAP global header", file=sys.stderr)
            self.close()
            return False

        magic_bytes = raw[:4]
        if magic_bytes == b"\xd4\xc3\xb2\xa1":
            endian = "<"
        elif magic_bytes == b"\xa1\xb2\xc3\xd4":
            endian = ">"
        else:
            magic = int.from_bytes(magic_bytes, "little", signed=False)
            print(f"Error: Invalid PCAP magic number: 0x{magic:x}", file=sys.stderr)
            self.close()
            return False

        fields = struct.unpack(endian + "IHHIIII", raw)
        self.global_header = PcapGlobalHeader(
            magic_number=fields[0],
            version_major=fields[1],
            version_minor=fields[2],
            thiszone=fields[3],
            sigfigs=fields[4],
            snaplen=fields[5],
            network=fields[6],
            endian=endian,
            raw=raw,
        )

        print(f"Opened PCAP file: {filename}")
        print(f"  Version: {self.global_header.version_major}.{self.global_header.version_minor}")
        print(f"  Snaplen: {self.global_header.snaplen} bytes")
        link = " (Ethernet)" if self.global_header.network == 1 else ""
        print(f"  Link type: {self.global_header.network}{link}")
        return True

    def close(self) -> None:
        if self.file is not None:
            self.file.close()
        self.file = None

    def read_next_packet(self) -> Optional[RawPacket]:
        if self.file is None or self.global_header is None:
            return None

        raw_header = self.file.read(16)
        if len(raw_header) == 0:
            return None
        if len(raw_header) != 16:
            return None

        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
            self.global_header.endian + "IIII", raw_header
        )

        if incl_len > self.global_header.snaplen or incl_len > 65535:
            print(f"Error: Invalid packet length: {incl_len}", file=sys.stderr)
            return None

        data = self.file.read(incl_len)
        if len(data) != incl_len:
            print("Error: Could not read packet data", file=sys.stderr)
            return None

        return RawPacket(PcapPacketHeader(ts_sec, ts_usec, incl_len, orig_len), data)


class EtherType:
    IPV4 = 0x0800
    IPV6 = 0x86DD
    ARP = 0x0806


class Protocol:
    ICMP = 1
    TCP = 6
    UDP = 17


class TCPFlags:
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20


@dataclass
class ParsedPacket:
    timestamp_sec: int = 0
    timestamp_usec: int = 0
    src_mac: str = ""
    dest_mac: str = ""
    ether_type: int = 0
    has_ip: bool = False
    ip_version: int = 0
    src_ip: str = ""
    dest_ip: str = ""
    protocol: int = 0
    ttl: int = 0
    has_tcp: bool = False
    has_udp: bool = False
    src_port: int = 0
    dest_port: int = 0
    tcp_flags: int = 0
    seq_number: int = 0
    ack_number: int = 0
    payload_offset: int = 0
    payload_length: int = 0
    payload_data: bytes = b""


@dataclass
class Packet:
    id: int
    ts_sec: int
    ts_usec: int
    tuple: FiveTuple
    data: bytes
    tcp_flags: int
    payload_offset: int
    payload_length: int
    iface: Optional[str] = None


class Rules:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._blocked_ips: set[str] = set()
        self._blocked_apps: set[AppType] = set()
        self._blocked_domains: List[str] = []

    @staticmethod
    def app_from_name(app: str) -> Optional[AppType]:
        for i in range(int(AppType.APP_COUNT)):
            app_type = AppType(i)
            if app_type_to_string(app_type).lower() == app.lower():
                return app_type
        return None

    def block_ip(self, ip: str) -> None:
        with self._lock:
            self._blocked_ips.add(ip)
        print(f"[Rules] Blocked IP: {ip}")

    def unblock_ip(self, ip: str) -> None:
        with self._lock:
            self._blocked_ips.discard(ip)
        print(f"[Rules] Unblocked IP: {ip}")

    def block_app(self, app: str) -> bool:
        app_type = self.app_from_name(app)
        if app_type is None:
            print(f"[Rules] Unknown app: {app}", file=sys.stderr)
            return False
        with self._lock:
            self._blocked_apps.add(app_type)
        print(f"[Rules] Blocked app: {app_type_to_string(app_type)}")
        return True

    def unblock_app(self, app: str) -> bool:
        app_type = self.app_from_name(app)
        if app_type is None:
            print(f"[Rules] Unknown app: {app}", file=sys.stderr)
            return False
        with self._lock:
            self._blocked_apps.discard(app_type)
        print(f"[Rules] Unblocked app: {app_type_to_string(app_type)}")
        return True

    def block_domain(self, domain: str) -> None:
        with self._lock:
            if domain not in self._blocked_domains:
                self._blocked_domains.append(domain)
        print(f"[Rules] Blocked domain: {domain}")

    def unblock_domain(self, domain: str) -> None:
        with self._lock:
            self._blocked_domains = [item for item in self._blocked_domains if item != domain]
        print(f"[Rules] Unblocked domain: {domain}")

    def blocked_domains_snapshot(self) -> List[str]:
        with self._lock:
            return list(self._blocked_domains)

    def is_domain_blocked(self, domain: str) -> bool:
        if not domain:
            return False
        lower_domain = domain.lower()
        with self._lock:
            return any(blocked.lower() in lower_domain for blocked in self._blocked_domains)

    def is_blocked(self, src_ip: str, dst_ip: str, app: AppType, sni: str) -> bool:
        with self._lock:
            if src_ip in self._blocked_ips or dst_ip in self._blocked_ips:
                return True
            if app in self._blocked_apps:
                return True
            lower_sni = sni.lower()
            for domain in self._blocked_domains:
                if domain.lower() in lower_sni:
                    return True
        return False

    def snapshot(self) -> Dict[str, List[str]]:
        with self._lock:
            return {
                "ips": sorted(list(self._blocked_ips)),
                "apps": sorted(app_type_to_string(app) for app in self._blocked_apps),
                "domains": sorted(self._blocked_domains),
            }


@dataclass
class Stats:
    total_packets: int = 0
    total_bytes: int = 0
    forwarded: int = 0
    dropped: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    app_counts: Dict[AppType, int] = field(default_factory=dict)
    detected_snis: Dict[str, AppType] = field(default_factory=dict)
    recent_packets: deque = field(default_factory=lambda: deque(maxlen=500))
    status: str = "idle"
    input_file: str = ""
    output_file: str = ""
    started_at: float = 0.0
    finished_at: float = 0.0
    anomaly_counts: Dict[str, int] = field(default_factory=dict)
    recent_anomalies: deque = field(default_factory=lambda: deque(maxlen=100))
    global_analytics: Any = field(default=None, init=False)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self) -> None:
        from dpi_engine.analytics import GlobalAnalytics
        self.global_analytics = GlobalAnalytics()

    def set_status(
        self,
        status: str,
        input_file: Optional[str] = None,
        output_file: Optional[str] = None,
    ) -> None:
        with self.lock:
            self.status = status
            if input_file is not None:
                self.input_file = input_file
            if output_file is not None:
                self.output_file = output_file
            if status == "running":
                self.started_at = time.time()
                self.finished_at = 0.0
            elif status in {"finished", "failed"}:
                self.finished_at = time.time()

    def record_packet(self, packet_size: int, is_tcp: bool, is_udp: bool) -> None:
        with self.lock:
            self.total_packets += 1
            self.total_bytes += packet_size
            if is_tcp:
                self.tcp_packets += 1
            elif is_udp:
                self.udp_packets += 1

    def record_forwarded(self) -> None:
        with self.lock:
            self.forwarded += 1

    def record_dropped(self) -> None:
        with self.lock:
            self.dropped += 1

    def record_app(self, app: AppType, sni: str) -> None:
        with self.lock:
            self.app_counts[app] = self.app_counts.get(app, 0) + 1
            if sni:
                self.detected_snis[sni] = app

    def record_packet_decision(
        self,
        packet: Packet,
        app: AppType,
        sni: str,
        action: str,
        fp_id: int,
        ja3: str = "",
        ja4: str = "",
        eti: str = "",
        country: str = "Unknown",
    ) -> None:
        with self.lock:
            self.recent_packets.append(
                {
                    "id": packet.id,
                    "time": f"{packet.ts_sec}.{packet.ts_usec:06d}",
                    "src": f"{packet.tuple.src_ip}:{packet.tuple.src_port}",
                    "dst": f"{packet.tuple.dst_ip}:{packet.tuple.dst_port}",
                    "protocol": "TCP"
                    if packet.tuple.protocol == 6
                    else "UDP"
                    if packet.tuple.protocol == 17
                    else str(packet.tuple.protocol),
                    "app": app_type_to_string(app),
                    "domain": sni,
                    "action": action,
                    "size": len(packet.data),
                    "fp": fp_id,
                    "ja3": ja3,
                    "ja4": ja4,
                    "eti": eti,
                    "country": country,
                }
            )

    def snapshot(self) -> Tuple[int, int, int, int, int, int, Dict[AppType, int], Dict[str, AppType]]:
        with self.lock:
            return (
                self.total_packets,
                self.total_bytes,
                self.forwarded,
                self.dropped,
                self.tcp_packets,
                self.udp_packets,
                dict(self.app_counts),
                dict(self.detected_snis),
            )

    def dashboard_snapshot(self) -> Dict[str, object]:
        with self.lock:
            return {
                "status": self.status,
                "input_file": self.input_file,
                "output_file": self.output_file,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "forwarded": self.forwarded,
                "dropped": self.dropped,
                "tcp_packets": self.tcp_packets,
                "udp_packets": self.udp_packets,
                "app_counts": dict(self.app_counts),
                "detected_snis": dict(self.detected_snis),
                "recent_packets": list(self.recent_packets),
                "anomaly_counts": dict(self.anomaly_counts),
                "recent_anomalies": list(self.recent_anomalies),
                "analytics": self.global_analytics.dashboard_snapshot() if self.global_analytics else {},
            }


class TSQueue:
    def __init__(self, max_size: int = 10000) -> None:
        self._queue: "queue.Queue[Packet]" = queue.Queue(maxsize=max_size)
        self._shutdown = threading.Event()

    def push(self, item: Packet) -> None:
        while not self._shutdown.is_set():
            try:
                self._queue.put(item, timeout=0.1)
                return
            except queue.Full:
                continue

    def pop(self, timeout_ms: int = 100) -> Optional[Packet]:
        try:
            return self._queue.get(timeout=timeout_ms / 1000.0)
        except queue.Empty:
            return None

    def task_done(self) -> None:
        self._queue.task_done()

    def join(self) -> None:
        self._queue.join()

    def shutdown(self) -> None:
        self._shutdown.set()

    def size(self) -> int:
        return self._queue.qsize()

    def empty(self) -> bool:
        return self._queue.empty()

    @property
    def is_shutdown(self) -> bool:
        return self._shutdown.is_set()
