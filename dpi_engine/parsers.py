from __future__ import annotations

import socket
import struct
import hashlib
from typing import Dict, List, Optional, Tuple, Any

from dpi_engine.common import (
    RawPacket,
    ParsedPacket,
    EtherType,
    Protocol,
    TCPFlags,
    FiveTuple,
    AppType,
    sni_to_app_type
)


class PacketParser:
    @staticmethod
    def parse(raw: RawPacket) -> Optional[ParsedPacket]:
        parsed = ParsedPacket(
            timestamp_sec=raw.header.ts_sec,
            timestamp_usec=raw.header.ts_usec,
        )
        data = raw.data
        offset = 0

        ok, offset = PacketParser._parse_ethernet(data, parsed, offset)
        if not ok:
            return None

        if parsed.ether_type == EtherType.IPV4:
            ok, offset = PacketParser._parse_ipv4(data, parsed, offset)
            if not ok:
                return None

            if parsed.protocol == Protocol.TCP:
                ok, offset = PacketParser._parse_tcp(data, parsed, offset)
                if not ok:
                    return None
            elif parsed.protocol == Protocol.UDP:
                ok, offset = PacketParser._parse_udp(data, parsed, offset)
                if not ok:
                    return None
        elif parsed.ether_type == EtherType.IPV6:
            ok, offset = PacketParser._parse_ipv6(data, parsed, offset)
            if not ok:
                return None

            if parsed.protocol == Protocol.TCP:
                ok, offset = PacketParser._parse_tcp(data, parsed, offset)
                if not ok:
                    return None
            elif parsed.protocol == Protocol.UDP:
                ok, offset = PacketParser._parse_udp(data, parsed, offset)
                if not ok:
                    return None

        parsed.payload_offset = offset
        if offset < len(data):
            parsed.payload_length = len(data) - offset
            parsed.payload_data = data[offset:]
        else:
            parsed.payload_length = 0
            parsed.payload_data = b""

        return parsed

    @staticmethod
    def _parse_ethernet(data: bytes, parsed: ParsedPacket, offset: int) -> Tuple[bool, int]:
        if len(data) < 14:
            return False, offset
        parsed.dest_mac = PacketParser.mac_to_string(data[0:6])
        parsed.src_mac = PacketParser.mac_to_string(data[6:12])
        parsed.ether_type = struct.unpack("!H", data[12:14])[0]
        return True, 14

    @staticmethod
    def _parse_ipv4(data: bytes, parsed: ParsedPacket, offset: int) -> Tuple[bool, int]:
        if len(data) < offset + 20:
            return False, offset

        ip_data = data[offset:]
        version_ihl = ip_data[0]
        parsed.ip_version = (version_ihl >> 4) & 0x0F
        ihl = version_ihl & 0x0F

        if parsed.ip_version != 4:
            return False, offset

        ip_header_len = ihl * 4
        if ip_header_len < 20 or len(data) < offset + ip_header_len:
            return False, offset

        parsed.ttl = ip_data[8]
        parsed.protocol = ip_data[9]
        parsed.src_ip = ".".join(str(b) for b in ip_data[12:16])
        parsed.dest_ip = ".".join(str(b) for b in ip_data[16:20])
        parsed.has_ip = True
        return True, offset + ip_header_len

    @staticmethod
    def _parse_ipv6(data: bytes, parsed: ParsedPacket, offset: int) -> Tuple[bool, int]:
        if len(data) < offset + 40:
            return False, offset

        ipv6_data = data[offset:]
        version = (ipv6_data[0] >> 4) & 0x0F
        if version != 6:
            return False, offset

        parsed.ip_version = 6
        parsed.has_ip = True

        next_header = ipv6_data[6]
        parsed.ttl = ipv6_data[7]

        try:
            parsed.src_ip = socket.inet_ntop(socket.AF_INET6, ipv6_data[8:24])
            parsed.dest_ip = socket.inet_ntop(socket.AF_INET6, ipv6_data[24:40])
        except Exception:
            return False, offset

        offset += 40

        # Extension headers
        ext_headers = {0, 43, 44, 50, 51, 60}
        while next_header in ext_headers:
            if len(data) < offset + 2:
                break
            next_header = data[offset]
            hdr_len = (data[offset + 1] + 1) * 8
            if len(data) < offset + hdr_len:
                break
            offset += hdr_len

        parsed.protocol = next_header
        return True, offset

    @staticmethod
    def _parse_tcp(data: bytes, parsed: ParsedPacket, offset: int) -> Tuple[bool, int]:
        if len(data) < offset + 20:
            return False, offset

        tcp_data = data[offset:]
        parsed.src_port = struct.unpack("!H", tcp_data[0:2])[0]
        parsed.dest_port = struct.unpack("!H", tcp_data[2:4])[0]
        parsed.seq_number = struct.unpack("!I", tcp_data[4:8])[0]
        parsed.ack_number = struct.unpack("!I", tcp_data[8:12])[0]
        data_offset = (tcp_data[12] >> 4) & 0x0F
        tcp_header_len = data_offset * 4
        parsed.tcp_flags = tcp_data[13]

        if tcp_header_len < 20 or len(data) < offset + tcp_header_len:
            return False, offset

        parsed.has_tcp = True
        return True, offset + tcp_header_len

    @staticmethod
    def _parse_udp(data: bytes, parsed: ParsedPacket, offset: int) -> Tuple[bool, int]:
        if len(data) < offset + 8:
            return False, offset

        udp_data = data[offset:]
        parsed.src_port = struct.unpack("!H", udp_data[0:2])[0]
        parsed.dest_port = struct.unpack("!H", udp_data[2:4])[0]
        parsed.has_udp = True
        return True, offset + 8

    @staticmethod
    def mac_to_string(mac: bytes) -> str:
        return ":".join(f"{byte:02x}" for byte in mac)


class SNIExtractor:
    CONTENT_TYPE_HANDSHAKE = 0x16
    HANDSHAKE_CLIENT_HELLO = 0x01
    EXTENSION_SNI = 0x0000
    SNI_TYPE_HOSTNAME = 0x00

    @staticmethod
    def read_uint16_be(data: bytes, offset: int = 0) -> int:
        return (data[offset] << 8) | data[offset + 1]

    @staticmethod
    def read_uint24_be(data: bytes, offset: int = 0) -> int:
        return (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]

    @staticmethod
    def is_tls_client_hello(payload: bytes) -> bool:
        length = len(payload)
        if length < 9:
            return False
        if payload[0] != SNIExtractor.CONTENT_TYPE_HANDSHAKE:
            return False
        version = SNIExtractor.read_uint16_be(payload, 1)
        if version < 0x0300 or version > 0x0304:
            return False
        record_length = SNIExtractor.read_uint16_be(payload, 3)
        if record_length > length - 5:
            return False
        if payload[5] != SNIExtractor.HANDSHAKE_CLIENT_HELLO:
            return False
        return True

    @staticmethod
    def extract(payload: bytes) -> Optional[str]:
        length = len(payload)
        if not SNIExtractor.is_tls_client_hello(payload):
            return None

        offset = 5
        _handshake_length = SNIExtractor.read_uint24_be(payload, offset + 1)
        offset += 4

        offset += 2
        offset += 32

        if offset >= length:
            return None
        session_id_length = payload[offset]
        offset += 1 + session_id_length

        if offset + 2 > length:
            return None
        cipher_suites_length = SNIExtractor.read_uint16_be(payload, offset)
        offset += 2 + cipher_suites_length

        if offset >= length:
            return None
        compression_methods_length = payload[offset]
        offset += 1 + compression_methods_length

        if offset + 2 > length:
            return None
        extensions_length = SNIExtractor.read_uint16_be(payload, offset)
        offset += 2

        extensions_end = offset + extensions_length
        if extensions_end > length:
            extensions_end = length

        while offset + 4 <= extensions_end:
            extension_type = SNIExtractor.read_uint16_be(payload, offset)
            extension_length = SNIExtractor.read_uint16_be(payload, offset + 2)
            offset += 4

            if offset + extension_length > extensions_end:
                break

            if extension_type == SNIExtractor.EXTENSION_SNI:
                if extension_length < 5:
                    break

                sni_list_length = SNIExtractor.read_uint16_be(payload, offset)
                if sni_list_length < 3:
                    break

                sni_type = payload[offset + 2]
                sni_length = SNIExtractor.read_uint16_be(payload, offset + 3)

                if sni_type != SNIExtractor.SNI_TYPE_HOSTNAME:
                    break
                if sni_length > extension_length - 5:
                    break

                return payload[offset + 5 : offset + 5 + sni_length].decode(
                    "ascii", errors="ignore"
                )

            offset += extension_length

        return None


class HTTPHostExtractor:
    @staticmethod
    def is_http_request(payload: bytes) -> bool:
        if len(payload) < 4:
            return False
        methods = (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI")
        return any(payload[:4] == method for method in methods)

    @staticmethod
    def extract(payload: bytes) -> Optional[str]:
        if not HTTPHostExtractor.is_http_request(payload):
            return None

        length = len(payload)
        for i in range(0, max(0, length - 6)):
            if (
                payload[i : i + 1].lower() == b"h"
                and payload[i + 1 : i + 2].lower() == b"o"
                and payload[i + 2 : i + 3].lower() == b"s"
                and payload[i + 3 : i + 4].lower() == b"t"
                and payload[i + 4] == ord(":")
            ):
                start = i + 5
                while start < length and payload[start] in (ord(" "), ord("\t")):
                    start += 1

                end = start
                while end < length and payload[end] not in (ord("\r"), ord("\n")):
                    end += 1

                if end > start:
                    host = payload[start:end].decode("ascii", errors="ignore")
                    colon_pos = host.find(":")
                    if colon_pos != -1:
                        host = host[:colon_pos]
                    return host
        return None


class DNSExtractor:
    @staticmethod
    def is_dns_query(payload: bytes) -> bool:
        if len(payload) < 12:
            return False
        flags = payload[2]
        if flags & 0x80:
            return False
        qdcount = (payload[4] << 8) | payload[5]
        return qdcount != 0

    @staticmethod
    def extract_query(payload: bytes) -> Optional[str]:
        if not DNSExtractor.is_dns_query(payload):
            return None

        offset = 12
        labels: List[str] = []
        while offset < len(payload):
            label_length = payload[offset]
            if label_length == 0:
                break
            if label_length > 63:
                break

            offset += 1
            if offset + label_length > len(payload):
                break
            labels.append(payload[offset : offset + label_length].decode("ascii", errors="ignore"))
            offset += label_length

        domain = ".".join(labels)
        return domain or None


class QUICSNIExtractor:
    @staticmethod
    def is_quic_initial(payload: bytes) -> bool:
        if len(payload) < 5:
            return False
        return (payload[0] & 0x80) != 0

    @staticmethod
    def extract(payload: bytes) -> Optional[str]:
        if not QUICSNIExtractor.is_quic_initial(payload):
            return None
        for i in range(0, max(0, len(payload) - 50)):
            if payload[i] == 0x01 and i >= 5:
                result = SNIExtractor.extract(payload[i - 5 :])
                if result:
                    return result
        return None


def is_grease(val: int) -> bool:
    return (val & 0x0f0f) == 0x0a0a and (val & 0xff) == (val >> 8)


class TLSClientHelloParser:
    @staticmethod
    def parse_client_hello(payload: bytes) -> Optional[Dict[str, Any]]:
        if len(payload) < 9:
            return None
        if payload[0] != 0x16:  # Handshake record
            return None
        record_version = (payload[1] << 8) | payload[2]
        record_len = (payload[3] << 8) | payload[4]
        if record_len > len(payload) - 5:
            return None

        offset = 5
        handshake_type = payload[offset]
        if handshake_type != 0x01:  # ClientHello
            return None

        handshake_len = (payload[offset + 1] << 16) | (payload[offset + 2] << 8) | payload[offset + 3]
        offset += 4
        if handshake_len > len(payload) - offset:
            pass

        if offset + 2 > len(payload):
            return None
        client_version = (payload[offset] << 8) | payload[offset + 1]
        offset += 2

        if offset + 32 > len(payload):
            return None
        random_bytes = payload[offset : offset + 32]
        offset += 32

        if offset >= len(payload):
            return None
        session_id_len = payload[offset]
        offset += 1
        if offset + session_id_len > len(payload):
            return None
        session_id = payload[offset : offset + session_id_len]
        offset += session_id_len

        if offset + 2 > len(payload):
            return None
        cipher_suites_len = (payload[offset] << 8) | payload[offset + 1]
        offset += 2
        if offset + cipher_suites_len > len(payload):
            return None

        cipher_suites = []
        for i in range(0, cipher_suites_len, 2):
            if offset + i + 2 > len(payload):
                break
            cipher = (payload[offset + i] << 8) | payload[offset + i + 1]
            cipher_suites.append(cipher)
        offset += cipher_suites_len

        if offset >= len(payload):
            return None
        compression_len = payload[offset]
        offset += 1
        if offset + compression_len > len(payload):
            return None
        compression_methods = list(payload[offset : offset + compression_len])
        offset += compression_len

        extensions = []
        supported_groups = []
        point_formats = []
        alpn_protocols = []
        signature_algorithms = []
        supported_versions = []

        if offset + 2 <= len(payload):
            extensions_len = (payload[offset] << 8) | payload[offset + 1]
            offset += 2
            ext_end = offset + extensions_len
            if ext_end > len(payload):
                ext_end = len(payload)

            while offset + 4 <= ext_end:
                ext_type = (payload[offset] << 8) | payload[offset + 1]
                ext_len = (payload[offset + 2] << 8) | payload[offset + 3]
                offset += 4

                if offset + ext_len > ext_end:
                    break

                ext_data = payload[offset : offset + ext_len]
                extensions.append((ext_type, ext_data))

                if ext_type == 10:  # supported_groups
                    if len(ext_data) >= 2:
                        groups_len = (ext_data[0] << 8) | ext_data[1]
                        for j in range(0, groups_len, 2):
                            if j + 3 < len(ext_data):
                                group = (ext_data[2 + j] << 8) | ext_data[2 + j + 1]
                                supported_groups.append(group)
                elif ext_type == 11:  # ec_point_formats
                    if len(ext_data) >= 1:
                        formats_len = ext_data[0]
                        point_formats = list(ext_data[1 : 1 + formats_len])
                elif ext_type == 13:  # signature_algorithms
                    if len(ext_data) >= 2:
                        sigs_len = (ext_data[0] << 8) | ext_data[1]
                        for j in range(0, sigs_len, 2):
                            if j + 3 < len(ext_data):
                                sig = (ext_data[2 + j] << 8) | ext_data[2 + j + 1]
                                signature_algorithms.append(sig)
                elif ext_type == 16:  # ALPN
                    if len(ext_data) >= 2:
                        alpn_len = (ext_data[0] << 8) | ext_data[1]
                        alpn_offset = 2
                        while alpn_offset < len(ext_data):
                            proto_len = ext_data[alpn_offset]
                            alpn_offset += 1
                            if alpn_offset + proto_len <= len(ext_data):
                                proto = ext_data[alpn_offset : alpn_offset + proto_len].decode("ascii", errors="ignore")
                                alpn_protocols.append(proto)
                            alpn_offset += proto_len
                elif ext_type == 43:  # supported_versions
                    if len(ext_data) >= 1:
                        versions_len = ext_data[0]
                        for j in range(0, versions_len, 2):
                            if j + 2 <= len(ext_data):
                                ver = (ext_data[1 + j] << 8) | ext_data[1 + j + 1]
                                supported_versions.append(ver)

                offset += ext_len

        return {
            "client_version": client_version,
            "cipher_suites": cipher_suites,
            "extensions": [t[0] for t in extensions],
            "extensions_raw": extensions,
            "supported_groups": supported_groups,
            "point_formats": point_formats,
            "alpn_protocols": alpn_protocols,
            "signature_algorithms": signature_algorithms,
            "supported_versions": supported_versions,
        }


def get_tls_version_ja4(client_hello: Dict[str, Any]) -> str:
    versions = client_hello.get("supported_versions", [])
    if versions:
        if 0x0304 in versions:
            return "13"
        if 0x0303 in versions:
            return "12"
        if 0x0302 in versions:
            return "11"
        if 0x0301 in versions:
            return "10"

    client_version = client_hello.get("client_version", 0)
    if client_version == 0x0304:
        return "13"
    elif client_version == 0x0303:
        return "12"
    elif client_version == 0x0302:
        return "11"
    elif client_version == 0x0301:
        return "10"
    elif client_version == 0x0300:
        return "s3"
    return "00"


def generate_ja3(client_hello: Dict[str, Any]) -> Tuple[str, str]:
    version = str(client_hello["client_version"])
    ciphers = "-".join(str(c) for c in client_hello["cipher_suites"] if not is_grease(c))
    extensions = "-".join(str(e) for e in client_hello["extensions"] if not is_grease(e))
    groups = "-".join(str(g) for g in client_hello["supported_groups"] if not is_grease(g))
    formats = "-".join(str(f) for f in client_hello["point_formats"] if not is_grease(f))
    ja3_str = f"{version},{ciphers},{extensions},{groups},{formats}"
    ja3_hash = hashlib.md5(ja3_str.encode("utf-8")).hexdigest()
    return ja3_str, ja3_hash


def generate_ja4(client_hello: Dict[str, Any], is_quic: bool = False, has_sni: bool = False, sni_is_ip: bool = False) -> str:
    protocol = "q" if is_quic else "t"
    version = get_tls_version_ja4(client_hello)
    sni_char = "d" if has_sni and not sni_is_ip else "i" if sni_is_ip else "n"

    ciphers_filtered = [c for c in client_hello["cipher_suites"] if not is_grease(c)]
    extensions_filtered = [e for e in client_hello["extensions"] if not is_grease(e)]

    cipher_count_str = f"{min(len(ciphers_filtered), 99):02d}"
    ext_count_str = f"{min(len(extensions_filtered), 99):02d}"

    alpn_first = "00"
    if client_hello.get("alpn_protocols"):
        first_proto = client_hello["alpn_protocols"][0].lower()
        if len(first_proto) >= 2:
            alpn_first = first_proto[:2]
        else:
            alpn_first = first_proto + "0"

    ja4_a = f"{protocol}{version}{sni_char}{cipher_count_str}{ext_count_str}{alpn_first}"

    if ciphers_filtered:
        sorted_ciphers = sorted(ciphers_filtered)
        ciphers_hex_str = ",".join(f"{c:04x}" for c in sorted_ciphers)
        ja4_b = hashlib.sha256(ciphers_hex_str.encode("utf-8")).hexdigest()[:12]
    else:
        ja4_b = "000000000000"

    exts_c = [e for e in extensions_filtered if e not in (0, 16)]
    sorted_exts = sorted(exts_c)
    exts_hex_str = ",".join(f"{e:04x}" for e in sorted_exts) if sorted_exts else ""

    sigs_filtered = [s for s in client_hello["signature_algorithms"] if not is_grease(s)]
    sigs_hex_str = ",".join(f"{s:04x}" for s in sigs_filtered) if sigs_filtered else ""

    if exts_hex_str and sigs_hex_str:
        ja4_c_str = f"{exts_hex_str}_{sigs_hex_str}"
    elif exts_hex_str:
        ja4_c_str = exts_hex_str
    elif sigs_hex_str:
        ja4_c_str = f"_{sigs_hex_str}"
    else:
        ja4_c_str = ""

    if ja4_c_str:
        ja4_c = hashlib.sha256(ja4_c_str.encode("utf-8")).hexdigest()[:12]
    else:
        ja4_c = "000000000000"

    return f"{ja4_a}_{ja4_b}_{ja4_c}"


class HuffmanDecoder:
    class Node:
        def __init__(self):
            self.left = None
            self.right = None
            self.val = -1

    def __init__(self, codes: List[int], lengths: List[int]) -> None:
        self.root = self.Node()
        for sym, (code, length) in enumerate(zip(codes, lengths)):
            curr = self.root
            for i in range(length):
                bit = (code >> (length - 1 - i)) & 1
                if bit == 0:
                    if curr.left is None:
                        curr.left = self.Node()
                    curr = curr.left
                else:
                    if curr.right is None:
                        curr.right = self.Node()
                    curr = curr.right
            curr.val = sym

    def decode(self, data: bytes) -> bytes:
        out = bytearray()
        curr = self.root
        for byte in data:
            for i in range(8):
                bit = (byte >> (7 - i)) & 1
                curr = curr.left if bit == 0 else curr.right
                if curr is None:
                    return bytes(out)
                if curr.val != -1:
                    if curr.val == 256:  # EOS
                        break
                    out.append(curr.val)
                    curr = self.root
        return bytes(out)


HUFFMAN_CODES = [
    0x1ff8, 0x7fffd8, 0xfffffe2, 0xfffffe3, 0xfffffe4, 0xfffffe5, 0xfffffe6, 0xfffffe7, 0xfffffe8, 0xffffea, 0x3ffffffc, 0xfffffe9, 0xfffffea, 0x3ffffffd, 0xfffffeb, 0xfffffec,
    0xfffffed, 0xfffffee, 0xfffffef, 0xffffff0, 0xffffff1, 0xffffff2, 0x3ffffffe, 0xffffff3, 0xffffff4, 0xffffff5, 0xffffff6, 0xffffff7, 0xffffff8, 0xffffff9, 0xffffffa, 0xffffffb,
    0x14, 0x3f8, 0x3f9, 0xffa, 0x1ff9, 0x15, 0xf8, 0x7fa, 0x3fa, 0x3fb, 0xf9, 0x7fb, 0xfa, 0x16, 0x17, 0x18,
    0x0, 0x1, 0x2, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x5c, 0xfb, 0x7ffc, 0x20, 0xffb, 0x3fc,
    0x1ffa, 0x21, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,
    0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0xfc, 0x73, 0xfd, 0x1ffb, 0x7fff0, 0x1ffc, 0x3ffc, 0x22,
    0x7ffd, 0x3, 0x23, 0x4, 0x24, 0x5, 0x25, 0x26, 0x27, 0x6, 0x74, 0x75, 0x28, 0x29, 0x2a, 0x7,
    0x2b, 0x76, 0x2c, 0x8, 0x9, 0x2d, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7ffe, 0x7fc, 0x3ffd, 0x1ffd, 0xffffffc,
    0xfffe6, 0x3fffd2, 0xfffe7, 0xfffe8, 0x3fffd3, 0x3fffd4, 0x3fffd5, 0x7fffd9, 0x3fffd6, 0x7fffda, 0x7fffdb, 0x7fffdc, 0x7fffdd, 0x7fffde, 0xffffeb, 0x7fffdf,
    0xffffec, 0xffffed, 0x3fffd7, 0x7fffe0, 0xffffee, 0x7fffe1, 0x7fffe2, 0x7fffe3, 0x7fffe4, 0x1fffdc, 0x3fffd8, 0x7fffe5, 0x3fffd9, 0x7fffe6, 0x7fffe7, 0xffffef,
    0x3fffda, 0x1fffdd, 0xfffe9, 0x3fffdb, 0x3fffdc, 0x7fffe8, 0x7fffe9, 0x1fffde, 0x7fffea, 0x3fffdd, 0x3fffde, 0xfffff0, 0x1fffdf, 0x3fffdf, 0x7fffeb, 0x7fffec,
    0x1fffe0, 0x1fffe1, 0x3fffe0, 0x1fffe2, 0x7fffed, 0x3fffe1, 0x7fffee, 0x7fffef, 0xfffea, 0x3fffe2, 0x3fffe3, 0x3fffe4, 0x7ffff0, 0x3fffe5, 0x3fffe6, 0x7ffff1,
    0x3ffffe0, 0x3ffffe1, 0xfffeb, 0x7fff1, 0x3fffe7, 0x7ffff2, 0x3fffe8, 0x1ffffec, 0x3ffffe2, 0x3ffffe3, 0x3ffffe4, 0x7ffffde, 0x7ffffdf, 0x3ffffe5, 0xfffff1, 0x1ffffed,
    0x7fff2, 0x1fffe3, 0x3ffffe6, 0x7ffffe0, 0x7ffffe1, 0x3ffffe7, 0x7ffffe2, 0xfffff2, 0x1fffe4, 0x1fffe5, 0x3ffffe8, 0x3ffffe9, 0xffffffd, 0x7ffffe3, 0x7ffffe4, 0x7ffffe5,
    0xfffec, 0xfffff3, 0xfffed, 0x1fffe6, 0x3fffe9, 0x1fffe7, 0x1fffe8, 0x7ffff3, 0x3fffea, 0x3fffeb, 0x1ffffee, 0x1ffffef, 0xfffff4, 0xfffff5, 0x3ffffea, 0x7ffff4,
    0x3ffffeb, 0x7ffffe6, 0x3ffffec, 0x3ffffed, 0x7ffffe7, 0x7ffffe8, 0x7ffffe9, 0x7ffffea, 0x7ffffeb, 0xffffffe, 0x7ffffec, 0x7ffffed, 0x7ffffee, 0x7ffffef, 0x7fffff0, 0x3ffffee,
    0x3fffffff
]
HUFFMAN_LENGTHS = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
    28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
     6, 10, 10, 12, 13,  6,  8, 11, 10, 10,  8, 11,  8,  6,  6,  6,
     5,  5,  5,  6,  6,  6,  6,  6,  6,  6,  7,  8, 15,  6, 12, 10,
    13,  6,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,
     7,  7,  7,  7,  7,  7,  7,  7,  8,  7,  8, 13, 19, 13, 14,  6,
    15,  5,  6,  5,  6,  5,  6,  6,  6,  5,  7,  7,  6,  6,  6,  5,
     6,  7,  6,  5,  5,  6,  7,  7,  7,  7,  7, 15, 11, 14, 13, 28,
    20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
    24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
    22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
    21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
    26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
    19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
    20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
    26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
    30
]

hpack_huffman_decoder = HuffmanDecoder(HUFFMAN_CODES, HUFFMAN_LENGTHS)


class HTTP2Parser:
    STATIC_TABLE = {
        1: (":authority", ""),
        2: (":method", "GET"),
        3: (":method", "POST"),
        4: (":path", "/"),
        5: (":path", "/index.html"),
        6: (":scheme", "http"),
        7: (":scheme", "https"),
        8: (":status", "200"),
        58: ("user-agent", "")
    }

    def __init__(self, decoder: HuffmanDecoder) -> None:
        self.decoder = decoder

    def extract_headers(self, payload: bytes) -> Dict[str, str]:
        headers = {}
        offset = 0
        while offset + 9 <= len(payload):
            frame_len = (payload[offset] << 16) | (payload[offset+1] << 8) | payload[offset+2]
            frame_type = payload[offset+3]
            frame_flags = payload[offset+4]
            stream_id = ((payload[offset+5] & 0x7f) << 24) | (payload[offset+6] << 16) | (payload[offset+7] << 8) | payload[offset+8]

            if offset + 9 + frame_len > len(payload):
                break

            frame_payload = payload[offset + 9 : offset + 9 + frame_len]
            offset += 9 + frame_len

            if frame_type == 0x01:  # HEADERS
                h_offset = 0
                pad_len = 0
                if frame_flags & 0x08:  # PADDED
                    if h_offset < len(frame_payload):
                        pad_len = frame_payload[h_offset]
                        h_offset += 1
                if frame_flags & 0x20:  # PRIORITY
                    h_offset += 5

                fragment_len = len(frame_payload) - h_offset - pad_len
                if fragment_len > 0:
                    fragment = frame_payload[h_offset : h_offset + fragment_len]
                    headers.update(self._decode_hpack(fragment))
            elif frame_type == 0x09:  # CONTINUATION
                headers.update(self._decode_hpack(frame_payload))

        return headers

    def _decode_hpack(self, data: bytes) -> Dict[str, str]:
        headers = {}
        offset = 0

        def parse_int(offset: int, prefix_mask: int) -> Tuple[int, int]:
            if offset >= len(data):
                return 0, offset
            b = data[offset]
            val = b & prefix_mask
            if val < prefix_mask:
                return val, offset + 1
            val = prefix_mask
            shift = 0
            offset += 1
            while offset < len(data):
                b = data[offset]
                val += (b & 0x7f) << shift
                offset += 1
                if (b & 0x80) == 0:
                    break
                shift += 7
            return val, offset

        def parse_str(offset: int) -> Tuple[str, int]:
            if offset >= len(data):
                return "", offset
            is_huffman = (data[offset] & 0x80) != 0
            length, offset = parse_int(offset, 0x7f)
            if offset + length > len(data):
                return "", len(data)
            str_bytes = data[offset : offset + length]
            offset += length
            if is_huffman:
                try:
                    str_bytes = self.decoder.decode(str_bytes)
                except Exception:
                    pass
            return str_bytes.decode("utf-8", errors="ignore"), offset

        while offset < len(data):
            b = data[offset]
            if b & 0x80:  # Indexed Header Field
                idx, offset = parse_int(offset, 0x7f)
                if idx in self.STATIC_TABLE:
                    name, val = self.STATIC_TABLE[idx]
                    headers[name] = val
            elif (b & 0xc0) == 0x40:  # Literal Header Field with Incremental Indexing
                idx, offset = parse_int(offset, 0x3f)
                if idx > 0:
                    name = self.STATIC_TABLE.get(idx, ("", ""))[0]
                    val, offset = parse_str(offset)
                else:
                    name, offset = parse_str(offset)
                    val, offset = parse_str(offset)
                if name:
                    headers[name] = val
            elif (b & 0xf0) in (0x00, 0x10):  # Literal without Indexing / Never Indexed
                idx, offset = parse_int(offset, 0x0f)
                if idx > 0:
                    name = self.STATIC_TABLE.get(idx, ("", ""))[0]
                    val, offset = parse_str(offset)
                else:
                    name, offset = parse_str(offset)
                    val, offset = parse_str(offset)
                if name:
                    headers[name] = val
            else:
                offset += 1

        return headers


class QUICParser:
    @staticmethod
    def parse_quic_varint(data: bytes, offset: int) -> Tuple[int, int]:
        if offset >= len(data):
            return 0, offset
        first = data[offset]
        prefix = first >> 6
        val = first & 0x3f
        if prefix == 0:
            return val, offset + 1
        elif prefix == 1:
            if offset + 2 > len(data):
                return 0, len(data)
            return (val << 8) | data[offset+1], offset + 2
        elif prefix == 2:
            if offset + 4 > len(data):
                return 0, len(data)
            return (val << 24) | (data[offset+1] << 16) | (data[offset+2] << 8) | data[offset+3], offset + 4
        else:
            if offset + 8 > len(data):
                return 0, len(data)
            v = val
            for i in range(1, 8):
                v = (v << 8) | data[offset+i]
            return v, offset + 8

    @classmethod
    def parse_initial_packet(cls, payload: bytes) -> Optional[bytes]:
        if len(payload) < 7:
            return None
        first = payload[0]
        if not (first & 0x80):
            return None
        packet_type = (first & 0x30) >> 4
        if packet_type != 0x00:  # Initial
            return None

        version = (payload[1] << 24) | (payload[2] << 16) | (payload[3] << 8) | payload[4]
        if version not in (1, 0xff00001d):
            return None

        dcid_len = payload[5]
        offset = 6
        if offset + dcid_len + 1 > len(payload):
            return None
        offset += dcid_len

        scid_len = payload[offset]
        offset += 1
        if offset + scid_len > len(payload):
            return None
        offset += scid_len

        token_len, offset = cls.parse_quic_varint(payload, offset)
        if offset + token_len > len(payload):
            return None
        offset += token_len

        length, offset = cls.parse_quic_varint(payload, offset)
        if offset > len(payload):
            return None

        pn_len = (first & 0x03) + 1
        offset += pn_len

        while offset < len(payload):
            if offset >= len(payload):
                break
            frame_type, offset = cls.parse_quic_varint(payload, offset)
            if frame_type == 0x00:  # PADDING
                while offset < len(payload) and payload[offset] == 0x00:
                    offset += 1
                continue
            elif frame_type == 0x06:  # CRYPTO
                crypto_offset, offset = cls.parse_quic_varint(payload, offset)
                crypto_len, offset = cls.parse_quic_varint(payload, offset)
                if offset + crypto_len > len(payload):
                    return None
                return payload[offset : offset + crypto_len]
            elif frame_type in (0x02, 0x03):  # ACK
                largest_ack, offset = cls.parse_quic_varint(payload, offset)
                ack_delay, offset = cls.parse_quic_varint(payload, offset)
                ack_block_count, offset = cls.parse_quic_varint(payload, offset)
                first_ack_block, offset = cls.parse_quic_varint(payload, offset)
                for _ in range(ack_block_count):
                    gap, offset = cls.parse_quic_varint(payload, offset)
                    ack_block_len, offset = cls.parse_quic_varint(payload, offset)
            elif frame_type == 0x01:  # PING
                continue
            else:
                break

        for i in range(0, max(0, len(payload) - 50)):
            if payload[i] == 0x16 and payload[i+1] == 0x03:
                if i + 5 < len(payload) and payload[i+5] == 0x01:
                    return payload[i:]
        return None


class DNSResponseParser:
    @staticmethod
    def is_dns_response(payload: bytes) -> bool:
        if len(payload) < 12:
            return False
        flags = (payload[2] << 8) | payload[3]
        is_response = (flags & 0x8000) != 0
        ancount = (payload[6] << 8) | payload[7]
        return is_response and ancount > 0

    @staticmethod
    def parse_response(payload: bytes) -> Tuple[Optional[str], List[str]]:
        if not DNSResponseParser.is_dns_response(payload):
            return None, []

        qdcount = (payload[4] << 8) | payload[5]
        ancount = (payload[6] << 8) | payload[7]

        offset = 12

        # 1. Skip Question Section
        query_domain = ""
        for _ in range(qdcount):
            labels = []
            while offset < len(payload):
                length = payload[offset]
                if length == 0:
                    offset += 1
                    break
                if (length & 0xC0) == 0xC0: # Pointer
                    offset += 2
                    break
                offset += 1
                if offset + length > len(payload):
                    break
                labels.append(payload[offset : offset + length].decode("ascii", errors="ignore"))
                offset += length
            if labels:
                query_domain = ".".join(labels)
            offset += 4 # Skip QTYPE and QCLASS

        # 2. Parse Answer Section
        resolved_ips = []
        for _ in range(ancount):
            if offset >= len(payload):
                break
            # Skip name
            while offset < len(payload):
                length = payload[offset]
                if length == 0:
                    offset += 1
                    break
                if (length & 0xC0) == 0xC0:
                    offset += 2
                    break
                offset += 1 + length

            if offset + 10 > len(payload):
                break

            type_ = (payload[offset] << 8) | payload[offset + 1]
            rdlength = (payload[offset + 8] << 8) | payload[offset + 9]
            offset += 10

            if offset + rdlength > len(payload):
                break

            rdata = payload[offset : offset + rdlength]
            offset += rdlength

            if type_ == 1 and rdlength == 4: # A record (IPv4)
                ip = ".".join(str(b) for b in rdata)
                resolved_ips.append(ip)
            elif type_ == 28 and rdlength == 16: # AAAA record (IPv6)
                try:
                    import socket
                    ip = socket.inet_ntop(socket.AF_INET6, rdata)
                    resolved_ips.append(ip)
                except Exception:
                    pass

        return query_domain or None, resolved_ips
