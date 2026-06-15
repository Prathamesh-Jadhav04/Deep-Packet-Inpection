import struct
import sys

def parse_pcap(filename):
    try:
        f = open(filename, 'rb')
    except Exception as e:
        print(f"Error opening file: {e}")
        return

    # Read global header
    header = f.read(24)
    if len(header) < 24:
        print("Invalid PCAP: header too short")
        return

    magic = struct.unpack("<I", header[0:4])[0]
    if magic == 0xA1B2C3D4:
        endian = "<"
    elif magic == 0xD4C3B2A1:
        endian = ">"
    else:
        print(f"Unknown magic number: {hex(magic)}")
        return

    packet_count = 0
    tcp_count = 0
    udp_count = 0
    dns_queries = {}
    dest_ips = {}
    tls_snis = {}

    while True:
        pkt_header = f.read(16)
        if len(pkt_header) < 16:
            break

        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", pkt_header)
        data = f.read(incl_len)
        if len(data) < incl_len:
            break

        packet_count += 1

        # Parse ethernet
        if len(data) < 14:
            continue
        eth_type = struct.unpack("!H", data[12:14])[0]
        if eth_type != 0x0800: # Only IPv4 for simplicity
            continue

        # Parse IP
        ip_offset = 14
        if len(data) < ip_offset + 20:
            continue
        version_ihl = data[ip_offset]
        ihl = version_ihl & 0x0F
        ip_header_len = ihl * 4
        protocol = data[ip_offset + 9]
        src_ip = ".".join(str(b) for b in data[ip_offset + 12 : ip_offset + 16])
        dst_ip = ".".join(str(b) for b in data[ip_offset + 16 : ip_offset + 20])

        # Parse TCP/UDP
        l4_offset = ip_offset + ip_header_len
        if protocol == 6: # TCP
            tcp_count += 1
            if len(data) < l4_offset + 20:
                continue
            src_port, dst_port = struct.unpack("!HH", data[l4_offset : l4_offset + 4])
            tcp_header_len = ((data[l4_offset + 12] >> 4) & 0x0F) * 4
            payload_offset = l4_offset + tcp_header_len
            
            # Record dest port 443/80 IPs
            if dst_port in (80, 443):
                dest_ips[dst_ip] = dest_ips.get(dst_ip, 0) + 1

            # Parse TLS Client Hello
            payload = data[payload_offset:]
            if dst_port == 443 and len(payload) >= 9 and payload[0] == 0x16 and payload[5] == 0x01:
                # Basic SNI extraction
                try:
                    # Look for SNI extension in payload
                    for j in range(len(payload) - 10):
                        if payload[j] == 0x00 and payload[j+1] == 0x00: # SNI extension type
                            ext_len = (payload[j+2] << 8) | payload[j+3]
                            if j + 4 + ext_len <= len(payload):
                                list_len = (payload[j+4] << 8) | payload[j+5]
                                name_type = payload[j+6]
                                name_len = (payload[j+7] << 8) | payload[j+8]
                                if name_type == 0 and name_len < 100:
                                    sni = payload[j+9 : j+9+name_len].decode('ascii', errors='ignore')
                                    if '.' in sni:
                                        tls_snis[sni] = tls_snis.get(sni, 0) + 1
                except Exception:
                    pass

        elif protocol == 17: # UDP
            udp_count += 1
            if len(data) < l4_offset + 8:
                continue
            src_port, dst_port = struct.unpack("!HH", data[l4_offset : l4_offset + 4])
            payload_offset = l4_offset + 8
            
            # Record DNS queries
            if dst_port == 53 or src_port == 53:
                payload = data[payload_offset:]
                # Very basic DNS query parsing
                if len(payload) > 12:
                    qdcount = (payload[4] << 8) | payload[5]
                    if qdcount > 0:
                        offset = 12
                        labels = []
                        while offset < len(payload):
                            length = payload[offset]
                            if length == 0:
                                break
                            if (length & 0xC0) == 0xC0:
                                break
                            offset += 1
                            labels.append(payload[offset : offset + length].decode('ascii', errors='ignore'))
                            offset += length
                        if labels:
                            qname = ".".join(labels)
                            dns_queries[qname] = dns_queries.get(qname, 0) + 1

    f.close()

    print(f"Total packets parsed: {packet_count}")
    print(f"TCP packets: {tcp_count}, UDP packets: {udp_count}")
    print("\nTop Destination IPs (port 80/443):")
    for ip, count in sorted(dest_ips.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {ip}: {count} packets")

    print("\nTop DNS Queries:")
    for query, count in sorted(dns_queries.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {query}: {count} queries")

    print("\nTop TLS SNIs detected:")
    for sni, count in sorted(tls_snis.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {sni}: {count} handshakes")

if __name__ == "__main__":
    parse_pcap("live_output.pcap")
