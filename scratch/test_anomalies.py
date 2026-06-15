import sys
import struct
import random
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from dpi_engine.pipeline import PCAPWriter
from dpi_engine.common import FiveTuple

def generate_anomaly_pcap(filename: str = "test_anomalies.pcap") -> None:
    writer = PCAPWriter(filename)
    user_mac = "00:11:22:33:44:55"
    gateway_mac = "aa:bb:cc:dd:ee:ff"
    
    # Helper to create headers
    from dpi_engine.pipeline import create_ethernet_header, create_ip_header, create_tcp_header, create_udp_header
    
    # --- Scenario 1: TCP SYN Flood Anomaly ---
    # Client sends 25 SYN packets on port 443 without completing handshake
    syn_src_ip = "192.168.1.51"
    syn_dst_ip = "104.16.85.20"
    syn_src_port = 55555
    syn_dst_port = 443
    for seq in range(1000, 1025):
        eth = create_ethernet_header(user_mac, gateway_mac)
        tcp = create_tcp_header(syn_src_port, syn_dst_port, seq, 0, 0x02) # SYN
        ip = create_ip_header(syn_src_ip, syn_dst_ip, 6, len(tcp))
        writer.write_packet(eth + ip + tcp)
        
    # --- Scenario 2: DNS Tunneling Anomaly ---
    # Exceeding length and Shannon entropy
    dns_src_ip = "192.168.1.52"
    dns_dst_ip = "8.8.8.8"
    dns_src_port = 61234
    
    # Let's generate a query for an extremely long high-entropy subdomain
    tunneling_subdomain = "YTI5OGNlMzRhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWI.exfil.badsite.com"
    
    def create_dns_query_raw(domain: str, txid: int) -> bytes:
        txid_bytes = struct.pack(">H", txid)
        flags = struct.pack(">H", 0x0100) # query
        counts = struct.pack(">HHHH", 1, 0, 0, 0)
        question = b""
        for label in domain.split("."):
            question += struct.pack("B", len(label)) + label.encode("ascii")
        question += struct.pack("B", 0)
        question += struct.pack(">HH", 1, 1) # Type A, Class IN
        return txid_bytes + flags + counts + question

    eth = create_ethernet_header(user_mac, gateway_mac)
    dns_query = create_dns_query_raw(tunneling_subdomain, 0x1234)
    udp = create_udp_header(dns_src_port, 53, len(dns_query))
    ip = create_ip_header(dns_src_ip, dns_dst_ip, 17, len(udp) + len(dns_query))
    writer.write_packet(eth + ip + udp + dns_query)

    # --- Scenario 3: HTTP Request Smuggling Anomaly ---
    # Both Content-Length and Transfer-Encoding: chunked present
    smuggle_src_ip = "192.168.1.53"
    smuggle_dst_ip = "93.184.216.34"
    smuggle_src_port = 52345
    smuggle_dst_port = 80
    
    # Complete 3-way handshake first to establish TCP
    # SYN
    eth = create_ethernet_header(user_mac, gateway_mac)
    tcp = create_tcp_header(smuggle_src_port, smuggle_dst_port, 2000, 0, 0x02)
    ip = create_ip_header(smuggle_src_ip, smuggle_dst_ip, 6, len(tcp))
    writer.write_packet(eth + ip + tcp)
    
    # SYN-ACK
    eth = create_ethernet_header(gateway_mac, user_mac)
    tcp = create_tcp_header(smuggle_dst_port, smuggle_src_port, 5000, 2001, 0x12)
    ip = create_ip_header(smuggle_dst_ip, smuggle_src_ip, 6, len(tcp))
    writer.write_packet(eth + ip + tcp)
    
    # ACK
    eth = create_ethernet_header(user_mac, gateway_mac)
    tcp = create_tcp_header(smuggle_src_port, smuggle_dst_port, 2001, 5001, 0x10)
    ip = create_ip_header(smuggle_src_ip, smuggle_dst_ip, 6, len(tcp))
    writer.write_packet(eth + ip + tcp)
    
    # HTTP payload with smuggling headers
    http_payload = (
        "POST / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: chunked\r\n\r\n"
        "0\r\n\r\n"
    ).encode("ascii")
    
    tcp = create_tcp_header(smuggle_src_port, smuggle_dst_port, 2001, 5001, 0x18)
    ip = create_ip_header(smuggle_src_ip, smuggle_dst_ip, 6, len(tcp) + len(http_payload))
    writer.write_packet(eth + ip + tcp + http_payload)
    
    writer.close()
    print(f"Created {filename} with anomaly-triggering traffic.")

if __name__ == "__main__":
    generate_anomaly_pcap()
