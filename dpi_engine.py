#!/usr/bin/env python3
"""
Python DPI Engine.

Features:
- PCAP reading/writing
- Ethernet/IPv4/TCP/UDP parsing
- TLS SNI, HTTP Host, and DNS query extraction
- SNI/domain to application classification
- Hash-based Reader -> LB -> FP -> Output threading pipeline
- Flow-based blocking by source IP, application, or domain substring

No third-party packages are required.
"""

from __future__ import annotations

import argparse
import sys
import time
from typing import List, Optional

from dpi_engine.common import (
    Rules,
    app_type_to_string,
    list_scapy_interfaces,
)
from dpi_engine.pipeline import (
    DPIEngine,
    generate_test_pcap,
)
from dpi_engine.ui import (
    DashboardController,
    DashboardServer,
)


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="DPI Engine v2.0 - Multithreaded deep packet inspection engine",
    )
    parser.add_argument("input_pcap", nargs="?", help="Input PCAP file")
    parser.add_argument("output_pcap", nargs="?", help="Output filtered PCAP file")
    parser.add_argument("--block-ip", action="append", default=[], help="Block source IP")
    parser.add_argument("--block-app", action="append", default=[], help="Block application")
    parser.add_argument("--block-domain", action="append", default=[], help="Block domain substring")
    parser.add_argument("--lbs", type=int, default=2, help="Number of load balancer threads")
    parser.add_argument("--fps", type=int, default=2, help="FP threads per LB")
    parser.add_argument("--live", action="store_true", help="Capture live packets with Scapy/Npcap")
    parser.add_argument("--iface", help="Scapy interface name for --live")
    parser.add_argument("--duration", type=float, help="Live capture duration in seconds")
    parser.add_argument("--count", type=int, default=0, help="Live capture packet count limit")
    parser.add_argument("--bpf", help="Optional BPF filter for live capture")
    parser.add_argument("--list-ifaces", action="store_true", help="List Scapy interfaces and exit")
    parser.add_argument("--dashboard", action="store_true", help="Start local web dashboard")
    parser.add_argument("--dashboard-host", default="127.0.0.1", help="Dashboard bind host")
    parser.add_argument("--dashboard-port", type=int, default=8765, help="Dashboard port")
    parser.add_argument(
        "--no-dashboard-wait",
        action="store_true",
        help="Stop dashboard as soon as processing finishes",
    )
    parser.add_argument(
        "--generate-test-pcap",
        metavar="FILE",
        help="Generate a test PCAP and exit",
    )
    return parser.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)

    if args.list_ifaces:
        return 0 if list_scapy_interfaces() else 1

    if args.generate_test_pcap:
        generate_test_pcap(args.generate_test_pcap)
        return 0

    control_dashboard = args.dashboard and not args.live and not args.input_pcap and not args.output_pcap

    if control_dashboard:
        output_pcap = ""
    elif args.live:
        output_pcap = args.output_pcap or args.input_pcap
        if not output_pcap:
            print("Usage: python dpi_engine.py --live <output.pcap> [options]", file=sys.stderr)
            return 1
    else:
        if not args.input_pcap or not args.output_pcap:
            print(
                "Usage: python dpi_engine.py <input.pcap> <output.pcap> [options]",
                file=sys.stderr,
            )
            return 1
        output_pcap = args.output_pcap

    if args.lbs <= 0 or args.fps <= 0:
        print("--lbs and --fps must be positive integers", file=sys.stderr)
        return 1
    if args.count < 0:
        print("--count must be zero or a positive integer", file=sys.stderr)
        return 1
    if args.duration is not None and args.duration <= 0:
        print("--duration must be a positive number", file=sys.stderr)
        return 1

    if control_dashboard:
        controller = DashboardController(DPIEngine.Config(num_lbs=args.lbs, fps_per_lb=args.fps))
        for ip in args.block_ip:
            controller.add_rule("ip", ip)
        for app in args.block_app:
            controller.add_rule("app", app)
        for domain in args.block_domain:
            controller.add_rule("domain", domain)

        dashboard = DashboardServer(controller, args.dashboard_host, args.dashboard_port)
        try:
            dashboard.start()
        except OSError as exc:
            print(f"Could not start dashboard: {exc}", file=sys.stderr)
            return 1

        print(f"[Dashboard] Control center running at {dashboard.url}")
        print("[Dashboard] Open the URL, choose an interface, then press Start Live.")
        print("[Dashboard] Press Ctrl+C here to stop the server.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[Dashboard] Stopping...")
        finally:
            controller.shutdown()
            dashboard.stop()
        return 0

    engine = DPIEngine(DPIEngine.Config(num_lbs=args.lbs, fps_per_lb=args.fps))

    for ip in args.block_ip:
        engine.block_ip(ip)
    for app in args.block_app:
        engine.block_app(app)
    for domain in args.block_domain:
        engine.block_domain(domain)

    dashboard: Optional[DashboardServer] = None
    if args.dashboard:
        dashboard = DashboardServer(engine, args.dashboard_host, args.dashboard_port)
        try:
            dashboard.start()
        except OSError as exc:
            print(f"Could not start dashboard: {exc}", file=sys.stderr)
            return 1
        print(f"[Dashboard] Open this URL: {dashboard.url}")

    try:
        if args.live:
            ok = engine.process_live(
                output_file=output_pcap,
                iface=args.iface,
                duration=args.duration,
                packet_count=args.count,
                bpf_filter=args.bpf,
            )
        else:
            ok = engine.process(args.input_pcap, output_pcap)

        if not ok:
            return 1

        print(f"\nOutput written to: {output_pcap}")

        if dashboard is not None and not args.no_dashboard_wait:
            print(f"[Dashboard] Still running at {dashboard.url}")
            print("[Dashboard] Press Ctrl+C to stop.")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n[Dashboard] Stopping...")
    finally:
        if dashboard is not None:
            dashboard.stop()

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
