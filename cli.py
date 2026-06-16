import click
import sys
import os
import time
import json
import urllib.request
import urllib.error
from typing import Optional, Dict, Any

def api_request(path: str, method: str = "GET", data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    url = f"http://127.0.0.1:8765{path}"
    headers = {"Content-Type": "application/json"}
    req_data = json.dumps(data).encode("utf-8") if data is not None else None
    
    req = urllib.request.Request(url, data=req_data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=3.0) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as e:
        raise ConnectionError(
            "Could not connect to the DPI Dashboard at http://127.0.0.1:8765.\n"
            "Make sure the dashboard is running (start it with 'dpi dashboard')."
        )

@click.group()
def main():
    """DPI Engine Command Line Interface.
    
    Easily control the deep packet inspection platform, configure rules,
    view real-time stats, and run offline PCAP analysis.
    """
    pass

@main.command()
@click.option("--host", default="127.0.0.1", help="Host to bind the dashboard server")
@click.option("--port", default=8765, help="Port to bind the dashboard server")
@click.option("--lbs", default=2, help="Number of Load Balancer threads")
@click.option("--fps", default=2, help="FP threads per LB")
def dashboard(host, port, lbs, fps):
    """Launch the Web Dashboard Control Center."""
    from dpi_engine.pipeline import DPIEngine
    from dpi_engine.ui import DashboardController, DashboardServer
    
    click.echo(click.style(f"Initializing DPI Dashboard Server on {host}:{port}...", fg="cyan"))
    controller = DashboardController(DPIEngine.Config(num_lbs=lbs, fps_per_lb=fps))
    server = DashboardServer(controller, host, port)
    try:
        server.start()
    except OSError as exc:
        click.echo(click.style(f"Error starting dashboard: {exc}", fg="red"), err=True)
        sys.exit(1)
        
    click.echo(click.style(f"[OK] Dashboard is running at: {server.url}", fg="green", bold=True))
    click.echo(click.style("Press Ctrl+C to stop the dashboard server.", fg="yellow"))
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        click.echo(click.style("\nStopping dashboard...", fg="cyan"))
    finally:
        controller.shutdown()
        server.stop()

@main.command()
@click.option("--iface", default="", help="Network interface to capture from")
@click.option("--output", default="live_output.pcap", help="Output PCAP file name")
@click.option("--duration", type=float, default=None, help="Duration in seconds (empty for manual stop)")
@click.option("--count", type=int, default=0, help="Packet count limit (0 for unlimited)")
@click.option("--bpf", default="", help="BPF filter (e.g. 'tcp port 443')")
def start(iface, output, duration, count, bpf):
    """Start a live packet capture session."""
    payload = {
        "iface": iface,
        "output_file": output,
        "duration": duration,
        "count": count,
        "bpf": bpf
    }
    try:
        res = api_request("/api/live/start", "POST", payload)
        if res.get("ok"):
            click.echo(click.style(f"[OK] {res.get('message')}", fg="green"))
        else:
            click.echo(click.style(f"Error: {res.get('message')}", fg="red"), err=True)
    except Exception as e:
        click.echo(click.style(str(e), fg="red"), err=True)

@main.command()
def stop():
    """Stop the active live capture session."""
    try:
        res = api_request("/api/live/stop", "POST", {})
        if res.get("ok"):
            click.echo(click.style(f"[OK] {res.get('message')}", fg="green"))
        else:
            click.echo(click.style(f"Error: {res.get('message')}", fg="red"), err=True)
    except Exception as e:
        click.echo(click.style(str(e), fg="red"), err=True)

@main.command()
def status():
    """Show current status, packet statistics, and throughput."""
    try:
        res = api_request("/api/stats")
        status_str = res.get("status", "unknown").upper()
        color = "green" if status_str == "RUNNING" else "yellow" if status_str == "FINISHED" else "cyan"
        
        click.echo(click.style("=== DPI ENGINE STATUS ===", fg="blue", bold=True))
        click.echo(f"Engine State:  " + click.style(status_str, fg=color, bold=True))
        click.echo(f"Input File:    {res.get('input_file') or '-'}")
        click.echo(f"Output File:   {res.get('output_file') or '-'}")
        click.echo(f"Elapsed Time:  {res.get('elapsed', 0.0):.1f}s")
        
        click.echo(click.style("\n--- Packet Counters ---", fg="cyan"))
        click.echo(f"Total Packets: {res.get('total_packets', 0):,}")
        click.echo(f"Total Bytes:   {res.get('total_bytes', 0):,}")
        click.echo(f"TCP Packets:   {res.get('tcp_packets', 0):,}")
        click.echo(f"UDP Packets:   {res.get('udp_packets', 0):,}")
        click.echo(f"Forwarded:     " + click.style(f"{res.get('forwarded', 0):,}", fg="green"))
        click.echo(f"Dropped:       " + click.style(f"{res.get('dropped', 0):,}", fg="red" if res.get('dropped', 0) > 0 else "white"))
        click.echo(f"Drop Rate:     {res.get('drop_rate', 0.0):.1f}%")
        
        # Rolling Analytics
        analytics = res.get("analytics", {})
        rolling_bps = analytics.get("rolling_bps", 0.0)
        rolling_pps = analytics.get("rolling_pps", 0.0)
        
        bps_str = ""
        if rolling_bps > 1000000.0:
            bps_str = f"{rolling_bps / 1000000.0:.2f} Mbps"
        elif rolling_bps > 1000.0:
            bps_str = f"{rolling_bps / 1000.0:.2f} Kbps"
        else:
            bps_str = f"{rolling_bps:.1f} bps"
            
        click.echo(click.style("\n--- Live Analytics (10s window) ---", fg="cyan"))
        click.echo(f"Throughput:    " + click.style(bps_str, fg="green", bold=True))
        click.echo(f"Packet Rate:   {rolling_pps:.1f} pps")
        
    except Exception as e:
        click.echo(click.style(str(e), fg="red"), err=True)

@main.command()
@click.argument("pcap_file", type=click.Path(exists=True))
@click.option("--output", default="output.pcap", help="Output filtered PCAP file")
@click.option("--block-ip", multiple=True, help="IP to block")
@click.option("--block-app", multiple=True, help="Application name to block")
@click.option("--block-domain", multiple=True, help="Domain substring to block")
@click.option("--lbs", default=2, help="Number of Load Balancer threads")
@click.option("--fps", default=2, help="FP threads per LB")
def replay(pcap_file, output, block_ip, block_app, block_domain, lbs, fps):
    """Replay and inspect a sample PCAP file offline."""
    from dpi_engine.pipeline import DPIEngine
    
    engine = DPIEngine(DPIEngine.Config(num_lbs=lbs, fps_per_lb=fps))
    for ip in block_ip:
        engine.block_ip(ip)
    for app in block_app:
        engine.block_app(app)
    for domain in block_domain:
        engine.block_domain(domain)
        
    click.echo(click.style(f"Replaying {pcap_file} -> {output}...", fg="cyan"))
    ok = engine.process(pcap_file, output)
    if ok:
        click.echo(click.style("[OK] Replay completed successfully.", fg="green", bold=True))
    else:
        click.echo(click.style("Error: Replay failed.", fg="red"), err=True)
        sys.exit(1)

@main.command()
@click.option("--file", default="export_report.json", help="File to export results to")
@click.option("--type", "export_type", type=click.Choice(["stats", "packets", "anomalies", "all"]), default="all", help="Data type to export")
def export(file, export_type):
    """Export engine metrics or packet decision logs to a file."""
    try:
        res = api_request("/api/stats")
        if export_type == "stats":
            data = {
                "total_packets": res.get("total_packets"),
                "total_bytes": res.get("total_bytes"),
                "forwarded": res.get("forwarded"),
                "dropped": res.get("dropped"),
                "app_counts": res.get("app_counts"),
                "anomaly_counts": res.get("anomaly_counts")
            }
        elif export_type == "packets":
            data = res.get("recent_packets", [])
        elif export_type == "anomalies":
            data = res.get("recent_anomalies", [])
        else:
            data = res
            
        with open(file, "w") as f:
            json.dump(data, f, indent=2)
        click.echo(click.style(f"[OK] Data successfully exported to {file}", fg="green"))
    except Exception as e:
        click.echo(click.style(str(e), fg="red"), err=True)

@click.group(name="rules")
def rules_group():
    """Manage blocking rules (IPs, apps, domains)."""
    pass
    
@rules_group.command(name="list")
def rules_list():
    """List all configured blocking rules."""
    try:
        res = api_request("/api/rules")
        rules = res.get("rules", {})
        click.echo(click.style("=== ACTIVE BLOCKING RULES ===", fg="blue", bold=True))
        
        click.echo(click.style("\nBlocked Source IPs:", fg="cyan"))
        ips = rules.get("ips", [])
        if ips:
            for ip in ips: click.echo(f"  - {ip}")
        else: click.echo("  None")
            
        click.echo(click.style("\nBlocked Applications:", fg="cyan"))
        apps = rules.get("apps", [])
        if apps:
            for app in apps: click.echo(f"  - {app}")
        else: click.echo("  None")
            
        click.echo(click.style("\nBlocked Domains (substrings):", fg="cyan"))
        domains = rules.get("domains", [])
        if domains:
            for domain in domains: click.echo(f"  - {domain}")
        else: click.echo("  None")
    except Exception as e:
        click.echo(click.style(str(e), fg="red"), err=True)
        
@rules_group.command(name="add")
@click.argument("rule_type", type=click.Choice(["ip", "app", "domain"]))
@click.argument("value")
def rules_add(rule_type, value):
    """Add a new blocking rule."""
    try:
        res = api_request("/api/rules", "POST", {"type": rule_type, "value": value})
        if res.get("ok"):
            click.echo(click.style(f"[OK] Rule added: {res.get('message')}", fg="green"))
        else:
            click.echo(click.style(f"Error: {res.get('message')}", fg="red"), err=True)
    except Exception as e:
        click.echo(click.style(str(e), fg="red"), err=True)
        
@rules_group.command(name="remove")
@click.argument("rule_type", type=click.Choice(["ip", "app", "domain"]))
@click.argument("value")
def rules_remove(rule_type, value):
    """Remove an existing blocking rule."""
    try:
        res = api_request("/api/rules", "DELETE", {"type": rule_type, "value": value})
        if res.get("ok"):
            click.echo(click.style(f"[OK] Rule removed: {res.get('message')}", fg="green"))
        else:
            click.echo(click.style(f"Error: {res.get('message')}", fg="red"), err=True)
    except Exception as e:
        click.echo(click.style(str(e), fg="red"), err=True)

main.add_command(rules_group)

@main.command()
def alerts():
    """List recent protocol anomalies and security alerts."""
    try:
        res = api_request("/api/stats")
        anomalies = res.get("recent_anomalies", [])
        click.echo(click.style("=== RECENT SECURITY ALERTS / ANOMALIES ===", fg="red", bold=True))
        if not anomalies:
            click.echo("No anomalies detected yet.")
            return
            
        for idx, anom in enumerate(reversed(anomalies), start=1):
            date_str = time.strftime('%H:%M:%S', time.localtime(anom.get("timestamp")))
            click.echo(f"[{click.style(date_str, fg='cyan')}] " + 
                       click.style(anom.get("type"), fg="red", bold=True) + 
                       f" on flow {anom.get('flow')} ({anom.get('app')})")
            click.echo(f"  ↳ {anom.get('description')}\n")
    except Exception as e:
        click.echo(click.style(str(e), fg="red"), err=True)

@click.group(name="threat-intel")
def threat_intel_group():
    """Manage Threat Intelligence feeds."""
    pass

@threat_intel_group.command(name="update")
def threat_intel_update():
    """Trigger update/ingestion of dynamic threat feeds."""
    try:
        click.echo(click.style("Triggering threat intelligence feed update...", fg="cyan"))
        res = api_request("/api/threat-intel/update", "POST", {})
        if res.get("ok"):
            click.echo(click.style(f"[OK] {res.get('message')}", fg="green"))
        else:
            click.echo(click.style(f"Error: {res.get('message')}", fg="red"), err=True)
    except Exception as e:
        click.echo(click.style(str(e), fg="red"), err=True)

main.add_command(threat_intel_group)

if __name__ == "__main__":
    main()
