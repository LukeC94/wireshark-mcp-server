from mcp.server.mcpserver import MCPServer
import subprocess, json
from datetime import datetime
from pathlib import Path

mcp = MCPServer("wireshark-mcp-server")

@mcp.tool()
def list_interfaces():
    result = subprocess.run(
        ["tshark", "-D"],
        capture_output=True,
        text=True
    )

    interfaces = []
    for line in result.stdout.strip().split("\n"):
        parts = line.split(". ",1)
        index = parts[0]
        rest = parts[1]

        paren_start = rest.rfind("(")
        device = rest[:paren_start].strip()
        name = rest[paren_start+1:-1]

        interfaces.append({
            "index": index,
            "device": device,
            "name": name,
        })

    return interfaces

@mcp.tool()
def capture_traffic(duration_seconds: int,interface: str="Wi-Fi"):
    Path("captures").mkdir(exist_ok=True)
    filepath = f"captures/capture_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pcap"

    result = subprocess.run(
        ["tshark", "-i", interface, "-a", f"duration:{duration_seconds}", "-w", filepath],
        capture_output=True,
        text=True
    )

    return {
        "status": "success" if result.returncode == 0 else "error",
        "filepath": filepath,
        "duration_seconds": duration_seconds,
        "interface": interface,
        "message": result.stderr.strip()
    }

@mcp.tool()
def summarize_capture(pcap_path: str):

    result = subprocess.run(
        ["tshark", "-r", pcap_path, "-T", "fields", "-e", "ip.dst", "-e", "tcp.dstport", "-e", "udp.dstport", "-e", "frame.protocols", "-e", "frame.len"],
        capture_output=True,
        text=True
    )

    ips = set()
    ports = set()
    protocols = set()
    total_bytes = 0
    packet_count = 0

    for line in result.stdout.strip().split("\n"):
        if not line:
            continue
        fields = line.split("\t")
        packet_count += 1

        if fields[0]:
            ips.add(fields[0])
        if fields[1]:
            ports.add(fields[1])
        if fields[2]:
            ports.add(fields[2])
        if fields[3]:
            protocols.add(fields[3])
        if fields[4]:
            total_bytes += int(fields[4])

    return {
        "status": "success" if result.returncode == 0 else "error",
        "packet_count": packet_count,
        "unique_destination_ips": list(ips),
        "unique_destination_ports": list(ports),
        "protocols": list(protocols),
        "total_bytes": total_bytes,
    }

def check_unusual_ports(packets):
    common_ports = {"80", "443", "53", "67", "68", "5353"}
    flags = []
    seen = set()

    for p in packets:
        port = p["tcp_port"] or p["udp_port"]
        if port and port not in common_ports and port not in seen:
            seen.add(port)
            flags.append({
                "reason": "Unusual port detected",
                "detail":f"Traffic on port {port} to {p['ip_dst']}"
            })
        return flags

def check_traffic_volume(packets):


@mcp.tool()
def flag_suspicious(pcap_path: str):

    result = subprocess.run(
        ["tshark", "-r", "<path>", "-T", "fields", "-e", "ip.dst", "-e", "tcp.dstport", "-e", "udp.dstport", "-e", "frame.protocols", "-e", "frame.len", "-e", "ip.src", "-e", "dns.qry.name", "-e", "http.authorization"],
        capture_output=True,
        text=True
    )


if __name__ == "__main__":
    mcp.run()