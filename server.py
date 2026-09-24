from mcp.server.mcpserver import MCPServer
import subprocess, json
from datetime import datetime
from pathlib import Path

import shutil

TSHARK = shutil.which("tshark") or r"C:\Program Files\Wireshark\tshark.exe"

mcp = MCPServer("wireshark-mcp-server")

@mcp.tool()
def list_interfaces():
    result = subprocess.run(
        [TSHARK, "-D"],
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

CAPTURES_DIR = Path(__file__).parent / "captures"

@mcp.tool()
def capture_traffic(duration_seconds: int, interface: str = "Wi-Fi"):
    CAPTURES_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = str(CAPTURES_DIR / f"capture_{timestamp}.pcap")

    result = subprocess.run(
        [TSHARK, "-i", interface, "-a", f"duration:{duration_seconds}", "-w", filepath],
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
        [TSHARK, "-r", pcap_path, "-T", "fields", "-e", "ip.dst", "-e", "tcp.dstport", "-e", "udp.dstport", "-e", "frame.protocols", "-e", "frame.len"],
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

def parse_packets(tshark_output):
    """Parse tshark field output into a list of packet dicts."""
    packets = []
    for line in tshark_output.strip().split("\n"):
        if not line:
            continue
        fields = line.split("\t")
        packets.append({
            "ip_dst": fields[0] if len(fields) > 0 else "",
            "tcp_port": fields[1] if len(fields) > 1 else "",
            "udp_port": fields[2] if len(fields) > 2 else "",
            "protocols": fields[3] if len(fields) > 3 else "",
            "frame_len": fields[4] if len(fields) > 4 else "",
            "ip_src": fields[5] if len(fields) > 5 else "",
            "dns_query": fields[6] if len(fields) > 6 else "",
            "http_auth": fields[7] if len(fields) > 7 else "",
        })
    return packets


def check_unusual_ports(packets):
    """Flag traffic on non-standard ports.

    Most legitimate traffic uses well-known ports (80, 443, 53, etc.).
    Traffic on unusual ports can indicate tunneling, backdoors, or
    misconfigured services. This is a simple allowlist check.
    """
    common_ports = {"80", "443", "53", "67", "68", "5353"}
    flags = []
    seen = set()

    for p in packets:
        port = p["tcp_port"] or p["udp_port"]
        if port and port not in common_ports and port not in seen:
            seen.add(port)
            flags.append({
                "heuristic": "unusual_port",
                "reason": "Unusual port detected",
                "detail": f"Traffic on port {port} to {p['ip_dst']}",
            })
    return flags


def check_traffic_volume(packets):
    """Flag any single host that sends a disproportionate share of traffic.

    If one source IP accounts for more than 70% of total bytes in the
    capture, it may indicate exfiltration, a misconfigured service, or
    a denial-of-service attempt.
    """
    from collections import defaultdict
    volume_by_src = defaultdict(int)
    total = 0

    for p in packets:
        if p["frame_len"] and p["ip_src"]:
            size = int(p["frame_len"])
            volume_by_src[p["ip_src"]] += size
            total += size

    flags = []
    if total == 0:
        return flags

    for src, vol in volume_by_src.items():
        ratio = vol / total
        if ratio > 0.70 and len(volume_by_src) > 1:
            flags.append({
                "heuristic": "traffic_volume",
                "reason": "Single host dominates traffic volume",
                "detail": f"{src} sent {vol} bytes ({ratio:.0%} of total)",
            })
    return flags


def check_dns_flood(packets):
    """Flag a high number of distinct DNS queries in the capture.

    Malware often beacons to a command-and-control server by resolving
    many unique domain names, or exfiltrates data encoded in DNS queries.
    More than 50 unique queried domains in a single capture is suspicious.
    """
    domains = set()
    for p in packets:
        if p["dns_query"]:
            domains.add(p["dns_query"])

    flags = []
    if len(domains) > 50:
        flags.append({
            "heuristic": "dns_flood",
            "reason": "High number of distinct DNS queries",
            "detail": f"{len(domains)} unique domains queried (threshold: 50)",
        })
    return flags


def check_repeated_connections(packets):
    """Flag repeated connection attempts to the same destination.

    More than 20 packets to the same IP:port in a short capture can
    indicate port scanning, brute-force attempts, or a retry loop from
    a misconfigured client.
    """
    from collections import Counter
    dest_counts = Counter()

    for p in packets:
        port = p["tcp_port"] or p["udp_port"]
        if p["ip_dst"] and port:
            dest_counts[(p["ip_dst"], port)] += 1

    flags = []
    for (ip, port), count in dest_counts.items():
        if count > 20:
            flags.append({
                "heuristic": "repeated_connections",
                "reason": "Repeated connections to same destination",
                "detail": f"{count} packets to {ip}:{port}",
            })
    return flags


def check_plaintext_credentials(packets):
    """Flag HTTP Basic Auth headers seen in plaintext.

    HTTP Basic Auth sends base64-encoded credentials that are trivially
    reversible. Seeing this header in a capture means credentials were
    transmitted without TLS. The actual credential value is never logged.
    """
    flags = []
    seen_hosts = set()

    for p in packets:
        if p["http_auth"] and p["ip_dst"] not in seen_hosts:
            seen_hosts.add(p["ip_dst"])
            flags.append({
                "heuristic": "plaintext_credentials",
                "reason": "Plaintext credentials detected (HTTP Basic Auth)",
                "detail": f"HTTP Basic Auth header sent to {p['ip_dst']} — credential value redacted",
            })
    return flags


@mcp.tool()
def flag_suspicious(pcap_path: str):
    """Analyze a pcap file for potentially suspicious traffic patterns."""
    result = subprocess.run(
        [
            TSHARK, "-r", pcap_path, "-T", "fields",
            "-e", "ip.dst", "-e", "tcp.dstport", "-e", "udp.dstport",
            "-e", "frame.protocols", "-e", "frame.len",
            "-e", "ip.src", "-e", "dns.qry.name", "-e", "http.authorization",
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        return {"status": "error", "message": result.stderr.strip()}

    packets = parse_packets(result.stdout)

    flags = []
    flags.extend(check_unusual_ports(packets))
    flags.extend(check_traffic_volume(packets))
    flags.extend(check_dns_flood(packets))
    flags.extend(check_repeated_connections(packets))
    flags.extend(check_plaintext_credentials(packets))

    return {
        "status": "success",
        "packets_analyzed": len(packets),
        "flags": flags,
        "flags_count": len(flags),
    }


if __name__ == "__main__":
    mcp.run()