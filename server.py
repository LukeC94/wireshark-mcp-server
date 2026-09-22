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
        # Each line looks like 1. \Device\NPF_{...} (Wi-Fi)
        # Split into parts and parse out the index, device, and name
        parts = line.split(". ",1)
        index = parts[0]
        rest = parts[1]

        # The name is inside parentheses at the end
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



if __name__ == "__main__":
    mcp.run()