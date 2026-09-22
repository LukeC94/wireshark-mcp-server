from mcp.server.mcpserver import MCPServer
import subprocess, json

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

if __name__ == "__main__":
    mcp.run()