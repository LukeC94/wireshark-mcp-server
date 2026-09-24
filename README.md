# Wireshark MCP Server

An MCP (Model Context Protocol) server that wraps `tshark` (Wireshark's CLI) to let AI agents capture and analyze network traffic. Ask Claude to capture packets, summarize what's happening on your network, and flag potentially suspicious activity — all through natural language.

## Prerequisites

- **Python 3.10+**
- **Wireshark / tshark** — [download here](https://www.wireshark.org/download.html). Make sure `tshark` is on your PATH.
- **Elevated permissions** — Packet capture requires admin/root privileges:
  - **Windows**: Run your terminal as Administrator, or ensure Npcap was installed with "Allow non-admin users to capture" checked
  - **macOS/Linux**: Run with `sudo`, or add your user to the `wireshark` group

## Setup

```bash
git clone https://github.com/YOUR_USERNAME/wireshark-mcp-server.git
cd wireshark-mcp-server
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Verify tshark is accessible:

```bash
tshark -D
```

## Claude Desktop Configuration

Add the following to your `claude_desktop_config.json`. Use the absolute path to the Python executable **inside your venv** and the absolute path to `server.py`:

```json
{
  "mcpServers": {
    "wireshark": {
      "command": "C:\\path\\to\\wireshark-mcp-server\\venv\\Scripts\\python.exe",
      "args": ["C:\\path\\to\\wireshark-mcp-server\\server.py"]
    }
  }
}
```

**Finding the config file:**

| Install method | Config file location |
|---|---|
| Standard installer | `%APPDATA%\Claude\claude_desktop_config.json` |
| Microsoft Store | `%LOCALAPPDATA%\Packages\Claude_<id>\LocalCache\Roaming\Claude\claude_desktop_config.json` |

> **Tip:** If you're not sure which one, check Claude Desktop's logs at `%LOCALAPPDATA%\Claude\logs\main.log` — look for a line starting with `Reading claude_desktop_config.json from` to see the exact path.

After saving the config, restart Claude Desktop. You should see the wireshark tools available in a new chat.

## Tools

### `list_interfaces()`

Lists available network interfaces for capture.

### `capture_traffic(duration_seconds, interface="Wi-Fi")`

Runs a timed packet capture and saves it to a `.pcap` file in the `captures/` directory.

### `summarize_capture(pcap_path)`

Parses a saved capture and returns unique destination IPs, ports, protocols, and total byte count.

### `flag_suspicious(pcap_path)`

Applies five heuristics to flag potentially suspicious traffic:

| Heuristic | What it checks |
|---|---|
| **Unusual ports** | Traffic on non-standard ports (outside 80, 443, 53, etc.) |
| **Traffic volume** | A single host sending >70% of total bytes |
| **DNS flood** | More than 50 unique DNS queries (possible beaconing) |
| **Repeated connections** | >20 packets to the same IP:port |
| **Plaintext credentials** | HTTP Basic Auth headers sent without TLS |

These are simple, explainable heuristics — not a replacement for a real IDS. Each one is a separate function with a docstring explaining the rationale.

## Example Prompts

Once connected via Claude Desktop, try:

- "List my network interfaces"
- "Capture 10 seconds of traffic on Wi-Fi"
- "Summarize the capture you just took"
- "Flag anything suspicious in that capture"
- "Capture 30 seconds of traffic and then analyze it for me"

## Privacy & Safety

- This tool **only captures traffic on your own machine's network interface**. It does not and cannot see other devices' traffic.
- Captured `.pcap` files may contain sensitive metadata (domains visited, IP addresses). They are gitignored by default — do not commit them.
- The plaintext credentials heuristic **never logs or prints actual credential values** — it only flags that an auth header was present.

## Future Work

- Real-time/streaming capture during a conversation
- Persistent storage or indexing of past captures
- ML-based anomaly detection beyond simple heuristics
- Web dashboard for visualizing capture data
- Support for capturing on remote hosts
