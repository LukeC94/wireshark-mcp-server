# Wireshark MCP Server

## Project Goal
Build an MCP (Model Context Protocol) server in Python that wraps `tshark`
(Wireshark's CLI) to capture and analyze network traffic, surfacing
potentially suspicious activity through tool calls an AI agent (e.g. Claude
Desktop) can invoke.

This is a learning + portfolio project. Priorities, in order:
1. Working end-to-end demo by end of day
2. Clean, readable code and a good README (this is going on GitHub)
3. Genuinely learn how MCP servers and `tshark`/Wireshark internals work
   along the way — don't just generate a black box, understand each piece

## Scope (Day 1 — keep this tight)
**In scope:**
- Local stdio MCP server, Python, using the official `mcp` SDK
- Wraps `tshark` via subprocess (not the Wireshark GUI, not pyshark unless
  needed — prefer calling `tshark` directly and parsing its output, since
  that's the most transferable skill)
- Tools to build:
  - `capture_traffic(duration_seconds, interface=None)` — run a timed
    capture, save to a `.pcap` file, return a summary
  - `list_interfaces()` — list available network interfaces to capture on
  - `summarize_capture(pcap_path)` — parse a saved capture and return
    unique destination hosts/IPs, ports, protocols, and byte counts
  - `flag_suspicious(pcap_path)` — apply a small set of simple heuristics
    (see below) and return flagged connections with a plain-language reason
- A `README.md` with setup instructions, example prompts, and a screenshot
  or sample output
- A `requirements.txt` and a `claude_desktop_config.json` example snippet

**Out of scope for Day 1** (note as "Future work" in README, don't build):
- Real-time/streaming capture while the agent is mid-conversation
- ARP spoofing, MITM, or capturing another device's traffic
- A UI or dashboard
- Persistent storage/database of captures — flat `.pcap` files are fine
- ML-based anomaly detection — heuristics only, and label them as such

## Suspicious-traffic heuristics (v1 — simple and explainable)
Keep these obvious and inspectable, not clever:
- Connections to unusual/non-standard ports for common protocols
- A single host generating a disproportionate share of traffic volume
- DNS queries to a large number of distinct domains in a short window
  (possible beaconing/exfiltration pattern)
- Repeated connection attempts to the same destination in quick succession
- Plaintext protocols carrying what looks like credentials (e.g. HTTP
  Basic Auth headers) — flag only, never log/print the actual credential
  value

Each heuristic should be its own small function with a docstring
explaining what it checks and why it might indicate something suspicious,
so the code doubles as a learning resource.

## Tech stack
- Python 3.10+
- `mcp` (official Python MCP SDK) for the server
- `tshark` (must be installed separately — document this clearly as a
  prerequisite, do not attempt to bundle it)
- Standard library (`subprocess`, `json`, `pathlib`) — avoid extra
  dependencies unless there's a clear reason

## Safety / permissions notes (address explicitly in README)
- Packet capture requires elevated permissions on most systems (root/sudo
  on Linux/macOS, WinPcap/Npcap admin rights on Windows) — call this out
  up front, don't let a user discover it via a cryptic error
- This tool only captures traffic visible to the host it runs on (i.e.
  the laptop's own network interface) — it does not and should not
  attempt to see other devices' traffic on the network
- Captured `.pcap` files may contain sensitive data (visited domains,
  metadata) — add a `.gitignore` entry so capture files are never
  committed to the repo

## Working style for this session
- Build incrementally: get `list_interfaces` working end-to-end first
  (simplest possible tool, proves the MCP wiring works), then
  `capture_traffic`, then the two analysis tools
- After each tool works, pause and explain briefly what it's doing and
  why, since understanding is a stated goal — don't just move to the next
  one silently
- Prefer explicit, readable code over clever one-liners
- Write the README as you go, not all at the end

## Definition of done for today
- [ ] All four tools implemented and working against a real local capture
- [ ] README with setup, prerequisites, and example usage
- [ ] `.gitignore` excludes `.pcap` files and venv artifacts
- [ ] `requirements.txt` present
- [ ] Tested against `claude_desktop_config.json` locally
- [ ] Repo pushed to GitHub with a clear commit history (not one giant
      commit) so it reads well as a portfolio piece
