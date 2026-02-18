# TCPDumper

A browser-based Wireshark-lite packet analyzer built in Go. Live capture and PCAP file support with a real-time web UI featuring 3D network visualization, security threat detection, and deep packet analysis.

![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue)

## Features

### Packet Capture & Analysis
- **Live capture** on any network interface with BPF filter support
- **PCAP file upload** — load `.pcap`, `.pcapng`, `.cap` files for offline analysis
- **Protocol parsing** — Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMPv4, DNS, HTTP (heuristic)
- **3-pane layout** — packet list, expandable protocol tree, hex + ASCII dump
- **Display filters** — boolean logic (`tcp && !dns`), IP search (`ip==10.0.0.1`), port filters (`port==443`)
- **Virtual scrolling** — handles thousands of packets without DOM slowdown

### 3D Network Graph
- Real-time Three.js visualization of network traffic as an interactive graph
- IP addresses rendered as nodes, packets as animated arc particles
- Protocol-colored edges and nodes (TCP, UDP, DNS, HTTP, ARP, ICMP)
- **Expandable fullscreen mode** with controls panel:
  - Protocol filter checkboxes to toggle visibility
  - Sliders for particle speed, node size, edge opacity, arc height
  - IP search with node highlighting
  - Live stats overlay — top talkers, protocol breakdown, node/edge counts
- OrbitControls — left drag to orbit, right drag to pan, scroll to zoom

### Security Threat Detection
- Real-time analysis with 11 attack pattern detectors:
  - Port Scan, SYN Flood, Xmas Tree Scan, FIN Scan, NULL Scan
  - Brute Force (SSH/RDP/FTP/Telnet), ICMP Sweep, ARP Spoofing
  - DNS Tunneling, UDP Flood, Large Packet Detection
- Collapsible alerts side panel with severity levels (Critical/High/Medium/Low)
- One-click IP filtering from alert entries

### Deep Packet Analysis Modal
- Tabbed interface: Summary, Layers, Hex Dump, Visualization, Payload
- **Protocol flow diagram** — SVG layer stack visualization
- **Byte distribution chart** with Shannon entropy calculation
- **Byte heatmap** — color-coded grid with hover inspection
- **TCP flag visualization** — colored flag boxes (URG, ACK, PSH, RST, SYN, FIN)
- **Payload decoder** — automatic string extraction, Base64 detection, URL-encoded content
- **Export** — copy JSON to clipboard, download JSON or hex dump files

### UI
- Dark/Light theme toggle (Catppuccin Mocha/Latte)
- Resizable panes with drag handles
- Filter preset dropdown with 12 common filters
- Auto-reconnecting WebSocket connection
- Toast notifications for errors and status

## Requirements

- Go 1.21+
- `libpcap-dev` (Linux) or `libpcap` (macOS)

## Quick Start

```bash
# Install libpcap (Linux)
sudo apt-get install -y libpcap-dev

# Build
go build -o tcpdumper .

# Run (requires root for packet capture)
sudo ./tcpdumper --port 8080
```

Open **http://localhost:8080** in your browser.

## Usage

1. Select a network interface from the dropdown
2. Optionally enter a BPF filter (e.g. `tcp port 80`)
3. Click **Start** to begin capturing
4. Click any packet row to view protocol details and hex dump
5. Click **Deep Analysis** for the full analysis modal
6. Use display filters to narrow results: `tcp`, `ip==192.168.1.1`, `port==443`, `dns || http`
7. Click **Expand** on the 3D view for fullscreen network graph with controls
8. Toggle **Alerts** to monitor for suspicious network patterns
9. Upload `.pcap` files via **Open PCAP** for offline analysis

## Architecture

```
tcpdumper/
├── main.go                          # Entry point, HTTP server
├── internal/
│   ├── models/
│   │   ├── packet.go                # PacketInfo, LayerDetail, LayerField
│   │   └── messages.go              # WebSocket message types
│   ├── capture/
│   │   ├── capture.go               # Live capture via gopacket/pcap
│   │   └── pcapreader.go            # PCAP file reader
│   ├── parser/
│   │   ├── parser.go                # Packet → PacketInfo + hex dump
│   │   └── layers.go                # Per-protocol field extraction
│   ├── engine/
│   │   └── engine.go                # Session manager, client registry, broadcast
│   └── handlers/
│       ├── http.go                  # Routes, static files, PCAP upload
│       └── websocket.go             # WebSocket upgrade, read/write loops
└── web/
    ├── embed.go                     # //go:embed static/*
    └── static/
        ├── index.html
        ├── css/style.css            # Catppuccin dark/light themes
        └── js/
            ├── app.js               # WebSocket, message dispatch, toolbar
            ├── packetlist.js         # Virtual-scrolled packet table
            ├── packetdetail.js       # Expandable protocol tree
            ├── hexview.js            # Hex + ASCII dump
            ├── filters.js            # Display filter parser
            ├── view3d.js             # Three.js 3D network graph
            ├── security.js           # Real-time threat detection
            └── packetmodal.js        # Deep analysis modal
```

## WebSocket Protocol

JSON messages with `{type, payload}` envelope:

| Direction | Type | Description |
|-----------|------|-------------|
| Client → | `get_interfaces` | Request available interfaces |
| Client → | `start_capture` | Start capture with interface + BPF filter |
| Client → | `stop_capture` | Stop active capture |
| ← Server | `interfaces` | List of available interfaces |
| ← Server | `packet` | Parsed packet data |
| ← Server | `capture_started` | Capture confirmation |
| ← Server | `capture_stopped` | Capture stopped |
| ← Server | `stats` | Capture statistics |
| ← Server | `error` | Error message |

## Dependencies

- [gopacket](https://github.com/google/gopacket) — packet capture and decoding
- [gorilla/websocket](https://github.com/gorilla/websocket) — WebSocket support
- [Three.js](https://threejs.org/) r128 — 3D visualization (CDN)
