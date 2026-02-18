# Sniffox

A real-time, browser-based network packet analyzer and security operations dashboard built in Go. Capture live traffic or upload PCAPs, inspect every byte with deep protocol dissection, visualize your network in 3D, and detect attacks as they happen — all from a single tab.

![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue)

## What It Does

Capture packets live on any network interface or upload a `.pcap` file for offline analysis. Everything runs in the browser — no desktop app needed.

- **Packet capture** with BPF filter support
- **Protocol parsing** for Ethernet, ARP, IPv4/v6, TCP, UDP, ICMP, DNS, and HTTP
- **3-pane layout** — packet list, protocol tree, and hex/ASCII dump
- **Display filters** with boolean logic (`tcp && !dns`, `ip==10.0.0.1`, `port==443`)
- **Direction filters** — `inbound`, `outbound`, `local`, `external`, `broadcast`
- **Virtual scrolling** so it doesn't choke on thousands of packets

## Security Dashboard

A full security operations view with live metric cards updated once per second:

- **Threat Level** — SAFE / LOW / MEDIUM / HIGH / CRITICAL gauge, color-coded by active alert severity
- **Traffic Rate** — packets/s and bytes/s with a 60-second sparkline
- **Protocol Distribution** — horizontal bar chart showing TCP, UDP, DNS, ICMP, ARP, HTTP, and Other
- **Top Talkers** — top 5 source IPs by packet count with relative volume bars
- **Active Attacks** — count and severity-colored tags for currently active threat types
- **Bandwidth** — inbound/outbound rates and totals with dual sparkline

When a SYN flood or UDP flood is detected, a **DDoS Attack Banner** activates with a pulsing red border, attack details, and a 30-bar intensity chart.

### Threat Detection

11 attack pattern detectors running in real time:

- Port Scan, SYN Flood, Xmas Tree Scan, FIN Scan, NULL Scan
- Brute Force (SSH, RDP, FTP, Telnet, databases), ICMP Sweep, ARP Spoofing
- DNS Tunneling, UDP Flood, Large Packet / Amplification Detection

Alerts appear in a log below the dashboard sorted by severity. Click any IP in an alert to filter the packet list.

## 3D Network Graph

Real-time Three.js visualization that maps your network traffic as an interactive graph. IPs become nodes, packets become animated particles traveling between them. Color-coded by protocol.

Expand it fullscreen and you get:
- Protocol filter toggles
- Sliders for particle speed, node size, edge opacity, arc height
- IP search with node highlighting
- Live stats — top talkers, protocol breakdown, node/edge counts
- Orbit, pan, and zoom controls

## Deep Packet Analysis

Click any packet and hit **Deep Analysis** for a tabbed breakdown:

- **Summary** — quick overview with protocol flow diagram
- **Layers** — full protocol layer detail with field-level inspection
- **Hex Dump** — complete byte dump with ASCII sidebar
- **Visualization** — byte distribution chart, Shannon entropy, color-coded byte heatmap
- **Payload** — automatic string extraction, Base64 detection, URL-decoded content
- **TCP flags** — visual flag boxes (URG, ACK, PSH, RST, SYN, FIN)
- **Export** — copy as JSON, download JSON, download hex dump

## Setup

**Requirements:** Go 1.21+ and libpcap.

```bash
# Install libpcap (Linux)
sudo apt-get install -y libpcap-dev

# Build
go build -o sniffox .

# Run (needs root for capture)
sudo ./sniffox --port 8080
```

Open `http://localhost:8080`.

## How to Use

1. Pick a network interface from the dropdown
2. Add a BPF filter if you want (e.g. `tcp port 80`)
3. Hit **Start**
4. Click any packet row for details and hex dump
5. Use display filters to narrow things down
6. Switch to **Security** to see the live dashboard and alerts
7. Expand the **Network Graph** for a 3D view of your traffic
8. Upload `.pcap` files via **Open PCAP** for offline analysis

## Project Structure

```
sniffox/
├── main.go                     # Entry point, HTTP server
├── internal/
│   ├── models/                 # Packet and WebSocket message types
│   ├── capture/                # Live capture + PCAP file reader
│   ├── parser/                 # Packet parsing + per-protocol field extraction
│   ├── engine/                 # Session manager, client registry, broadcast
│   └── handlers/               # HTTP routes, static files, WebSocket
└── web/
    └── static/
        ├── index.html
        ├── css/style.css       # Dark / Dim / Light themes
        └── js/
            ├── app.js          # WebSocket, message dispatch
            ├── router.js       # Client-side page routing
            ├── packetlist.js   # Virtual-scrolled packet table
            ├── packetdetail.js # Protocol tree
            ├── hexview.js      # Hex + ASCII dump
            ├── filters.js      # Display filter parser
            ├── view3d.js       # Three.js 3D graph
            ├── security.js     # Threat detection + security dashboard
            └── packetmodal.js  # Deep analysis modal
```

## Dependencies

- [gopacket](https://github.com/google/gopacket) — packet capture and decoding
- [gorilla/websocket](https://github.com/gorilla/websocket) — WebSocket support
- [Three.js](https://threejs.org/) r128 — 3D visualization (CDN)
