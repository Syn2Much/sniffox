# Sniffox

A network sniffer/packet analyzer in the browser. Real-time packet capture, protocol dissection, 3D traffic visualization, and threat detection.

Built in Go with an embedded web UI. No Electron, no desktop app, no deps beyond libpcap.

![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue)

## Features

### Packet Capture & Analysis
- Live capture on any network interface with BPF filter support
- PCAP file upload (`.pcap`, `.pcapng`, `.cap`) for offline analysis
- Protocol parsing for Ethernet, ARP, IPv4/v6, TCP, UDP, ICMP, ICMPv6, DNS, HTTP, TLS (with SNI extraction), DHCP, NTP, and 802.1Q VLAN
- 3-pane Wireshark-style layout — packet list, protocol tree, hex/ASCII dump
- Display filters with boolean logic (`tcp && !dns`, `ip==10.0.0.1`, `port==443`, `tls.sni==example.com`)
- Direction filters — `inbound`, `outbound`, `local`, `external`, `broadcast`
- Virtual scrolling for large captures with right-click context menu

### Security Dashboard
Live security operations view with metric cards updated once per second:

- **Threat Level** gauge — SAFE / LOW / MEDIUM / HIGH / CRITICAL
- **Traffic Rate** — packets/s and bytes/s with 60-second sparkline
- **Protocol Distribution** — horizontal bar chart across 10 protocol categories
- **Top Talkers** — top 5 source IPs by packet count
- **Active Attacks** — count with severity-colored tags
- **Bandwidth** — inbound/outbound rates and totals with dual sparkline
- **DDoS Banner** — activates during SYN/UDP floods with pulsing animation and intensity chart

11 real-time threat detectors: Port Scan, SYN Flood, Xmas Tree Scan, FIN Scan, NULL Scan, Brute Force, ICMP Sweep, ARP Spoofing, DNS Tunneling, UDP Flood, and Large Packet / Amplification.

### Flow Tracking
Packets grouped into connections with a sortable flow table — source/destination, protocol, packet/byte counts, duration, and TCP state (SYN_SENT -> ESTABLISHED -> FIN_WAIT -> CLOSED). Toggle between Packets and Flows views. Click a flow to filter the packet list (`flow==N`).

### TCP Stream Reassembly
Full TCP byte-stream reconstruction via gopacket's `tcpassembly`. "Follow TCP Stream" dialog shows reassembled client/server data in alternating colors with ASCII, Hex, and Raw views. Automatic HTTP request/response extraction with headers and body preview. Filter by `stream==N`.

### 3D Network Graph
Interactive Three.js visualization — IPs become nodes, packets become animated particles traveling between them. Protocol color-coded. Includes fullscreen mode, protocol filters, visual sliders, IP search, and live stats. Graceful fallback when WebGL is unavailable.

### Deep Packet Analysis
Tabbed inspector for any captured packet:

- **Summary** — overview with protocol flow diagram
- **Layers** — full field-level protocol detail
- **Hex Dump** — byte dump with ASCII sidebar
- **Visualization** — byte distribution chart, Shannon entropy, byte heatmap
- **Payload** — string extraction, Base64 detection, URL decoding
- **Export** — copy/download as JSON or hex dump

## Quick Start

```bash
sudo apt-get install -y libpcap-dev   # Linux
go build -o sniffox .
sudo ./sniffox --port 8080
```

Open `http://localhost:8080`, pick an interface, and start sniffing.

## Project Structure

```
sniffox/
├── main.go                     # Entry point, HTTP server
├── internal/
│   ├── models/                 # Packet and WebSocket message types
│   ├── capture/                # Live capture + PCAP file reader
│   ├── parser/                 # Packet parsing, protocol extraction, TLS/DHCP/NTP
│   ├── flow/                   # Flow tracking + TCP state machine
│   ├── stream/                 # TCP stream reassembly + HTTP extraction
│   ├── engine/                 # Session manager, client registry, broadcast
│   └── handlers/               # HTTP routes, static files, WebSocket
└── web/
    └── static/
        ├── index.html
        ├── favicon.svg         # Fox logo
        ├── css/style.css       # Dark / Dim / Light themes
        └── js/
            ├── app.js          # WebSocket, message dispatch
            ├── router.js       # Client-side page routing
            ├── packetlist.js   # Virtual-scrolled packet table + context menu
            ├── packetdetail.js # Protocol tree + Follow Stream button
            ├── hexview.js      # Hex + ASCII dump
            ├── filters.js      # Display filter parser (protocol, flow, stream, TLS SNI)
            ├── flows.js        # Flow table UI
            ├── streams.js      # TCP stream viewer
            ├── view3d.js       # Three.js 3D graph
            ├── security.js     # Threat detection + security dashboard
            └── packetmodal.js  # Deep analysis modal
```

## Dependencies

- [gopacket](https://github.com/google/gopacket) — packet capture
- [gorilla/websocket](https://github.com/gorilla/websocket) — WebSocket
- [Three.js](https://threejs.org/) r128 — 3D visualization (CDN)
