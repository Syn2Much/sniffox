# Sniffox

A network sniffer/packet analyzer in your browser. Real-time packet capture, protocol dissection, 3D traffic visualization, and threat detection.

Built with Go and an embedded web UI — no Electron, no desktop app, just libpcap.

![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue)

---

## ✨ Features

### 📡 Packet Capture & Analysis
- Live capture on any network interface with BPF filter support  
- Upload PCAP files (`.pcap`, `.pcapng`, `.cap`) for offline analysis  
- Protocol parsing: Ethernet, ARP, IPv4/v6, TCP, UDP, ICMP, ICMPv6, DNS, HTTP, TLS (SNI), DHCP, NTP, 802.1Q VLAN  
- Three-pane Wireshark-style layout — packet list, protocol tree, hex/ASCII dump  
- Display filters with boolean logic (`tcp && !dns`, `ip==10.0.0.1`, `tls.sni==example.com`)  
- Direction filters — `inbound`, `outbound`, `local`, `external`, `broadcast`  
- Virtual scrolling for large captures + right-click context menu  

### 📊 Security Dashboard
Live security operations view, updated every second:

- **Threat level** — SAFE / LOW / MEDIUM / HIGH / CRITICAL  
- **Traffic rate** — packets/s + bytes/s with 60s sparkline  
- **Protocol distribution** — horizontal bar chart (10 categories)  
- **Top talkers** — top 5 source IPs by packet count  
- **Active attacks** — count + severity-colored tags  
- **Bandwidth** — inbound/outbound rates with dual sparkline  
- **DDoS banner** — activates during SYN/UDP floods with pulsing animation  

**11 threat detectors**: Port Scan, SYN Flood, Xmas Tree Scan, FIN Scan, NULL Scan, Brute Force, ICMP Sweep, ARP Spoofing, DNS Tunneling, UDP Flood, Large Packet / Amplification.

### 🔄 Flow Tracking
Group packets into connections — view source/destination, protocol, packet/byte counts, duration, TCP state. Toggle between Packets and Flows views. Click a flow to filter the packet list (`flow==N`).

### 🔁 TCP Stream Reassembly
Full TCP byte-stream reconstruction. "Follow TCP Stream" dialog shows client/server data in alternating colors (ASCII/Hex/Raw views). Automatic HTTP request/response extraction. Filter by `stream==N`.

### 🌐 3D Network Graph
Interactive Three.js visualization — IPs become nodes, packets become animated particles. Protocol color-coding, fullscreen mode, visual sliders, IP search, live stats. Graceful WebGL fallback.

### 🔍 Deep Packet Analysis
Tabbed inspector for any packet:

- **Summary** — overview with protocol flow diagram  
- **Layers** — full field-level protocol detail  
- **Hex Dump** — byte dump with ASCII sidebar  
- **Visualization** — byte distribution, Shannon entropy, heatmap  
- **Payload** — string extraction, Base64 detection, URL decoding  
- **Export** — copy/download as JSON or hex dump  

---

## 🚀 Quick Start

```bash
# Install libpcap (Linux)
sudo apt-get install -y libpcap-dev

# Build
go build -o sniffox .

# Run (root required for packet capture)
sudo ./sniffox --port 8080
```

Open `http://localhost:8080`, pick an interface, and start sniffing.

---

## 📁 Project Structure

```
sniffox/
├── main.go                          # Entry point, HTTP server
├── internal/
│   ├── models/                       # Packet & WebSocket message types
│   ├── capture/                       # Live capture + PCAP file reader
│   ├── parser/                         # Protocol extraction (TLS/DHCP/NTP)
│   ├── flow/                             # Flow tracking + TCP state
│   ├── stream/                         # TCP reassembly + HTTP
│   ├── engine/                         # Session manager, client broadcast
│   └── handlers/                       # HTTP routes, WebSocket
└── web/
    └── static/
        ├── index.html
        ├── favicon.svg                  # Fox logo
        ├── css/style.css                 # Dark/Dim/Light themes
        └── js/
            ├── app.js                      # WebSocket, message dispatch
            ├── router.js                    # Client-side routing
            ├── packetlist.js                # Virtual-scrolled table
            ├── packetdetail.js              # Protocol tree
            ├── hexview.js                    # Hex + ASCII dump
            ├── filters.js                    # Display filter parser
            ├── flows.js                       # Flow table UI
            ├── streams.js                     # TCP stream viewer
            ├── view3d.js                       # 3D graph
            ├── security.js                     # Threat dashboard
            └── packetmodal.js                  # Deep analysis modal
```

---

## 📦 Dependencies

- [gopacket](https://github.com/google/gopacket) — packet capture  
- [gorilla/websocket](https://github.com/gorilla/websocket) — WebSocket  
- [Three.js](https://threejs.org/) r128 — 3D visualization (CDN)  

---

**Sniffox** — because network analysis shouldn't require a PhD in Wireshark. 🦊
