# Sniffox 🦊

A network sniffer/packet analyzer in the browser. Real-time packet capture, protocol dissection, 3D traffic visualization, and threat detection.

Built in Go with an embedded web UI. No Electron, no desktop app, no deps beyond libpcap. 

![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue)

## What It Does

- **Live capture** on any interface with BPF filters, or upload `.pcap` files for offline analysis
- **Protocol parsing** — Ethernet, ARP, IPv4/v6, TCP, UDP, ICMP, DNS, HTTP
- **Wireshark-style 3-pane layout** — packet list, protocol tree, hex/ASCII dump
- **Display filters** — boolean logic (`tcp && !dns`), IP/port filters, direction filters (`inbound`, `outbound`, `broadcast`)
- **Security dashboard** — live threat level gauge, traffic sparklines, protocol distribution, top talkers, DDoS detection with 11 attack pattern detectors
- **3D network graph** — Three.js visualization with IPs as nodes, packets as animated particles, fullscreen mode with controls
- **Deep packet analysis** — per-packet inspector with layer detail, byte heatmap, Shannon entropy, payload decoding, JSON/hex export

## Quick Start

```bash
sudo apt-get install -y libpcap-dev   # Linux
go build -o sniffox .
sudo ./sniffox --port 8080
```

Open `http://localhost:8080`, pick an interface, start sniffing.

## Dependencies

- [gopacket](https://github.com/google/gopacket) — packet capture
- [gorilla/websocket](https://github.com/gorilla/websocket) — WebSocket
- [Three.js](https://threejs.org/) r128 — 3D visualization (CDN)
