# Sniffox 🦊

Real-time network packet analyzer in the browser. Capture, dissect, visualize, and detect threats — all from a single tab.

Built with Go + embedded web UI. No Electron, no desktop app, just libpcap.

<img alt="image" src="https://github.com/user-attachments/assets/a6a07d9b-04b4-4130-b933-17aed86aaa4a" />

![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue)
![AI Assisted](https://img.shields.io/badge/AI-Assisted-blueviolet?logo=anthropic&logoColor=white)

## Quick Start

```bash
sudo apt-get install -y libpcap-dev
go build -o sniffox .
sudo ./sniffox --port 8080
```

Open `http://localhost:8080`, pick an interface, start sniffing.

## Features

**Capture & Analysis** — Live capture with BPF filters or upload PCAP files. 14 protocols parsed (Ethernet, ARP, IPv4/v6, TCP, UDP, ICMP, ICMPv6, DNS, HTTP, TLS with SNI, DHCP, NTP, VLAN). Three-pane Wireshark-style layout with virtual scrolling and right-click context menu.

**Display Filters** — Boolean logic (`tcp && !dns`), IP/port matching (`ip==10.0.0.1`, `port==443`), TLS inspection (`tls.sni==example.com`), direction filters (`inbound`, `outbound`, `broadcast`), flow/stream filters (`flow==1`, `stream==1`).

**Flow Tracking** — Packets grouped into connections with sortable flow table. Per-flow stats, TCP state machine (SYN_SENT through CLOSED), directional packet/byte counts. Click a flow to filter packets.

**TCP Stream Reassembly** — Full byte-stream reconstruction with "Follow TCP Stream" dialog. Client/server data in alternating colors, ASCII/Hex/Raw views, automatic HTTP request/response extraction.

**Security Dashboard** — Live threat level gauge, traffic rate sparklines, protocol distribution, top talkers, bandwidth monitoring, DDoS attack banner. 11 threat detectors including port scan, SYN flood, ARP spoofing, DNS tunneling, and more.

**3D Network Graph** — Three.js visualization with IPs as nodes and packets as animated particles. Protocol color-coding, fullscreen mode, IP search, live stats. WebGL fallback when GPU unavailable.

**Deep Packet Analysis** — Per-packet inspector with protocol layers, hex dump, byte distribution heatmap, Shannon entropy, payload decoding, and JSON/hex export.

## Project Structure

```
internal/
  models/      Packet & message types
  capture/     Live capture + PCAP reader
  parser/      Protocol extraction (14 protocols)
  flow/        Flow tracking + TCP state machine
  stream/      TCP reassembly + HTTP extraction
  engine/      Session manager, broadcast
  handlers/    HTTP routes, WebSocket

web/static/
  js/          app, router, packetlist, packetdetail, hexview,
               filters, flows, streams, view3d, security, packetmodal
  css/         Dark / Dim / Light themes
```

## Dependencies

[gopacket](https://github.com/google/gopacket) for packet capture, [gorilla/websocket](https://github.com/gorilla/websocket) for WebSocket, [Three.js](https://threejs.org/) r128 for 3D visualization.
