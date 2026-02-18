# Changelog

All notable changes to TCPDumper are documented here.

## [0.4.0] - 2026-02-18

### Fixed
- 3D network graph pane is now a dynamic flex participant — all four panes (packet list, detail, hex, 3D) can be drag-resized to any proportion simultaneously
- Removed fixed-height accordion wrapper that prevented proper layout adjustment

## [0.3.0] - 2026-02-18

### Added
- 3D network graph is collapsed by default — click the header bar to open
- Three.js scene lazy-loads on first open (no GPU/memory cost while closed)
- Packets received while graph is closed are queued (up to 2k) and replayed on open

## [0.2.0] - 2026-02-18

### Added
- **Direction-based display filters**: `inbound`, `outbound`, `local`, `external`, `broadcast`, `unicast`
- Combinable with all existing filters (e.g. `outbound && tcp`, `inbound && !arp`)
- Filter preset dropdown reorganized into optgroups: Direction, Protocol, Combined, Port
- Local IP addresses auto-detected from network interfaces for direction matching

## [0.1.0] - 2026-02-18

### Added
- Live packet capture on any network interface with BPF filter support
- PCAP file upload (.pcap, .pcapng, .cap) for offline analysis
- Protocol parsing: Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMPv4, DNS, HTTP
- 3-pane layout: packet list (virtual-scrolled), protocol detail tree, hex + ASCII dump
- Display filter engine with boolean logic (`&&`, `||`, `!`, parentheses)
- IP filters: `ip==ADDR`, `ip.src==ADDR`, `ip.dst==ADDR`, `port==N`
- 3D network graph (Three.js) with protocol-colored nodes, edges, and animated particles
- OrbitControls for camera (orbit, pan, zoom)
- Expandable fullscreen mode for 3D view with controls panel
- Protocol filter checkboxes and visual sliders (speed, node size, edge opacity, arc height)
- IP search with node highlighting and live stats overlay (top talkers, protocol breakdown)
- Real-time security threat detection with 11 attack pattern detectors
  - Port Scan, SYN Flood, Xmas Tree Scan, FIN Scan, NULL Scan
  - Brute Force, ICMP Sweep, ARP Spoofing, DNS Tunneling, UDP Flood, Large Packet
- Collapsible alerts side panel with severity levels and one-click IP filtering
- Deep packet analysis modal with tabbed interface
  - Summary, Layers, Hex Dump, Visualization, Payload tabs
  - Protocol flow diagram (SVG), byte distribution chart with entropy
  - Byte heatmap, TCP flag visualization, ASCII payload dump
  - Payload decoder (string extraction, Base64, URL-encoded)
  - Export: copy JSON, download JSON, download hex dump
- Dark/Light theme toggle (Catppuccin Mocha/Latte) with localStorage persistence
- 12 filter presets in dropdown
- Resizable panes with drag handles
- Auto-reconnecting WebSocket connection
- rAF message batching (100 packets/tick) for UI performance
- Virtual scrolling in packet table for large captures
- Async buffered WebSocket send with backpressure (drop-on-full)
- Server-side PCAP pacing to prevent flooding
