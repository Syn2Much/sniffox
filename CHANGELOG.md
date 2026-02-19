# Changelog

All notable changes to Sniffox are documented here.

## [0.9.0] - 2026-02-19

### Added
- **Welcome onboarding state** — capture page shows a guided welcome screen with SVG radar icon, 3-step instructions, and keyboard shortcut hints when no packets are loaded; auto-transitions to capture view on first packet
- **Keyboard shortcuts**
  - `Ctrl+F` / `Cmd+F` to focus the display filter input
  - `Arrow Up/Down` to navigate packets in the packet list with auto-scroll
  - `Alt+1/2/3/4` for quick page navigation (Capture/Graph/Security/Analysis)
  - `Escape` to dismiss stream viewer, 3D expand overlay, or blur filter
- **Live capture indicator** — pulsing red "LIVE" badge in toolbar during active capture
- **Packet rate display** in status bar (e.g. "142 pkt/s") during capture
- **Tab count badges** — Packets and Flows tabs show live counts (e.g. "Packets 1.2K")
- **"Deep Analysis" in context menu** — right-click a packet row to open deep analysis directly
- **Stream download buttons** — "Save Hex" and "Save Raw" buttons replace in-browser hex/raw rendering to prevent crashes on large streams

### Changed
- **Navigation bar redesigned** — pill-shaped active states with background fill and glow instead of underlines; better spacing and hover effects; taller navbar (42px)
- **Page transitions** — smooth fade + slide animation when switching between pages
- **Toolbar reorganized** — controls grouped into logical sections (capture, filtering, file); BPF filter placeholder clarified to "Capture filter (BPF)"; display filter placeholder made more descriptive
- **Stream viewer** — ASCII view capped at 64KB for display safety with truncation message; non-printable chars render as plain `.` instead of `<span>` elements to avoid DOM explosion on large streams
- **Toasts redesigned** — slide in from right, click to dismiss, exit animation, backdrop blur; added "success" toast type (green); shown on capture start and PCAP load
- **Context menu improved** — scale-in animation, backdrop blur, viewport edge clamping, larger shadow
- **Empty states** now include icons above text
- **Security dashboard cards** — subtle hover effect with shadow and border highlight
- **Alert badge** has pop-in animation

### Fixed
- Large TCP streams (hex/raw view) no longer crash the browser — replaced DOM rendering with file download
- Context menu no longer clips off-screen on viewport edges
- Filter input shows green border when active filter applied
- Status bar connection indicator has glow when connected, blink animation when connecting

## [0.8.0] - 2026-02-18

### Added
- **TCP Stream Reassembly** — full byte-stream reconstruction via gopacket `tcpassembly`
  - "Follow TCP Stream" dialog from packet detail or right-click context menu
  - Client/server data displayed in alternating colors (ASCII, Hex, Raw views)
  - Automatic HTTP request/response extraction with headers and body preview
  - Per-direction 256KB ring buffer, assembler runs in dedicated goroutine
  - `stream==N` display filter to isolate packets belonging to a stream
  - New backend: `internal/stream/assembler.go`, `internal/stream/http.go`
  - New frontend: `web/static/js/streams.js`

### Added
- **WebGL Fallback** — graceful degradation when GPU/WebGL is unavailable
  - Try/catch detection before Three.js renderer creation
  - Shows friendly "WebGL Not Available" message instead of crashing the page

### Fixed
- Capture area layout broken after adding flow tabs — added `flex-direction: column` to `#capture-area`

## [0.7.0] - 2026-02-18

### Added
- **Flow Tracking** — packets grouped into bidirectional connections
  - Sortable flow table with Packets/Flows tab toggle
  - Per-flow stats: packet count, byte count, duration, TCP state
  - TCP state machine tracking (SYN_SENT → ESTABLISHED → FIN_WAIT → CLOSED)
  - Directional counters (forward/reverse packets and bytes)
  - Click a flow row to filter packet list by `flow==N`
  - Flow table broadcasts every 1 second via WebSocket
  - New backend: `internal/flow/tracker.go`, `internal/parser/extract.go`
  - New frontend: `web/static/js/flows.js`
- **Right-click context menu** on packet list — Follow TCP Stream, Filter by Flow, Filter by Source/Dest IP

## [0.6.0] - 2026-02-18

### Added
- **Expanded Protocol Support** — 6 new protocol parsers (14 total)
  - TLS with SNI extraction from ClientHello (manual byte parser for handshake internals)
  - DHCPv4 with operation type, client MAC, message type, requested IP
  - NTP with version, mode, stratum, reference timestamp
  - ICMPv6 with type code and checksum
  - VLAN (802.1Q) with VLAN ID, priority, encapsulated type
  - `tls.sni==hostname` display filter for TLS server name inspection
- New protocol filter keywords: `tls`, `dhcp`, `ntp`, `icmpv6`, `vlan`
- Protocol colors for new protocols in packet list and 3D graph
- New backend: `internal/parser/tls.go`

### Changed
- Rebranded from TCPDumper to **Sniffox** — binary, module path, all UI references updated

## [0.5.0] - 2026-02-18

### Added
- **Security Dashboard** with 6 real-time metric cards above the alert list
  - Threat Level gauge (SAFE/LOW/MEDIUM/HIGH/CRITICAL) color-coded by active alert severity
  - Traffic Rate card with packets/s, bytes/s, and 60-second SVG sparkline
  - Protocol Distribution horizontal bar chart (TCP/UDP/DNS/ICMP/ARP/HTTP/Other)
  - Top Talkers showing top 5 source IPs by packet count with relative volume bars
  - Active Attacks count with severity-colored tags for current attack types
  - Bandwidth card with inbound/outbound rates, totals, and dual sparkline
- **DDoS Attack Banner** that activates during SYN flood / UDP flood events with pulsing animation, attack details, and 30-bar intensity chart
- Dashboard data collected per-packet in fast path (zero DOM writes), rendered once per second via setInterval
- Exported `isLocalAddr` from Filters module for directional bandwidth tracking

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
