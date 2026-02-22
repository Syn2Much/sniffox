# Changelog

All notable changes to Sniffox are documented here.

## [0.11.1] - 2026-02-22

### Fixed
- **Timeline render loop not restarting** — navigating away from the timeline page stopped the animation frame loop, but returning never restarted it, leaving the canvas blank
- **Wrong packet field name in timeline, endpoints, and threat intel** — JS code referenced `pkt.time` (undefined) instead of `pkt.timestamp`, causing all three views to receive `0` for every packet timestamp

## [0.11.0] - 2026-02-22

### Added
- **PCAP Export/Download** — "Export" button in the capture toolbar downloads all captured packets as a `.pcap` file; backend stores raw packet bytes and link type during live capture and PCAP import, writes valid PCAP via `pcapgo.Writer` at `/api/export`
- **Packet Bookmarks & Annotations** — right-click any packet row to bookmark it; bookmarked packets show a gold star indicator and subtle row highlight; slide-out bookmarks panel (toolbar button) lists all bookmarks with editable note fields, quick navigation, and remove buttons; `bookmarked` display filter keyword shows only starred packets; persisted in localStorage
- **Command Palette (Ctrl+K)** — Spotlight-style overlay with fuzzy search across 30+ commands: page navigation, capture controls (start/stop/clear/export/save session), display filter presets, theme switching, and tool shortcuts; keyboard navigable with arrow keys + Enter
- **Session Persistence** — save the current capture to the server as a named session (PCAP + JSON metadata in `sessions/` directory); new "Sessions" page with card grid showing session name, date, packet count, and file size; load any past session to replay it in the capture view; delete sessions; accessible from nav bar, toolbar "Save" button, and command palette
- `number==N` display filter to jump to a specific packet by number
- Keyboard shortcut `Alt+9` for Sessions page navigation

### Changed
- Navigation expanded from 8 to 9 routes (added Sessions)
- Context menu gains "Bookmark Packet" / "Remove Bookmark" toggle as first item
- Welcome state shows `Ctrl+K` command palette shortcut hint

## [0.10.1] - 2026-02-21

### Fixed
- **Topology graph off-center on HiDPI displays** — render viewport used `canvas.width` (physical pixels) for center calculation while the canvas context already had a DPR scale transform, pushing the graph to the bottom-right corner on Retina/2x screens
- **Animation loops burning CPU on hidden pages** — timeline, topology, and 3D graph RAF loops now stop when the user navigates away and restart on return
- **Crash in deep analysis on non-standard TCP packets** — `tcpLayer.fields` could be undefined, causing `.find()` to throw when opening the flag visualization

### Added
- Screenshots of live capture added to README (capture, security dashboard, endpoints, topology, deep packet analysis)

## [0.10.0] - 2026-02-20

### Added
- **4 new analysis pages** with dedicated navigation tabs
  - **Timeline** — interactive canvas-based packet timeline with protocol-colored lanes, mini-map, zoom/pan, hover tooltips, and protocol filter chips
  - **Topology** — 2D force-directed host communication graph with physics simulation, node dragging/pinning, edge thickness by packet count, and protocol coloring
  - **Endpoints** — per-IP statistics table with sent/recv packet and byte counters, peer counts, protocol badges, first/last-seen timestamps, sortable columns, and search filtering
  - **Threat Intel** — MITRE ATT&CK technique mapping grid, IOC (Indicators of Compromise) tracking, per-host risk scoring with color bands, and geo-IP classification (private/public/multicast/loopback)
- **10 new protocol parsers** (24 total)
  - Network: IGMP (type, max response time, group address), GRE (protocol, checksum/key/sequence), SCTP (ports, verification tag, checksum), STP (protocol ID, version, root/bridge priority)
  - Application heuristics: SSH (banner detection), QUIC (long header + version), MQTT (CONNECT packet + protocol level), SIP (method + call-ID), Modbus/TCP (function codes), RDP (TPKT + PDU type)
  - New backend: `internal/parser/appheuristics.go`
- **JA3 TLS fingerprinting** — MD5 hash of client version, cipher suites, extensions, supported curves, and EC point formats with GREASE filtering; cipher suite name lookup for 30+ suites
- **Per-protocol statistics** — backend tracks packet/byte counts per protocol, broadcast to clients every 2s via `capture_stats` WebSocket message
- **Dstat-style traffic graph** on Security dashboard — 60-second rolling stacked area chart showing per-protocol packet rates with legend
- **3 new threat detectors** — IGMP flood, GRE tunnel detection, SIP brute force (REGISTER method)
- **SCTP flow extraction** — SCTP packets now tracked in flow table with source/dest ports
- Keyboard shortcuts extended to `Alt+1-8` for all 8 navigation routes
- Protocol colors for all new protocols in packet list, 3D graph, and filter engine
- Capture filter dropdown includes all new protocol options

### Changed
- Navigation expanded from 4 to 8 routes (added Timeline, Topology, Endpoints, Threat Intel)
- DNS parser enhanced with response code, authority/additional record counts
- Security dashboard forwards alerts to Threat Intel module
- TLS detail view now shows JA3 hash, sorted cipher suites, extensions list, supported groups, and EC point formats

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
