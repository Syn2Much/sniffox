# Sniffox

## What This Is
Real-time network packet analyzer with a browser UI. Go backend with embedded static files, no build step for frontend.

## Tech Stack
- **Backend:** Go 1.21+, gopacket (libpcap), gorilla/websocket
- **Frontend:** Vanilla JS (no framework, no bundler), Three.js r128 via CDN
- **Embedding:** `web/embed.go` uses `//go:embed static/*` to bundle all static files into the binary

## Build & Run
```bash
go build -o sniffox .
sudo ./sniffox --port 8080   # root needed for pcap
```

## Architecture

### Backend Packages
- `internal/models/` — PacketInfo, WSMessage, FlowInfo, StreamEvent structs
- `internal/capture/` — LiveCapture (pcap.OpenLive), PcapReader for file uploads
- `internal/parser/` — Packet parsing + protocol extraction. `layers.go` has parseLayer() type switch for 14 protocols. `tls.go` has manual ClientHello byte parser for SNI. `extract.go` extracts flow tuples.
- `internal/flow/` — Flow tracker with normalized 5-tuple keys and TCP state machine (NEW→SYN_SENT→ESTABLISHED→FIN_WAIT→CLOSED). Capped at 10k flows with 5min idle eviction.
- `internal/stream/` — TCP stream reassembly via gopacket tcpassembly. Manager runs in its own goroutine fed by chan (cap 4096). 256KB buffer per stream direction. `http.go` extracts HTTP request/response.
- `internal/engine/` — Central coordinator. Manages capture sessions, flow tracker, stream manager. Broadcasts packets to WS clients. Flow broadcaster ticks every 1s.
- `internal/handlers/` — HTTP routes (`http.go`), WebSocket handler (`websocket.go`). WS commands: get_interfaces, start_capture, stop_capture, get_flows, get_stream_data.

### Frontend Files (web/static/js/)
- `app.js` — WebSocket connection, message dispatch, toolbar controls, theme cycling
- `router.js` — Hash-based SPA router (#/capture, #/graph, #/security, #/analysis)
- `packetlist.js` — Virtual-scrolled packet table with right-click context menu
- `packetdetail.js` — Protocol tree with "Follow Stream" button
- `filters.js` — Display filter compiler. Supports: protocol keywords, ip/port filters, direction filters, flow==N, stream==N, tls.sni==hostname, boolean logic (&&, ||, !)
- `flows.js` — Flow table UI, receives flow_update WS messages
- `streams.js` — TCP stream viewer overlay (ASCII/Hex/Raw views)
- `view3d.js` — Three.js 3D network graph. Detects WebGL availability before init.
- `security.js` — Security dashboard with 11 threat detectors
- `packetmodal.js` — Deep packet analysis page

### CSS Themes
`style.css` has three themes via `[data-theme]` attribute: dark, dim, light. CSS variables defined at top.

## Key Patterns
- All JS modules use the IIFE module pattern: `const ModuleName = (() => { ... return { init, ... }; })();`
- Modules init'd in app.js `init()` function, called on DOMContentLoaded
- WebSocket messages are `{type, payload}` JSON envelopes
- Packets broadcast as `{type: "packet", payload: PacketInfo}`
- Flow updates broadcast as `{type: "flow_update", payload: []FlowInfo}` every 1s
- gopacket ApplicationLayer uses `LayerContents()` not `Contents()` — this was a past bug

## Known Constraints
- WebGL not available in all environments — view3d.js has fallback message
- pcap requires root/sudo for live capture
- No hot reload — must rebuild binary for Go/static file changes (`go build -o sniffox .`)
- Three.js loaded from CDN (cdnjs + unpkg) — requires internet on first load

## Don't
- Don't add emojis to code files unless asked
- Don't push the compiled binary to git (it's in .gitignore)
- Don't use `appLayer.Contents()` — use `appLayer.LayerContents()` (gopacket interface)
