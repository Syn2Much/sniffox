// topology.js — 2D force-directed host-to-host communication graph
'use strict';

const Topology = (() => {
    let canvas = null;
    let ctx = null;
    let animFrameId = null;
    let running = false;

    // Graph data
    const nodes = new Map();   // ip -> node object
    const edges = new Map();   // "ip1|ip2" -> edge object

    const MAX_NODES = 100;
    const MAX_EDGES = 500;

    // Protocol colors
    const PROTO_COLORS = {
        tcp:     '#7aa2f7',
        udp:     '#5cb4d6',
        dns:     '#73daca',
        http:    '#9ece6a',
        arp:     '#ff9e64',
        icmp:    '#e0af68',
        tls:     '#f5a0d0',
        ssh:     '#cba6f7',
        quic:    '#f38ba8',
    };
    const DEFAULT_COLOR = '#c0caf5';

    // Force simulation constants
    const REPULSION = 5000;
    const SPRING_LENGTH = 120;
    const SPRING_STRENGTH = 0.01;
    const GRAVITY = 0.02;
    const DAMPING = 0.85;
    const TIME_STEP = 1;

    // Camera / viewport
    let viewX = 0;
    let viewY = 0;
    let zoom = 1;

    // Interaction state
    let draggedNode = null;
    let isDraggingCanvas = false;
    let dragStartX = 0;
    let dragStartY = 0;
    let viewStartX = 0;
    let viewStartY = 0;
    let mouseX = 0;
    let mouseY = 0;
    let hoveredNode = null;
    let hoveredEdge = null;

    // Tooltip element
    let tooltip = null;

    // ───────────────────────────────────────────────
    // Helpers
    // ───────────────────────────────────────────────

    function stripPort(addr) {
        if (!addr || typeof addr !== 'string') return addr;
        // IPv6 with port: [::1]:80 -> ::1
        if (addr.startsWith('[')) {
            const bracketEnd = addr.indexOf(']');
            if (bracketEnd !== -1) {
                return addr.substring(1, bracketEnd);
            }
        }
        // IPv4 with port: 192.168.1.1:443 -> 192.168.1.1
        // Only strip if there is exactly one colon (avoid stripping IPv6)
        const colonCount = (addr.match(/:/g) || []).length;
        if (colonCount === 1) {
            return addr.substring(0, addr.indexOf(':'));
        }
        return addr;
    }

    function edgeKey(a, b) {
        return a < b ? a + '|' + b : b + '|' + a;
    }

    function protocolColor(proto) {
        if (!proto) return DEFAULT_COLOR;
        return PROTO_COLORS[proto.toLowerCase()] || DEFAULT_COLOR;
    }

    function dominantProtocol(protoCounts) {
        let best = null;
        let bestCount = 0;
        for (const p in protoCounts) {
            if (protoCounts[p] > bestCount) {
                bestCount = protoCounts[p];
                best = p;
            }
        }
        return best;
    }

    function nodeRadius(pktCount) {
        // Logarithmic scaling: base radius 6, grows with log
        return 6 + Math.log2(1 + pktCount) * 2.5;
    }

    function formatBytes(b) {
        if (b < 1024) return b + ' B';
        if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
        if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB';
        return (b / 1073741824).toFixed(2) + ' GB';
    }

    // Convert screen coordinates to world coordinates
    function screenToWorld(sx, sy) {
        const rect = canvas.getBoundingClientRect();
        const cx = rect.width / 2;
        const cy = rect.height / 2;
        return {
            x: (sx - cx) / zoom + viewX,
            y: (sy - cy) / zoom + viewY,
        };
    }

    // Convert world coordinates to screen coordinates
    function worldToScreen(wx, wy) {
        const rect = canvas.getBoundingClientRect();
        const cx = rect.width / 2;
        const cy = rect.height / 2;
        return {
            x: (wx - viewX) * zoom + cx,
            y: (wy - viewY) * zoom + cy,
        };
    }

    // ───────────────────────────────────────────────
    // Node / Edge management
    // ───────────────────────────────────────────────

    function getOrCreateNode(ip) {
        if (nodes.has(ip)) return nodes.get(ip);
        if (nodes.size >= MAX_NODES) return null;

        const angle = Math.random() * Math.PI * 2;
        const dist = 50 + Math.random() * 100;
        const node = {
            ip: ip,
            x: viewX + Math.cos(angle) * dist,
            y: viewY + Math.sin(angle) * dist,
            vx: 0,
            vy: 0,
            packets: 0,
            bytes: 0,
            protocols: {},   // proto -> count
            connectedHosts: new Set(),
            pinned: false,
        };
        nodes.set(ip, node);
        return node;
    }

    function getOrCreateEdge(srcIP, dstIP) {
        const key = edgeKey(srcIP, dstIP);
        if (edges.has(key)) return edges.get(key);
        if (edges.size >= MAX_EDGES) return null;

        const edge = {
            key: key,
            src: srcIP,
            dst: dstIP,
            packets: 0,
            bytes: 0,
            protocols: {},   // proto -> count
        };
        edges.set(key, edge);
        return edge;
    }

    // ───────────────────────────────────────────────
    // Public: addPacket
    // ───────────────────────────────────────────────

    function addPacket(pkt) {
        if (!pkt || !pkt.srcAddr || !pkt.dstAddr) return;

        const srcIP = stripPort(pkt.srcAddr);
        const dstIP = stripPort(pkt.dstAddr);
        const proto = (pkt.protocol || 'unknown').toLowerCase();
        const len = pkt.length || 0;

        const srcNode = getOrCreateNode(srcIP);
        const dstNode = getOrCreateNode(dstIP);
        if (!srcNode || !dstNode) return;

        // Update source node
        srcNode.packets++;
        srcNode.bytes += len;
        srcNode.protocols[proto] = (srcNode.protocols[proto] || 0) + 1;
        srcNode.connectedHosts.add(dstIP);

        // Update destination node
        dstNode.packets++;
        dstNode.bytes += len;
        dstNode.protocols[proto] = (dstNode.protocols[proto] || 0) + 1;
        dstNode.connectedHosts.add(srcIP);

        // Update edge
        const edge = getOrCreateEdge(srcIP, dstIP);
        if (!edge) return;
        edge.packets++;
        edge.bytes += len;
        edge.protocols[proto] = (edge.protocols[proto] || 0) + 1;
    }

    // ───────────────────────────────────────────────
    // Force simulation
    // ───────────────────────────────────────────────

    function simulate() {
        const nodeList = Array.from(nodes.values());
        const n = nodeList.length;
        if (n === 0) return;

        const centerX = viewX;
        const centerY = viewY;

        // Repulsion between all node pairs (Coulomb)
        for (let i = 0; i < n; i++) {
            for (let j = i + 1; j < n; j++) {
                const a = nodeList[i];
                const b = nodeList[j];
                let dx = a.x - b.x;
                let dy = a.y - b.y;
                let distSq = dx * dx + dy * dy;
                if (distSq < 1) distSq = 1;
                const dist = Math.sqrt(distSq);
                const force = REPULSION / distSq;
                const fx = (dx / dist) * force;
                const fy = (dy / dist) * force;

                if (!a.pinned) { a.vx += fx * TIME_STEP; a.vy += fy * TIME_STEP; }
                if (!b.pinned) { b.vx -= fx * TIME_STEP; b.vy -= fy * TIME_STEP; }
            }
        }

        // Attraction along edges (Hooke)
        for (const edge of edges.values()) {
            const a = nodes.get(edge.src);
            const b = nodes.get(edge.dst);
            if (!a || !b) continue;

            let dx = b.x - a.x;
            let dy = b.y - a.y;
            const dist = Math.sqrt(dx * dx + dy * dy);
            if (dist < 0.1) continue;

            const displacement = dist - SPRING_LENGTH;
            const force = SPRING_STRENGTH * displacement;
            const fx = (dx / dist) * force;
            const fy = (dy / dist) * force;

            if (!a.pinned) { a.vx += fx * TIME_STEP; a.vy += fy * TIME_STEP; }
            if (!b.pinned) { b.vx -= fx * TIME_STEP; b.vy -= fy * TIME_STEP; }
        }

        // Gravity toward center + damping + position update
        for (const node of nodeList) {
            if (node.pinned) {
                node.vx = 0;
                node.vy = 0;
                continue;
            }

            // Gravity pull toward center
            node.vx += (centerX - node.x) * GRAVITY * TIME_STEP;
            node.vy += (centerY - node.y) * GRAVITY * TIME_STEP;

            // Damping
            node.vx *= DAMPING;
            node.vy *= DAMPING;

            // Update position
            node.x += node.vx * TIME_STEP;
            node.y += node.vy * TIME_STEP;
        }
    }

    // ───────────────────────────────────────────────
    // Rendering
    // ───────────────────────────────────────────────

    function render() {
        if (!ctx || !canvas) return;

        const dpr = window.devicePixelRatio || 1;
        const w = canvas.width;
        const h = canvas.height;

        ctx.clearRect(0, 0, w, h);
        ctx.save();

        // Apply viewport transform (use CSS pixel center, not physical pixel center)
        const cx = w / dpr / 2;
        const cy = h / dpr / 2;
        ctx.translate(cx, cy);
        ctx.scale(zoom, zoom);
        ctx.translate(-viewX, -viewY);

        // Draw edges
        for (const edge of edges.values()) {
            const a = nodes.get(edge.src);
            const b = nodes.get(edge.dst);
            if (!a || !b) continue;

            const isHovered = hoveredEdge && hoveredEdge.key === edge.key;
            const thickness = Math.min(1 + Math.log2(1 + edge.packets) * 1.2, 10);
            const dp = dominantProtocol(edge.protocols);
            const color = protocolColor(dp);

            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.strokeStyle = color;
            ctx.globalAlpha = isHovered ? 1.0 : 0.45;
            ctx.lineWidth = isHovered ? thickness + 2 : thickness;
            ctx.stroke();
            ctx.globalAlpha = 1.0;
        }

        // Draw nodes
        for (const node of nodes.values()) {
            const dp = dominantProtocol(node.protocols);
            const color = protocolColor(dp);
            const r = nodeRadius(node.packets);
            const isHovered = hoveredNode && hoveredNode.ip === node.ip;
            const isDragged = draggedNode && draggedNode.ip === node.ip;

            // Glow for hovered/dragged
            if (isHovered || isDragged) {
                ctx.beginPath();
                ctx.arc(node.x, node.y, r + 5, 0, Math.PI * 2);
                ctx.fillStyle = color;
                ctx.globalAlpha = 0.25;
                ctx.fill();
                ctx.globalAlpha = 1.0;
            }

            // Node circle
            ctx.beginPath();
            ctx.arc(node.x, node.y, r, 0, Math.PI * 2);
            ctx.fillStyle = color;
            ctx.fill();

            // Border
            ctx.strokeStyle = isHovered ? '#ffffff' : 'rgba(0,0,0,0.4)';
            ctx.lineWidth = isHovered ? 2 : 1;
            ctx.stroke();

            // Label
            const fontSize = Math.max(9, Math.min(12, 10 / zoom));
            ctx.font = fontSize + 'px monospace';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'top';
            ctx.fillStyle = '#a9b1d6';
            ctx.fillText(node.ip, node.x, node.y + r + 4);
        }

        ctx.restore();

        // Draw tooltip outside of world transform
        drawTooltip();
    }

    function drawTooltip() {
        if (!tooltip) return;

        if (hoveredNode) {
            const node = hoveredNode;
            const screen = worldToScreen(node.x, node.y);
            const r = nodeRadius(node.packets) * zoom;

            // Build protocol summary (top 3)
            const protos = Object.entries(node.protocols)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 3)
                .map(e => e[0].toUpperCase() + ': ' + e[1])
                .join(', ');

            tooltip.style.display = 'block';
            tooltip.innerHTML =
                '<strong>' + escHtml(node.ip) + '</strong><br>' +
                'Packets: ' + node.packets + '<br>' +
                'Protocols: ' + escHtml(protos) + '<br>' +
                'Connected hosts: ' + node.connectedHosts.size;

            positionTooltip(screen.x + r + 10, screen.y - 10);
        } else if (hoveredEdge) {
            const edge = hoveredEdge;
            const a = nodes.get(edge.src);
            const b = nodes.get(edge.dst);
            if (!a || !b) { tooltip.style.display = 'none'; return; }

            const midScreen = worldToScreen((a.x + b.x) / 2, (a.y + b.y) / 2);

            const protos = Object.entries(edge.protocols)
                .sort((a, b) => b[1] - a[1])
                .map(e => e[0].toUpperCase() + ': ' + e[1])
                .join(', ');

            tooltip.style.display = 'block';
            tooltip.innerHTML =
                '<strong>' + escHtml(edge.src) + ' &harr; ' + escHtml(edge.dst) + '</strong><br>' +
                'Packets: ' + edge.packets + '<br>' +
                'Bytes: ' + formatBytes(edge.bytes) + '<br>' +
                'Protocols: ' + escHtml(protos);

            positionTooltip(midScreen.x + 10, midScreen.y - 10);
        } else {
            tooltip.style.display = 'none';
        }
    }

    function positionTooltip(x, y) {
        if (!tooltip || !canvas) return;
        const rect = canvas.getBoundingClientRect();
        const tw = tooltip.offsetWidth || 200;
        const th = tooltip.offsetHeight || 80;

        // Keep tooltip within canvas bounds
        if (x + tw > rect.width) x = x - tw - 20;
        if (y + th > rect.height) y = y - th - 20;
        if (x < 0) x = 10;
        if (y < 0) y = 10;

        tooltip.style.left = x + 'px';
        tooltip.style.top = y + 'px';
    }

    function escHtml(str) {
        if (!str) return '';
        return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    // ───────────────────────────────────────────────
    // Animation loop
    // ───────────────────────────────────────────────

    function tick() {
        if (!running) return;
        simulate();
        render();
        animFrameId = requestAnimationFrame(tick);
    }

    function startAnimation() {
        if (running) return;
        running = true;
        animFrameId = requestAnimationFrame(tick);
    }

    function stopAnimation() {
        running = false;
        if (animFrameId != null) {
            cancelAnimationFrame(animFrameId);
            animFrameId = null;
        }
    }

    // ───────────────────────────────────────────────
    // Hit testing
    // ───────────────────────────────────────────────

    function nodeAtScreen(sx, sy) {
        const world = screenToWorld(sx, sy);
        let closest = null;
        let closestDist = Infinity;

        for (const node of nodes.values()) {
            const dx = world.x - node.x;
            const dy = world.y - node.y;
            const dist = Math.sqrt(dx * dx + dy * dy);
            const r = nodeRadius(node.packets);
            if (dist <= r && dist < closestDist) {
                closestDist = dist;
                closest = node;
            }
        }
        return closest;
    }

    function edgeAtScreen(sx, sy) {
        const world = screenToWorld(sx, sy);
        let closest = null;
        let closestDist = Infinity;
        const threshold = 6 / zoom; // pixel tolerance in world space

        for (const edge of edges.values()) {
            const a = nodes.get(edge.src);
            const b = nodes.get(edge.dst);
            if (!a || !b) continue;

            // Point-to-segment distance
            const dx = b.x - a.x;
            const dy = b.y - a.y;
            const lenSq = dx * dx + dy * dy;
            if (lenSq < 0.01) continue;

            let t = ((world.x - a.x) * dx + (world.y - a.y) * dy) / lenSq;
            t = Math.max(0, Math.min(1, t));

            const px = a.x + t * dx;
            const py = a.y + t * dy;
            const dist = Math.sqrt((world.x - px) * (world.x - px) + (world.y - py) * (world.y - py));

            if (dist <= threshold && dist < closestDist) {
                closestDist = dist;
                closest = edge;
            }
        }
        return closest;
    }

    // ───────────────────────────────────────────────
    // Event handlers
    // ───────────────────────────────────────────────

    function onMouseDown(e) {
        const rect = canvas.getBoundingClientRect();
        const sx = e.clientX - rect.left;
        const sy = e.clientY - rect.top;

        const node = nodeAtScreen(sx, sy);
        if (node) {
            draggedNode = node;
            draggedNode.pinned = true;
            canvas.style.cursor = 'grabbing';
        } else {
            isDraggingCanvas = true;
            dragStartX = e.clientX;
            dragStartY = e.clientY;
            viewStartX = viewX;
            viewStartY = viewY;
            canvas.style.cursor = 'move';
        }
    }

    function onMouseMove(e) {
        const rect = canvas.getBoundingClientRect();
        mouseX = e.clientX - rect.left;
        mouseY = e.clientY - rect.top;

        if (draggedNode) {
            const world = screenToWorld(mouseX, mouseY);
            draggedNode.x = world.x;
            draggedNode.y = world.y;
            draggedNode.vx = 0;
            draggedNode.vy = 0;
            return;
        }

        if (isDraggingCanvas) {
            const dx = (e.clientX - dragStartX) / zoom;
            const dy = (e.clientY - dragStartY) / zoom;
            viewX = viewStartX - dx;
            viewY = viewStartY - dy;
            return;
        }

        // Hover detection
        const node = nodeAtScreen(mouseX, mouseY);
        if (node) {
            hoveredNode = node;
            hoveredEdge = null;
            canvas.style.cursor = 'pointer';
        } else {
            hoveredNode = null;
            const edge = edgeAtScreen(mouseX, mouseY);
            hoveredEdge = edge;
            canvas.style.cursor = edge ? 'pointer' : 'default';
        }
    }

    function onMouseUp() {
        if (draggedNode) {
            draggedNode.pinned = false;
            draggedNode = null;
        }
        isDraggingCanvas = false;
        canvas.style.cursor = 'default';
    }

    function onWheel(e) {
        e.preventDefault();
        const delta = e.deltaY > 0 ? 0.9 : 1.1;
        const newZoom = Math.max(0.1, Math.min(5, zoom * delta));

        // Zoom toward mouse position
        const rect = canvas.getBoundingClientRect();
        const mx = e.clientX - rect.left;
        const my = e.clientY - rect.top;
        const worldBefore = screenToWorld(mx, my);

        zoom = newZoom;

        const worldAfter = screenToWorld(mx, my);
        viewX += worldBefore.x - worldAfter.x;
        viewY += worldBefore.y - worldAfter.y;
    }

    function onMouseLeave() {
        hoveredNode = null;
        hoveredEdge = null;
        if (tooltip) tooltip.style.display = 'none';
        if (!draggedNode) {
            isDraggingCanvas = false;
            canvas.style.cursor = 'default';
        }
    }

    // ───────────────────────────────────────────────
    // Canvas sizing
    // ───────────────────────────────────────────────

    function resizeCanvas() {
        if (!canvas) return;
        const parent = canvas.parentElement;
        if (!parent) return;
        const dpr = window.devicePixelRatio || 1;
        const w = parent.clientWidth;
        const h = parent.clientHeight;
        canvas.width = w * dpr;
        canvas.height = h * dpr;
        canvas.style.width = w + 'px';
        canvas.style.height = h + 'px';
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }

    // ───────────────────────────────────────────────
    // Tooltip element creation
    // ───────────────────────────────────────────────

    function createTooltip() {
        tooltip = document.createElement('div');
        tooltip.style.cssText =
            'position:absolute;display:none;pointer-events:none;' +
            'background:rgba(26,27,38,0.92);color:#c0caf5;' +
            'border:1px solid #3b3d57;border-radius:6px;' +
            'padding:8px 12px;font-size:12px;line-height:1.5;' +
            'font-family:monospace;z-index:100;max-width:320px;' +
            'white-space:nowrap;box-shadow:0 4px 12px rgba(0,0,0,0.4);';

        const wrapper = canvas.parentElement || canvas;
        if (wrapper !== canvas) {
            wrapper.style.position = wrapper.style.position || 'relative';
        }
        wrapper.appendChild(tooltip);
    }

    // ───────────────────────────────────────────────
    // Public API
    // ───────────────────────────────────────────────

    function init() {
        canvas = document.getElementById('topology-canvas');
        if (!canvas) return;
        ctx = canvas.getContext('2d');

        resizeCanvas();
        createTooltip();

        // Event listeners
        canvas.addEventListener('mousedown', onMouseDown);
        canvas.addEventListener('mousemove', onMouseMove);
        canvas.addEventListener('mouseup', onMouseUp);
        canvas.addEventListener('mouseleave', onMouseLeave);
        canvas.addEventListener('wheel', onWheel, { passive: false });
        window.addEventListener('resize', resizeCanvas);

        startAnimation();
    }

    function clear() {
        nodes.clear();
        edges.clear();
        hoveredNode = null;
        hoveredEdge = null;
        draggedNode = null;
        isDraggingCanvas = false;
        viewX = 0;
        viewY = 0;
        zoom = 1;
        if (tooltip) tooltip.style.display = 'none';
    }

    function onPageVisible() {
        resizeCanvas();
        if (!running) {
            startAnimation();
        }
    }

    function onPageHidden() {
        stopAnimation();
    }

    return { init, addPacket, clear, onPageVisible, onPageHidden };
})();
