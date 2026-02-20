// timeline.js — Interactive timeline visualization for network packet events
'use strict';

const Timeline = (() => {
    // --- Protocol color map ---
    const PROTO_COLORS = {
        tcp:     '#7aa2f7',
        udp:     '#5cb4d6',
        dns:     '#73daca',
        http:    '#9ece6a',
        arp:     '#ff9e64',
        icmp:    '#e0af68',
        tls:     '#f5a0d0',
        dhcp:    '#94e2d5',
        ntp:     '#f9e2af',
        igmp:    '#a6e3a1',
        gre:     '#fab387',
        sctp:    '#89b4fa',
        ssh:     '#cba6f7',
        quic:    '#f38ba8',
        mqtt:    '#94e2d5',
        sip:     '#f9e2af',
        modbus:  '#b4befe',
        rdp:     '#eba0ac',
    };
    const DEFAULT_COLOR = '#c0caf5';

    // --- State ---
    let canvas = null;
    let ctx = null;
    let filterContainer = null;

    // All packets stored as lightweight records
    let packets = [];
    let firstTime = null;     // epoch seconds of the very first packet
    let lastTime = 0;         // relative seconds of the latest packet

    // Protocol visibility (all visible by default)
    const protoVisible = {};  // protocol -> bool
    // Track which protocols we have seen (in order of appearance)
    const protoOrder = [];

    // --- Viewport / Zoom / Pan ---
    let viewStart = 0;        // left edge in relative seconds
    let viewEnd = 10;         // right edge in relative seconds
    let userPanned = false;   // true once user drags; disables auto-scroll

    // Interaction
    let isDragging = false;
    let dragStartX = 0;
    let dragStartViewStart = 0;
    let dragStartViewEnd = 0;

    // Hover / tooltip
    let hoveredPacket = null;
    let mouseX = -1;
    let mouseY = -1;
    let tooltipEl = null;

    // Mini-map
    const MINIMAP_HEIGHT = 28;

    // Canvas layout constants
    const HEADER_HEIGHT = MINIMAP_HEIGHT + 4; // mini-map + gap
    const AXIS_HEIGHT = 24;                   // bottom time axis
    const EVENT_RADIUS = 3;
    const ROW_HEIGHT = 10;
    const PADDING_LEFT = 0;
    const PADDING_RIGHT = 0;

    // Rendering
    let rafId = null;
    let needsRedraw = true;

    // Batch rendering: we keep a pre-filtered snapshot that is rebuilt
    // only when filter state or packet set changes.
    let filteredPackets = [];
    let filteredDirty = true;

    // --- Computed dimensions ---
    let canvasW = 0;
    let canvasH = 0;
    let plotLeft = 0;
    let plotRight = 0;
    let plotTop = 0;
    let plotBottom = 0;
    let plotW = 0;
    let plotH = 0;

    // =====================================================================
    //  Init
    // =====================================================================
    function init() {
        canvas = document.getElementById('timeline-canvas');
        filterContainer = document.getElementById('timeline-filters');
        if (!canvas) return;

        ctx = canvas.getContext('2d');

        // Create tooltip element
        tooltipEl = document.createElement('div');
        tooltipEl.className = 'tl-tooltip';
        tooltipEl.style.cssText = 'position:fixed;display:none;pointer-events:none;z-index:5000;' +
            'background:var(--bg-surface);border:1px solid var(--border);border-radius:6px;' +
            'padding:6px 10px;font-size:11px;color:var(--text-main);font-family:inherit;' +
            'box-shadow:0 4px 16px rgba(0,0,0,0.25);max-width:340px;line-height:1.5;';
        document.body.appendChild(tooltipEl);

        // Event listeners
        canvas.addEventListener('wheel', onWheel, { passive: false });
        canvas.addEventListener('mousedown', onMouseDown);
        canvas.addEventListener('mousemove', onMouseMove);
        canvas.addEventListener('mouseleave', onMouseLeave);
        window.addEventListener('mouseup', onMouseUp);
        window.addEventListener('resize', onResize);

        computeLayout();
        startRenderLoop();
    }

    // =====================================================================
    //  Layout
    // =====================================================================
    function computeLayout() {
        if (!canvas) return;
        const parent = canvas.parentElement;
        if (!parent) return;
        const rect = parent.getBoundingClientRect();
        const dpr = window.devicePixelRatio || 1;

        canvasW = Math.max(100, Math.floor(rect.width));
        canvasH = Math.max(80, Math.floor(rect.height));

        canvas.width = canvasW * dpr;
        canvas.height = canvasH * dpr;
        canvas.style.width = canvasW + 'px';
        canvas.style.height = canvasH + 'px';
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

        plotLeft = PADDING_LEFT + 2;
        plotRight = canvasW - PADDING_RIGHT - 2;
        plotTop = HEADER_HEIGHT;
        plotBottom = canvasH - AXIS_HEIGHT;
        plotW = plotRight - plotLeft;
        plotH = plotBottom - plotTop;

        needsRedraw = true;
    }

    // =====================================================================
    //  addPacket
    // =====================================================================
    function addPacket(pkt) {
        if (!pkt) return;
        const proto = (pkt.protocol || 'unknown').toLowerCase();
        const absTime = parseFloat(pkt.time) || 0;

        if (firstTime === null) {
            firstTime = absTime;
        }
        const relTime = absTime - firstTime;
        if (relTime > lastTime) lastTime = relTime;

        const rec = {
            number: pkt.number,
            time: relTime,
            srcAddr: pkt.srcAddr || '',
            dstAddr: pkt.dstAddr || '',
            protocol: proto,
            info: pkt.info || '',
            length: pkt.length || 0,
            color: PROTO_COLORS[proto] || DEFAULT_COLOR,
        };
        packets.push(rec);
        filteredDirty = true;

        // Track protocol for filter chips
        if (!(proto in protoVisible)) {
            protoVisible[proto] = true;
            protoOrder.push(proto);
            rebuildFilterChips();
        }

        // Auto-scroll: keep latest packet visible unless user has panned
        if (!userPanned) {
            autoScrollToLatest();
        }

        needsRedraw = true;
    }

    function autoScrollToLatest() {
        const span = viewEnd - viewStart;
        if (lastTime > viewEnd - span * 0.05) {
            viewEnd = lastTime + span * 0.1;
            viewStart = viewEnd - span;
            if (viewStart < 0) viewStart = 0;
        }
    }

    // =====================================================================
    //  clear
    // =====================================================================
    function clear() {
        packets = [];
        filteredPackets = [];
        filteredDirty = true;
        firstTime = null;
        lastTime = 0;
        viewStart = 0;
        viewEnd = 10;
        userPanned = false;
        hoveredPacket = null;
        hideTooltip();

        // Reset protocol tracking
        Object.keys(protoVisible).forEach(k => delete protoVisible[k]);
        protoOrder.length = 0;
        rebuildFilterChips();

        needsRedraw = true;
    }

    // =====================================================================
    //  onPageVisible
    // =====================================================================
    function onPageVisible() {
        computeLayout();
        needsRedraw = true;
    }

    // =====================================================================
    //  Filter chips
    // =====================================================================
    function rebuildFilterChips() {
        if (!filterContainer) return;
        filterContainer.innerHTML = '';

        for (const proto of protoOrder) {
            const chip = document.createElement('span');
            chip.className = 'tl-filter-chip' + (protoVisible[proto] ? ' tl-chip-active' : '');
            chip.dataset.proto = proto;
            chip.style.cssText = 'display:inline-flex;align-items:center;gap:4px;padding:2px 8px;' +
                'border-radius:10px;font-size:10px;font-weight:600;cursor:pointer;user-select:none;' +
                'margin:2px 3px;transition:opacity 0.15s,background 0.15s;' +
                'border:1px solid ' + (PROTO_COLORS[proto] || DEFAULT_COLOR) + ';' +
                'font-family:inherit;letter-spacing:0.3px;text-transform:uppercase;';
            updateChipStyle(chip, proto);

            const dot = document.createElement('span');
            dot.style.cssText = 'width:6px;height:6px;border-radius:50%;display:inline-block;' +
                'background:' + (PROTO_COLORS[proto] || DEFAULT_COLOR) + ';';
            chip.appendChild(dot);

            const label = document.createTextNode(proto);
            chip.appendChild(label);

            chip.addEventListener('click', () => {
                protoVisible[proto] = !protoVisible[proto];
                updateChipStyle(chip, proto);
                chip.classList.toggle('tl-chip-active', protoVisible[proto]);
                filteredDirty = true;
                needsRedraw = true;
            });

            filterContainer.appendChild(chip);
        }
    }

    function updateChipStyle(chip, proto) {
        const color = PROTO_COLORS[proto] || DEFAULT_COLOR;
        if (protoVisible[proto]) {
            chip.style.background = hexToRgba(color, 0.18);
            chip.style.color = color;
            chip.style.opacity = '1';
        } else {
            chip.style.background = 'transparent';
            chip.style.color = 'var(--text-dim)';
            chip.style.opacity = '0.45';
        }
    }

    // =====================================================================
    //  Filtered packets cache
    // =====================================================================
    function rebuildFiltered() {
        filteredPackets = [];
        for (let i = 0, len = packets.length; i < len; i++) {
            const p = packets[i];
            if (protoVisible[p.protocol] !== false) {
                filteredPackets.push(p);
            }
        }
        filteredDirty = false;
    }

    // =====================================================================
    //  Rendering
    // =====================================================================
    function startRenderLoop() {
        function tick() {
            rafId = requestAnimationFrame(tick);
            if (needsRedraw) {
                needsRedraw = false;
                draw();
            }
        }
        rafId = requestAnimationFrame(tick);
    }

    function draw() {
        if (!ctx || canvasW <= 0 || canvasH <= 0) return;
        if (filteredDirty) rebuildFiltered();

        // Clear
        ctx.clearRect(0, 0, canvasW, canvasH);

        // Background
        ctx.fillStyle = getComputedStyle(canvas).getPropertyValue('--canvas-bg') || '#000';
        ctx.fillRect(0, 0, canvasW, canvasH);

        drawMinimap();
        drawEvents();
        drawTimeAxis();
        drawHoverHighlight();
    }

    // --- Mini-map ---
    function drawMinimap() {
        const mmTop = 0;
        const mmH = MINIMAP_HEIGHT;
        const mmLeft = plotLeft;
        const mmRight = plotRight;
        const mmW = mmRight - mmLeft;

        // Background
        ctx.fillStyle = 'rgba(255,255,255,0.03)';
        ctx.fillRect(mmLeft, mmTop, mmW, mmH);

        // Border bottom
        ctx.strokeStyle = 'rgba(255,255,255,0.06)';
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(mmLeft, mmTop + mmH);
        ctx.lineTo(mmRight, mmTop + mmH);
        ctx.stroke();

        if (filteredPackets.length === 0 || lastTime <= 0) return;

        // Draw density bars in the mini-map using buckets
        const bucketCount = Math.min(Math.floor(mmW / 2), 200);
        if (bucketCount <= 0) return;
        const buckets = new Uint32Array(bucketCount);
        const fullSpan = lastTime || 1;

        for (let i = 0, len = filteredPackets.length; i < len; i++) {
            const t = filteredPackets[i].time;
            let bi = Math.floor((t / fullSpan) * bucketCount);
            if (bi >= bucketCount) bi = bucketCount - 1;
            if (bi < 0) bi = 0;
            buckets[bi]++;
        }

        let maxBucket = 0;
        for (let i = 0; i < bucketCount; i++) {
            if (buckets[i] > maxBucket) maxBucket = buckets[i];
        }
        if (maxBucket === 0) maxBucket = 1;

        const barW = mmW / bucketCount;
        ctx.fillStyle = 'rgba(122,162,247,0.35)';
        for (let i = 0; i < bucketCount; i++) {
            if (buckets[i] === 0) continue;
            const h = (buckets[i] / maxBucket) * (mmH - 4);
            const x = mmLeft + i * barW;
            ctx.fillRect(x, mmTop + mmH - 2 - h, Math.max(1, barW - 0.5), h);
        }

        // Viewport indicator
        const vxStart = mmLeft + (viewStart / fullSpan) * mmW;
        const vxEnd = mmLeft + (viewEnd / fullSpan) * mmW;
        const vw = Math.max(4, vxEnd - vxStart);

        ctx.fillStyle = 'rgba(122,162,247,0.12)';
        ctx.fillRect(vxStart, mmTop, vw, mmH);

        ctx.strokeStyle = 'rgba(122,162,247,0.5)';
        ctx.lineWidth = 1;
        ctx.strokeRect(vxStart + 0.5, mmTop + 0.5, vw - 1, mmH - 1);
    }

    // --- Events ---
    function drawEvents() {
        if (filteredPackets.length === 0 || plotW <= 0 || plotH <= 0) return;

        const span = viewEnd - viewStart;
        if (span <= 0) return;

        // We assign a Y lane per-protocol (stacked rows)
        // Build a mapping of visible protocols to Y lane
        const laneMap = {};
        let laneCount = 0;
        for (let i = 0; i < protoOrder.length; i++) {
            const p = protoOrder[i];
            if (protoVisible[p] !== false) {
                laneMap[p] = laneCount++;
            }
        }
        if (laneCount === 0) return;

        // Compute row height dynamically so lanes fill available plot height
        const dynRowH = Math.max(ROW_HEIGHT, Math.min(28, plotH / laneCount));
        const totalLaneH = laneCount * dynRowH;
        const yOffset = plotTop + Math.max(0, (plotH - totalLaneH) / 2);

        // Draw faint lane separators and protocol labels
        ctx.font = '9px monospace';
        ctx.textAlign = 'right';
        ctx.textBaseline = 'middle';
        for (const proto in laneMap) {
            const lane = laneMap[proto];
            const ly = yOffset + lane * dynRowH + dynRowH / 2;

            // Lane background stripe (alternating)
            if (lane % 2 === 0) {
                ctx.fillStyle = 'rgba(255,255,255,0.015)';
                ctx.fillRect(plotLeft, yOffset + lane * dynRowH, plotW, dynRowH);
            }

            // Protocol label on the left
            ctx.fillStyle = 'rgba(255,255,255,0.2)';
            ctx.fillText(proto.toUpperCase(), plotLeft + 38, ly);
        }

        // Batch render events by color for fewer state changes
        // First pass: group packets by color
        const colorGroups = {};
        const pxScale = plotW / span;

        // Only render packets within the visible time range (with small margin)
        const tMin = viewStart;
        const tMax = viewEnd;

        for (let i = 0, len = filteredPackets.length; i < len; i++) {
            const p = filteredPackets[i];
            if (p.time < tMin || p.time > tMax) continue;
            const lane = laneMap[p.protocol];
            if (lane === undefined) continue;

            const x = plotLeft + 40 + (p.time - viewStart) * pxScale * ((plotW - 40) / plotW);
            const y = yOffset + lane * dynRowH + dynRowH / 2;

            if (!colorGroups[p.color]) colorGroups[p.color] = [];
            colorGroups[p.color].push(x, y, i);
        }

        // Second pass: draw circles grouped by color
        const r = EVENT_RADIUS;
        for (const color in colorGroups) {
            const arr = colorGroups[color];
            ctx.fillStyle = color;
            ctx.beginPath();
            for (let j = 0, jlen = arr.length; j < jlen; j += 3) {
                const cx = arr[j];
                const cy = arr[j + 1];
                ctx.moveTo(cx + r, cy);
                ctx.arc(cx, cy, r, 0, Math.PI * 2);
            }
            ctx.fill();
        }
    }

    // --- Time axis ---
    function drawTimeAxis() {
        const axisY = plotBottom + 2;

        // Axis line
        ctx.strokeStyle = 'rgba(255,255,255,0.15)';
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(plotLeft, plotBottom);
        ctx.lineTo(plotRight, plotBottom);
        ctx.stroke();

        const span = viewEnd - viewStart;
        if (span <= 0) return;

        // Tick calculation — aim for roughly 8-12 ticks
        const targetTicks = Math.max(4, Math.min(12, Math.floor(plotW / 80)));
        const rawStep = span / targetTicks;
        const step = niceStep(rawStep);

        const startTick = Math.ceil(viewStart / step) * step;

        ctx.font = '10px monospace';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';
        ctx.fillStyle = 'rgba(255,255,255,0.4)';

        for (let t = startTick; t <= viewEnd; t += step) {
            const x = plotLeft + ((t - viewStart) / span) * plotW;
            if (x < plotLeft || x > plotRight) continue;

            // Tick mark
            ctx.strokeStyle = 'rgba(255,255,255,0.1)';
            ctx.beginPath();
            ctx.moveTo(x, plotBottom);
            ctx.lineTo(x, plotBottom + 4);
            ctx.stroke();

            // Grid line (faint)
            ctx.strokeStyle = 'rgba(255,255,255,0.03)';
            ctx.beginPath();
            ctx.moveTo(x, plotTop);
            ctx.lineTo(x, plotBottom);
            ctx.stroke();

            // Label
            ctx.fillStyle = 'rgba(255,255,255,0.4)';
            ctx.fillText(formatTime(t), x, axisY + 4);
        }
    }

    // --- Hover highlight ---
    function drawHoverHighlight() {
        if (!hoveredPacket) return;

        const span = viewEnd - viewStart;
        if (span <= 0) return;

        const pxScale = plotW / span;

        // Rebuild lane map
        const laneMap = {};
        let laneCount = 0;
        for (let i = 0; i < protoOrder.length; i++) {
            const p = protoOrder[i];
            if (protoVisible[p] !== false) {
                laneMap[p] = laneCount++;
            }
        }
        if (laneCount === 0) return;

        const dynRowH = Math.max(ROW_HEIGHT, Math.min(28, plotH / laneCount));
        const totalLaneH = laneCount * dynRowH;
        const yOffset = plotTop + Math.max(0, (plotH - totalLaneH) / 2);

        const lane = laneMap[hoveredPacket.protocol];
        if (lane === undefined) return;

        const x = plotLeft + 40 + (hoveredPacket.time - viewStart) * pxScale * ((plotW - 40) / plotW);
        const y = yOffset + lane * dynRowH + dynRowH / 2;

        // Glow ring
        ctx.beginPath();
        ctx.arc(x, y, EVENT_RADIUS + 4, 0, Math.PI * 2);
        ctx.strokeStyle = hoveredPacket.color;
        ctx.lineWidth = 2;
        ctx.stroke();

        // Larger filled dot
        ctx.beginPath();
        ctx.arc(x, y, EVENT_RADIUS + 1, 0, Math.PI * 2);
        ctx.fillStyle = hoveredPacket.color;
        ctx.fill();
    }

    // =====================================================================
    //  Time formatting helpers
    // =====================================================================
    function formatTime(seconds) {
        if (seconds < 0) seconds = 0;
        if (seconds < 60) {
            return seconds.toFixed(2) + 's';
        }
        const m = Math.floor(seconds / 60);
        const s = (seconds % 60).toFixed(1);
        return m + ':' + (s < 10 ? '0' : '') + s;
    }

    function niceStep(raw) {
        const mag = Math.pow(10, Math.floor(Math.log10(raw)));
        const frac = raw / mag;
        if (frac <= 1.5) return mag;
        if (frac <= 3.5) return 2 * mag;
        if (frac <= 7.5) return 5 * mag;
        return 10 * mag;
    }

    // =====================================================================
    //  Interaction: Zoom (wheel)
    // =====================================================================
    function onWheel(e) {
        e.preventDefault();
        if (plotW <= 0) return;

        const rect = canvas.getBoundingClientRect();
        const mx = e.clientX - rect.left;

        // Where in the timeline does the cursor point?
        const frac = Math.max(0, Math.min(1, (mx - plotLeft) / plotW));
        const span = viewEnd - viewStart;
        const tAtCursor = viewStart + frac * span;

        // Zoom factor
        const zoomFactor = e.deltaY > 0 ? 1.15 : (1 / 1.15);
        let newSpan = span * zoomFactor;

        // Clamp minimum span to ~0.01s and max to full timeline extent * 1.2
        const minSpan = 0.01;
        const maxSpan = Math.max(10, (lastTime || 10) * 1.2);
        newSpan = Math.max(minSpan, Math.min(maxSpan, newSpan));

        // Adjust view so the point under the cursor stays in place
        viewStart = tAtCursor - frac * newSpan;
        viewEnd = viewStart + newSpan;

        // Prevent going below 0
        if (viewStart < 0) {
            viewStart = 0;
            viewEnd = newSpan;
        }

        userPanned = true;
        needsRedraw = true;
    }

    // =====================================================================
    //  Interaction: Pan (drag)
    // =====================================================================
    function onMouseDown(e) {
        if (e.button !== 0) return;
        const rect = canvas.getBoundingClientRect();
        const my = e.clientY - rect.top;

        // Only start drag in the plot or mini-map area
        if (my < 0 || my > canvasH) return;

        // If click is in the mini-map, jump the viewport
        if (my < MINIMAP_HEIGHT && lastTime > 0) {
            const mx = e.clientX - rect.left;
            const frac = Math.max(0, Math.min(1, (mx - plotLeft) / plotW));
            const span = viewEnd - viewStart;
            const targetCenter = frac * lastTime;
            viewStart = targetCenter - span / 2;
            viewEnd = viewStart + span;
            if (viewStart < 0) { viewStart = 0; viewEnd = span; }
            userPanned = true;
            needsRedraw = true;
            return;
        }

        isDragging = true;
        dragStartX = e.clientX;
        dragStartViewStart = viewStart;
        dragStartViewEnd = viewEnd;
        canvas.style.cursor = 'grabbing';
        e.preventDefault();
    }

    function onMouseMove(e) {
        const rect = canvas.getBoundingClientRect();
        mouseX = e.clientX - rect.left;
        mouseY = e.clientY - rect.top;

        if (isDragging) {
            const dx = e.clientX - dragStartX;
            const span = dragStartViewEnd - dragStartViewStart;
            const timeDelta = -(dx / plotW) * span;

            viewStart = dragStartViewStart + timeDelta;
            viewEnd = dragStartViewEnd + timeDelta;

            // Keep left bound at 0
            if (viewStart < 0) {
                viewEnd -= viewStart;
                viewStart = 0;
            }

            userPanned = true;
            needsRedraw = true;
        } else {
            // Hit test for hover
            updateHover();
        }
    }

    function onMouseUp() {
        if (isDragging) {
            isDragging = false;
            if (canvas) canvas.style.cursor = '';
        }
    }

    function onMouseLeave() {
        mouseX = -1;
        mouseY = -1;
        hoveredPacket = null;
        hideTooltip();
        needsRedraw = true;
    }

    // =====================================================================
    //  Hover / tooltip
    // =====================================================================
    function updateHover() {
        if (mouseX < 0 || mouseY < 0 || plotW <= 0) {
            if (hoveredPacket) {
                hoveredPacket = null;
                hideTooltip();
                needsRedraw = true;
            }
            return;
        }

        const span = viewEnd - viewStart;
        if (span <= 0) return;
        const pxScale = plotW / span;

        // Rebuild lane map
        const laneMap = {};
        let laneCount = 0;
        for (let i = 0; i < protoOrder.length; i++) {
            const p = protoOrder[i];
            if (protoVisible[p] !== false) {
                laneMap[p] = laneCount++;
            }
        }
        if (laneCount === 0) return;

        const dynRowH = Math.max(ROW_HEIGHT, Math.min(28, plotH / laneCount));
        const totalLaneH = laneCount * dynRowH;
        const yOffset = plotTop + Math.max(0, (plotH - totalLaneH) / 2);

        // Find closest event within hit radius
        let bestDist = 12; // max pixel distance
        let bestPkt = null;

        // Convert mouseX to time
        const adjustedPlotW = plotW - 40;
        const mouseTime = viewStart + ((mouseX - plotLeft - 40) / adjustedPlotW) * span;

        // Narrow search window in time
        const hitTimeDelta = (bestDist / adjustedPlotW) * span;
        const tMin = mouseTime - hitTimeDelta;
        const tMax = mouseTime + hitTimeDelta;

        for (let i = 0, len = filteredPackets.length; i < len; i++) {
            const p = filteredPackets[i];
            if (p.time < tMin || p.time > tMax) continue;
            const lane = laneMap[p.protocol];
            if (lane === undefined) continue;

            const px = plotLeft + 40 + (p.time - viewStart) * pxScale * (adjustedPlotW / plotW);
            const py = yOffset + lane * dynRowH + dynRowH / 2;

            const dx = mouseX - px;
            const dy = mouseY - py;
            const dist = Math.sqrt(dx * dx + dy * dy);

            if (dist < bestDist) {
                bestDist = dist;
                bestPkt = p;
            }
        }

        if (bestPkt !== hoveredPacket) {
            hoveredPacket = bestPkt;
            if (hoveredPacket) {
                showTooltip(hoveredPacket);
            } else {
                hideTooltip();
            }
            needsRedraw = true;
        } else if (hoveredPacket) {
            // Update tooltip position even if same packet
            positionTooltip();
        }
    }

    function showTooltip(pkt) {
        if (!tooltipEl) return;
        const proto = pkt.protocol.toUpperCase();
        const color = pkt.color;
        tooltipEl.innerHTML =
            '<div style="margin-bottom:3px;">' +
                '<span style="display:inline-block;width:8px;height:8px;border-radius:50%;' +
                    'background:' + esc(color) + ';margin-right:5px;vertical-align:middle;"></span>' +
                '<strong style="color:' + esc(color) + ';">' + esc(proto) + '</strong>' +
                ' <span style="color:var(--text-dim);font-size:10px;">#' + esc(String(pkt.number)) + '</span>' +
            '</div>' +
            '<div style="color:var(--text-sub);">' +
                esc(pkt.srcAddr) + ' &rarr; ' + esc(pkt.dstAddr) +
            '</div>' +
            '<div style="color:var(--text-dim);font-size:10px;margin-top:2px;">' +
                'Time: ' + formatTime(pkt.time) + ' | ' +
                pkt.length + ' bytes' +
            '</div>' +
            (pkt.info ? '<div style="color:var(--text-dim);font-size:10px;margin-top:2px;' +
                'white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:320px;">' +
                esc(pkt.info) + '</div>' : '');
        tooltipEl.style.display = 'block';
        positionTooltip();
    }

    function positionTooltip() {
        if (!tooltipEl || !canvas) return;
        const rect = canvas.getBoundingClientRect();
        let tx = rect.left + mouseX + 14;
        let ty = rect.top + mouseY - 10;

        // Keep tooltip on screen
        const tw = tooltipEl.offsetWidth || 200;
        const th = tooltipEl.offsetHeight || 60;
        if (tx + tw > window.innerWidth - 10) {
            tx = rect.left + mouseX - tw - 14;
        }
        if (ty + th > window.innerHeight - 10) {
            ty = window.innerHeight - th - 10;
        }
        if (ty < 0) ty = 4;

        tooltipEl.style.left = tx + 'px';
        tooltipEl.style.top = ty + 'px';
    }

    function hideTooltip() {
        if (tooltipEl) tooltipEl.style.display = 'none';
    }

    // =====================================================================
    //  Resize
    // =====================================================================
    function onResize() {
        computeLayout();
    }

    // =====================================================================
    //  Utilities
    // =====================================================================
    function hexToRgba(hex, alpha) {
        const r = parseInt(hex.slice(1, 3), 16);
        const g = parseInt(hex.slice(3, 5), 16);
        const b = parseInt(hex.slice(5, 7), 16);
        return 'rgba(' + r + ',' + g + ',' + b + ',' + alpha + ')';
    }

    function esc(s) {
        if (!s) return '';
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    // =====================================================================
    //  Public API
    // =====================================================================
    return { init, addPacket, clear, onPageVisible };
})();
