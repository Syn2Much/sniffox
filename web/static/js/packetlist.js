// packetlist.js — Top pane: virtual-scrolled packet table
'use strict';

const PacketList = (() => {
    let packets = [];
    let displayIndices = []; // indices into packets[] that pass the current filter
    let selectedIndex = -1;
    let filterFn = null;

    // DOM
    let pane = null;
    let tbody = null;

    // Virtual scroll
    const ROW_HEIGHT = 24;
    let scrollTop = 0;
    let viewportHeight = 0;
    let spacerTop = null;
    let spacerBottom = null;
    let renderedRange = { start: 0, end: 0 };
    const OVERSCAN = 30; // extra rows above/below viewport

    // Incoming packet buffer — flushed by rAF
    let pendingPackets = [];
    let rafId = null;

    function init() {
        pane = document.getElementById('packet-list-pane');
        tbody = document.getElementById('packet-tbody');

        // Insert virtual-scroll spacers
        spacerTop = document.createElement('tr');
        spacerTop.id = 'spacer-top';
        spacerBottom = document.createElement('tr');
        spacerBottom.id = 'spacer-bottom';

        pane.addEventListener('scroll', onScroll);
        window.addEventListener('resize', scheduleRender);

        scheduleRender();
    }

    function addPacket(pkt) {
        pendingPackets.push(pkt);
        if (!rafId) {
            rafId = requestAnimationFrame(flushPending);
        }
    }

    function flushPending() {
        rafId = null;
        const batch = pendingPackets;
        pendingPackets = [];
        if (batch.length === 0) return;

        const wasAtBottom = pane.scrollHeight - pane.scrollTop - pane.clientHeight < ROW_HEIGHT * 2;

        for (const pkt of batch) {
            const idx = packets.length;
            packets.push(pkt);
            if (!filterFn || filterFn(pkt)) {
                displayIndices.push(idx);
            }
        }

        renderViewport();

        if (wasAtBottom) {
            pane.scrollTop = pane.scrollHeight;
        }
    }

    function onScroll() {
        scrollTop = pane.scrollTop;
        renderViewport();
    }

    function scheduleRender() {
        if (!rafId) {
            rafId = requestAnimationFrame(() => {
                rafId = null;
                renderViewport();
            });
        }
    }

    function renderViewport() {
        if (!pane || !tbody) return;
        viewportHeight = pane.clientHeight;
        const totalRows = displayIndices.length;
        const totalHeight = totalRows * ROW_HEIGHT;

        // Which rows are visible?
        const firstVisible = Math.floor(scrollTop / ROW_HEIGHT);
        const visibleCount = Math.ceil(viewportHeight / ROW_HEIGHT);
        const start = Math.max(0, firstVisible - OVERSCAN);
        const end = Math.min(totalRows, firstVisible + visibleCount + OVERSCAN);

        // Skip re-render if range unchanged
        if (start === renderedRange.start && end === renderedRange.end && tbody.rows.length > 0) {
            return;
        }
        renderedRange = { start, end };

        // Build rows
        const frag = document.createDocumentFragment();

        // Top spacer
        const topH = start * ROW_HEIGHT;
        const topTr = document.createElement('tr');
        topTr.style.height = topH + 'px';
        frag.appendChild(topTr);

        for (let i = start; i < end; i++) {
            const pktIdx = displayIndices[i];
            const pkt = packets[pktIdx];
            const tr = document.createElement('tr');
            tr.dataset.index = pktIdx;
            tr.className = 'proto-' + pkt.protocol.toLowerCase();
            if (pktIdx === selectedIndex) tr.classList.add('selected');
            tr.style.height = ROW_HEIGHT + 'px';
            tr.innerHTML =
                '<td>' + pkt.number + '</td>' +
                '<td>' + pkt.timestamp + '</td>' +
                '<td title="' + esc(pkt.srcAddr) + '">' + esc(pkt.srcAddr) + '</td>' +
                '<td title="' + esc(pkt.dstAddr) + '">' + esc(pkt.dstAddr) + '</td>' +
                '<td>' + esc(pkt.protocol) + '</td>' +
                '<td>' + pkt.length + '</td>' +
                '<td title="' + esc(pkt.info) + '">' + esc(pkt.info) + '</td>';
            tr.addEventListener('click', () => selectPacket(pktIdx, tr));
            frag.appendChild(tr);
        }

        // Bottom spacer
        const bottomH = Math.max(0, (totalRows - end) * ROW_HEIGHT);
        const bottomTr = document.createElement('tr');
        bottomTr.style.height = bottomH + 'px';
        frag.appendChild(bottomTr);

        tbody.textContent = ''; // clear fast
        tbody.appendChild(frag);
    }

    function selectPacket(idx, tr) {
        const prev = tbody.querySelector('tr.selected');
        if (prev) prev.classList.remove('selected');
        tr.classList.add('selected');
        selectedIndex = idx;

        const pkt = packets[idx];
        PacketDetail.show(pkt);
        HexView.show(pkt);
    }

    function applyFilter(filterText) {
        filterFn = Filters.compile(filterText);
        rebuildIndices();
        renderedRange = { start: 0, end: 0 };
        pane.scrollTop = 0;
        renderViewport();
    }

    function rebuildIndices() {
        displayIndices = [];
        selectedIndex = -1;
        if (!filterFn) {
            for (let i = 0; i < packets.length; i++) {
                displayIndices.push(i);
            }
        } else {
            for (let i = 0; i < packets.length; i++) {
                if (filterFn(packets[i])) {
                    displayIndices.push(i);
                }
            }
        }
    }

    function clear() {
        packets = [];
        displayIndices = [];
        selectedIndex = -1;
        filterFn = null;
        pendingPackets = [];
        renderedRange = { start: 0, end: 0 };
        if (rafId) { cancelAnimationFrame(rafId); rafId = null; }
        if (tbody) tbody.textContent = '';
    }

    function totalCount() {
        return packets.length;
    }

    function displayedCount() {
        return displayIndices.length;
    }

    function esc(s) {
        if (!s) return '';
        return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    return { init, addPacket, applyFilter, clear, totalCount, displayedCount };
})();
