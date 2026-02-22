// packetlist.js — Top pane: virtual-scrolled packet table with keyboard navigation
'use strict';

const PacketList = (() => {
    let packets = [];
    let displayIndices = []; // indices into packets[] that pass the current filter
    let selectedIndex = -1;
    let selectedDisplayIdx = -1; // index within displayIndices for keyboard nav
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

    // Context menu
    let ctxMenu = null;

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

        // Context menu
        createContextMenu();
        pane.addEventListener('contextmenu', onContextMenu);
        document.addEventListener('click', hideContextMenu);

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
            tr.dataset.displayIdx = i;
            tr.className = 'proto-' + pkt.protocol.toLowerCase();
            if (pktIdx === selectedIndex) tr.classList.add('selected');
            tr.style.height = ROW_HEIGHT + 'px';
            const bm = typeof Bookmarks !== 'undefined' && Bookmarks.isBookmarked(pkt.number);
            if (bm) tr.classList.add('bookmarked');
            tr.innerHTML =
                '<td>' + (bm ? '<span class="pkt-star">&#9733;</span>' : '') + pkt.number + '</td>' +
                '<td>' + pkt.timestamp + '</td>' +
                '<td title="' + esc(pkt.srcAddr) + '">' + esc(pkt.srcAddr) + '</td>' +
                '<td title="' + esc(pkt.dstAddr) + '">' + esc(pkt.dstAddr) + '</td>' +
                '<td>' + esc(pkt.protocol) + '</td>' +
                '<td>' + pkt.length + '</td>' +
                '<td title="' + esc(pkt.info) + '">' + esc(pkt.info) + '</td>';
            tr.addEventListener('click', () => selectPacket(pktIdx, tr, i));
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

    function selectPacket(idx, tr, displayIdx) {
        const prev = tbody.querySelector('tr.selected');
        if (prev) prev.classList.remove('selected');
        if (tr) tr.classList.add('selected');
        selectedIndex = idx;
        if (displayIdx !== undefined) selectedDisplayIdx = displayIdx;

        const pkt = packets[idx];
        PacketDetail.show(pkt);
        HexView.show(pkt);
    }

    // --- Keyboard Navigation ---
    function navigateByKey(direction) {
        if (displayIndices.length === 0) return;

        let newDisplayIdx;
        if (selectedDisplayIdx < 0) {
            newDisplayIdx = direction > 0 ? 0 : displayIndices.length - 1;
        } else {
            newDisplayIdx = selectedDisplayIdx + direction;
        }

        // Clamp
        newDisplayIdx = Math.max(0, Math.min(displayIndices.length - 1, newDisplayIdx));
        if (newDisplayIdx === selectedDisplayIdx && selectedIndex >= 0) return;

        selectedDisplayIdx = newDisplayIdx;
        const pktIdx = displayIndices[newDisplayIdx];

        // Ensure the row is visible (scroll if needed)
        const rowTop = newDisplayIdx * ROW_HEIGHT;
        const rowBottom = rowTop + ROW_HEIGHT;
        if (rowTop < pane.scrollTop) {
            pane.scrollTop = rowTop;
        } else if (rowBottom > pane.scrollTop + pane.clientHeight) {
            pane.scrollTop = rowBottom - pane.clientHeight;
        }

        // Find the rendered row or trigger re-render
        renderViewport();

        const tr = tbody.querySelector('tr[data-index="' + pktIdx + '"]');
        selectPacket(pktIdx, tr, newDisplayIdx);
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
        selectedDisplayIdx = -1;
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
        selectedDisplayIdx = -1;
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

    // --- Context Menu ---

    function createContextMenu() {
        ctxMenu = document.createElement('div');
        ctxMenu.className = 'pkt-context-menu';
        ctxMenu.style.display = 'none';
        ctxMenu.innerHTML =
            '<div class="pkt-ctx-item" data-action="toggle-bookmark">&#9733; Bookmark Packet</div>' +
            '<div class="pkt-ctx-sep"></div>' +
            '<div class="pkt-ctx-item" data-action="follow-stream">Follow TCP Stream</div>' +
            '<div class="pkt-ctx-item" data-action="filter-flow">Filter by Flow</div>' +
            '<div class="pkt-ctx-sep"></div>' +
            '<div class="pkt-ctx-item" data-action="filter-src">Filter by Source IP</div>' +
            '<div class="pkt-ctx-item" data-action="filter-dst">Filter by Dest IP</div>' +
            '<div class="pkt-ctx-sep"></div>' +
            '<div class="pkt-ctx-item" data-action="deep-analysis">Deep Analysis</div>';
        document.body.appendChild(ctxMenu);

        ctxMenu.addEventListener('click', (e) => {
            const action = e.target.dataset.action;
            if (!action) return;
            hideContextMenu();
            handleContextAction(action);
        });
    }

    let ctxPacket = null;

    function onContextMenu(e) {
        // Find the row
        const tr = e.target.closest('tr[data-index]');
        if (!tr) return;
        e.preventDefault();

        const idx = parseInt(tr.dataset.index, 10);
        ctxPacket = packets[idx];
        if (!ctxPacket) return;

        // Position menu
        ctxMenu.style.display = 'block';
        ctxMenu.style.left = e.clientX + 'px';
        ctxMenu.style.top = e.clientY + 'px';

        // Clamp to viewport
        requestAnimationFrame(() => {
            const rect = ctxMenu.getBoundingClientRect();
            if (rect.right > window.innerWidth) {
                ctxMenu.style.left = (e.clientX - rect.width) + 'px';
            }
            if (rect.bottom > window.innerHeight) {
                ctxMenu.style.top = (e.clientY - rect.height) + 'px';
            }
        });

        // Update bookmark label
        const bmItem = ctxMenu.querySelector('[data-action="toggle-bookmark"]');
        if (bmItem && typeof Bookmarks !== 'undefined') {
            bmItem.innerHTML = Bookmarks.isBookmarked(ctxPacket.number)
                ? '&#9733; Remove Bookmark'
                : '&#9734; Bookmark Packet';
        }

        // Enable/disable stream option
        const streamItem = ctxMenu.querySelector('[data-action="follow-stream"]');
        if (streamItem) {
            streamItem.style.opacity = ctxPacket.streamId ? '1' : '0.4';
            streamItem.style.pointerEvents = ctxPacket.streamId ? 'auto' : 'none';
        }

        // Enable/disable flow option
        const flowItem = ctxMenu.querySelector('[data-action="filter-flow"]');
        if (flowItem) {
            flowItem.style.opacity = ctxPacket.flowId ? '1' : '0.4';
            flowItem.style.pointerEvents = ctxPacket.flowId ? 'auto' : 'none';
        }
    }

    function hideContextMenu() {
        if (ctxMenu) ctxMenu.style.display = 'none';
    }

    function handleContextAction(action) {
        if (!ctxPacket) return;
        const filterInput = document.getElementById('display-filter');

        switch (action) {
            case 'toggle-bookmark':
                if (typeof Bookmarks !== 'undefined') {
                    Bookmarks.toggle(ctxPacket);
                    // Force re-render to update bookmark indicator
                    renderedRange = { start: 0, end: 0 };
                    renderViewport();
                }
                break;
            case 'follow-stream':
                if (ctxPacket.streamId && typeof Streams !== 'undefined') {
                    Streams.open(ctxPacket.streamId);
                }
                break;
            case 'filter-flow':
                if (ctxPacket.flowId && filterInput) {
                    filterInput.value = 'flow==' + ctxPacket.flowId;
                    filterInput.dispatchEvent(new Event('input'));
                }
                break;
            case 'filter-src': {
                const ip = stripPort(ctxPacket.srcAddr);
                if (ip && filterInput) {
                    filterInput.value = 'ip.src==' + ip;
                    filterInput.dispatchEvent(new Event('input'));
                }
                break;
            }
            case 'filter-dst': {
                const ip = stripPort(ctxPacket.dstAddr);
                if (ip && filterInput) {
                    filterInput.value = 'ip.dst==' + ip;
                    filterInput.dispatchEvent(new Event('input'));
                }
                break;
            }
            case 'deep-analysis':
                if (typeof PacketModal !== 'undefined') {
                    PacketModal.open(ctxPacket);
                }
                break;
        }
    }

    function stripPort(addr) {
        if (!addr) return '';
        const i = addr.lastIndexOf(':');
        return i > 0 ? addr.substring(0, i) : addr;
    }

    function esc(s) {
        if (!s) return '';
        return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    return { init, addPacket, applyFilter, clear, totalCount, displayedCount, navigateByKey };
})();
