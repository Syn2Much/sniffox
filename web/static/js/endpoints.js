// endpoints.js — Endpoint statistics table: tracks per-IP packet/byte counters, peers, protocols
'use strict';

const Endpoints = (() => {
    // DOM references
    let tbody = null;
    let searchInput = null;
    let statsEl = null;

    // Data: ip -> endpoint object
    const endpointMap = new Map();

    // Conversation tracking: normalized pair key "ipA<->ipB" -> true
    const conversationSet = new Set();

    // Protocol frequency counter for summary stats
    const globalProtoCounts = {};

    // Sort state
    let sortKey = 'totalPackets';
    let sortAsc = false;

    // Search/filter
    let searchTerm = '';

    // Dirty flag + batched rendering
    let dirty = false;
    let renderTimer = null;
    const RENDER_INTERVAL = 500; // ms

    // ==================== PUBLIC API ====================

    function init() {
        tbody = document.getElementById('endpoints-table-body');
        searchInput = document.getElementById('endpoints-search');
        statsEl = document.getElementById('endpoints-stats');

        // Search listener
        if (searchInput) {
            searchInput.addEventListener('input', () => {
                searchTerm = searchInput.value.trim().toLowerCase();
                scheduleDirtyRender();
            });
        }

        // Sort header click handlers
        document.querySelectorAll('[data-sort]').forEach(th => {
            // Only bind headers that belong to the endpoints table
            if (th.closest('thead') && th.closest('table') &&
                th.closest('table').querySelector('#endpoints-table-body')) {
                th.addEventListener('click', () => {
                    setSort(th.dataset.sort);
                });
            }
        });

        // Start the batched render timer
        renderTimer = setInterval(() => {
            if (dirty) {
                dirty = false;
                render();
            }
        }, RENDER_INTERVAL);
    }

    function addPacket(pkt) {
        if (!pkt) return;

        const srcAddr = stripPort(pkt.srcAddr || '');
        const dstAddr = stripPort(pkt.dstAddr || '');
        const protocol = (pkt.protocol || 'Unknown').toUpperCase();
        const length = pkt.length || 0;
        const time = pkt.time || Date.now();

        if (!srcAddr && !dstAddr) return;

        // Track global protocol counts
        globalProtoCounts[protocol] = (globalProtoCounts[protocol] || 0) + 1;

        // Track conversation (unique IP pair, order-independent)
        if (srcAddr && dstAddr && srcAddr !== dstAddr) {
            const pairKey = srcAddr < dstAddr
                ? srcAddr + '<->' + dstAddr
                : dstAddr + '<->' + srcAddr;
            conversationSet.add(pairKey);
        }

        // Update source endpoint
        if (srcAddr) {
            const ep = getOrCreateEndpoint(srcAddr, time);
            ep.totalPackets++;
            ep.packetsSent++;
            ep.totalBytes += length;
            ep.bytesSent += length;
            ep.lastSeen = Math.max(ep.lastSeen, time);
            ep.protocols.add(protocol);
            if (dstAddr && dstAddr !== srcAddr) {
                ep.peers.add(dstAddr);
            }
        }

        // Update destination endpoint
        if (dstAddr) {
            const ep = getOrCreateEndpoint(dstAddr, time);
            ep.totalPackets++;
            ep.packetsRecv++;
            ep.totalBytes += length;
            ep.bytesRecv += length;
            ep.lastSeen = Math.max(ep.lastSeen, time);
            ep.protocols.add(protocol);
            if (srcAddr && srcAddr !== dstAddr) {
                ep.peers.add(srcAddr);
            }
        }

        scheduleDirtyRender();
    }

    function clear() {
        endpointMap.clear();
        conversationSet.clear();
        for (const k of Object.keys(globalProtoCounts)) {
            delete globalProtoCounts[k];
        }
        searchTerm = '';
        if (searchInput) searchInput.value = '';
        dirty = false;
        renderEmptyState();
        renderStats();
    }

    // ==================== INTERNALS ====================

    function getOrCreateEndpoint(ip, time) {
        let ep = endpointMap.get(ip);
        if (!ep) {
            ep = {
                ip: ip,
                totalPackets: 0,
                packetsSent: 0,
                packetsRecv: 0,
                totalBytes: 0,
                bytesSent: 0,
                bytesRecv: 0,
                peers: new Set(),
                protocols: new Set(),
                firstSeen: time,
                lastSeen: time
            };
            endpointMap.set(ip, ep);
        }
        return ep;
    }

    function stripPort(addr) {
        if (!addr) return '';
        // IPv6 with port: [::1]:8080 -> ::1
        if (addr.charAt(0) === '[') {
            const closeBracket = addr.indexOf(']');
            if (closeBracket !== -1) {
                return addr.substring(1, closeBracket);
            }
        }
        // IPv4 with port: 1.2.3.4:80 -> 1.2.3.4
        // Only strip if there is exactly one colon (IPv6 has multiple)
        const colonCount = (addr.match(/:/g) || []).length;
        if (colonCount === 1) {
            return addr.substring(0, addr.indexOf(':'));
        }
        return addr;
    }

    function scheduleDirtyRender() {
        dirty = true;
    }

    function setSort(key) {
        if (sortKey === key) {
            sortAsc = !sortAsc;
        } else {
            sortKey = key;
            sortAsc = false;
        }
        render();
    }

    // ==================== RENDERING ====================

    function render() {
        if (!tbody) return;

        let endpoints = Array.from(endpointMap.values());

        // Filter by search term
        if (searchTerm) {
            endpoints = endpoints.filter(ep =>
                ep.ip.toLowerCase().indexOf(searchTerm) !== -1
            );
        }

        // Sort
        endpoints.sort((a, b) => {
            let va = getSortValue(a, sortKey);
            let vb = getSortValue(b, sortKey);
            if (typeof va === 'string') {
                va = va.toLowerCase();
                vb = (vb || '').toLowerCase();
            }
            if (va < vb) return sortAsc ? -1 : 1;
            if (va > vb) return sortAsc ? 1 : -1;
            return 0;
        });

        // Update sort indicators on column headers
        updateSortIndicators();

        if (endpoints.length === 0) {
            renderEmptyState();
            renderStats();
            return;
        }

        let html = '';
        for (let i = 0; i < endpoints.length; i++) {
            const ep = endpoints[i];
            html += renderRow(ep);
        }
        tbody.innerHTML = html;

        renderStats();
    }

    function renderRow(ep) {
        const protoBadges = buildProtoBadges(ep.protocols);
        const firstTs = formatTimestamp(ep.firstSeen);
        const lastTs = formatTimestamp(ep.lastSeen);

        return '<tr class="ep-row">' +
            '<td class="ep-ip">' + esc(ep.ip) + protoBadges + '</td>' +
            '<td class="ep-num">' + ep.totalPackets + '</td>' +
            '<td class="ep-num">' + ep.packetsSent + '</td>' +
            '<td class="ep-num">' + ep.packetsRecv + '</td>' +
            '<td class="ep-num">' + formatBytes(ep.totalBytes) + '</td>' +
            '<td class="ep-num">' + formatBytes(ep.bytesSent) + '</td>' +
            '<td class="ep-num">' + formatBytes(ep.bytesRecv) + '</td>' +
            '<td class="ep-num">' + ep.peers.size + '</td>' +
            '<td class="ep-ts">' + firstTs + '</td>' +
            '<td class="ep-ts">' + lastTs + '</td>' +
            '</tr>';
    }

    function renderEmptyState() {
        if (!tbody) return;
        tbody.innerHTML = '<tr><td colspan="10" class="ep-empty">' +
            'No endpoints observed — start a capture to see network hosts</td></tr>';
    }

    function renderStats() {
        if (!statsEl) return;

        const totalEndpoints = endpointMap.size;
        const totalConversations = conversationSet.size;
        const topProto = getTopProtocol();

        statsEl.innerHTML =
            '<span class="ep-stat">' +
                '<span class="ep-stat-label">Endpoints:</span> ' +
                '<span class="ep-stat-value">' + totalEndpoints + '</span>' +
            '</span>' +
            '<span class="ep-stat">' +
                '<span class="ep-stat-label">Conversations:</span> ' +
                '<span class="ep-stat-value">' + totalConversations + '</span>' +
            '</span>' +
            '<span class="ep-stat">' +
                '<span class="ep-stat-label">Top Protocol:</span> ' +
                '<span class="ep-stat-value">' + esc(topProto) + '</span>' +
            '</span>';
    }

    function buildProtoBadges(protocols) {
        if (!protocols || protocols.size === 0) return '';
        let html = '';
        for (const proto of protocols) {
            const cls = 'ep-proto-' + proto.toLowerCase().replace(/[^a-z0-9]/g, '');
            html += ' <span class="ep-proto-badge ' + cls + '">' + esc(proto) + '</span>';
        }
        return html;
    }

    function updateSortIndicators() {
        document.querySelectorAll('[data-sort]').forEach(th => {
            if (th.closest('table') &&
                th.closest('table').querySelector('#endpoints-table-body')) {
                th.classList.remove('sort-asc', 'sort-desc');
                if (th.dataset.sort === sortKey) {
                    th.classList.add(sortAsc ? 'sort-asc' : 'sort-desc');
                }
            }
        });
    }

    function getTopProtocol() {
        let topProto = '--';
        let topCount = 0;
        for (const proto of Object.keys(globalProtoCounts)) {
            if (globalProtoCounts[proto] > topCount) {
                topCount = globalProtoCounts[proto];
                topProto = proto;
            }
        }
        return topProto;
    }

    function getSortValue(ep, key) {
        switch (key) {
            case 'ip':           return ep.ip;
            case 'totalPackets': return ep.totalPackets;
            case 'packetsSent':  return ep.packetsSent;
            case 'packetsRecv':  return ep.packetsRecv;
            case 'totalBytes':   return ep.totalBytes;
            case 'bytesSent':    return ep.bytesSent;
            case 'bytesRecv':    return ep.bytesRecv;
            case 'peers':        return ep.peers.size;
            case 'firstSeen':    return ep.firstSeen;
            case 'lastSeen':     return ep.lastSeen;
            default:             return ep.totalPackets;
        }
    }

    // ==================== FORMATTING HELPERS ====================

    function formatBytes(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
        if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
        return (bytes / 1073741824).toFixed(2) + ' GB';
    }

    function formatTimestamp(ts) {
        if (!ts) return '--';
        const d = new Date(ts);
        if (isNaN(d.getTime())) return '--';
        const h = String(d.getHours()).padStart(2, '0');
        const m = String(d.getMinutes()).padStart(2, '0');
        const s = String(d.getSeconds()).padStart(2, '0');
        const ms = String(d.getMilliseconds()).padStart(3, '0');
        return h + ':' + m + ':' + s + '.' + ms;
    }

    function esc(s) {
        if (!s) return '';
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    return { init, addPacket, clear };
})();
