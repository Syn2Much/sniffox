// flows.js — Flow table module: receives flow_update messages, renders sortable flow table
'use strict';

const Flows = (() => {
    let container = null;
    let flowMap = new Map(); // id -> flow object
    let sortKey = 'lastSeen';
    let sortAsc = false;
    let visible = false;

    function init() {
        container = document.getElementById('flow-table-body');

        // Sort header click handlers
        document.querySelectorAll('.flow-th[data-sort]').forEach(th => {
            th.addEventListener('click', () => {
                setSort(th.dataset.sort);
            });
        });
    }

    function setVisible(v) {
        visible = v;
        if (visible) render();
    }

    function update(flows) {
        if (!Array.isArray(flows)) return;
        flowMap.clear();
        for (const f of flows) {
            flowMap.set(f.id, f);
        }
        if (visible) render();
    }

    function render() {
        if (!container) return;

        const flows = Array.from(flowMap.values());

        // Sort
        flows.sort((a, b) => {
            let va = a[sortKey], vb = b[sortKey];
            if (typeof va === 'string') {
                va = va.toLowerCase();
                vb = (vb || '').toLowerCase();
            }
            if (va < vb) return sortAsc ? -1 : 1;
            if (va > vb) return sortAsc ? 1 : -1;
            return 0;
        });

        if (flows.length === 0) {
            container.innerHTML = '<tr><td colspan="9" class="flow-empty">No flows detected — start a capture to see connections</td></tr>';
            return;
        }

        let html = '';
        for (const f of flows) {
            const duration = f.lastSeen > f.firstSeen
                ? ((f.lastSeen - f.firstSeen) / 1000).toFixed(1) + 's'
                : '< 1s';
            const stateClass = f.tcpState ? 'flow-state-' + f.tcpState.toLowerCase().replace(/_/g, '') : '';

            html += '<tr class="flow-row" data-flow-id="' + f.id + '">' +
                '<td class="flow-id">' + f.id + '</td>' +
                '<td title="' + esc(f.srcIp) + '">' + esc(f.srcIp) + portStr(f.srcPort) + '</td>' +
                '<td title="' + esc(f.dstIp) + '">' + esc(f.dstIp) + portStr(f.dstPort) + '</td>' +
                '<td class="proto-' + (f.protocol || '').toLowerCase() + '">' + esc(f.protocol) + '</td>' +
                '<td>' + f.packetCount + '</td>' +
                '<td>' + formatBytes(f.byteCount) + '</td>' +
                '<td>' + duration + '</td>' +
                '<td class="' + stateClass + '">' + esc(f.tcpState || '—') + '</td>' +
                '<td class="flow-dir">' + f.fwdPackets + ' / ' + f.revPackets + '</td>' +
                '</tr>';
        }
        container.innerHTML = html;

        // Click handler — filter packet list by flow
        container.querySelectorAll('.flow-row').forEach(row => {
            row.addEventListener('click', () => {
                const flowId = row.dataset.flowId;
                const filterInput = document.getElementById('display-filter');
                if (filterInput) {
                    filterInput.value = 'flow==' + flowId;
                    filterInput.dispatchEvent(new Event('input'));
                }
                // Switch to packets view
                const pktTab = document.querySelector('.capture-view-tab[data-view="packets"]');
                if (pktTab) pktTab.click();
            });
        });
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

    function clear() {
        flowMap.clear();
        if (container) {
            container.innerHTML = '<tr><td colspan="9" class="flow-empty">No flows detected — start a capture to see connections</td></tr>';
        }
    }

    function portStr(port) {
        return port ? ':' + port : '';
    }

    function formatBytes(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
        if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
        return (bytes / 1073741824).toFixed(2) + ' GB';
    }

    function esc(s) {
        if (!s) return '';
        return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    return { init, update, setVisible, setSort, clear };
})();
