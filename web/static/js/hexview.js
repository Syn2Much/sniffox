// hexview.js — Bottom pane: hex + ASCII dump
'use strict';

const HexView = (() => {
    let container = null;

    function init() {
        container = document.getElementById('hex-content');
    }

    function show(pkt) {
        if (!pkt || !pkt.hexDump) {
            container.innerHTML = '<div class="empty-state">No hex data available</div>';
            return;
        }
        // hexDump is pre-formatted with offset | hex | ascii per line
        const lines = pkt.hexDump.split('\n');
        container.innerHTML = lines.map(line => {
            if (!line.trim()) return '';
            // Format: "0000  xx xx xx ...  |ascii...|"
            const match = line.match(/^([0-9a-f]+)\s{2}(.+?)\s{2}\|(.+)\|$/i);
            if (match) {
                return `<span class="hex-offset">${match[1]}</span>  <span class="hex-bytes">${esc(match[2])}</span>  <span class="hex-ascii">|${esc(match[3])}|</span>`;
            }
            return esc(line);
        }).join('\n');
    }

    function clear() {
        if (container) {
            container.innerHTML = '<div class="empty-state">Select a packet to view hex dump</div>';
        }
    }

    function esc(s) {
        return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    return { init, show, clear };
})();
