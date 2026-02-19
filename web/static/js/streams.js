// streams.js — TCP stream viewer: "Follow TCP Stream" dialog
// ASCII view is capped for display safety; Hex and Raw are download-only.
'use strict';

const Streams = (() => {
    let overlay = null;
    let contentEl = null;

    // Max bytes to render as ASCII in the DOM to avoid browser freeze
    const MAX_DISPLAY_BYTES = 64 * 1024; // 64 KB

    // Store decoded bytes for downloads
    let lastClientBytes = '';
    let lastServerBytes = '';

    function init() {
        overlay = document.getElementById('stream-overlay');
        if (!overlay) return;

        const closeBtn = document.getElementById('stream-close-btn');
        if (closeBtn) {
            closeBtn.addEventListener('click', close);
        }

        // Download buttons
        const dlHex = document.getElementById('stream-dl-hex');
        const dlRaw = document.getElementById('stream-dl-raw');
        if (dlHex) dlHex.addEventListener('click', downloadHex);
        if (dlRaw) dlRaw.addEventListener('click', downloadRaw);

        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && overlay && overlay.classList.contains('stream-visible')) {
                close();
            }
        });

        contentEl = document.getElementById('stream-content');
    }

    function open(streamId) {
        if (!overlay) return;
        overlay.classList.add('stream-visible');
        lastClientBytes = '';
        lastServerBytes = '';
        if (contentEl) contentEl.innerHTML = '<div class="stream-loading">Loading stream data...</div>';

        // Request stream data from server
        App.send('get_stream_data', { streamId: streamId });
    }

    function handleStreamData(data) {
        if (!overlay || !overlay.classList.contains('stream-visible')) return;
        overlay._lastData = data;
        renderData(data);
    }

    function renderData(data) {
        if (!contentEl) return;

        let html = '';

        // HTTP info section
        if (data.httpInfo) {
            const h = data.httpInfo;
            html += '<div class="stream-http-info">';
            html += '<div class="stream-http-title">HTTP Transaction</div>';
            if (h.method) {
                html += '<div class="stream-http-line"><span class="stream-http-method">' + esc(h.method) + '</span> ' + esc(h.url) + '</div>';
            }
            if (h.statusCode) {
                html += '<div class="stream-http-line">Status: <span class="stream-http-status">' + h.statusCode + '</span> ' + esc(h.statusText) + '</div>';
            }
            if (h.contentType) {
                html += '<div class="stream-http-line">Content-Type: ' + esc(h.contentType) + '</div>';
            }
            if (h.reqHeaders && Object.keys(h.reqHeaders).length > 0) {
                html += '<div class="stream-http-headers-title">Request Headers</div>';
                for (const [k, v] of Object.entries(h.reqHeaders)) {
                    html += '<div class="stream-http-header">' + esc(k) + ': ' + esc(v) + '</div>';
                }
            }
            if (h.respHeaders && Object.keys(h.respHeaders).length > 0) {
                html += '<div class="stream-http-headers-title">Response Headers</div>';
                for (const [k, v] of Object.entries(h.respHeaders)) {
                    html += '<div class="stream-http-header">' + esc(k) + ': ' + esc(v) + '</div>';
                }
            }
            if (h.bodyPreview) {
                html += '<div class="stream-http-headers-title">Body Preview</div>';
                html += '<pre class="stream-http-body">' + esc(h.bodyPreview) + '</pre>';
            }
            html += '</div>';
        }

        // Decode base64 data and store for downloads
        lastClientBytes = data.clientData ? atob(data.clientData) : '';
        lastServerBytes = data.serverData ? atob(data.serverData) : '';

        html += '<div class="stream-data-section">';
        if (lastClientBytes.length > 0) {
            html += '<div class="stream-direction stream-client">';
            html += '<div class="stream-direction-label">Client Data (' + formatSize(lastClientBytes.length) + ')</div>';
            html += '<pre class="stream-data-pre stream-client-data">' + formatAsciiSafe(lastClientBytes) + '</pre>';
            html += '</div>';
        }
        if (lastServerBytes.length > 0) {
            html += '<div class="stream-direction stream-server">';
            html += '<div class="stream-direction-label">Server Data (' + formatSize(lastServerBytes.length) + ')</div>';
            html += '<pre class="stream-data-pre stream-server-data">' + formatAsciiSafe(lastServerBytes) + '</pre>';
            html += '</div>';
        }
        if (lastClientBytes.length === 0 && lastServerBytes.length === 0) {
            html += '<div class="stream-empty">No reassembled data available yet</div>';
        }
        html += '</div>';

        contentEl.innerHTML = html;
    }

    // ASCII view with a hard cap to avoid DOM explosion
    function formatAsciiSafe(str) {
        const limit = Math.min(str.length, MAX_DISPLAY_BYTES);
        let result = '';
        for (let i = 0; i < limit; i++) {
            const c = str.charCodeAt(i);
            if (c >= 32 && c < 127 || c === 10 || c === 13 || c === 9) {
                result += esc(str[i]);
            } else {
                result += '.';
            }
        }
        if (str.length > MAX_DISPLAY_BYTES) {
            result += '\n\n--- Truncated: showing ' + formatSize(MAX_DISPLAY_BYTES) + ' of ' + formatSize(str.length) + ' ---\n';
            result += '--- Use "Save Hex" or "Save Raw" to download the full stream ---';
        }
        return result;
    }

    // --- Downloads ---

    function downloadHex() {
        if (!lastClientBytes && !lastServerBytes) {
            App.showToast('No stream data to download', 'error');
            return;
        }
        let text = '';
        if (lastClientBytes.length > 0) {
            text += '=== CLIENT DATA (' + lastClientBytes.length + ' bytes) ===\n';
            text += buildHexDump(lastClientBytes);
            text += '\n';
        }
        if (lastServerBytes.length > 0) {
            text += '=== SERVER DATA (' + lastServerBytes.length + ' bytes) ===\n';
            text += buildHexDump(lastServerBytes);
        }
        downloadFile('stream.hex', text, 'text/plain');
        App.showToast('Hex dump downloaded', 'success');
    }

    function downloadRaw() {
        if (!lastClientBytes && !lastServerBytes) {
            App.showToast('No stream data to download', 'error');
            return;
        }
        // Combine client + server into a single binary blob
        const combined = lastClientBytes + lastServerBytes;
        const bytes = new Uint8Array(combined.length);
        for (let i = 0; i < combined.length; i++) {
            bytes[i] = combined.charCodeAt(i);
        }
        const blob = new Blob([bytes], { type: 'application/octet-stream' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'stream.bin';
        a.click();
        URL.revokeObjectURL(a.href);
        App.showToast('Raw stream downloaded', 'success');
    }

    function buildHexDump(str) {
        let result = '';
        for (let offset = 0; offset < str.length; offset += 16) {
            // Offset
            result += offset.toString(16).padStart(8, '0') + '  ';
            // Hex bytes
            let ascii = '';
            for (let i = 0; i < 16; i++) {
                if (offset + i < str.length) {
                    const b = str.charCodeAt(offset + i);
                    result += b.toString(16).padStart(2, '0') + ' ';
                    ascii += (b >= 32 && b < 127) ? str[offset + i] : '.';
                } else {
                    result += '   ';
                    ascii += ' ';
                }
                if (i === 7) result += ' ';
            }
            result += ' |' + ascii + '|\n';
        }
        return result;
    }

    function downloadFile(filename, text, mime) {
        const blob = new Blob([text], { type: mime || 'text/plain' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = filename;
        a.click();
        URL.revokeObjectURL(a.href);
    }

    function formatSize(bytes) {
        if (bytes < 1024) return bytes + ' bytes';
        if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / 1048576).toFixed(1) + ' MB';
    }

    function close() {
        if (overlay) {
            overlay.classList.remove('stream-visible');
            overlay._lastData = null;
        }
        lastClientBytes = '';
        lastServerBytes = '';
    }

    function esc(s) {
        if (!s) return '';
        return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    return { init, open, handleStreamData, close };
})();
