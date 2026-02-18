// streams.js — TCP stream viewer: "Follow TCP Stream" dialog
'use strict';

const Streams = (() => {
    let overlay = null;
    let contentEl = null;
    let viewMode = 'ascii'; // ascii, hex, raw

    function init() {
        overlay = document.getElementById('stream-overlay');
        if (!overlay) return;

        const closeBtn = document.getElementById('stream-close-btn');
        if (closeBtn) {
            closeBtn.addEventListener('click', close);
        }

        document.querySelectorAll('.stream-view-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                viewMode = btn.dataset.mode;
                document.querySelectorAll('.stream-view-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                // Re-render with current data
                if (overlay._lastData) renderData(overlay._lastData);
            });
        });

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

        // Decode base64 data
        const clientBytes = data.clientData ? atob(data.clientData) : '';
        const serverBytes = data.serverData ? atob(data.serverData) : '';

        html += '<div class="stream-data-section">';
        if (clientBytes.length > 0) {
            html += '<div class="stream-direction stream-client">';
            html += '<div class="stream-direction-label">Client Data (' + clientBytes.length + ' bytes)</div>';
            html += '<pre class="stream-data-pre stream-client-data">' + formatData(clientBytes) + '</pre>';
            html += '</div>';
        }
        if (serverBytes.length > 0) {
            html += '<div class="stream-direction stream-server">';
            html += '<div class="stream-direction-label">Server Data (' + serverBytes.length + ' bytes)</div>';
            html += '<pre class="stream-data-pre stream-server-data">' + formatData(serverBytes) + '</pre>';
            html += '</div>';
        }
        if (clientBytes.length === 0 && serverBytes.length === 0) {
            html += '<div class="stream-empty">No reassembled data available yet</div>';
        }
        html += '</div>';

        contentEl.innerHTML = html;
    }

    function formatData(str) {
        switch (viewMode) {
            case 'hex':
                return formatHex(str);
            case 'raw':
                return esc(str);
            case 'ascii':
            default:
                return formatAscii(str);
        }
    }

    function formatAscii(str) {
        let result = '';
        for (let i = 0; i < str.length; i++) {
            const c = str.charCodeAt(i);
            if (c >= 32 && c < 127 || c === 10 || c === 13 || c === 9) {
                result += esc(str[i]);
            } else {
                result += '<span class="stream-nonprint">.</span>';
            }
        }
        return result;
    }

    function formatHex(str) {
        let result = '';
        for (let offset = 0; offset < str.length; offset += 16) {
            // Offset
            result += '<span class="hex-offset">' + offset.toString(16).padStart(4, '0') + '</span>  ';
            // Hex bytes
            let ascii = '';
            for (let i = 0; i < 16; i++) {
                if (offset + i < str.length) {
                    const b = str.charCodeAt(offset + i);
                    result += '<span class="hex-bytes">' + b.toString(16).padStart(2, '0') + '</span> ';
                    ascii += (b >= 32 && b < 127) ? str[offset + i] : '.';
                } else {
                    result += '   ';
                    ascii += ' ';
                }
                if (i === 7) result += ' ';
            }
            result += ' <span class="hex-ascii">|' + esc(ascii) + '|</span>\n';
        }
        return result;
    }

    function close() {
        if (overlay) {
            overlay.classList.remove('stream-visible');
            overlay._lastData = null;
        }
    }

    function esc(s) {
        if (!s) return '';
        return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    return { init, open, handleStreamData, close };
})();
