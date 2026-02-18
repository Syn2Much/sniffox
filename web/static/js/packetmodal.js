// packetmodal.js — Analysis page: deep packet inspection with tabs and graphical views
'use strict';

const PacketModal = (() => {
    let body = null;
    let currentPkt = null;
    let activeTab = 'summary';

    function init() {
        body = document.getElementById('analysis-body');

        // Tab switching
        document.querySelectorAll('.analysis-tab-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                switchTab(btn.dataset.tab);
            });
        });

        // Export buttons
        const exportJsonBtn = document.getElementById('analysis-export-json');
        const exportHexBtn = document.getElementById('analysis-export-hex');
        const exportCopyBtn = document.getElementById('analysis-export-copy');
        if (exportJsonBtn) exportJsonBtn.addEventListener('click', exportJson);
        if (exportHexBtn) exportHexBtn.addEventListener('click', exportHex);
        if (exportCopyBtn) exportCopyBtn.addEventListener('click', exportCopy);
    }

    function open(pkt) {
        if (!pkt) return;
        currentPkt = pkt;

        // Mark body as having a packet (hides empty state, shows tabs)
        if (body) body.classList.add('has-packet');

        // Header
        document.getElementById('analysis-pkt-num').textContent = '#' + pkt.number;
        document.getElementById('analysis-pkt-proto').textContent = pkt.protocol;
        document.getElementById('analysis-pkt-proto').className = 'modal-proto proto-' + pkt.protocol.toLowerCase();
        document.getElementById('analysis-pkt-info').textContent = pkt.info;

        // Render all tabs content
        renderSummary(pkt);
        renderLayers(pkt);
        renderHex(pkt);
        renderByteChart(pkt);
        renderAscii(pkt);
        renderFlags(pkt);
        renderHeatmap(pkt);
        renderFlowDiagram(pkt);
        renderPayloadDecode(pkt);

        // Show summary tab by default
        switchTab('summary');

        // Navigate to the analysis page
        Router.navigate('analysis');
    }

    function switchTab(tab) {
        activeTab = tab;
        document.querySelectorAll('.analysis-tab-btn').forEach(btn => {
            btn.classList.toggle('analysis-tab-active', btn.dataset.tab === tab);
        });
        document.querySelectorAll('.analysis-tab-panel').forEach(panel => {
            panel.classList.toggle('analysis-tab-panel-visible', panel.dataset.panel === tab);
        });
    }

    // --- Summary Tab ---
    function renderSummary(pkt) {
        const el = document.getElementById('modal-summary');
        const cards = [
            { label: 'Source', value: pkt.srcAddr || '-' },
            { label: 'Destination', value: pkt.dstAddr || '-' },
            { label: 'Protocol', value: pkt.protocol },
            { label: 'Length', value: pkt.length + ' bytes' },
            { label: 'Timestamp', value: pkt.timestamp },
            { label: 'Layers', value: pkt.layers ? pkt.layers.map(l => l.name).join(' > ') : '-' },
        ];
        el.innerHTML = cards.map(c =>
            `<div class="summary-card"><div class="summary-label">${c.label}</div><div class="summary-value">${esc(c.value)}</div></div>`
        ).join('');
    }

    // --- Layers Tab ---
    function renderLayers(pkt) {
        const el = document.getElementById('modal-layers');
        const elFull = document.getElementById('modal-layers-full');
        if (!pkt.layers || pkt.layers.length === 0) {
            el.innerHTML = '<div class="modal-empty">No layer data</div>';
            if (elFull) elFull.innerHTML = '<div class="modal-empty">No layer data</div>';
            return;
        }
        const html = pkt.layers.map(layer => {
            const fields = (layer.fields || []).map(f => {
                let row = `<tr><td class="field-name-cell">${esc(f.name)}</td><td class="field-value-cell">${esc(f.value)}</td></tr>`;
                if (f.children && f.children.length > 0) {
                    row += f.children.map(c =>
                        `<tr class="child-field"><td class="field-name-cell">&nbsp;&nbsp;${esc(c.name)}</td><td class="field-value-cell">${esc(c.value)}</td></tr>`
                    ).join('');
                }
                return row;
            }).join('');
            return `<div class="modal-layer-block">
                <div class="modal-layer-name">${esc(layer.name)}</div>
                <table class="modal-field-table"><tbody>${fields}</tbody></table>
            </div>`;
        }).join('');
        el.innerHTML = html;
        if (elFull) elFull.innerHTML = html;
    }

    function renderFlags(pkt) {
        const el = document.getElementById('modal-flags');
        let tcpLayer = null;
        if (pkt.layers) {
            for (const l of pkt.layers) {
                if (l.name === 'TCP') { tcpLayer = l; break; }
            }
        }
        if (!tcpLayer) {
            el.innerHTML = '<div class="modal-empty">N/A (not TCP)</div>';
            return;
        }

        const flagField = tcpLayer.fields.find(f => f.name === 'Flags');
        const flagStr = flagField ? flagField.value : '';
        const allFlags = ['URG', 'ACK', 'PSH', 'RST', 'SYN', 'FIN'];

        el.innerHTML = `<div class="flag-grid">${allFlags.map(f => {
            const active = flagStr.toUpperCase().includes(f);
            return `<div class="flag-box ${active ? 'flag-active' : 'flag-inactive'}">${f}</div>`;
        }).join('')}</div>` +
        `<div class="flag-raw">${esc(flagStr)}</div>`;
    }

    // --- Hex Tab ---
    function renderHex(pkt) {
        const el = document.getElementById('modal-hex');
        if (!pkt.hexDump) {
            el.innerHTML = '<div class="modal-empty">No hex data</div>';
            return;
        }
        const lines = pkt.hexDump.split('\n');
        el.innerHTML = lines.map(line => {
            if (!line.trim()) return '';
            const match = line.match(/^([0-9a-f]+)\s{2}(.+?)\s{2}\|(.+)\|$/i);
            if (match) {
                return `<span class="hex-offset">${match[1]}</span>  <span class="hex-bytes">${esc(match[2])}</span>  <span class="hex-ascii">|${esc(match[3])}|</span>`;
            }
            return esc(line);
        }).join('\n');
    }

    // --- Visualization Tab ---
    function renderByteChart(pkt) {
        const el = document.getElementById('modal-bytechart');
        if (!pkt.rawHex || pkt.rawHex.length < 2) {
            el.innerHTML = '<div class="modal-empty">No data for analysis</div>';
            return;
        }
        const freq = new Array(256).fill(0);
        for (let i = 0; i < pkt.rawHex.length; i += 2) {
            const b = parseInt(pkt.rawHex.substr(i, 2), 16);
            freq[b]++;
        }
        const maxFreq = Math.max(...freq, 1);
        const totalBytes = pkt.rawHex.length / 2;

        let entropy = 0;
        for (let i = 0; i < 256; i++) {
            if (freq[i] > 0) {
                const p = freq[i] / totalBytes;
                entropy -= p * Math.log2(p);
            }
        }

        let printable = 0;
        for (let i = 0x20; i <= 0x7e; i++) printable += freq[i];
        const printableRatio = (printable / totalBytes * 100).toFixed(1);

        const nullRatio = (freq[0] / totalBytes * 100).toFixed(1);

        const barWidth = 3;
        const svgWidth = 256 * barWidth;
        const svgHeight = 80;
        let bars = '';
        for (let i = 0; i < 256; i++) {
            const h = (freq[i] / maxFreq) * svgHeight;
            const color = i >= 0x20 && i <= 0x7e ? 'var(--green)' : i === 0 ? 'var(--red)' : 'var(--accent)';
            if (h > 0) {
                bars += `<rect x="${i * barWidth}" y="${svgHeight - h}" width="${barWidth - 1}" height="${h}" fill="${color}" opacity="0.7"/>`;
            }
        }

        el.innerHTML =
            `<div class="bytechart-stats">` +
                `<span>Entropy: <strong>${entropy.toFixed(2)}</strong> / 8.00</span>` +
                `<span>Printable: <strong>${printableRatio}%</strong></span>` +
                `<span>Null bytes: <strong>${nullRatio}%</strong></span>` +
                `<span>Total: <strong>${totalBytes}</strong> bytes</span>` +
            `</div>` +
            `<div class="bytechart-svg-wrap">` +
                `<svg viewBox="0 0 ${svgWidth} ${svgHeight}" class="bytechart-svg">${bars}</svg>` +
                `<div class="bytechart-labels"><span>0x00</span><span>0x20</span><span>0x7F</span><span>0xFF</span></div>` +
            `</div>` +
            `<div class="bytechart-legend">` +
                `<span><span class="legend-dot" style="background:var(--green)"></span> Printable ASCII</span>` +
                `<span><span class="legend-dot" style="background:var(--red)"></span> Null</span>` +
                `<span><span class="legend-dot" style="background:var(--accent)"></span> Non-printable</span>` +
            `</div>`;
    }

    function renderHeatmap(pkt) {
        const el = document.getElementById('modal-heatmap');
        if (!pkt.rawHex || pkt.rawHex.length < 2) {
            el.innerHTML = '<div class="modal-empty">No data for heatmap</div>';
            return;
        }

        const totalBytes = pkt.rawHex.length / 2;
        const cols = 32;
        const rows = Math.ceil(totalBytes / cols);
        const maxRows = Math.min(rows, 64); // Cap at 64 rows

        let html = '<div class="heatmap-grid" style="grid-template-columns: repeat(' + cols + ', 1fr);">';
        for (let r = 0; r < maxRows; r++) {
            for (let c = 0; c < cols; c++) {
                const idx = (r * cols + c) * 2;
                if (idx >= pkt.rawHex.length) {
                    html += '<div class="heatmap-cell heatmap-empty"></div>';
                    continue;
                }
                const b = parseInt(pkt.rawHex.substr(idx, 2), 16);
                const isPrintable = b >= 0x20 && b <= 0x7e;
                const isNull = b === 0;
                const offset = r * cols + c;

                // Color: hue from 240 (blue/cold) at 0x00 to 0 (red/hot) at 0xFF
                const hue = 240 - (b / 255) * 240;
                const sat = isNull ? 0 : 80;
                const lum = isNull ? 15 : 30 + (b / 255) * 30;
                const char = isPrintable ? String.fromCharCode(b) : '.';

                html += `<div class="heatmap-cell" style="background:hsl(${hue},${sat}%,${lum}%)" ` +
                    `title="Offset: 0x${offset.toString(16).padStart(4, '0')}  Byte: 0x${b.toString(16).padStart(2, '0')} (${b})  Char: ${char}">` +
                    `</div>`;
            }
        }
        html += '</div>';
        if (rows > maxRows) {
            html += `<div class="heatmap-info">Showing ${maxRows * cols} of ${totalBytes} bytes</div>`;
        }
        html += `<div class="heatmap-scale">` +
            `<span>0x00</span>` +
            `<div class="heatmap-gradient"></div>` +
            `<span>0xFF</span>` +
        `</div>`;
        el.innerHTML = html;
    }

    function renderFlowDiagram(pkt) {
        const el = document.getElementById('modal-flow');
        if (!pkt.layers || pkt.layers.length === 0) {
            el.innerHTML = '<div class="modal-empty">No layer data for flow</div>';
            return;
        }

        const layers = pkt.layers;
        const svgH = 60;
        const boxW = 100;
        const gap = 40;
        const totalW = layers.length * boxW + (layers.length - 1) * gap;
        const svgW = Math.max(totalW + 40, 400);

        let svg = `<svg viewBox="0 0 ${svgW} ${svgH}" class="flow-svg">`;

        layers.forEach((layer, i) => {
            const x = 20 + i * (boxW + gap);
            const y = 10;
            const h = 40;

            // Color by layer type
            const colors = {
                'Ethernet': 'var(--peach)', 'IPv4': 'var(--accent)', 'IPv6': 'var(--mauve)',
                'TCP': 'var(--green)', 'UDP': 'var(--accent-dim)', 'ARP': 'var(--peach)',
                'DNS': 'var(--teal)', 'ICMP': 'var(--yellow)', 'HTTP': 'var(--green)',
            };
            const color = colors[layer.name] || 'var(--text-dim)';

            svg += `<rect x="${x}" y="${y}" width="${boxW}" height="${h}" rx="5" ` +
                `fill="none" stroke="${color}" stroke-width="2" opacity="0.8"/>`;
            svg += `<text x="${x + boxW/2}" y="${y + h/2 + 5}" text-anchor="middle" ` +
                `fill="${color}" font-size="12" font-weight="600" font-family="monospace">${esc(layer.name)}</text>`;

            // Arrow to next
            if (i < layers.length - 1) {
                const ax = x + boxW;
                const ay = y + h / 2;
                svg += `<line x1="${ax}" y1="${ay}" x2="${ax + gap - 5}" y2="${ay}" ` +
                    `stroke="var(--text-dim)" stroke-width="1.5" marker-end="url(#arrowhead)"/>`;
            }
        });

        // Arrowhead marker
        svg += `<defs><marker id="arrowhead" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">` +
            `<polygon points="0 0, 8 3, 0 6" fill="var(--text-dim)"/></marker></defs>`;
        svg += '</svg>';

        // Add size info per layer
        let info = '<div class="flow-info">';
        layers.forEach(layer => {
            const fieldCount = (layer.fields || []).length;
            info += `<span class="flow-layer-tag">${esc(layer.name)}: ${fieldCount} fields</span>`;
        });
        info += '</div>';

        el.innerHTML = svg + info;
    }

    // --- Payload Tab ---
    function renderAscii(pkt) {
        const el = document.getElementById('modal-ascii');
        if (!pkt.rawHex || pkt.rawHex.length < 2) {
            el.innerHTML = '<div class="modal-empty">No data</div>';
            return;
        }
        let text = '';
        for (let i = 0; i < pkt.rawHex.length; i += 2) {
            const b = parseInt(pkt.rawHex.substr(i, 2), 16);
            text += (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : '.';
        }
        el.textContent = text;
    }

    function renderPayloadDecode(pkt) {
        const el = document.getElementById('modal-payload-decode');
        if (!pkt.rawHex || pkt.rawHex.length < 2) {
            el.innerHTML = '<div class="modal-empty">No payload data</div>';
            return;
        }

        // Raw bytes
        const bytes = [];
        for (let i = 0; i < pkt.rawHex.length; i += 2) {
            bytes.push(parseInt(pkt.rawHex.substr(i, 2), 16));
        }

        // Extract ASCII printable content (rough payload extraction)
        let asciiStr = '';
        for (const b of bytes) {
            asciiStr += (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : '.';
        }

        // Try to find strings (runs of 4+ printable chars)
        const strings = [];
        let current = '';
        for (const b of bytes) {
            if (b >= 0x20 && b <= 0x7e) {
                current += String.fromCharCode(b);
            } else {
                if (current.length >= 4) strings.push(current);
                current = '';
            }
        }
        if (current.length >= 4) strings.push(current);

        // Base64 detection
        const base64Regex = /[A-Za-z0-9+/]{20,}={0,2}/g;
        const b64Matches = asciiStr.match(base64Regex) || [];
        let b64Decoded = '';
        if (b64Matches.length > 0) {
            try {
                b64Decoded = atob(b64Matches[0]);
            } catch (e) {
                b64Decoded = '(invalid base64)';
            }
        }

        // URL-encoded detection
        const urlRegex = /%[0-9A-Fa-f]{2}/g;
        const urlMatches = asciiStr.match(urlRegex) || [];
        let urlDecoded = '';
        if (urlMatches.length > 2) {
            try {
                urlDecoded = decodeURIComponent(asciiStr.replace(/[^\x20-\x7e]/g, ''));
            } catch (e) {
                urlDecoded = '(decode error)';
            }
        }

        let html = '';

        // Extracted strings
        if (strings.length > 0) {
            html += '<div class="decode-section"><div class="decode-title">Extracted Strings (' + strings.length + ')</div>';
            html += '<pre class="decode-pre">' + strings.map(s => esc(s)).join('\n') + '</pre></div>';
        }

        // Base64
        if (b64Matches.length > 0) {
            html += '<div class="decode-section"><div class="decode-title">Base64 Detected</div>';
            html += '<pre class="decode-pre">' + esc(b64Matches[0].substring(0, 200)) + '</pre>';
            html += '<div class="decode-subtitle">Decoded:</div>';
            html += '<pre class="decode-pre">' + esc(b64Decoded.substring(0, 500)) + '</pre></div>';
        }

        // URL-encoded
        if (urlMatches.length > 2) {
            html += '<div class="decode-section"><div class="decode-title">URL-Encoded Content</div>';
            html += '<pre class="decode-pre">' + esc(urlDecoded.substring(0, 500)) + '</pre></div>';
        }

        if (!html) {
            html = '<div class="modal-empty">No decodable payload patterns found</div>';
        }

        el.innerHTML = html;
    }

    // --- Export ---
    function exportJson() {
        if (!currentPkt) return;
        const json = JSON.stringify(currentPkt, null, 2);
        downloadText('packet-' + currentPkt.number + '.json', json);
    }

    function exportHex() {
        if (!currentPkt || !currentPkt.hexDump) return;
        downloadText('packet-' + currentPkt.number + '.hex', currentPkt.hexDump);
    }

    function exportCopy() {
        if (!currentPkt) return;
        const json = JSON.stringify(currentPkt, null, 2);
        navigator.clipboard.writeText(json).then(() => {
            const btn = document.getElementById('analysis-export-copy');
            if (btn) {
                btn.textContent = 'Copied!';
                setTimeout(() => { btn.textContent = 'Copy JSON'; }, 1500);
            }
        });
    }

    function downloadText(filename, text) {
        const blob = new Blob([text], { type: 'text/plain' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = filename;
        a.click();
        URL.revokeObjectURL(a.href);
    }

    function esc(s) {
        if (!s) return '';
        return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    return { init, open };
})();
