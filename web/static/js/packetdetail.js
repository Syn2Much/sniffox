// packetdetail.js — Middle pane: expandable protocol tree
'use strict';

const PacketDetail = (() => {
    let container = null;

    function init() {
        container = document.getElementById('detail-tree');
    }

    function show(pkt) {
        if (!pkt || !pkt.layers || pkt.layers.length === 0) {
            container.innerHTML = '<div class="empty-state">No layer details available</div>';
            return;
        }
        container.innerHTML = '';

        // Action button bar
        const bar = document.createElement('div');
        bar.className = 'detail-action-bar';

        const analyzeBtn = document.createElement('button');
        analyzeBtn.className = 'detail-analyze-btn';
        analyzeBtn.textContent = 'Deep Analysis';
        analyzeBtn.addEventListener('click', () => PacketModal.open(pkt));
        bar.appendChild(analyzeBtn);

        // Follow Stream button — shown when packet has a stream ID
        if (pkt.streamId) {
            const streamBtn = document.createElement('button');
            streamBtn.className = 'detail-stream-btn';
            streamBtn.textContent = 'Follow Stream';
            streamBtn.addEventListener('click', () => {
                if (typeof Streams !== 'undefined') {
                    Streams.open(pkt.streamId);
                }
            });
            bar.appendChild(streamBtn);
        }

        container.appendChild(bar);

        pkt.layers.forEach(layer => {
            container.appendChild(buildLayerNode(layer));
        });
    }

    function buildLayerNode(layer) {
        const node = document.createElement('div');
        node.className = 'layer-node';

        const header = document.createElement('div');
        header.className = 'layer-header';

        const toggle = document.createElement('span');
        toggle.className = 'layer-toggle';
        toggle.textContent = '\u25BC';

        const name = document.createElement('span');
        name.textContent = layer.name;

        header.appendChild(toggle);
        header.appendChild(name);

        const fields = document.createElement('div');
        fields.className = 'layer-fields';
        if (layer.fields) {
            layer.fields.forEach(f => {
                fields.appendChild(buildField(f));
            });
        }

        header.addEventListener('click', () => {
            fields.classList.toggle('collapsed');
            toggle.textContent = fields.classList.contains('collapsed') ? '\u25B6' : '\u25BC';
        });

        node.appendChild(header);
        node.appendChild(fields);
        return node;
    }

    function buildField(field) {
        const row = document.createElement('div');
        row.className = 'field-row';
        row.innerHTML = `<span class="field-name">${esc(field.name)}:</span> ${esc(field.value)}`;

        if (field.children && field.children.length > 0) {
            const children = document.createElement('div');
            children.className = 'field-children';
            field.children.forEach(c => children.appendChild(buildField(c)));
            row.appendChild(children);
        }

        return row;
    }

    function clear() {
        if (container) {
            container.innerHTML = '<div class="empty-state">Select a packet to view details</div>';
        }
    }

    function esc(s) {
        if (!s) return '';
        return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    return { init, show, clear };
})();
