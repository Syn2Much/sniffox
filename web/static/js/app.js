// app.js — WebSocket connection, message dispatch, toolbar controls
'use strict';

const App = (() => {
    let ws = null;
    let reconnectTimer = null;
    const RECONNECT_DELAY = 3000;

    const els = {};

    // Batch incoming WS packets — process up to N per rAF tick
    let msgQueue = [];
    let msgRafId = null;
    const MSG_BATCH_SIZE = 100;

    function init() {
        els.interfaceSelect = document.getElementById('interface-select');
        els.bpfFilter = document.getElementById('bpf-filter');
        els.displayFilter = document.getElementById('display-filter');
        els.filterPreset = document.getElementById('filter-preset');
        els.btnStart = document.getElementById('btn-start');
        els.btnStop = document.getElementById('btn-stop');
        els.btnClear = document.getElementById('btn-clear');
        els.btnTheme = document.getElementById('btn-theme');
        els.themeIcon = document.getElementById('theme-icon');
        els.pcapFile = document.getElementById('pcap-file');
        els.connectionIndicator = document.getElementById('connection-indicator');
        els.connectionStatus = document.getElementById('connection-status');
        els.packetCount = document.getElementById('packet-count');
        els.displayedCount = document.getElementById('displayed-count');
        els.captureInfo = document.getElementById('capture-info');

        els.btnStart.addEventListener('click', startCapture);
        els.btnStop.addEventListener('click', stopCapture);
        els.btnClear.addEventListener('click', clearPackets);
        els.pcapFile.addEventListener('change', uploadPcap);
        els.displayFilter.addEventListener('input', applyDisplayFilter);
        els.filterPreset.addEventListener('change', onFilterPreset);
        els.btnTheme.addEventListener('click', toggleTheme);

        PacketList.init();
        PacketDetail.init();
        HexView.init();
        View3D.init();
        Security.init();
        PacketModal.init();
        initResizers();
        initGraphControls();
        loadTheme();

        // Initialize router last — it triggers page navigation
        Router.init();
        Router.onChange((route) => {
            // Resize 3D view when graph page becomes visible
            if (route === 'graph') {
                View3D.onPageVisible();
            }
        });

        connect();
    }

    // --- Theme ---
    const THEMES = ['dark', 'dim', 'light'];
    const THEME_ICONS = { dark: '&#9790;', dim: '&#9788;', light: '&#9728;' };
    const THEME_LABELS = { dark: 'Dark', dim: 'Dim', light: 'Light' };

    function loadTheme() {
        const saved = localStorage.getItem('sniffox-theme') || 'dark';
        applyTheme(saved);
    }

    function toggleTheme() {
        const current = document.documentElement.getAttribute('data-theme');
        const idx = THEMES.indexOf(current);
        const next = THEMES[(idx + 1) % THEMES.length];
        applyTheme(next);
        localStorage.setItem('sniffox-theme', next);
    }

    function applyTheme(theme) {
        if (!THEMES.includes(theme)) theme = 'dark';
        document.documentElement.setAttribute('data-theme', theme);
        els.themeIcon.innerHTML = THEME_ICONS[theme];
        const labelEl = document.getElementById('theme-label');
        if (labelEl) labelEl.textContent = THEME_LABELS[theme];
        View3D.updateTheme(theme !== 'light');
    }

    // --- Filter presets ---
    function onFilterPreset() {
        const val = els.filterPreset.value;
        if (!val) return;
        els.displayFilter.value = val;
        els.filterPreset.value = '';
        applyDisplayFilter();
    }

    // --- WebSocket ---
    function connect() {
        setConnectionState('connecting');
        const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        ws = new WebSocket(`${proto}//${location.host}/ws`);

        ws.onopen = () => {
            setConnectionState('connected');
            clearReconnect();
            send('get_interfaces', null);
        };

        ws.onmessage = (evt) => {
            try {
                const msg = JSON.parse(evt.data);
                if (msg.type === 'packet') {
                    // Queue packets for batched processing
                    msgQueue.push(msg.payload);
                    if (!msgRafId) {
                        msgRafId = requestAnimationFrame(flushMsgQueue);
                    }
                } else {
                    // Control messages handled immediately
                    handleControl(msg);
                }
            } catch (e) {
                console.error('Bad WS message:', e);
            }
        };

        ws.onclose = () => {
            setConnectionState('disconnected');
            scheduleReconnect();
        };

        ws.onerror = () => {
            ws.close();
        };
    }

    function flushMsgQueue() {
        msgRafId = null;
        const batch = msgQueue.splice(0, MSG_BATCH_SIZE);
        for (const pkt of batch) {
            PacketList.addPacket(pkt);
            View3D.addPacket(pkt);
            Security.analyze(pkt);
        }
        updateCounts();

        // If there are still queued messages, schedule another tick
        if (msgQueue.length > 0) {
            msgRafId = requestAnimationFrame(flushMsgQueue);
        }
    }

    function handleControl(msg) {
        switch (msg.type) {
            case 'interfaces':
                populateInterfaces(msg.payload);
                break;
            case 'capture_started':
                setCaptureState(true, msg.payload);
                break;
            case 'capture_stopped':
                setCaptureState(false, null);
                break;
            case 'stats':
                updateStats(msg.payload);
                break;
            case 'error':
                showToast(msg.payload.message, 'error');
                break;
        }
    }

    function scheduleReconnect() {
        if (reconnectTimer) return;
        reconnectTimer = setTimeout(() => {
            reconnectTimer = null;
            connect();
        }, RECONNECT_DELAY);
    }

    function clearReconnect() {
        if (reconnectTimer) {
            clearTimeout(reconnectTimer);
            reconnectTimer = null;
        }
    }

    function setConnectionState(state) {
        els.connectionIndicator.className = state;
        const labels = { connected: 'Connected', disconnected: 'Disconnected', connecting: 'Connecting...' };
        els.connectionStatus.textContent = labels[state] || state;
    }

    function send(type, payload) {
        if (!ws || ws.readyState !== WebSocket.OPEN) return;
        ws.send(JSON.stringify({ type, payload }));
    }

    function populateInterfaces(interfaces) {
        els.interfaceSelect.innerHTML = '<option value="">-- Select Interface --</option>';
        if (!interfaces) return;
        const allAddrs = [];
        interfaces.forEach(iface => {
            const opt = document.createElement('option');
            opt.value = iface.name;
            const addrs = iface.addresses ? ` (${iface.addresses.join(', ')})` : '';
            opt.textContent = iface.name + addrs;
            els.interfaceSelect.appendChild(opt);
            if (iface.addresses) {
                iface.addresses.forEach(a => allAddrs.push(a));
            }
        });
        // Feed local IPs to the filter engine for direction filters
        Filters.setLocalAddresses(allAddrs);
        // Sync graph page interface select
        syncGraphInterfaceSelect();
    }

    function startCapture() {
        const iface = els.interfaceSelect.value;
        if (!iface) {
            showToast('Please select a network interface', 'error');
            return;
        }
        clearPackets();
        send('start_capture', {
            interface: iface,
            bpfFilter: els.bpfFilter.value
        });
    }

    function stopCapture() {
        // Optimistic UI — update immediately for responsiveness
        setCaptureState(false, null);
        send('stop_capture', null);
    }

    function setCaptureState(capturing, info) {
        els.btnStart.disabled = capturing;
        els.btnStop.disabled = !capturing;
        els.interfaceSelect.disabled = capturing;
        els.bpfFilter.disabled = capturing;
        // Sync graph page buttons
        if (els.graphBtnStart) els.graphBtnStart.disabled = capturing;
        if (els.graphBtnStop) els.graphBtnStop.disabled = !capturing;
        if (els.graphIfaceSelect) els.graphIfaceSelect.disabled = capturing;
        if (capturing && info) {
            els.captureInfo.textContent = `Capturing on ${info.interfaceName || ''}`;
        } else {
            els.captureInfo.textContent = 'Capture stopped';
        }
    }

    // --- Graph page capture controls ---
    function initGraphControls() {
        els.graphIfaceSelect = document.getElementById('graph-interface-select');
        els.graphBtnStart = document.getElementById('graph-btn-start');
        els.graphBtnStop = document.getElementById('graph-btn-stop');
        if (!els.graphBtnStart) return;

        els.graphBtnStart.addEventListener('click', () => {
            // Sync selection to main select before starting
            if (els.graphIfaceSelect) {
                els.interfaceSelect.value = els.graphIfaceSelect.value;
            }
            startCapture();
        });
        els.graphBtnStop.addEventListener('click', stopCapture);

        // Keep graph select in sync with main select
        els.interfaceSelect.addEventListener('change', () => {
            if (els.graphIfaceSelect) els.graphIfaceSelect.value = els.interfaceSelect.value;
        });
        els.graphIfaceSelect.addEventListener('change', () => {
            els.interfaceSelect.value = els.graphIfaceSelect.value;
        });
    }

    function syncGraphInterfaceSelect() {
        if (!els.graphIfaceSelect) return;
        els.graphIfaceSelect.innerHTML = els.interfaceSelect.innerHTML;
        els.graphIfaceSelect.value = els.interfaceSelect.value;
    }

    function clearPackets() {
        msgQueue = [];
        if (msgRafId) { cancelAnimationFrame(msgRafId); msgRafId = null; }
        PacketList.clear();
        PacketDetail.clear();
        HexView.clear();
        View3D.clear();
        Security.clear();
        updateCounts();
    }

    function uploadPcap(e) {
        const file = e.target.files[0];
        if (!file) return;
        const formData = new FormData();
        formData.append('file', file);
        clearPackets();
        els.captureInfo.textContent = `Loading ${file.name}...`;

        fetch('/api/upload', { method: 'POST', body: formData })
            .then(r => {
                if (!r.ok) return r.text().then(t => { throw new Error(t); });
                els.captureInfo.textContent = `Loaded ${file.name}`;
            })
            .catch(err => {
                showToast('Upload failed: ' + err.message, 'error');
                els.captureInfo.textContent = '';
            });
        e.target.value = '';
    }

    function applyDisplayFilter() {
        const filterText = els.displayFilter.value.trim();
        PacketList.applyFilter(filterText);
        updateCounts();
    }

    function updateCounts() {
        els.packetCount.textContent = PacketList.totalCount();
        els.displayedCount.textContent = PacketList.displayedCount();
        const alertTotal = document.getElementById('alert-total');
        if (alertTotal) alertTotal.textContent = document.getElementById('alert-badge').textContent || '0';
    }

    function updateStats(stats) {
        if (stats.packetCount !== undefined) {
            els.packetCount.textContent = stats.packetCount;
        }
    }

    function showToast(message, type) {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `toast ${type || 'info'}`;
        toast.textContent = message;
        container.appendChild(toast);
        setTimeout(() => toast.remove(), 5000);
    }

    // --- Resizers ---
    function initResizers() {
        setupResizer('resizer-1', 'packet-list-pane', 'packet-detail-pane');
        setupResizer('resizer-2', 'packet-detail-pane', 'hex-view-pane');
    }

    function setupResizer(resizerId, topPaneId, bottomPaneId) {
        const resizer = document.getElementById(resizerId);
        const topPane = document.getElementById(topPaneId);
        const bottomPane = document.getElementById(bottomPaneId);
        if (!resizer || !topPane || !bottomPane) return;
        let startY, startTopH, startBottomH;

        resizer.addEventListener('mousedown', (e) => {
            e.preventDefault();
            startY = e.clientY;
            startTopH = topPane.getBoundingClientRect().height;
            startBottomH = bottomPane.getBoundingClientRect().height;
            resizer.classList.add('active');
            document.addEventListener('mousemove', onMouseMove);
            document.addEventListener('mouseup', onMouseUp);
        });

        function onMouseMove(e) {
            const dy = e.clientY - startY;
            const newTop = Math.max(60, startTopH + dy);
            const newBottom = Math.max(60, startBottomH - dy);
            topPane.style.flex = 'none';
            bottomPane.style.flex = 'none';
            topPane.style.height = newTop + 'px';
            bottomPane.style.height = newBottom + 'px';
        }

        function onMouseUp() {
            resizer.classList.remove('active');
            document.removeEventListener('mousemove', onMouseMove);
            document.removeEventListener('mouseup', onMouseUp);
        }
    }

    document.addEventListener('DOMContentLoaded', init);

    return { send, showToast };
})();
