// app.js — WebSocket connection, message dispatch, toolbar controls, keyboard shortcuts
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

    // Current capture view: 'packets' or 'flows'
    let captureView = 'packets';

    // Track capture state for welcome/live display
    let isCapturing = false;
    let hasPackets = false;

    // Packet rate tracking
    let pktRateCount = 0;
    let pktRateInterval = null;
    let currentRate = 0;

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
        els.welcomeState = document.getElementById('welcome-state');
        els.captureTabs = document.getElementById('capture-tabs');
        els.liveIndicator = document.getElementById('live-indicator');
        els.statusRate = document.getElementById('status-rate');
        els.tabPktCount = document.getElementById('tab-pkt-count');
        els.tabFlowCount = document.getElementById('tab-flow-count');

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
        Flows.init();
        Streams.init();
        if (typeof Timeline !== 'undefined') Timeline.init();
        if (typeof Topology !== 'undefined') Topology.init();
        if (typeof Endpoints !== 'undefined') Endpoints.init();
        if (typeof ThreatIntel !== 'undefined') ThreatIntel.init();
        if (typeof Bookmarks !== 'undefined') Bookmarks.init();
        if (typeof CommandPalette !== 'undefined') CommandPalette.init();
        if (typeof Sessions !== 'undefined') Sessions.init();
        initResizers();
        initGraphControls();
        initCaptureViewTabs();
        initKeyboardShortcuts();
        initSaveSession();
        loadTheme();

        // Packet rate display
        pktRateInterval = setInterval(updateRate, 1000);

        // Initialize router last — it triggers page navigation
        Router.init();
        Router.onChange((route) => {
            // Stop animation loops on pages we're leaving
            if (route !== 'graph') View3D.onPageHidden();
            if (route !== 'timeline' && typeof Timeline !== 'undefined') Timeline.onPageHidden();
            if (route !== 'topology' && typeof Topology !== 'undefined') Topology.onPageHidden();

            // Start animation loops on the page we're entering
            if (route === 'graph') View3D.onPageVisible();
            if (route === 'timeline' && typeof Timeline !== 'undefined') Timeline.onPageVisible();
            if (route === 'topology' && typeof Topology !== 'undefined') Topology.onPageVisible();

            // Refresh sessions list when navigating to sessions page
            if (route === 'sessions' && typeof Sessions !== 'undefined') Sessions.loadList();
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

    // --- Welcome/Capture State Management ---
    function showCaptureUI() {
        if (hasPackets) return;
        hasPackets = true;
        if (els.welcomeState) els.welcomeState.classList.add('hidden');
        if (els.captureTabs) els.captureTabs.style.display = 'flex';
        const panes = document.getElementById('panes');
        if (panes) panes.style.display = 'flex';
    }

    function showWelcomeState() {
        hasPackets = false;
        if (els.welcomeState) els.welcomeState.classList.remove('hidden');
        if (els.captureTabs) els.captureTabs.style.display = 'none';
        const panes = document.getElementById('panes');
        if (panes) panes.style.display = 'none';
        const flowWrap = document.getElementById('flow-table-wrap');
        if (flowWrap) flowWrap.style.display = 'none';
    }

    // --- Capture View Tabs (Packets / Flows) ---
    function initCaptureViewTabs() {
        document.querySelectorAll('.capture-view-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.capture-view-tab').forEach(t => t.classList.remove('active'));
                tab.classList.add('active');
                captureView = tab.dataset.view;

                const packetsView = document.getElementById('panes');
                const flowsView = document.getElementById('flow-table-wrap');

                if (captureView === 'flows') {
                    if (packetsView) packetsView.style.display = 'none';
                    if (flowsView) flowsView.style.display = 'flex';
                    Flows.setVisible(true);
                } else {
                    if (packetsView) packetsView.style.display = 'flex';
                    if (flowsView) flowsView.style.display = 'none';
                    Flows.setVisible(false);
                }
            });
        });
    }

    // --- Keyboard Shortcuts ---
    function initKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            // Ctrl+F or Cmd+F -> focus display filter
            if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
                // Only intercept on capture page
                if (Router.current() === 'capture') {
                    e.preventDefault();
                    if (els.displayFilter) {
                        els.displayFilter.focus();
                        els.displayFilter.select();
                    }
                }
            }

            // Escape -> dismiss overlays and clear filter focus
            if (e.key === 'Escape') {
                // Close stream viewer if open
                const streamOverlay = document.getElementById('stream-overlay');
                if (streamOverlay && streamOverlay.classList.contains('stream-visible')) {
                    if (typeof Streams !== 'undefined') Streams.close();
                    return;
                }
                // Close 3D expand if open
                const v3dOverlay = document.getElementById('v3d-expand-overlay');
                if (v3dOverlay && v3dOverlay.classList.contains('v3d-expanded')) {
                    v3dOverlay.classList.remove('v3d-expanded');
                    return;
                }
                // Blur active filter
                if (document.activeElement === els.displayFilter || document.activeElement === els.bpfFilter) {
                    document.activeElement.blur();
                }
            }

            // Arrow keys for packet navigation (only when not in an input)
            if (e.key === 'ArrowUp' || e.key === 'ArrowDown') {
                const active = document.activeElement;
                const isInput = active && (active.tagName === 'INPUT' || active.tagName === 'SELECT' || active.tagName === 'TEXTAREA');
                if (!isInput && Router.current() === 'capture') {
                    e.preventDefault();
                    PacketList.navigateByKey(e.key === 'ArrowUp' ? -1 : 1);
                }
            }

            // Number keys 1-9 for quick page navigation (when not in input)
            if (e.key >= '1' && e.key <= '9' && e.altKey) {
                const active = document.activeElement;
                const isInput = active && (active.tagName === 'INPUT' || active.tagName === 'SELECT' || active.tagName === 'TEXTAREA');
                if (!isInput) {
                    e.preventDefault();
                    const routes = ['capture', 'graph', 'security', 'analysis', 'timeline', 'topology', 'endpoints', 'threatintel', 'sessions'];
                    const idx = parseInt(e.key) - 1;
                    if (routes[idx]) Router.navigate(routes[idx]);
                }
            }
        });
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

        if (batch.length > 0 && !hasPackets) {
            showCaptureUI();
        }

        for (const pkt of batch) {
            PacketList.addPacket(pkt);
            View3D.addPacket(pkt);
            Security.analyze(pkt);
            if (typeof Timeline !== 'undefined') Timeline.addPacket(pkt);
            if (typeof Topology !== 'undefined') Topology.addPacket(pkt);
            if (typeof Endpoints !== 'undefined') Endpoints.addPacket(pkt);
            if (typeof ThreatIntel !== 'undefined') ThreatIntel.addPacket(pkt);
            pktRateCount++;
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
            case 'flow_update':
                Flows.update(msg.payload);
                updateFlowCount();
                break;
            case 'stream_data':
                Streams.handleStreamData(msg.payload);
                break;
            case 'flows':
                Flows.update(msg.payload);
                updateFlowCount();
                break;
            case 'capture_stats':
                updateStats(msg.payload);
                break;
            case 'stream_event':
                if (typeof Streams !== 'undefined' && Streams.handleStreamEvent) {
                    Streams.handleStreamEvent(msg.payload);
                }
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
        isCapturing = capturing;
        els.btnStart.disabled = capturing;
        els.btnStop.disabled = !capturing;
        els.interfaceSelect.disabled = capturing;
        els.bpfFilter.disabled = capturing;
        // Sync graph page buttons
        if (els.graphBtnStart) els.graphBtnStart.disabled = capturing;
        if (els.graphBtnStop) els.graphBtnStop.disabled = !capturing;
        if (els.graphIfaceSelect) els.graphIfaceSelect.disabled = capturing;
        // Live indicator
        if (els.liveIndicator) {
            els.liveIndicator.classList.toggle('active', capturing);
        }
        if (capturing && info) {
            els.captureInfo.textContent = 'Capturing on ' + (info.interfaceName || '');
            showToast('Capture started on ' + (info.interfaceName || ''), 'success');
        } else if (!capturing) {
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
        Flows.clear();
        if (typeof Timeline !== 'undefined') Timeline.clear();
        if (typeof Topology !== 'undefined') Topology.clear();
        if (typeof Endpoints !== 'undefined') Endpoints.clear();
        if (typeof ThreatIntel !== 'undefined') ThreatIntel.clear();
        showWelcomeState();
        pktRateCount = 0;
        currentRate = 0;
        updateCounts();
    }

    function uploadPcap(e) {
        const file = e.target.files[0];
        if (!file) return;
        const formData = new FormData();
        formData.append('file', file);
        clearPackets();
        els.captureInfo.textContent = 'Loading ' + file.name + '...';

        fetch('/api/upload', { method: 'POST', body: formData })
            .then(r => {
                if (!r.ok) return r.text().then(t => { throw new Error(t); });
                els.captureInfo.textContent = 'Loaded ' + file.name;
                showToast('Loaded ' + file.name, 'success');
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
        // Visual feedback on filter input
        els.displayFilter.classList.remove('filter-error', 'filter-active');
        if (filterText) {
            els.displayFilter.classList.add('filter-active');
        }
        updateCounts();
    }

    function updateCounts() {
        const total = PacketList.totalCount();
        const displayed = PacketList.displayedCount();
        els.packetCount.textContent = total;
        els.displayedCount.textContent = displayed;
        const alertTotal = document.getElementById('alert-total');
        if (alertTotal) alertTotal.textContent = document.getElementById('alert-badge').textContent || '0';
        // Update tab counts
        if (els.tabPktCount) els.tabPktCount.textContent = formatCompact(displayed);
    }

    function updateFlowCount() {
        if (els.tabFlowCount && typeof Flows !== 'undefined' && Flows.count) {
            els.tabFlowCount.textContent = formatCompact(Flows.count());
        }
    }

    function updateRate() {
        currentRate = pktRateCount;
        pktRateCount = 0;
        if (els.statusRate && isCapturing) {
            els.statusRate.textContent = currentRate + ' pkt/s';
        } else if (els.statusRate) {
            els.statusRate.textContent = '';
        }
    }

    function formatCompact(n) {
        if (n < 1000) return String(n);
        if (n < 10000) return (n / 1000).toFixed(1) + 'K';
        if (n < 1000000) return Math.round(n / 1000) + 'K';
        return (n / 1000000).toFixed(1) + 'M';
    }

    function updateStats(stats) {
        if (stats.packetCount !== undefined) {
            els.packetCount.textContent = stats.packetCount;
        }
    }

    function showToast(message, type) {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = 'toast ' + (type || 'info');
        toast.textContent = message;
        // Click to dismiss
        toast.addEventListener('click', () => {
            toast.classList.add('toast-exit');
            setTimeout(() => toast.remove(), 250);
        });
        container.appendChild(toast);
        // Auto-dismiss with exit animation
        setTimeout(() => {
            if (toast.parentElement) {
                toast.classList.add('toast-exit');
                setTimeout(() => toast.remove(), 250);
            }
        }, 4500);
    }

    // --- Save Session Button ---
    function initSaveSession() {
        const btn = document.getElementById('btn-save-session');
        if (!btn) return;
        btn.addEventListener('click', () => {
            if (typeof Sessions !== 'undefined') {
                Sessions.saveFromPalette();
            }
        });
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
