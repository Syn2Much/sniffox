// commandpalette.js — Ctrl+K command palette for quick navigation and actions
'use strict';

const CommandPalette = (() => {
    let overlayEl = null;
    let inputEl = null;
    let listEl = null;
    let visible = false;
    let selectedIdx = 0;
    let filteredCommands = [];

    const commands = [
        // Navigation
        { id: 'nav-capture', label: 'Go to Capture', section: 'Navigation', icon: '&#9654;', action: () => Router.navigate('capture') },
        { id: 'nav-graph', label: 'Go to 3D Graph', section: 'Navigation', icon: '&#9672;', action: () => Router.navigate('graph') },
        { id: 'nav-security', label: 'Go to Security Dashboard', section: 'Navigation', icon: '&#9888;', action: () => Router.navigate('security') },
        { id: 'nav-analysis', label: 'Go to Packet Analysis', section: 'Navigation', icon: '&#9881;', action: () => Router.navigate('analysis') },
        { id: 'nav-timeline', label: 'Go to Timeline', section: 'Navigation', icon: '&#9866;', action: () => Router.navigate('timeline') },
        { id: 'nav-topology', label: 'Go to Topology', section: 'Navigation', icon: '&#9737;', action: () => Router.navigate('topology') },
        { id: 'nav-endpoints', label: 'Go to Endpoints', section: 'Navigation', icon: '&#9783;', action: () => Router.navigate('endpoints') },
        { id: 'nav-threatintel', label: 'Go to Threat Intel', section: 'Navigation', icon: '&#9760;', action: () => Router.navigate('threatintel') },
        { id: 'nav-sessions', label: 'Go to Sessions', section: 'Navigation', icon: '&#128190;', action: () => Router.navigate('sessions') },

        // Capture actions
        { id: 'start-capture', label: 'Start Capture', section: 'Capture', icon: '&#9654;', action: () => document.getElementById('btn-start')?.click() },
        { id: 'stop-capture', label: 'Stop Capture', section: 'Capture', icon: '&#9632;', action: () => document.getElementById('btn-stop')?.click() },
        { id: 'clear-packets', label: 'Clear All Packets', section: 'Capture', icon: '&#10006;', action: () => document.getElementById('btn-clear')?.click() },
        { id: 'export-pcap', label: 'Download PCAP Export', section: 'Capture', icon: '&#11015;', action: () => window.location.href = '/api/export' },
        { id: 'save-session', label: 'Save Current Session', section: 'Capture', icon: '&#128190;', action: () => { if (typeof Sessions !== 'undefined') Sessions.saveFromPalette(); } },

        // Filters
        { id: 'filter-tcp', label: 'Filter: TCP only', section: 'Filters', icon: '&#128269;', action: () => setFilter('tcp') },
        { id: 'filter-udp', label: 'Filter: UDP only', section: 'Filters', icon: '&#128269;', action: () => setFilter('udp') },
        { id: 'filter-dns', label: 'Filter: DNS only', section: 'Filters', icon: '&#128269;', action: () => setFilter('dns') },
        { id: 'filter-http', label: 'Filter: HTTP only', section: 'Filters', icon: '&#128269;', action: () => setFilter('http') },
        { id: 'filter-tls', label: 'Filter: TLS only', section: 'Filters', icon: '&#128269;', action: () => setFilter('tls') },
        { id: 'filter-arp', label: 'Filter: ARP only', section: 'Filters', icon: '&#128269;', action: () => setFilter('arp') },
        { id: 'filter-no-arp', label: 'Filter: No ARP', section: 'Filters', icon: '&#128269;', action: () => setFilter('!arp') },
        { id: 'filter-inbound', label: 'Filter: Inbound traffic', section: 'Filters', icon: '&#128269;', action: () => setFilter('inbound') },
        { id: 'filter-outbound', label: 'Filter: Outbound traffic', section: 'Filters', icon: '&#128269;', action: () => setFilter('outbound') },
        { id: 'filter-bookmarked', label: 'Filter: Bookmarked packets', section: 'Filters', icon: '&#9733;', action: () => setFilter('bookmarked') },
        { id: 'filter-clear', label: 'Clear Display Filter', section: 'Filters', icon: '&#128269;', action: () => setFilter('') },

        // Theme
        { id: 'theme-dark', label: 'Theme: Dark', section: 'Settings', icon: '&#9790;', action: () => applyTheme('dark') },
        { id: 'theme-dim', label: 'Theme: Dim', section: 'Settings', icon: '&#9788;', action: () => applyTheme('dim') },
        { id: 'theme-light', label: 'Theme: Light', section: 'Settings', icon: '&#9728;', action: () => applyTheme('light') },

        // Tools
        { id: 'focus-filter', label: 'Focus Display Filter', section: 'Tools', icon: '&#128269;', action: () => { const f = document.getElementById('display-filter'); if (f) { f.focus(); f.select(); } } },
        { id: 'toggle-bookmarks', label: 'Toggle Bookmarks Panel', section: 'Tools', icon: '&#9733;', action: () => { if (typeof Bookmarks !== 'undefined') document.getElementById('btn-bookmarks')?.click(); } },
    ];

    function init() {
        createOverlay();
        document.addEventListener('keydown', onKeyDown);
    }

    function createOverlay() {
        overlayEl = document.createElement('div');
        overlayEl.id = 'cmd-palette';
        overlayEl.className = 'cmd-palette';
        overlayEl.innerHTML =
            '<div class="cmd-palette-dialog">' +
                '<div class="cmd-palette-input-wrap">' +
                    '<span class="cmd-palette-icon">&#128269;</span>' +
                    '<input class="cmd-palette-input" id="cmd-palette-input" type="text" placeholder="Type a command..." autocomplete="off" spellcheck="false">' +
                    '<kbd class="kbd cmd-palette-esc">Esc</kbd>' +
                '</div>' +
                '<div class="cmd-palette-list" id="cmd-palette-list"></div>' +
                '<div class="cmd-palette-footer">' +
                    '<span><kbd class="kbd">&uarr;</kbd><kbd class="kbd">&darr;</kbd> navigate</span>' +
                    '<span><kbd class="kbd">Enter</kbd> select</span>' +
                    '<span><kbd class="kbd">Esc</kbd> close</span>' +
                '</div>' +
            '</div>';
        document.body.appendChild(overlayEl);

        inputEl = overlayEl.querySelector('#cmd-palette-input');
        listEl = overlayEl.querySelector('#cmd-palette-list');

        inputEl.addEventListener('input', onInput);
        overlayEl.addEventListener('click', (e) => {
            if (e.target === overlayEl) close();
        });
    }

    function onKeyDown(e) {
        // Ctrl+K or Cmd+K to open
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            if (visible) {
                close();
            } else {
                open();
            }
            return;
        }

        if (!visible) return;

        if (e.key === 'Escape') {
            e.preventDefault();
            close();
        } else if (e.key === 'ArrowDown') {
            e.preventDefault();
            selectedIdx = Math.min(selectedIdx + 1, filteredCommands.length - 1);
            renderList();
            scrollToSelected();
        } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            selectedIdx = Math.max(selectedIdx - 1, 0);
            renderList();
            scrollToSelected();
        } else if (e.key === 'Enter') {
            e.preventDefault();
            if (filteredCommands[selectedIdx]) {
                execute(filteredCommands[selectedIdx]);
            }
        }
    }

    function open() {
        visible = true;
        overlayEl.classList.add('cmd-palette-visible');
        inputEl.value = '';
        selectedIdx = 0;
        filterCommands('');
        inputEl.focus();
    }

    function close() {
        visible = false;
        overlayEl.classList.remove('cmd-palette-visible');
    }

    function onInput() {
        selectedIdx = 0;
        filterCommands(inputEl.value);
    }

    function filterCommands(query) {
        const q = query.toLowerCase().trim();
        if (!q) {
            filteredCommands = commands.slice();
        } else {
            filteredCommands = commands.filter(cmd => {
                return fuzzyMatch(q, cmd.label.toLowerCase()) || fuzzyMatch(q, cmd.section.toLowerCase());
            });
        }
        renderList();
    }

    function fuzzyMatch(query, text) {
        let qi = 0;
        for (let ti = 0; ti < text.length && qi < query.length; ti++) {
            if (text[ti] === query[qi]) qi++;
        }
        return qi === query.length;
    }

    function renderList() {
        if (filteredCommands.length === 0) {
            listEl.innerHTML = '<div class="cmd-palette-empty">No matching commands</div>';
            return;
        }

        let html = '';
        let currentSection = '';
        for (let i = 0; i < filteredCommands.length; i++) {
            const cmd = filteredCommands[i];
            if (cmd.section !== currentSection) {
                currentSection = cmd.section;
                html += '<div class="cmd-palette-section">' + esc(currentSection) + '</div>';
            }
            const selected = i === selectedIdx ? ' cmd-palette-item-selected' : '';
            html += '<div class="cmd-palette-item' + selected + '" data-idx="' + i + '">' +
                '<span class="cmd-palette-item-icon">' + cmd.icon + '</span>' +
                '<span class="cmd-palette-item-label">' + esc(cmd.label) + '</span>' +
            '</div>';
        }
        listEl.innerHTML = html;

        // Click handler
        listEl.querySelectorAll('.cmd-palette-item').forEach(el => {
            el.addEventListener('click', () => {
                const idx = parseInt(el.dataset.idx, 10);
                if (filteredCommands[idx]) execute(filteredCommands[idx]);
            });
            el.addEventListener('mouseenter', () => {
                selectedIdx = parseInt(el.dataset.idx, 10);
                renderList();
            });
        });
    }

    function scrollToSelected() {
        const selected = listEl.querySelector('.cmd-palette-item-selected');
        if (selected) selected.scrollIntoView({ block: 'nearest' });
    }

    function execute(cmd) {
        close();
        cmd.action();
    }

    function setFilter(text) {
        Router.navigate('capture');
        const filterInput = document.getElementById('display-filter');
        if (filterInput) {
            filterInput.value = text;
            filterInput.dispatchEvent(new Event('input'));
        }
    }

    function applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('sniffox-theme', theme);
        const labelEl = document.getElementById('theme-label');
        if (labelEl) labelEl.textContent = theme.charAt(0).toUpperCase() + theme.slice(1);
        const iconMap = { dark: '&#9790;', dim: '&#9788;', light: '&#9728;' };
        const iconEl = document.getElementById('theme-icon');
        if (iconEl) iconEl.innerHTML = iconMap[theme] || '';
        if (typeof View3D !== 'undefined') View3D.updateTheme(theme !== 'light');
    }

    function esc(s) {
        if (!s) return '';
        return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    return { init };
})();
