// bookmarks.js — Packet bookmarks & annotations with localStorage persistence
'use strict';

const Bookmarks = (() => {
    const STORAGE_KEY = 'sniffox-bookmarks';
    // Map of packet number -> { note: string, timestamp: number }
    let bookmarks = {};
    let panelVisible = false;
    let panelEl = null;
    let listEl = null;
    let badgeEl = null;

    function init() {
        load();
        createPanel();
        createToolbarButton();
    }

    function load() {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            if (raw) bookmarks = JSON.parse(raw);
        } catch (e) {
            bookmarks = {};
        }
    }

    function save() {
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(bookmarks));
        } catch (e) { /* quota exceeded — ignore */ }
    }

    function isBookmarked(pktNum) {
        return !!bookmarks[pktNum];
    }

    function toggle(pkt) {
        const num = pkt.number;
        if (bookmarks[num]) {
            delete bookmarks[num];
        } else {
            bookmarks[num] = {
                note: '',
                timestamp: Date.now(),
                proto: pkt.protocol,
                src: pkt.srcAddr,
                dst: pkt.dstAddr,
                info: pkt.info
            };
        }
        save();
        updateBadge();
        if (panelVisible) renderList();
        return !!bookmarks[num];
    }

    function setNote(pktNum, note) {
        if (!bookmarks[pktNum]) return;
        bookmarks[pktNum].note = note;
        save();
    }

    function getNote(pktNum) {
        return bookmarks[pktNum] ? bookmarks[pktNum].note : '';
    }

    function count() {
        return Object.keys(bookmarks).length;
    }

    function getAll() {
        return Object.entries(bookmarks)
            .map(([num, data]) => ({ number: parseInt(num, 10), ...data }))
            .sort((a, b) => a.number - b.number);
    }

    function clearAll() {
        bookmarks = {};
        save();
        updateBadge();
        if (panelVisible) renderList();
    }

    // --- Filter integration ---
    function matchesFilter(pkt) {
        return !!bookmarks[pkt.number];
    }

    // --- UI: Toolbar Button ---
    function createToolbarButton() {
        const toolbar = document.getElementById('toolbar');
        if (!toolbar) return;

        const lastGroup = toolbar.querySelector('.toolbar-group:last-child');
        if (!lastGroup) return;

        const btn = document.createElement('button');
        btn.id = 'btn-bookmarks';
        btn.title = 'Bookmarks panel';
        btn.innerHTML = '&#9733; Bookmarks';
        badgeEl = document.createElement('span');
        badgeEl.className = 'bookmark-badge';
        badgeEl.style.display = 'none';
        btn.appendChild(badgeEl);
        btn.addEventListener('click', togglePanel);
        lastGroup.appendChild(btn);
        updateBadge();
    }

    function updateBadge() {
        if (!badgeEl) return;
        const c = count();
        if (c > 0) {
            badgeEl.textContent = c;
            badgeEl.style.display = 'inline';
        } else {
            badgeEl.style.display = 'none';
        }
    }

    // --- UI: Sidebar Panel ---
    function createPanel() {
        panelEl = document.createElement('div');
        panelEl.id = 'bookmarks-panel';
        panelEl.className = 'bookmarks-panel';
        panelEl.innerHTML =
            '<div class="bookmarks-header">' +
                '<span class="bookmarks-title">&#9733; Bookmarks</span>' +
                '<div class="bookmarks-actions">' +
                    '<button class="bookmarks-clear-btn" title="Clear all bookmarks">Clear</button>' +
                    '<button class="bookmarks-close-btn" title="Close">&times;</button>' +
                '</div>' +
            '</div>' +
            '<div class="bookmarks-list" id="bookmarks-list"></div>';
        document.getElementById('app').appendChild(panelEl);

        listEl = panelEl.querySelector('#bookmarks-list');
        panelEl.querySelector('.bookmarks-close-btn').addEventListener('click', togglePanel);
        panelEl.querySelector('.bookmarks-clear-btn').addEventListener('click', () => {
            if (count() > 0) clearAll();
        });
    }

    function togglePanel() {
        panelVisible = !panelVisible;
        panelEl.classList.toggle('bookmarks-visible', panelVisible);
        if (panelVisible) renderList();
    }

    function renderList() {
        const all = getAll();
        if (all.length === 0) {
            listEl.innerHTML = '<div class="bookmarks-empty">No bookmarked packets</div>';
            return;
        }

        const frag = document.createDocumentFragment();
        for (const bm of all) {
            const item = document.createElement('div');
            item.className = 'bookmark-item';
            item.innerHTML =
                '<div class="bookmark-row">' +
                    '<span class="bookmark-num">#' + bm.number + '</span>' +
                    '<span class="bookmark-proto">' + esc(bm.proto || '') + '</span>' +
                    '<span class="bookmark-addrs">' + esc(bm.src || '') + ' &rarr; ' + esc(bm.dst || '') + '</span>' +
                    '<button class="bookmark-remove" data-num="' + bm.number + '" title="Remove">&times;</button>' +
                '</div>' +
                '<div class="bookmark-info">' + esc(bm.info || '') + '</div>' +
                '<input class="bookmark-note" placeholder="Add a note..." value="' + esc(bm.note || '') + '" data-num="' + bm.number + '">';
            frag.appendChild(item);
        }
        listEl.textContent = '';
        listEl.appendChild(frag);

        // Event delegation
        listEl.querySelectorAll('.bookmark-remove').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const num = parseInt(btn.dataset.num, 10);
                delete bookmarks[num];
                save();
                updateBadge();
                renderList();
            });
        });
        listEl.querySelectorAll('.bookmark-note').forEach(input => {
            input.addEventListener('change', () => {
                setNote(parseInt(input.dataset.num, 10), input.value);
            });
        });
        listEl.querySelectorAll('.bookmark-item').forEach(item => {
            item.addEventListener('click', () => {
                const num = parseInt(item.querySelector('.bookmark-num').textContent.replace('#', ''), 10);
                // Apply filter to show this packet
                const filterInput = document.getElementById('display-filter');
                if (filterInput) {
                    filterInput.value = 'number==' + num;
                    filterInput.dispatchEvent(new Event('input'));
                }
            });
        });
    }

    function esc(s) {
        if (!s) return '';
        return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    return { init, isBookmarked, toggle, setNote, getNote, matchesFilter, count, getAll, clearAll };
})();
