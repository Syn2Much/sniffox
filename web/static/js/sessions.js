// sessions.js — Session persistence: save, load, and browse past captures
'use strict';

const Sessions = (() => {
    let sessions = [];
    let bodyEl = null;

    function init() {
        bodyEl = document.getElementById('sessions-body');
        if (!bodyEl) return;
        loadList();
    }

    function loadList() {
        fetch('/api/sessions')
            .then(r => r.json())
            .then(data => {
                sessions = data || [];
                render();
            })
            .catch(() => {
                sessions = [];
                render();
            });
    }

    function render() {
        if (!bodyEl) return;

        if (sessions.length === 0) {
            bodyEl.innerHTML =
                '<div class="sessions-empty">' +
                    '<div class="sessions-empty-icon">&#128190;</div>' +
                    '<div class="sessions-empty-title">No saved sessions</div>' +
                    '<div class="sessions-empty-sub">Capture packets, then click "Save Session" to save your capture for later analysis.</div>' +
                '</div>';
            return;
        }

        let html = '<div class="sessions-grid">';
        for (const s of sessions) {
            const date = s.timestamp ? new Date(s.timestamp).toLocaleString() : '—';
            const size = formatBytes(s.size || 0);
            html +=
                '<div class="session-card" data-id="' + esc(s.id) + '">' +
                    '<div class="session-card-header">' +
                        '<span class="session-card-name">' + esc(s.name) + '</span>' +
                        '<button class="session-delete-btn" data-id="' + esc(s.id) + '" title="Delete session">&times;</button>' +
                    '</div>' +
                    '<div class="session-card-meta">' +
                        '<div class="session-meta-row"><span class="session-meta-label">Date</span><span class="session-meta-val">' + esc(date) + '</span></div>' +
                        '<div class="session-meta-row"><span class="session-meta-label">Packets</span><span class="session-meta-val">' + (s.packets || 0) + '</span></div>' +
                        '<div class="session-meta-row"><span class="session-meta-label">Size</span><span class="session-meta-val">' + size + '</span></div>' +
                    '</div>' +
                    '<button class="session-load-btn" data-id="' + esc(s.id) + '">Load Session</button>' +
                '</div>';
        }
        html += '</div>';
        bodyEl.innerHTML = html;

        // Wire up buttons
        bodyEl.querySelectorAll('.session-load-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                loadSession(btn.dataset.id);
            });
        });
        bodyEl.querySelectorAll('.session-delete-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                deleteSession(btn.dataset.id);
            });
        });
    }

    function saveSession(name) {
        const body = JSON.stringify({ name: name || 'Capture' });
        return fetch('/api/sessions/save', { method: 'POST', body, headers: { 'Content-Type': 'application/json' } })
            .then(r => {
                if (!r.ok) return r.text().then(t => { throw new Error(t); });
                return r.json();
            })
            .then(meta => {
                if (typeof App !== 'undefined' && App.showToast) {
                    App.showToast('Session saved: ' + (meta.name || ''), 'success');
                }
                loadList();
                return meta;
            })
            .catch(err => {
                if (typeof App !== 'undefined' && App.showToast) {
                    App.showToast('Save failed: ' + err.message, 'error');
                }
            });
    }

    function loadSession(id) {
        const body = JSON.stringify({ id });
        fetch('/api/sessions/load', { method: 'POST', body, headers: { 'Content-Type': 'application/json' } })
            .then(r => {
                if (!r.ok) return r.text().then(t => { throw new Error(t); });
                if (typeof App !== 'undefined' && App.showToast) {
                    App.showToast('Session loaded', 'success');
                }
                Router.navigate('capture');
            })
            .catch(err => {
                if (typeof App !== 'undefined' && App.showToast) {
                    App.showToast('Load failed: ' + err.message, 'error');
                }
            });
    }

    function deleteSession(id) {
        const body = JSON.stringify({ id });
        fetch('/api/sessions/delete', { method: 'POST', body, headers: { 'Content-Type': 'application/json' } })
            .then(r => {
                if (!r.ok) return r.text().then(t => { throw new Error(t); });
                if (typeof App !== 'undefined' && App.showToast) {
                    App.showToast('Session deleted', 'success');
                }
                loadList();
            })
            .catch(err => {
                if (typeof App !== 'undefined' && App.showToast) {
                    App.showToast('Delete failed: ' + err.message, 'error');
                }
            });
    }

    // Called from command palette
    function saveFromPalette() {
        const name = prompt('Session name:', 'Capture ' + new Date().toLocaleString());
        if (name !== null) saveSession(name);
    }

    function formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return (bytes / Math.pow(k, i)).toFixed(1) + ' ' + sizes[i];
    }

    function esc(s) {
        if (!s) return '';
        return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    return { init, loadList, saveSession, saveFromPalette };
})();
