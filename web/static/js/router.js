// router.js — Hash-based SPA router with smooth page transitions
'use strict';

const Router = (() => {
    const routes = ['capture', 'graph', 'security', 'analysis', 'timeline', 'topology', 'endpoints', 'threatintel', 'sessions'];
    const defaultRoute = 'capture';
    let currentRoute = '';
    let onChangeCallbacks = [];

    function init() {
        window.addEventListener('hashchange', handleHash);
        // Wire up nav links
        document.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const route = link.dataset.route;
                if (route) navigate(route);
            });
        });
        handleHash();
    }

    function handleHash() {
        let hash = window.location.hash.replace(/^#\/?/, '');
        if (!routes.includes(hash)) hash = defaultRoute;
        if (hash === currentRoute) return;
        currentRoute = hash;
        applyRoute();
    }

    function applyRoute() {
        // Toggle page visibility with transition
        document.querySelectorAll('.page').forEach(page => {
            const isTarget = page.dataset.page === currentRoute;
            if (isTarget) {
                // Show the page, then animate in
                page.classList.add('page-active');
                // Force reflow then animate
                requestAnimationFrame(() => {
                    page.style.opacity = '1';
                    page.style.transform = 'translateY(0)';
                });
            } else {
                page.style.opacity = '';
                page.style.transform = '';
                page.classList.remove('page-active');
            }
        });
        // Toggle nav active state
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.toggle('nav-active', link.dataset.route === currentRoute);
        });
        // Fire callbacks
        for (const cb of onChangeCallbacks) {
            cb(currentRoute);
        }
    }

    function navigate(route) {
        window.location.hash = '#/' + route;
    }

    function current() {
        return currentRoute;
    }

    function onChange(cb) {
        onChangeCallbacks.push(cb);
    }

    return { init, navigate, current, onChange };
})();
