// router.js — Hash-based SPA router for page navigation
'use strict';

const Router = (() => {
    const routes = ['capture', 'graph', 'security', 'analysis'];
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
        // Toggle page visibility
        document.querySelectorAll('.page').forEach(page => {
            page.classList.toggle('page-active', page.dataset.page === currentRoute);
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
