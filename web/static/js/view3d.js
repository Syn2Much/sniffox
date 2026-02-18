// view3d.js — 3D network graph visualization using Three.js + OrbitControls
// Lazy-loaded: Three.js scene only initializes when user opens the accordion.
'use strict';

const View3D = (() => {
    let scene, camera, renderer, controls, canvas;
    let animating = true;
    let expanded = false;
    let initialized = false;
    let accordionOpen = false;

    // Packets queued before the scene is ready
    const pendingPackets = [];

    // Default camera position for reset
    const CAM_DEFAULT = { x: 0, y: 120, z: 200 };

    // Node/edge data
    const nodes = new Map();
    const edges = new Map();
    const particles = [];
    const MAX_NODES = 50;
    const MAX_PARTICLES = 300;
    const NODE_RADIUS = 4;

    const PROTO_COLORS = {
        tcp:  0x89b4fa,
        udp:  0x74c7ec,
        dns:  0x94e2d5,
        http: 0xa6e3a1,
        arp:  0xfab387,
        icmp: 0xf9e2af,
        ipv6: 0xcba6f7,
    };
    const DEFAULT_COLOR = 0xcdd6f4;

    // Filter/visibility state
    const protoVisible = { tcp: true, udp: true, dns: true, http: true, arp: true, icmp: true, ipv6: true, other: true };

    // Graphical settings
    const settings = {
        particleSpeed: 1.0,
        nodeScale: 1.0,
        edgeOpacity: 0.25,
        arcHeight: 15,
        labelSize: 1.0,
    };

    // Highlight state
    let highlightedIP = '';

    // Stats tracking
    const protoStats = {};
    const ipStats = {};

    // Called on DOMContentLoaded — only wires the accordion header, nothing heavy
    function init() {
        const header = document.getElementById('view3d-accordion-header');
        if (header) {
            header.addEventListener('click', (e) => {
                // Don't toggle if clicking a button inside the header
                if (e.target.closest('.v3d-hdr-btn')) return;
                toggleAccordion();
            });
        }
    }

    function toggleAccordion() {
        const acc = document.getElementById('view3d-accordion');
        if (!acc) return;
        accordionOpen = !accordionOpen;
        acc.classList.toggle('v3d-closed', !accordionOpen);

        const arrow = document.getElementById('v3d-arrow');
        const hint = document.getElementById('v3d-hint');
        if (arrow) arrow.innerHTML = accordionOpen ? '&#9660;' : '&#9654;';
        if (hint) hint.textContent = accordionOpen ? '' : 'Click to open';

        if (accordionOpen && !initialized) {
            initScene();
        }
        if (accordionOpen) {
            setTimeout(updateRendererSize, 50);
        }
    }

    // Heavy Three.js initialization — only runs once when user first opens the accordion
    function initScene() {
        canvas = document.getElementById('view3d-canvas');
        if (!canvas || typeof THREE === 'undefined') return;
        initialized = true;

        scene = new THREE.Scene();

        camera = new THREE.PerspectiveCamera(50, 2, 1, 2000);
        camera.position.set(CAM_DEFAULT.x, CAM_DEFAULT.y, CAM_DEFAULT.z);

        renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
        renderer.setPixelRatio(window.devicePixelRatio);
        updateRendererSize();

        // OrbitControls
        if (THREE.OrbitControls) {
            controls = new THREE.OrbitControls(camera, canvas);
            controls.enableDamping = true;
            controls.dampingFactor = 0.12;
            controls.rotateSpeed = 0.8;
            controls.panSpeed = 0.6;
            controls.zoomSpeed = 1.2;
            controls.minDistance = 30;
            controls.maxDistance = 800;
            controls.maxPolarAngle = Math.PI * 0.85;
            controls.target.set(0, 0, 0);
            controls.update();
        }

        // Lights
        scene.add(new THREE.AmbientLight(0xffffff, 0.6));
        const dirLight = new THREE.DirectionalLight(0xffffff, 0.8);
        dirLight.position.set(50, 100, 50);
        scene.add(dirLight);

        // Grid floor
        addGrid(true);

        // Toolbar buttons
        const resetBtn = document.getElementById('btn-3d-reset');
        const toggleBtn = document.getElementById('btn-3d-toggle');
        const expandBtn = document.getElementById('btn-3d-expand');
        if (resetBtn) resetBtn.addEventListener('click', resetCamera);
        if (toggleBtn) toggleBtn.addEventListener('click', toggleAnimation);
        if (expandBtn) expandBtn.addEventListener('click', toggleExpand);

        // Protocol filter checkboxes
        document.querySelectorAll('.v3d-proto-cb').forEach(cb => {
            cb.addEventListener('change', () => {
                protoVisible[cb.dataset.proto] = cb.checked;
                applyVisibility();
            });
        });

        // Sliders
        initSlider('v3d-speed', 'particleSpeed', 0.2, 3.0);
        initSlider('v3d-nodesize', 'nodeScale', 0.3, 3.0);
        initSlider('v3d-edgeopacity', 'edgeOpacity', 0.05, 1.0);
        initSlider('v3d-archeight', 'arcHeight', 0, 40);

        // IP search
        const ipSearch = document.getElementById('v3d-ip-search');
        if (ipSearch) {
            ipSearch.addEventListener('input', () => {
                highlightedIP = ipSearch.value.trim();
                applyHighlight();
            });
        }

        // Expand overlay close
        const closeBtn = document.getElementById('v3d-expand-close');
        if (closeBtn) closeBtn.addEventListener('click', collapseView);
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && expanded) collapseView();
        });

        // Controls panel toggle
        const ctrlToggle = document.getElementById('btn-3d-controls');
        if (ctrlToggle) {
            ctrlToggle.addEventListener('click', () => {
                const panel = document.getElementById('v3d-controls-panel');
                if (panel) panel.classList.toggle('v3d-controls-hidden');
            });
        }

        window.addEventListener('resize', updateRendererSize);

        animate();

        // Flush any packets that arrived before the scene was ready
        for (const pkt of pendingPackets) {
            addPacketInternal(pkt);
        }
        pendingPackets.length = 0;
    }

    function initSlider(id, key, min, max) {
        const el = document.getElementById(id);
        if (!el) return;
        el.min = min;
        el.max = max;
        el.step = (max - min) / 100;
        el.value = settings[key];
        const valEl = document.getElementById(id + '-val');
        if (valEl) valEl.textContent = Number(settings[key]).toFixed(2);
        el.addEventListener('input', () => {
            settings[key] = parseFloat(el.value);
            if (valEl) valEl.textContent = Number(settings[key]).toFixed(2);
            applySettings();
        });
    }

    function applySettings() {
        edges.forEach(e => {
            e.line.material.opacity = settings.edgeOpacity;
        });
        nodes.forEach(n => {
            const base = Math.min(3, 1 + Math.log2(Math.max(1, n.packetCount)) * 0.3);
            n.mesh.scale.setScalar(base * settings.nodeScale);
            n.label.scale.set(30 * settings.labelSize, 8 * settings.labelSize, 1);
        });
    }

    function applyVisibility() {
        edges.forEach((e) => {
            const proto = e.proto || 'other';
            const vis = protoVisible[proto] !== false;
            e.line.visible = vis;
        });
    }

    function applyHighlight() {
        nodes.forEach((n, ip) => {
            const match = highlightedIP && ip.includes(highlightedIP);
            if (highlightedIP) {
                n.mesh.material.emissiveIntensity = match ? 0.8 : 0.05;
                n.mesh.material.opacity = match ? 1.0 : 0.3;
                n.label.material.opacity = match ? 1.0 : 0.3;
                if (n.ring) n.ring.material.opacity = match ? 0.3 : 0.02;
            } else {
                n.mesh.material.emissiveIntensity = 0.2;
                n.mesh.material.opacity = 0.9;
                n.label.material.opacity = 1.0;
                if (n.ring) n.ring.material.opacity = 0.15;
            }
        });
    }

    function toggleExpand() {
        if (expanded) {
            collapseView();
        } else {
            expandView();
        }
    }

    function expandView() {
        expanded = true;
        const overlay = document.getElementById('v3d-expand-overlay');
        if (overlay) {
            overlay.classList.add('v3d-expanded');
            const target = document.getElementById('v3d-expand-canvas-wrap');
            if (target && canvas) target.appendChild(canvas);
        }
        setTimeout(updateRendererSize, 50);
        const btn = document.getElementById('btn-3d-expand');
        if (btn) btn.textContent = 'Collapse';
    }

    function collapseView() {
        expanded = false;
        const overlay = document.getElementById('v3d-expand-overlay');
        if (overlay) overlay.classList.remove('v3d-expanded');
        const pane = document.getElementById('view3d-pane');
        const legend = document.getElementById('view3d-legend');
        if (pane && canvas) {
            pane.insertBefore(canvas, legend);
        }
        setTimeout(updateRendererSize, 50);
        const btn = document.getElementById('btn-3d-expand');
        if (btn) btn.textContent = 'Expand';
    }

    function updateRendererSize() {
        if (!canvas || !renderer) return;
        let w, h;
        if (expanded) {
            const wrap = document.getElementById('v3d-expand-canvas-wrap');
            if (!wrap) return;
            const rect = wrap.getBoundingClientRect();
            w = rect.width;
            h = rect.height;
        } else {
            const pane = document.getElementById('view3d-pane');
            if (!pane) return;
            const rect = pane.getBoundingClientRect();
            const legendH = 24;
            w = rect.width;
            h = Math.max(60, rect.height - legendH);
        }
        canvas.width = w;
        canvas.height = h;
        canvas.style.width = w + 'px';
        canvas.style.height = h + 'px';
        renderer.setSize(w, h);
        camera.aspect = w / h;
        camera.updateProjectionMatrix();
    }

    function resetCamera() {
        if (!controls) return;
        camera.position.set(CAM_DEFAULT.x, CAM_DEFAULT.y, CAM_DEFAULT.z);
        controls.target.set(0, 0, 0);
        controls.update();
    }

    function toggleAnimation() {
        animating = !animating;
        const btn = document.getElementById('btn-3d-toggle');
        if (btn) btn.textContent = animating ? 'Pause' : 'Resume';
    }

    // Public addPacket — queues if scene not ready yet
    function addPacket(pkt) {
        if (!initialized) {
            // Cap queue so we don't eat memory while closed
            if (pendingPackets.length < 2000) pendingPackets.push(pkt);
            return;
        }
        addPacketInternal(pkt);
    }

    function addPacketInternal(pkt) {
        if (!scene || !pkt.srcAddr || !pkt.dstAddr) return;
        const src = pkt.srcAddr.split(':')[0] || pkt.srcAddr;
        const dst = pkt.dstAddr.split(':')[0] || pkt.dstAddr;
        if (!src || !dst) return;

        const proto = (pkt.protocol || '').toLowerCase();
        const color = PROTO_COLORS[proto] || DEFAULT_COLOR;

        // Stats
        protoStats[proto] = (protoStats[proto] || 0) + 1;
        ipStats[src] = (ipStats[src] || 0) + 1;
        ipStats[dst] = (ipStats[dst] || 0) + 1;

        // Visibility check
        const mappedProto = PROTO_COLORS[proto] ? proto : 'other';
        if (protoVisible[mappedProto] === false) return;

        ensureNode(src);
        ensureNode(dst);

        const srcNode = nodes.get(src);
        const dstNode = nodes.get(dst);
        if (!srcNode || !dstNode) return;
        srcNode.packetCount++;
        dstNode.packetCount++;

        const srcScale = Math.min(3, 1 + Math.log2(srcNode.packetCount) * 0.3) * settings.nodeScale;
        const dstScale = Math.min(3, 1 + Math.log2(dstNode.packetCount) * 0.3) * settings.nodeScale;
        srcNode.mesh.scale.setScalar(srcScale);
        dstNode.mesh.scale.setScalar(dstScale);

        const edgeKey = src + '->' + dst;
        if (!edges.has(edgeKey)) {
            createEdge(edgeKey, srcNode, dstNode, color, mappedProto);
        }
        edges.get(edgeKey).count++;

        spawnParticle(srcNode, dstNode, color);
        updateStatsOverlay();
    }

    function ensureNode(ip) {
        if (nodes.has(ip) || nodes.size >= MAX_NODES) return;

        const idx = nodes.size;
        const angle = idx * 137.5 * Math.PI / 180;
        const radius = 20 + Math.sqrt(idx) * 20;
        const x = Math.cos(angle) * radius;
        const z = Math.sin(angle) * radius;

        const geo = new THREE.SphereGeometry(NODE_RADIUS, 16, 12);
        const mat = new THREE.MeshPhongMaterial({
            color: 0x89b4fa, emissive: 0x89b4fa, emissiveIntensity: 0.2,
            transparent: true, opacity: 0.9,
        });
        const mesh = new THREE.Mesh(geo, mat);
        mesh.position.set(x, 0, z);
        scene.add(mesh);

        const label = makeLabel(ip);
        label.position.set(x, NODE_RADIUS + 6, z);
        scene.add(label);

        const ringGeo = new THREE.RingGeometry(NODE_RADIUS + 1, NODE_RADIUS + 2.5, 32);
        const ringMat = new THREE.MeshBasicMaterial({
            color: 0x89b4fa, transparent: true, opacity: 0.15, side: THREE.DoubleSide,
        });
        const ring = new THREE.Mesh(ringGeo, ringMat);
        ring.rotation.x = -Math.PI / 2;
        ring.position.set(x, -0.5, z);
        scene.add(ring);

        nodes.set(ip, { mesh, label, ring, x, z, packetCount: 0 });
    }

    function makeLabel(text) {
        const c = document.createElement('canvas');
        const ctx = c.getContext('2d');
        c.width = 256; c.height = 64;
        ctx.clearRect(0, 0, 256, 64);
        ctx.font = 'bold 22px monospace';
        ctx.textAlign = 'center';
        ctx.fillStyle = '#cdd6f4';
        ctx.fillText(text, 128, 38);
        const tex = new THREE.CanvasTexture(c);
        const mat = new THREE.SpriteMaterial({ map: tex, transparent: true, depthTest: false });
        const sprite = new THREE.Sprite(mat);
        sprite.scale.set(30, 8, 1);
        return sprite;
    }

    function createEdge(key, srcNode, dstNode, color, proto) {
        const points = [
            new THREE.Vector3(srcNode.x, 0, srcNode.z),
            new THREE.Vector3(dstNode.x, 0, dstNode.z),
        ];
        const geo = new THREE.BufferGeometry().setFromPoints(points);
        const mat = new THREE.LineBasicMaterial({ color, transparent: true, opacity: settings.edgeOpacity });
        const line = new THREE.Line(geo, mat);
        scene.add(line);
        edges.set(key, { line, count: 0, proto: proto || 'other' });
    }

    function spawnParticle(srcNode, dstNode, color) {
        while (particles.length >= MAX_PARTICLES) {
            const old = particles.shift();
            scene.remove(old.mesh);
            old.mesh.geometry.dispose();
            old.mesh.material.dispose();
        }
        const geo = new THREE.SphereGeometry(1.2, 8, 6);
        const mat = new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.9 });
        const mesh = new THREE.Mesh(geo, mat);
        mesh.position.set(srcNode.x, 0, srcNode.z);
        scene.add(mesh);
        particles.push({
            mesh,
            srcX: srcNode.x, srcZ: srcNode.z,
            dstX: dstNode.x, dstZ: dstNode.z,
            t: 0,
            speed: (0.008 + Math.random() * 0.012) * settings.particleSpeed,
        });
    }

    function animate() {
        requestAnimationFrame(animate);

        if (controls) controls.update();

        if (animating) {
            for (let i = particles.length - 1; i >= 0; i--) {
                const p = particles[i];
                p.t += p.speed * settings.particleSpeed;
                if (p.t >= 1) {
                    scene.remove(p.mesh);
                    p.mesh.geometry.dispose();
                    p.mesh.material.dispose();
                    particles.splice(i, 1);
                    continue;
                }
                const arcHeight = Math.sin(p.t * Math.PI) * settings.arcHeight;
                p.mesh.position.set(
                    p.srcX + (p.dstX - p.srcX) * p.t,
                    arcHeight,
                    p.srcZ + (p.dstZ - p.srcZ) * p.t,
                );
                p.mesh.material.opacity = 1 - p.t * 0.5;
            }

            const time = Date.now() * 0.002;
            nodes.forEach(node => {
                if (node.ring) {
                    node.ring.material.opacity = 0.1 + Math.sin(time) * 0.05;
                    node.ring.scale.setScalar(1 + Math.sin(time * 1.5) * 0.1);
                }
            });
        }

        updateRendererSize();
        if (renderer && scene && camera) {
            renderer.render(scene, camera);
        }
    }

    let statsTimer = null;
    function updateStatsOverlay() {
        if (statsTimer) return;
        statsTimer = setTimeout(() => {
            statsTimer = null;
            const el = document.getElementById('v3d-stats-content');
            if (!el) return;

            const sorted = Object.entries(ipStats).sort((a, b) => b[1] - a[1]).slice(0, 5);
            const nodeCount = nodes.size;
            const edgeCount = edges.size;
            const totalPkts = Object.values(protoStats).reduce((a, b) => a + b, 0);

            let html = `<div class="v3d-stats-row"><span>Nodes:</span><strong>${nodeCount}</strong></div>`;
            html += `<div class="v3d-stats-row"><span>Edges:</span><strong>${edgeCount}</strong></div>`;
            html += `<div class="v3d-stats-row"><span>Packets:</span><strong>${totalPkts}</strong></div>`;

            html += '<div class="v3d-stats-sep">Protocols</div>';
            Object.entries(protoStats).sort((a, b) => b[1] - a[1]).forEach(([proto, count]) => {
                const pct = totalPkts > 0 ? (count / totalPkts * 100).toFixed(0) : 0;
                html += `<div class="v3d-stats-row"><span>${proto.toUpperCase()}</span><strong>${count} (${pct}%)</strong></div>`;
            });

            if (sorted.length > 0) {
                html += '<div class="v3d-stats-sep">Top Talkers</div>';
                sorted.forEach(([ip, count]) => {
                    html += `<div class="v3d-stats-row v3d-stats-ip" data-ip="${ip}"><span>${ip}</span><strong>${count}</strong></div>`;
                });
            }

            el.innerHTML = html;

            el.querySelectorAll('.v3d-stats-ip').forEach(row => {
                row.addEventListener('click', () => {
                    const ip = row.dataset.ip;
                    const search = document.getElementById('v3d-ip-search');
                    if (search) {
                        search.value = ip;
                        highlightedIP = ip;
                        applyHighlight();
                    }
                });
            });
        }, 500);
    }

    function clear() {
        pendingPackets.length = 0;
        if (!scene) return;
        nodes.forEach(n => {
            scene.remove(n.mesh); scene.remove(n.label);
            if (n.ring) scene.remove(n.ring);
            n.mesh.geometry.dispose(); n.mesh.material.dispose();
        });
        nodes.clear();
        edges.forEach(e => {
            scene.remove(e.line); e.line.geometry.dispose(); e.line.material.dispose();
        });
        edges.clear();
        particles.forEach(p => {
            scene.remove(p.mesh); p.mesh.geometry.dispose(); p.mesh.material.dispose();
        });
        particles.length = 0;

        Object.keys(protoStats).forEach(k => delete protoStats[k]);
        Object.keys(ipStats).forEach(k => delete ipStats[k]);
        const el = document.getElementById('v3d-stats-content');
        if (el) el.innerHTML = '';
    }

    function addGrid(isDark) {
        const gridColor = isDark ? 0x313244 : 0xd0d0d0;
        const gridBg = isDark ? 0x1e1e2e : 0xf0f0f0;
        const grid = new THREE.GridHelper(400, 40, gridColor, gridBg);
        grid.position.y = -10;
        scene.add(grid);
    }

    function updateTheme(isDark) {
        if (!scene) return;
        scene.children.forEach(child => {
            if (child instanceof THREE.GridHelper) scene.remove(child);
        });
        addGrid(isDark);
    }

    return { init, addPacket, clear, updateTheme };
})();
