// view3d.js — 3D network graph visualization using Three.js + OrbitControls
// Lazy-loaded: Three.js scene only initializes when user navigates to the graph page.
'use strict';

const View3D = (() => {
    let scene, camera, renderer, controls, canvas;
    let animating = true;
    let expanded = false;
    let initialized = false;
    let isDarkTheme = true;

    // Packets queued before the scene is ready
    const pendingPackets = [];

    // Default camera position for reset
    const CAM_DEFAULT = { x: 60, y: 140, z: 220 };

    // Node/edge data
    const nodes = new Map();
    const edges = new Map();
    const particles = [];
    const MAX_NODES = 60;
    const MAX_PARTICLES = 500;
    const NODE_RADIUS = 3.5;

    // Brighter, more saturated protocol colors
    const PROTO_COLORS = {
        tcp:  0x7aa2f7,
        udp:  0x5cb4d6,
        dns:  0x73daca,
        http: 0x9ece6a,
        arp:  0xff9e64,
        icmp: 0xe0af68,
        ipv6: 0xbb9af7,
    };
    const DEFAULT_COLOR = 0xc0caf5;

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

    // Track dominant protocol per node for coloring
    const nodeProtoCount = {};  // ip -> { tcp: N, udp: M, ... }

    // Scene objects for cleanup
    let gridHelper = null;
    let pointLight = null;

    function init() {
        // Scene will be initialized lazily when graph page becomes visible
    }

    function onPageVisible() {
        if (!initialized) {
            initScene();
        } else {
            setTimeout(updateRendererSize, 50);
        }
    }

    function initScene() {
        canvas = document.getElementById('view3d-canvas');
        if (!canvas || typeof THREE === 'undefined') return;
        initialized = true;

        scene = new THREE.Scene();
        applySceneBg();

        camera = new THREE.PerspectiveCamera(45, 2, 1, 3000);
        camera.position.set(CAM_DEFAULT.x, CAM_DEFAULT.y, CAM_DEFAULT.z);

        renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: false });
        renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
        renderer.toneMapping = THREE.ACESFilmicToneMapping;
        renderer.toneMappingExposure = 1.2;
        updateRendererSize();

        // OrbitControls
        if (THREE.OrbitControls) {
            controls = new THREE.OrbitControls(camera, canvas);
            controls.enableDamping = true;
            controls.dampingFactor = 0.08;
            controls.rotateSpeed = 0.6;
            controls.panSpeed = 0.5;
            controls.zoomSpeed = 1.0;
            controls.minDistance = 30;
            controls.maxDistance = 800;
            controls.maxPolarAngle = Math.PI * 0.85;
            controls.target.set(0, 10, 0);
            controls.update();
        }

        // Lighting — more dramatic
        const ambient = new THREE.AmbientLight(0xffffff, 0.3);
        scene.add(ambient);

        const dirLight = new THREE.DirectionalLight(0xffffff, 0.6);
        dirLight.position.set(60, 120, 80);
        scene.add(dirLight);

        // Point light at center for glow
        pointLight = new THREE.PointLight(0x7aa2f7, 0.8, 400);
        pointLight.position.set(0, 30, 0);
        scene.add(pointLight);

        // Hemisphere light for ambient color
        const hemiLight = new THREE.HemisphereLight(0x7aa2f7, 0x1a1a2e, 0.3);
        scene.add(hemiLight);

        // Fog for depth
        applyFog();

        // Grid floor
        addGrid();

        // Center glow marker
        addCenterGlow();

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

    function applySceneBg() {
        if (!scene) return;
        scene.background = new THREE.Color(isDarkTheme ? 0x000000 : 0xdce0e8);
    }

    function applyFog() {
        if (!scene) return;
        if (isDarkTheme) {
            scene.fog = new THREE.FogExp2(0x000005, 0.0018);
        } else {
            scene.fog = new THREE.FogExp2(0xdce0e8, 0.0012);
        }
    }

    function addCenterGlow() {
        // Soft glow sprite at the center
        const glowCanvas = document.createElement('canvas');
        glowCanvas.width = 128;
        glowCanvas.height = 128;
        const ctx = glowCanvas.getContext('2d');
        const gradient = ctx.createRadialGradient(64, 64, 0, 64, 64, 64);
        gradient.addColorStop(0, 'rgba(122, 162, 247, 0.15)');
        gradient.addColorStop(0.5, 'rgba(122, 162, 247, 0.04)');
        gradient.addColorStop(1, 'rgba(122, 162, 247, 0)');
        ctx.fillStyle = gradient;
        ctx.fillRect(0, 0, 128, 128);
        const tex = new THREE.CanvasTexture(glowCanvas);
        const mat = new THREE.SpriteMaterial({ map: tex, transparent: true, depthWrite: false });
        const sprite = new THREE.Sprite(mat);
        sprite.scale.set(150, 150, 1);
        sprite.position.set(0, 0, 0);
        scene.add(sprite);
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
                n.mesh.material.emissiveIntensity = match ? 1.0 : 0.05;
                n.mesh.material.opacity = match ? 1.0 : 0.2;
                n.label.material.opacity = match ? 1.0 : 0.2;
                if (n.ring) n.ring.material.opacity = match ? 0.5 : 0.02;
                if (n.glow) n.glow.material.opacity = match ? 0.6 : 0.0;
            } else {
                n.mesh.material.emissiveIntensity = 0.4;
                n.mesh.material.opacity = 0.95;
                n.label.material.opacity = 1.0;
                if (n.ring) n.ring.material.opacity = 0.2;
                if (n.glow) n.glow.material.opacity = 0.3;
            }
        });
    }

    function toggleExpand() {
        if (expanded) collapseView();
        else expandView();
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
        if (w <= 0 || h <= 0) return;
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
        controls.target.set(0, 10, 0);
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

        // Track per-node protocol distribution
        if (!nodeProtoCount[src]) nodeProtoCount[src] = {};
        if (!nodeProtoCount[dst]) nodeProtoCount[dst] = {};
        nodeProtoCount[src][proto] = (nodeProtoCount[src][proto] || 0) + 1;
        nodeProtoCount[dst][proto] = (nodeProtoCount[dst][proto] || 0) + 1;

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

        // Update node color based on dominant protocol
        updateNodeColor(src, srcNode);
        updateNodeColor(dst, dstNode);

        const srcScale = Math.min(3, 1 + Math.log2(srcNode.packetCount) * 0.3) * settings.nodeScale;
        const dstScale = Math.min(3, 1 + Math.log2(dstNode.packetCount) * 0.3) * settings.nodeScale;
        srcNode.mesh.scale.setScalar(srcScale);
        dstNode.mesh.scale.setScalar(dstScale);

        const edgeKey = src < dst ? src + '<>' + dst : dst + '<>' + src;
        if (!edges.has(edgeKey)) {
            createEdge(edgeKey, srcNode, dstNode, color, mappedProto);
        }
        const edge = edges.get(edgeKey);
        edge.count++;
        // Thicken edge as traffic increases
        const thickness = Math.min(3, 1 + Math.log2(edge.count) * 0.4);
        edge.line.material.linewidth = thickness;

        spawnParticle(srcNode, dstNode, color);
        updateStatsOverlay();
    }

    function updateNodeColor(ip, node) {
        const counts = nodeProtoCount[ip];
        if (!counts) return;
        let maxProto = '';
        let maxCount = 0;
        for (const [p, c] of Object.entries(counts)) {
            if (c > maxCount) { maxCount = c; maxProto = p; }
        }
        const color = PROTO_COLORS[maxProto] || DEFAULT_COLOR;
        node.mesh.material.color.setHex(color);
        node.mesh.material.emissive.setHex(color);
        if (node.ring) {
            node.ring.material.color.setHex(color);
        }
        if (node.glow) {
            node.glow.material.color.setHex(color);
        }
    }

    function ensureNode(ip) {
        if (nodes.has(ip) || nodes.size >= MAX_NODES) return;

        const idx = nodes.size;
        // Golden angle spiral layout — more spread out
        const angle = idx * 137.508 * Math.PI / 180;
        const radius = 25 + Math.sqrt(idx) * 22;
        const x = Math.cos(angle) * radius;
        const z = Math.sin(angle) * radius;

        // Node sphere with higher quality
        const geo = new THREE.SphereGeometry(NODE_RADIUS, 24, 16);
        const mat = new THREE.MeshPhongMaterial({
            color: DEFAULT_COLOR,
            emissive: DEFAULT_COLOR,
            emissiveIntensity: 0.4,
            shininess: 80,
            transparent: true,
            opacity: 0.95,
        });
        const mesh = new THREE.Mesh(geo, mat);
        mesh.position.set(x, 0, z);
        scene.add(mesh);

        // IP label
        const label = makeLabel(ip);
        label.position.set(x, NODE_RADIUS + 7, z);
        scene.add(label);

        // Animated ring
        const ringGeo = new THREE.RingGeometry(NODE_RADIUS + 2, NODE_RADIUS + 3.5, 48);
        const ringMat = new THREE.MeshBasicMaterial({
            color: DEFAULT_COLOR, transparent: true, opacity: 0.2, side: THREE.DoubleSide,
        });
        const ring = new THREE.Mesh(ringGeo, ringMat);
        ring.rotation.x = -Math.PI / 2;
        ring.position.set(x, -0.5, z);
        scene.add(ring);

        // Glow sprite under the node
        const glow = makeGlowSprite(DEFAULT_COLOR);
        glow.position.set(x, 0, z);
        scene.add(glow);

        nodes.set(ip, { mesh, label, ring, glow, x, z, packetCount: 0 });
    }

    function makeGlowSprite(color) {
        const c = document.createElement('canvas');
        c.width = 64; c.height = 64;
        const ctx = c.getContext('2d');
        const gradient = ctx.createRadialGradient(32, 32, 0, 32, 32, 32);
        gradient.addColorStop(0, 'rgba(255, 255, 255, 0.5)');
        gradient.addColorStop(0.3, 'rgba(255, 255, 255, 0.15)');
        gradient.addColorStop(1, 'rgba(255, 255, 255, 0)');
        ctx.fillStyle = gradient;
        ctx.fillRect(0, 0, 64, 64);
        const tex = new THREE.CanvasTexture(c);
        const mat = new THREE.SpriteMaterial({
            map: tex, transparent: true, opacity: 0.3,
            color: color, depthWrite: false, blending: THREE.AdditiveBlending,
        });
        const sprite = new THREE.Sprite(mat);
        sprite.scale.set(20, 20, 1);
        return sprite;
    }

    function makeLabel(text) {
        const c = document.createElement('canvas');
        const ctx = c.getContext('2d');
        c.width = 256; c.height = 64;
        ctx.clearRect(0, 0, 256, 64);

        // Shadow for readability
        ctx.shadowColor = 'rgba(0, 0, 0, 0.8)';
        ctx.shadowBlur = 4;
        ctx.shadowOffsetX = 0;
        ctx.shadowOffsetY = 1;

        ctx.font = 'bold 20px monospace';
        ctx.textAlign = 'center';
        ctx.fillStyle = '#e0e4f0';
        ctx.fillText(text, 128, 38);
        const tex = new THREE.CanvasTexture(c);
        const mat = new THREE.SpriteMaterial({ map: tex, transparent: true, depthTest: false });
        const sprite = new THREE.Sprite(mat);
        sprite.scale.set(30, 8, 1);
        return sprite;
    }

    function createEdge(key, srcNode, dstNode, color, proto) {
        // Curved arc edge using QuadraticBezierCurve3
        const src = new THREE.Vector3(srcNode.x, 0, srcNode.z);
        const dst = new THREE.Vector3(dstNode.x, 0, dstNode.z);
        const mid = new THREE.Vector3(
            (srcNode.x + dstNode.x) / 2,
            settings.arcHeight * 0.5,
            (srcNode.z + dstNode.z) / 2
        );

        const curve = new THREE.QuadraticBezierCurve3(src, mid, dst);
        const points = curve.getPoints(32);
        const geo = new THREE.BufferGeometry().setFromPoints(points);
        const mat = new THREE.LineBasicMaterial({
            color, transparent: true, opacity: settings.edgeOpacity,
        });
        const line = new THREE.Line(geo, mat);
        scene.add(line);
        edges.set(key, { line, count: 0, proto: proto || 'other', srcNode, dstNode });
    }

    function spawnParticle(srcNode, dstNode, color) {
        while (particles.length >= MAX_PARTICLES) {
            const old = particles.shift();
            scene.remove(old.mesh);
            old.mesh.geometry.dispose();
            old.mesh.material.dispose();
            if (old.trail) {
                scene.remove(old.trail);
                old.trail.geometry.dispose();
                old.trail.material.dispose();
            }
        }

        // Glowing particle sphere
        const geo = new THREE.SphereGeometry(1.0, 8, 6);
        const mat = new THREE.MeshBasicMaterial({
            color, transparent: true, opacity: 1.0,
        });
        const mesh = new THREE.Mesh(geo, mat);
        mesh.position.set(srcNode.x, 0, srcNode.z);
        scene.add(mesh);

        // Trail line
        const trailPositions = new Float32Array(30 * 3); // 30 segments
        const trailGeo = new THREE.BufferGeometry();
        trailGeo.setAttribute('position', new THREE.BufferAttribute(trailPositions, 3));
        const trailMat = new THREE.LineBasicMaterial({
            color, transparent: true, opacity: 0.4,
        });
        const trail = new THREE.Line(trailGeo, trailMat);
        scene.add(trail);

        particles.push({
            mesh, trail,
            srcX: srcNode.x, srcZ: srcNode.z,
            dstX: dstNode.x, dstZ: dstNode.z,
            t: 0,
            speed: (0.006 + Math.random() * 0.010) * settings.particleSpeed,
            history: [],
        });
    }

    function animate() {
        requestAnimationFrame(animate);

        if (controls) controls.update();

        if (animating) {
            const time = Date.now() * 0.001;

            // Update particles
            for (let i = particles.length - 1; i >= 0; i--) {
                const p = particles[i];
                p.t += p.speed * settings.particleSpeed;
                if (p.t >= 1) {
                    scene.remove(p.mesh);
                    p.mesh.geometry.dispose();
                    p.mesh.material.dispose();
                    if (p.trail) {
                        scene.remove(p.trail);
                        p.trail.geometry.dispose();
                        p.trail.material.dispose();
                    }
                    particles.splice(i, 1);
                    continue;
                }

                const arcH = Math.sin(p.t * Math.PI) * settings.arcHeight;
                const px = p.srcX + (p.dstX - p.srcX) * p.t;
                const pz = p.srcZ + (p.dstZ - p.srcZ) * p.t;
                p.mesh.position.set(px, arcH, pz);
                p.mesh.material.opacity = Math.min(1.0, (1 - p.t) * 2);

                // Pulse size
                const pulse = 1.0 + Math.sin(p.t * Math.PI * 4) * 0.15;
                p.mesh.scale.setScalar(pulse);

                // Update trail
                p.history.push({ x: px, y: arcH, z: pz });
                if (p.history.length > 30) p.history.shift();

                if (p.trail && p.history.length > 1) {
                    const positions = p.trail.geometry.attributes.position.array;
                    for (let j = 0; j < 30; j++) {
                        const idx = Math.min(j, p.history.length - 1);
                        const pt = p.history[idx];
                        positions[j * 3] = pt.x;
                        positions[j * 3 + 1] = pt.y;
                        positions[j * 3 + 2] = pt.z;
                    }
                    p.trail.geometry.attributes.position.needsUpdate = true;
                    p.trail.geometry.setDrawRange(0, p.history.length);
                    p.trail.material.opacity = 0.3 * (1 - p.t);
                }
            }

            // Animate nodes
            nodes.forEach(node => {
                // Ring pulse
                if (node.ring) {
                    const phase = time * 1.2;
                    node.ring.material.opacity = 0.12 + Math.sin(phase) * 0.08;
                    node.ring.scale.setScalar(1 + Math.sin(phase * 0.8) * 0.15);
                    node.ring.rotation.z = time * 0.1;
                }
                // Glow pulse
                if (node.glow) {
                    const phase = time * 0.8;
                    const glowScale = 18 + Math.sin(phase) * 4;
                    node.glow.scale.set(glowScale, glowScale, 1);
                }
                // Node bob
                node.mesh.position.y = Math.sin(time * 0.5 + node.x * 0.1) * 1.5;
            });

            // Point light color shift
            if (pointLight) {
                const hue = (time * 0.02) % 1;
                pointLight.color.setHSL(hue * 0.15 + 0.6, 0.6, 0.6);
            }
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
        Object.keys(nodeProtoCount).forEach(k => delete nodeProtoCount[k]);
        if (!scene) return;
        nodes.forEach(n => {
            scene.remove(n.mesh); scene.remove(n.label);
            if (n.ring) scene.remove(n.ring);
            if (n.glow) scene.remove(n.glow);
            n.mesh.geometry.dispose(); n.mesh.material.dispose();
        });
        nodes.clear();
        edges.forEach(e => {
            scene.remove(e.line); e.line.geometry.dispose(); e.line.material.dispose();
        });
        edges.clear();
        particles.forEach(p => {
            scene.remove(p.mesh); p.mesh.geometry.dispose(); p.mesh.material.dispose();
            if (p.trail) {
                scene.remove(p.trail); p.trail.geometry.dispose(); p.trail.material.dispose();
            }
        });
        particles.length = 0;

        Object.keys(protoStats).forEach(k => delete protoStats[k]);
        Object.keys(ipStats).forEach(k => delete ipStats[k]);
        const el = document.getElementById('v3d-stats-content');
        if (el) el.innerHTML = '';
    }

    function addGrid() {
        if (gridHelper) scene.remove(gridHelper);
        const gridColor = isDarkTheme ? 0x111122 : 0xc0c0c0;
        const gridBg = isDarkTheme ? 0x080810 : 0xe0e0e0;
        gridHelper = new THREE.GridHelper(500, 50, gridColor, gridBg);
        gridHelper.position.y = -10;
        gridHelper.material.transparent = true;
        gridHelper.material.opacity = isDarkTheme ? 0.4 : 0.6;
        scene.add(gridHelper);
    }

    function updateTheme(dark) {
        isDarkTheme = dark;
        if (!scene) return;
        applySceneBg();
        applyFog();
        addGrid();
    }

    return { init, addPacket, clear, updateTheme, onPageVisible };
})();
