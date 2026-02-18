// security.js — Real-time threat detection engine + security dashboard
'use strict';

const Security = (() => {
    let container = null;
    let alertCount = 0;
    let badgeEl = null;
    let countEl = null;

    // Sliding window trackers (keyed by source IP)
    const synTracker = {};      // ip -> { ports: Set, count, firstSeen }
    const connTracker = {};     // ip -> { dstPorts: Map<port, count>, firstSeen }
    const icmpTracker = {};     // ip -> { targets: Set, count, firstSeen }
    const arpTable = {};        // ip -> { macs: Set }
    const dnsTracker = {};      // ip -> { queries: count, firstSeen, longNames: count }
    const udpFloodTracker = {}; // "src->dst" -> { count, firstSeen }
    const alerts = [];          // { id, severity, type, title, detail, timestamp, pktNumbers, srcIp }

    // Dedup: don't fire same alert type+source more than once per window
    const firedAlerts = {};     // "type:srcIp" -> lastFiredTime

    const WINDOW_MS = 10000;    // 10s sliding window
    const DEDUP_MS = 30000;     // suppress duplicate alerts for 30s

    // Thresholds
    const PORT_SCAN_THRESHOLD = 15;       // distinct ports from one IP
    const SYN_FLOOD_THRESHOLD = 50;       // SYN packets to same dest in window
    const BRUTE_FORCE_THRESHOLD = 10;     // connections to same auth port in window
    const ICMP_SWEEP_THRESHOLD = 10;      // ICMP to distinct targets
    const DNS_TUNNEL_NAME_LEN = 50;       // query name length
    const DNS_TUNNEL_RATE = 30;           // DNS queries in window
    const UDP_FLOOD_THRESHOLD = 100;      // UDP packets same src->dst in window
    const LARGE_PACKET_SIZE = 9000;       // jumbo/amplification

    const AUTH_PORTS = new Set(['22', '23', '3389', '5900', '21', '3306', '5432', '1433', '6379', '27017']);

    // ==================== DASHBOARD STATE ====================
    // Traffic rate — rolling 60 one-second buckets
    const RATE_BUCKETS = 60;
    let rateBuckets = [];       // { pkts, bytes, ts }
    let curBucket = { pkts: 0, bytes: 0, ts: 0 };

    // Protocol distribution — lifetime counters
    const protoCounts = { tcp: 0, udp: 0, dns: 0, icmp: 0, arp: 0, http: 0, other: 0 };

    // Top talkers — IP -> packet count
    const talkerCounts = {};

    // Bandwidth (directional)
    let bwInBytes = 0;
    let bwOutBytes = 0;
    let bwTotalIn = 0;
    let bwTotalOut = 0;
    const BW_BUCKETS = 60;
    let bwBuckets = [];         // { inB, outB, ts }
    let curBwBucket = { inB: 0, outB: 0, ts: 0 };

    // Active attacks — Map<type+srcIp, { type, severity, title, srcIp, lastSeen }>
    const activeAttacks = new Map();
    const ACTIVE_ATTACK_TTL = 30000; // 30s

    // DDoS state
    let ddosState = null;       // { type, source, target, startTime, rateBuckets[] }
    const DDOS_BARS = 30;
    const DDOS_TIMEOUT = 15000; // hide after 15s of no new flood alerts

    let dashboardInterval = null;

    function init() {
        container = document.getElementById('alert-list');
        badgeEl = document.getElementById('alert-badge');
        countEl = document.getElementById('security-alert-count');

        const clearBtn = document.getElementById('btn-alerts-clear');
        if (clearBtn) {
            clearBtn.addEventListener('click', clear);
        }

        // Start dashboard refresh at 1s interval
        if (!dashboardInterval) {
            dashboardInterval = setInterval(refreshDashboard, 1000);
        }
    }

    function analyze(pkt) {
        if (!pkt) return;
        const now = Date.now();
        const srcIp = stripPort(pkt.srcAddr);
        const dstIp = stripPort(pkt.dstAddr);
        const srcPort = extractPort(pkt.srcAddr);
        const dstPort = extractPort(pkt.dstAddr);
        const proto = (pkt.protocol || '').toLowerCase();
        const info = pkt.info || '';

        // --- Port Scan detection ---
        if (proto === 'tcp' && info.includes('SYN') && !info.includes('ACK')) {
            if (!synTracker[srcIp]) synTracker[srcIp] = { ports: new Set(), count: 0, firstSeen: now };
            const st = synTracker[srcIp];
            if (now - st.firstSeen > WINDOW_MS) { st.ports.clear(); st.count = 0; st.firstSeen = now; }
            st.ports.add(dstIp + ':' + dstPort);
            st.count++;
            if (st.ports.size >= PORT_SCAN_THRESHOLD) {
                fireAlert(now, 'critical', 'port_scan', 'Port Scan Detected',
                    `${srcIp} sent SYN to ${st.ports.size} distinct ports in ${(WINDOW_MS/1000)}s`,
                    pkt.number, srcIp);
            }
        }

        // --- SYN Flood detection ---
        if (proto === 'tcp' && info.includes('SYN') && !info.includes('ACK')) {
            const key = srcIp + '->' + dstIp;
            if (!connTracker[key]) connTracker[key] = { count: 0, firstSeen: now };
            const ct = connTracker[key];
            if (now - ct.firstSeen > WINDOW_MS) { ct.count = 0; ct.firstSeen = now; }
            ct.count++;
            if (ct.count >= SYN_FLOOD_THRESHOLD) {
                fireAlert(now, 'critical', 'syn_flood', 'SYN Flood',
                    `${srcIp} -> ${dstIp}: ${ct.count} SYN packets in ${(WINDOW_MS/1000)}s`,
                    pkt.number, srcIp);
            }
        }

        // --- Christmas Tree / NULL / FIN Scan ---
        if (proto === 'tcp') {
            const flags = extractFlags(info);
            if (flags.urg && flags.psh && flags.fin) {
                fireAlert(now, 'high', 'xmas_scan', 'Christmas Tree Scan',
                    `${srcIp} -> ${dstIp}:${dstPort} — TCP packet with URG+PSH+FIN flags (Xmas scan)`,
                    pkt.number, srcIp);
            }
            if (flags.fin && !flags.ack && !flags.syn && !flags.rst) {
                fireAlert(now, 'medium', 'fin_scan', 'FIN Scan',
                    `${srcIp} -> ${dstIp}:${dstPort} — bare FIN packet (stealth scan)`,
                    pkt.number, srcIp);
            }
            if (!flags.syn && !flags.ack && !flags.fin && !flags.rst && !flags.psh && !flags.urg) {
                fireAlert(now, 'medium', 'null_scan', 'NULL Scan',
                    `${srcIp} -> ${dstIp}:${dstPort} — TCP packet with no flags set`,
                    pkt.number, srcIp);
            }
        }

        // --- Brute Force (auth ports) ---
        if ((proto === 'tcp') && AUTH_PORTS.has(dstPort)) {
            const key = srcIp + ':' + dstPort;
            if (!connTracker[key]) connTracker[key] = { count: 0, firstSeen: now };
            const ct = connTracker[key];
            if (now - ct.firstSeen > WINDOW_MS) { ct.count = 0; ct.firstSeen = now; }
            ct.count++;
            if (ct.count >= BRUTE_FORCE_THRESHOLD) {
                const svc = portToService(dstPort);
                fireAlert(now, 'high', 'brute_force', 'Possible Brute Force',
                    `${srcIp} -> ${dstIp}:${dstPort} (${svc}): ${ct.count} connections in ${(WINDOW_MS/1000)}s`,
                    pkt.number, srcIp);
            }
        }

        // --- ICMP Sweep ---
        if (proto === 'icmp') {
            if (!icmpTracker[srcIp]) icmpTracker[srcIp] = { targets: new Set(), count: 0, firstSeen: now };
            const it = icmpTracker[srcIp];
            if (now - it.firstSeen > WINDOW_MS) { it.targets.clear(); it.count = 0; it.firstSeen = now; }
            it.targets.add(dstIp);
            it.count++;
            if (it.targets.size >= ICMP_SWEEP_THRESHOLD) {
                fireAlert(now, 'high', 'icmp_sweep', 'ICMP Ping Sweep',
                    `${srcIp} pinged ${it.targets.size} distinct hosts in ${(WINDOW_MS/1000)}s`,
                    pkt.number, srcIp);
            }
        }

        // --- ARP Spoofing ---
        if (proto === 'arp' && srcIp) {
            // Extract MAC from layers if available
            const mac = extractArpMac(pkt);
            if (mac) {
                if (!arpTable[srcIp]) arpTable[srcIp] = { macs: new Set() };
                arpTable[srcIp].macs.add(mac);
                if (arpTable[srcIp].macs.size > 1) {
                    const macList = [...arpTable[srcIp].macs].join(', ');
                    fireAlert(now, 'critical', 'arp_spoof', 'ARP Spoofing Detected',
                        `IP ${srcIp} claimed by multiple MACs: ${macList}`,
                        pkt.number, srcIp);
                }
            }
        }

        // --- DNS Tunneling ---
        if (proto === 'dns') {
            if (!dnsTracker[srcIp]) dnsTracker[srcIp] = { queries: 0, longNames: 0, firstSeen: now };
            const dt = dnsTracker[srcIp];
            if (now - dt.firstSeen > WINDOW_MS) { dt.queries = 0; dt.longNames = 0; dt.firstSeen = now; }
            dt.queries++;
            // Check for long query names in info
            const qname = extractDnsName(info);
            if (qname && qname.length > DNS_TUNNEL_NAME_LEN) {
                dt.longNames++;
                fireAlert(now, 'high', 'dns_tunnel', 'Possible DNS Tunneling',
                    `${srcIp}: unusually long DNS query (${qname.length} chars): ${qname.substring(0, 60)}...`,
                    pkt.number, srcIp);
            }
            if (dt.queries >= DNS_TUNNEL_RATE) {
                fireAlert(now, 'medium', 'dns_flood', 'High DNS Query Rate',
                    `${srcIp}: ${dt.queries} DNS queries in ${(WINDOW_MS/1000)}s`,
                    pkt.number, srcIp);
            }
        }

        // --- UDP Flood ---
        if (proto === 'udp') {
            const key = srcIp + '->' + dstIp;
            if (!udpFloodTracker[key]) udpFloodTracker[key] = { count: 0, firstSeen: now };
            const uf = udpFloodTracker[key];
            if (now - uf.firstSeen > WINDOW_MS) { uf.count = 0; uf.firstSeen = now; }
            uf.count++;
            if (uf.count >= UDP_FLOOD_THRESHOLD) {
                fireAlert(now, 'high', 'udp_flood', 'UDP Flood',
                    `${srcIp} -> ${dstIp}: ${uf.count} UDP packets in ${(WINDOW_MS/1000)}s`,
                    pkt.number, srcIp);
            }
        }

        // --- Abnormally Large Packets (amplification) ---
        if (pkt.length > LARGE_PACKET_SIZE) {
            fireAlert(now, 'low', 'large_packet', 'Abnormally Large Packet',
                `${srcIp} -> ${dstIp}: ${pkt.length} bytes (${proto.toUpperCase()}) — possible amplification`,
                pkt.number, srcIp);
        }

        // ==================== DASHBOARD FAST PATH ====================
        // (no DOM writes — only counter increments)

        const pktBytes = pkt.length || 0;
        const sec = Math.floor(now / 1000);

        // Traffic rate buckets
        if (curBucket.ts !== sec) {
            if (curBucket.ts !== 0) {
                rateBuckets.push({ pkts: curBucket.pkts, bytes: curBucket.bytes, ts: curBucket.ts });
                if (rateBuckets.length > RATE_BUCKETS) rateBuckets.shift();
            }
            curBucket.pkts = 0;
            curBucket.bytes = 0;
            curBucket.ts = sec;
        }
        curBucket.pkts++;
        curBucket.bytes += pktBytes;

        // Protocol counters
        if (proto === 'tcp') protoCounts.tcp++;
        else if (proto === 'udp') protoCounts.udp++;
        else if (proto === 'dns') protoCounts.dns++;
        else if (proto === 'icmp') protoCounts.icmp++;
        else if (proto === 'arp') protoCounts.arp++;
        else if (proto === 'http') protoCounts.http++;
        else protoCounts.other++;

        // Top talkers
        if (srcIp) {
            talkerCounts[srcIp] = (talkerCounts[srcIp] || 0) + 1;
        }

        // Bandwidth (directional)
        const dstIsLocal = typeof Filters !== 'undefined' && Filters.isLocalAddr ? Filters.isLocalAddr(pkt.dstAddr) : false;
        const srcIsLocal = typeof Filters !== 'undefined' && Filters.isLocalAddr ? Filters.isLocalAddr(pkt.srcAddr) : false;

        if (curBwBucket.ts !== sec) {
            if (curBwBucket.ts !== 0) {
                bwBuckets.push({ inB: curBwBucket.inB, outB: curBwBucket.outB, ts: curBwBucket.ts });
                if (bwBuckets.length > BW_BUCKETS) bwBuckets.shift();
            }
            curBwBucket.inB = 0;
            curBwBucket.outB = 0;
            curBwBucket.ts = sec;
        }

        if (dstIsLocal && !srcIsLocal) {
            curBwBucket.inB += pktBytes;
            bwTotalIn += pktBytes;
        } else if (srcIsLocal && !dstIsLocal) {
            curBwBucket.outB += pktBytes;
            bwTotalOut += pktBytes;
        }
    }

    function fireAlert(now, severity, type, title, detail, pktNumber, srcIp) {
        const dedupKey = type + ':' + srcIp;
        if (firedAlerts[dedupKey] && now - firedAlerts[dedupKey] < DEDUP_MS) return;
        firedAlerts[dedupKey] = now;

        alertCount++;
        const alert = {
            id: alertCount,
            severity,
            type,
            title,
            detail,
            timestamp: new Date(now).toLocaleTimeString(),
            pktNumber,
            srcIp,
        };
        alerts.push(alert);
        renderAlert(alert);
        updateBadge();

        // Record into activeAttacks
        const attackKey = type + ':' + srcIp;
        activeAttacks.set(attackKey, { type, severity, title, srcIp, lastSeen: now });

        // Trigger DDoS banner for flood-type attacks
        if (type === 'syn_flood' || type === 'udp_flood') {
            // Parse source->target from detail
            const parts = detail.match(/^([^\s]+)\s*->\s*([^:]+)/);
            const source = parts ? parts[1] : srcIp;
            const target = parts ? parts[2] : '—';
            const rateMatch = detail.match(/(\d+)\s+(SYN|UDP)\s+packets/i);
            const rate = rateMatch ? parseInt(rateMatch[1], 10) : 0;

            if (!ddosState || ddosState.type !== type) {
                ddosState = {
                    type: type === 'syn_flood' ? 'SYN Flood' : 'UDP Flood',
                    source,
                    target,
                    startTime: now,
                    rateBuckets: [],
                };
            }
            ddosState.lastSeen = now;
            ddosState.source = source;
            ddosState.target = target;
            ddosState.rateBuckets.push(rate);
            if (ddosState.rateBuckets.length > DDOS_BARS) ddosState.rateBuckets.shift();
        }
    }

    function renderAlert(alert) {
        if (!container) return;
        // Remove empty-state placeholder
        const empty = container.querySelector('.empty-state');
        if (empty) empty.remove();

        const el = document.createElement('div');
        el.className = `alert-entry severity-${alert.severity}`;
        el.innerHTML =
            `<div class="alert-header">` +
                `<span class="alert-severity">${sevLabel(alert.severity)}</span>` +
                `<span class="alert-title">${esc(alert.title)}</span>` +
                `<span class="alert-time">${alert.timestamp}</span>` +
            `</div>` +
            `<div class="alert-detail">${esc(alert.detail)}</div>` +
            `<div class="alert-actions">` +
                `<button class="alert-filter-btn" data-ip="${esc(alert.srcIp)}">Filter IP</button>` +
                `<span class="alert-pkt">Pkt #${alert.pktNumber}</span>` +
            `</div>`;

        // Click "Filter IP" to populate the display filter and navigate to capture page
        el.querySelector('.alert-filter-btn').addEventListener('click', () => {
            const filterInput = document.getElementById('display-filter');
            filterInput.value = 'ip==' + alert.srcIp;
            filterInput.dispatchEvent(new Event('input'));
            Router.navigate('capture');
        });

        container.prepend(el);

        // Cap at 200 entries in DOM
        while (container.children.length > 200) {
            container.lastChild.remove();
        }
    }

    function updateBadge() {
        if (badgeEl) {
            badgeEl.textContent = alerts.length;
            badgeEl.style.display = alerts.length > 0 ? 'inline-block' : 'none';
        }
        if (countEl) {
            countEl.textContent = alerts.length > 0 ? alerts.length + ' alert' + (alerts.length !== 1 ? 's' : '') : '';
        }
    }

    // ==================== DASHBOARD RENDERING (1s interval) ====================

    function refreshDashboard() {
        const now = Date.now();

        // Prune expired active attacks
        for (const [key, atk] of activeAttacks) {
            if (now - atk.lastSeen > ACTIVE_ATTACK_TTL) activeAttacks.delete(key);
        }

        renderThreatLevel();
        renderTrafficRate();
        renderProtocolBars();
        renderTopTalkers();
        renderActiveAttacks();
        renderBandwidth();
        renderDdosBanner(now);
    }

    function renderThreatLevel() {
        const el = document.getElementById('sec-threat');
        const detailEl = document.getElementById('sec-threat-detail');
        if (!el) return;

        // Score based on active attacks
        const sevScores = { critical: 4, high: 3, medium: 2, low: 1 };
        let maxScore = 0;
        let attackNames = [];
        for (const [, atk] of activeAttacks) {
            const s = sevScores[atk.severity] || 0;
            if (s > maxScore) maxScore = s;
            attackNames.push(atk.title);
        }

        const levels = ['safe', 'low', 'medium', 'high', 'critical'];
        const labels = ['SAFE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
        const level = levels[maxScore];

        el.className = 'sec-threat-gauge threat-' + level;
        el.querySelector('.threat-level-text').textContent = labels[maxScore];

        if (detailEl) {
            if (activeAttacks.size === 0) {
                detailEl.textContent = 'No active threats';
            } else {
                const unique = [...new Set(attackNames)];
                detailEl.textContent = unique.slice(0, 3).join(', ') + (unique.length > 3 ? '...' : '');
            }
        }
    }

    function renderTrafficRate() {
        const ppsEl = document.getElementById('sec-pps');
        const bpsEl = document.getElementById('sec-bps');
        const sparkEl = document.getElementById('sec-rate-sparkline');
        if (!ppsEl) return;

        // Get last complete bucket
        const lastBucket = rateBuckets.length > 0 ? rateBuckets[rateBuckets.length - 1] : { pkts: 0, bytes: 0 };

        ppsEl.textContent = formatNum(lastBucket.pkts);
        bpsEl.textContent = formatBytes(lastBucket.bytes) + '/s';

        if (sparkEl) {
            const data = rateBuckets.map(b => b.pkts);
            sparkEl.innerHTML = renderSparkline(data, RATE_BUCKETS, 'sec-sparkline-line', 'sec-sparkline-fill');
        }
    }

    function renderProtocolBars() {
        const el = document.getElementById('sec-proto-bars');
        if (!el) return;

        const total = protoCounts.tcp + protoCounts.udp + protoCounts.dns +
                      protoCounts.icmp + protoCounts.arp + protoCounts.http + protoCounts.other;

        if (total === 0) {
            el.innerHTML = '<div class="sec-card-empty">No traffic yet</div>';
            return;
        }

        const protos = [
            { key: 'tcp', label: 'TCP' },
            { key: 'udp', label: 'UDP' },
            { key: 'dns', label: 'DNS' },
            { key: 'icmp', label: 'ICMP' },
            { key: 'arp', label: 'ARP' },
            { key: 'http', label: 'HTTP' },
            { key: 'other', label: 'Other' },
        ];

        let html = '';
        for (const p of protos) {
            const count = protoCounts[p.key];
            if (count === 0) continue;
            const pct = (count / total * 100);
            html += `<div class="sec-proto-row">` +
                `<span class="sec-proto-label">${p.label}</span>` +
                `<div class="sec-proto-track"><div class="sec-proto-fill sec-proto-fill-${p.key}" style="width:${pct.toFixed(1)}%"></div></div>` +
                `<span class="sec-proto-pct">${pct < 1 ? '<1' : Math.round(pct)}%</span>` +
                `</div>`;
        }
        el.innerHTML = html;
    }

    function renderTopTalkers() {
        const el = document.getElementById('sec-top-talkers');
        if (!el) return;

        const entries = Object.entries(talkerCounts);
        if (entries.length === 0) {
            el.innerHTML = '<div class="sec-card-empty">No traffic yet</div>';
            return;
        }

        entries.sort((a, b) => b[1] - a[1]);
        const top5 = entries.slice(0, 5);
        const maxCount = top5[0][1];

        let html = '';
        for (const [ip, count] of top5) {
            const pct = (count / maxCount * 100).toFixed(1);
            html += `<div class="sec-talker-row">` +
                `<span class="sec-talker-ip" title="${esc(ip)}">${esc(ip)}</span>` +
                `<div class="sec-talker-track"><div class="sec-talker-fill" style="width:${pct}%"></div></div>` +
                `<span class="sec-talker-count">${formatNum(count)}</span>` +
                `</div>`;
        }
        el.innerHTML = html;
    }

    function renderActiveAttacks() {
        const countEl2 = document.getElementById('sec-attack-count');
        const tagsEl = document.getElementById('sec-attack-tags');
        if (!countEl2) return;

        countEl2.textContent = activeAttacks.size;

        if (tagsEl) {
            if (activeAttacks.size === 0) {
                tagsEl.innerHTML = '<div class="sec-card-empty">None</div>';
                return;
            }
            // Collect unique type+severity
            const seen = new Map();
            for (const [, atk] of activeAttacks) {
                if (!seen.has(atk.type)) {
                    seen.set(atk.type, atk);
                }
            }
            let html = '';
            for (const [, atk] of seen) {
                html += `<span class="sec-attack-tag sec-attack-tag-${atk.severity}">${esc(atk.title)}</span>`;
            }
            tagsEl.innerHTML = html;
        }
    }

    function renderBandwidth() {
        const inEl = document.getElementById('sec-bw-in');
        const outEl = document.getElementById('sec-bw-out');
        const totalInEl = document.getElementById('sec-bw-total-in');
        const totalOutEl = document.getElementById('sec-bw-total-out');
        const sparkEl = document.getElementById('sec-bw-sparkline');
        if (!inEl) return;

        const lastBw = bwBuckets.length > 0 ? bwBuckets[bwBuckets.length - 1] : { inB: 0, outB: 0 };

        inEl.textContent = formatBytes(lastBw.inB) + '/s';
        outEl.textContent = formatBytes(lastBw.outB) + '/s';
        if (totalInEl) totalInEl.textContent = formatBytes(bwTotalIn);
        if (totalOutEl) totalOutEl.textContent = formatBytes(bwTotalOut);

        if (sparkEl) {
            const dataIn = bwBuckets.map(b => b.inB);
            const dataOut = bwBuckets.map(b => b.outB);
            // Overlay two sparklines: in (blue) + out (green)
            const maxLen = BW_BUCKETS;
            const allMax = Math.max(
                dataIn.reduce((a, b) => Math.max(a, b), 0),
                dataOut.reduce((a, b) => Math.max(a, b), 0),
                1
            );
            const h = 32;
            const w = 250;
            const lineIn = buildSparkPoints(dataIn, maxLen, w, h, allMax);
            const lineOut = buildSparkPoints(dataOut, maxLen, w, h, allMax);

            sparkEl.innerHTML = `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">` +
                `<polygon points="${lineIn.fill}" class="sec-sparkline-fill"/>` +
                `<polyline points="${lineIn.line}" class="sec-sparkline-line"/>` +
                `<polygon points="${lineOut.fill}" class="sec-sparkline-fill-green"/>` +
                `<polyline points="${lineOut.line}" class="sec-sparkline-line-green"/>` +
                `</svg>`;
        }
    }

    function renderDdosBanner(now) {
        const bannerEl = document.getElementById('ddos-banner');
        if (!bannerEl) return;

        if (!ddosState || now - ddosState.lastSeen > DDOS_TIMEOUT) {
            bannerEl.style.display = 'none';
            if (ddosState && now - ddosState.lastSeen > DDOS_TIMEOUT) {
                ddosState = null;
            }
            return;
        }

        bannerEl.style.display = 'block';

        const typeEl = document.getElementById('ddos-type');
        const srcEl = document.getElementById('ddos-source');
        const tgtEl = document.getElementById('ddos-target');
        const rateEl = document.getElementById('ddos-rate');
        const durEl = document.getElementById('ddos-duration');
        const chartEl = document.getElementById('ddos-chart');

        if (typeEl) typeEl.textContent = ddosState.type;
        if (srcEl) srcEl.textContent = ddosState.source;
        if (tgtEl) tgtEl.textContent = ddosState.target;

        // Rate = last bucket value
        const lastRate = ddosState.rateBuckets.length > 0 ? ddosState.rateBuckets[ddosState.rateBuckets.length - 1] : 0;
        if (rateEl) rateEl.textContent = formatNum(lastRate) + ' pkt/s';

        // Duration
        const durSec = Math.floor((now - ddosState.startTime) / 1000);
        if (durEl) {
            if (durSec < 60) durEl.textContent = durSec + 's';
            else durEl.textContent = Math.floor(durSec / 60) + 'm ' + (durSec % 60) + 's';
        }

        // Bar chart
        if (chartEl) {
            chartEl.innerHTML = renderDdosBarChart(ddosState.rateBuckets);
        }
    }

    // ==================== HELPERS ====================

    function renderSparkline(data, maxLen, lineClass, fillClass) {
        const h = 32;
        const w = 250;
        const pts = buildSparkPoints(data, maxLen, w, h);

        return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">` +
            `<polygon points="${pts.fill}" class="${fillClass}"/>` +
            `<polyline points="${pts.line}" class="${lineClass}"/>` +
            `</svg>`;
    }

    function buildSparkPoints(data, maxLen, w, h, forceMax) {
        const len = Math.min(data.length, maxLen);
        const max = forceMax || Math.max(...data, 1);
        const step = len > 1 ? w / (maxLen - 1) : w;
        const offset = maxLen - len;

        let linePoints = '';
        let fillPoints = `${offset * step},${h} `;

        for (let i = 0; i < len; i++) {
            const x = ((offset + i) * step).toFixed(1);
            const y = (h - (data[i] / max) * (h - 2) - 1).toFixed(1);
            linePoints += `${x},${y} `;
            fillPoints += `${x},${y} `;
        }

        if (len > 0) {
            fillPoints += `${((offset + len - 1) * step).toFixed(1)},${h}`;
        } else {
            fillPoints += `0,${h}`;
        }

        return { line: linePoints.trim(), fill: fillPoints.trim() };
    }

    function renderDdosBarChart(buckets) {
        if (!buckets || buckets.length === 0) return '';
        const max = Math.max(...buckets, 1);
        let html = '';
        for (let i = 0; i < DDOS_BARS; i++) {
            const val = i < buckets.length ? buckets[buckets.length - DDOS_BARS + i] : 0;
            const actual = val !== undefined && val > 0 ? val : 0;
            const pct = (actual / max * 100).toFixed(1);
            html += `<div class="ddos-bar" style="height:${Math.max(pct, 3)}%"></div>`;
        }
        return html;
    }

    function formatBytes(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
        if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
        return (bytes / 1073741824).toFixed(2) + ' GB';
    }

    function formatNum(n) {
        if (n < 1000) return String(n);
        if (n < 1000000) return (n / 1000).toFixed(1) + 'K';
        return (n / 1000000).toFixed(1) + 'M';
    }

    function clear() {
        alerts.length = 0;
        alertCount = 0;
        Object.keys(synTracker).forEach(k => delete synTracker[k]);
        Object.keys(connTracker).forEach(k => delete connTracker[k]);
        Object.keys(icmpTracker).forEach(k => delete icmpTracker[k]);
        Object.keys(arpTable).forEach(k => delete arpTable[k]);
        Object.keys(dnsTracker).forEach(k => delete dnsTracker[k]);
        Object.keys(udpFloodTracker).forEach(k => delete udpFloodTracker[k]);
        Object.keys(firedAlerts).forEach(k => delete firedAlerts[k]);
        if (container) container.innerHTML = '<div class="empty-state">No alerts detected</div>';
        updateBadge();

        // Reset dashboard state
        rateBuckets = [];
        curBucket.pkts = 0; curBucket.bytes = 0; curBucket.ts = 0;
        protoCounts.tcp = 0; protoCounts.udp = 0; protoCounts.dns = 0;
        protoCounts.icmp = 0; protoCounts.arp = 0; protoCounts.http = 0; protoCounts.other = 0;
        Object.keys(talkerCounts).forEach(k => delete talkerCounts[k]);
        bwInBytes = 0; bwOutBytes = 0; bwTotalIn = 0; bwTotalOut = 0;
        bwBuckets = [];
        curBwBucket.inB = 0; curBwBucket.outB = 0; curBwBucket.ts = 0;
        activeAttacks.clear();
        ddosState = null;

        // Re-render dashboard immediately
        refreshDashboard();
    }

    // --- Original Helpers ---

    function stripPort(addr) {
        if (!addr) return '';
        const i = addr.lastIndexOf(':');
        return i > 0 ? addr.substring(0, i) : addr;
    }

    function extractPort(addr) {
        if (!addr) return '';
        const i = addr.lastIndexOf(':');
        return i > 0 ? addr.substring(i + 1) : '';
    }

    function extractFlags(info) {
        const flags = { syn: false, ack: false, fin: false, rst: false, psh: false, urg: false };
        if (!info) return flags;
        const m = info.match(/\[([^\]]+)\]/);
        if (!m) return flags;
        const s = m[1].toUpperCase();
        flags.syn = s.includes('SYN');
        flags.ack = s.includes('ACK');
        flags.fin = s.includes('FIN');
        flags.rst = s.includes('RST');
        flags.psh = s.includes('PSH');
        flags.urg = s.includes('URG');
        return flags;
    }

    function extractArpMac(pkt) {
        if (!pkt.layers) return null;
        for (const layer of pkt.layers) {
            if (layer.name === 'ARP') {
                for (const f of layer.fields) {
                    if (f.name === 'Sender MAC') return f.value;
                }
            }
        }
        return null;
    }

    function extractDnsName(info) {
        if (!info) return '';
        // DNS info looks like "Standard query A very.long.domain.example.com"
        const parts = info.split(/\s+/);
        // Find the longest token that looks like a domain
        for (let i = parts.length - 1; i >= 0; i--) {
            if (parts[i].includes('.') && parts[i].length > 5) return parts[i];
        }
        return '';
    }

    function portToService(port) {
        const map = {
            '22': 'SSH', '23': 'Telnet', '21': 'FTP', '3389': 'RDP', '5900': 'VNC',
            '3306': 'MySQL', '5432': 'PostgreSQL', '1433': 'MSSQL', '6379': 'Redis', '27017': 'MongoDB',
        };
        return map[port] || 'port ' + port;
    }

    function sevLabel(sev) {
        const map = { critical: 'CRIT', high: 'HIGH', medium: 'MED', low: 'LOW' };
        return map[sev] || sev.toUpperCase();
    }

    function esc(s) {
        if (!s) return '';
        return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    return { init, analyze, clear };
})();
