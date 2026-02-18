// security.js — Real-time threat detection engine
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

    function init() {
        container = document.getElementById('alert-list');
        badgeEl = document.getElementById('alert-badge');
        countEl = document.getElementById('security-alert-count');

        const clearBtn = document.getElementById('btn-alerts-clear');
        if (clearBtn) {
            clearBtn.addEventListener('click', clear);
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
    }

    // --- Helpers ---

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
