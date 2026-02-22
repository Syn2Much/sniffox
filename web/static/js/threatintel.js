// threatintel.js — Threat intelligence dashboard: MITRE ATT&CK mapping, IOCs, risk scores, geo-IP
'use strict';

const ThreatIntel = (() => {
    // ==================== STATE ====================

    // All observed IPs and their metadata
    const ipData = {};          // ip -> { firstSeen, lastSeen, pktCount, alerts: [], attackTypes: Set, riskScore: 0 }

    // DNS queries extracted from packet info
    const dnsQueries = {};      // domain -> { firstSeen, count, srcIps: Set }

    // Port tracking per IP
    const portActivity = {};    // ip -> Set of ports

    // IOC entries
    const iocEntries = [];      // { type, value, reason, firstSeen, pktCount }
    const iocIndex = {};        // "type:value" -> index in iocEntries

    // MITRE ATT&CK observed techniques
    const observedTechniques = new Set();   // technique IDs like "T1046"

    // Geo-IP counters
    const geoCounters = { private: 0, public: 0, multicast: 0, loopback: 0 };
    const classifiedIps = {};   // ip -> classification (avoid double-counting)

    // Dirty flag for throttled rendering
    let dirty = false;
    let refreshInterval = null;

    // ==================== MITRE ATT&CK DEFINITIONS ====================

    const TACTICS = [
        { id: 'reconnaissance',  name: 'Reconnaissance' },
        { id: 'initial-access',  name: 'Initial Access' },
        { id: 'execution',       name: 'Execution' },
        { id: 'persistence',     name: 'Persistence' },
        { id: 'c2',              name: 'C2' },
        { id: 'exfiltration',    name: 'Exfiltration' },
        { id: 'impact',          name: 'Impact' },
    ];

    const TECHNIQUES = [
        { id: 'T1046',     name: 'Network Service Discovery',  tactic: 'reconnaissance' },
        { id: 'T1018',     name: 'Remote System Discovery',    tactic: 'reconnaissance' },
        { id: 'T1595',     name: 'Active Scanning',            tactic: 'reconnaissance' },
        { id: 'T1190',     name: 'Exploit Public-Facing App',  tactic: 'initial-access' },
        { id: 'T1110',     name: 'Brute Force',                tactic: 'initial-access' },
        { id: 'T1059',     name: 'Command & Scripting',        tactic: 'execution' },
        { id: 'T1053',     name: 'Scheduled Task/Job',         tactic: 'execution' },
        { id: 'T1098',     name: 'Account Manipulation',       tactic: 'persistence' },
        { id: 'T1136',     name: 'Create Account',             tactic: 'persistence' },
        { id: 'T1071.004', name: 'DNS Protocol',               tactic: 'c2' },
        { id: 'T1071.001', name: 'Web Protocols',              tactic: 'c2' },
        { id: 'T1557',     name: 'AitM',                       tactic: 'c2' },
        { id: 'T1048',     name: 'Exfiltration Over Alt Proto', tactic: 'exfiltration' },
        { id: 'T1041',     name: 'Exfil Over C2 Channel',      tactic: 'exfiltration' },
        { id: 'T1498',     name: 'DDoS',                       tactic: 'impact' },
        { id: 'T1499',     name: 'Endpoint DoS',               tactic: 'impact' },
        { id: 'T1489',     name: 'Service Stop',               tactic: 'impact' },
    ];

    // Alert type -> MITRE technique mapping
    const ALERT_TO_TECHNIQUE = {
        port_scan:    'T1046',
        dns_tunnel:   'T1071.004',
        dns_flood:    'T1071.004',
        brute_force:  'T1110',
        syn_flood:    'T1498',
        arp_spoof:    'T1557',
        icmp_sweep:   'T1018',
        large_packet: 'T1499',
        udp_flood:    'T1498',
        xmas_scan:    'T1046',
        fin_scan:     'T1046',
        null_scan:    'T1046',
    };

    // Severity weight for risk scoring
    const SEVERITY_WEIGHTS = {
        critical: 25,
        high:     15,
        medium:   8,
        low:      3,
    };

    // ==================== INIT ====================

    function init() {
        renderMitreGrid();
        renderIocList();
        renderRiskTable();
        renderGeoSummary();

        if (!refreshInterval) {
            refreshInterval = setInterval(() => {
                if (dirty) {
                    dirty = false;
                    renderMitreGrid();
                    renderIocList();
                    renderRiskTable();
                    renderGeoSummary();
                }
            }, 1000);
        }
    }

    // ==================== PACKET INGESTION ====================

    function addPacket(pkt) {
        if (!pkt) return;

        const srcIp = stripPort(pkt.srcAddr);
        const dstIp = stripPort(pkt.dstAddr);
        const srcPort = extractPort(pkt.srcAddr);
        const dstPort = extractPort(pkt.dstAddr);
        const proto = (pkt.protocol || '').toLowerCase();
        const info = pkt.info || '';
        const now = pkt.timestamp || Date.now();

        // Track source IP
        if (srcIp) {
            trackIp(srcIp, now);
        }

        // Track destination IP
        if (dstIp) {
            trackIp(dstIp, now);
        }

        // Track port activity
        if (srcIp && srcPort) {
            if (!portActivity[srcIp]) portActivity[srcIp] = new Set();
            portActivity[srcIp].add(srcPort);
        }
        if (dstIp && dstPort) {
            if (!portActivity[dstIp]) portActivity[dstIp] = new Set();
            portActivity[dstIp].add(dstPort);
        }

        // Classify IPs for geo summary
        if (srcIp) classifyIp(srcIp);
        if (dstIp) classifyIp(dstIp);

        // Extract DNS queries from info
        if (proto === 'dns' && info) {
            const domain = extractDnsDomain(info);
            if (domain) {
                if (!dnsQueries[domain]) {
                    dnsQueries[domain] = { firstSeen: now, count: 0, srcIps: new Set() };
                }
                dnsQueries[domain].count++;
                if (srcIp) dnsQueries[domain].srcIps.add(srcIp);
            }
        }

        // Detect unusual port usage for IOC tracking
        if (dstPort) {
            const portNum = parseInt(dstPort, 10);
            if (!isNaN(portNum) && portNum > 0) {
                // Flag high ports used with common protocols as potentially suspicious
                if (portNum > 49152 && (proto === 'tcp' || proto === 'udp')) {
                    addIoc('port', dstPort, 'Ephemeral/high port communication', now);
                }
            }
        }

        dirty = true;
    }

    // ==================== ALERT INGESTION ====================

    function addAlert(alert) {
        if (!alert) return;

        const { type, severity, srcIp, title, detail } = alert;
        const now = Date.now();

        // Map alert to MITRE technique
        const techniqueId = ALERT_TO_TECHNIQUE[type];
        if (techniqueId) {
            observedTechniques.add(techniqueId);
        }

        // Update IP risk data
        if (srcIp) {
            if (!ipData[srcIp]) {
                ipData[srcIp] = {
                    firstSeen: now,
                    lastSeen: now,
                    pktCount: 0,
                    alerts: [],
                    attackTypes: new Set(),
                    riskScore: 0,
                };
            }
            const data = ipData[srcIp];
            data.lastSeen = now;
            data.alerts.push({ type, severity, title, time: now });
            if (type) data.attackTypes.add(type);
            data.riskScore = calculateRiskScore(data);

            // Add suspicious IP as IOC
            addIoc('ip', srcIp, title || 'Alert: ' + type, now);
        }

        // Add DNS-related IOCs from alert detail
        if ((type === 'dns_tunnel' || type === 'dns_flood') && detail) {
            const domain = extractDnsDomain(detail);
            if (domain) {
                addIoc('domain', domain, title || 'Suspicious DNS activity', now);
            }
        }

        dirty = true;
    }

    // ==================== RISK SCORE CALCULATION ====================

    function calculateRiskScore(data) {
        let score = 0;

        // Factor 1: Alert count (diminishing returns)
        const alertCount = data.alerts.length;
        score += Math.min(alertCount * 5, 30);

        // Factor 2: Severity of alerts
        for (const a of data.alerts) {
            score += (SEVERITY_WEIGHTS[a.severity] || 0);
        }

        // Factor 3: Variety of attack types (diversity penalty)
        score += data.attackTypes.size * 8;

        // Clamp to 0-100
        return Math.min(Math.max(Math.round(score), 0), 100);
    }

    // ==================== IP TRACKING ====================

    function trackIp(ip, now) {
        if (!ipData[ip]) {
            ipData[ip] = {
                firstSeen: now,
                lastSeen: now,
                pktCount: 0,
                alerts: [],
                attackTypes: new Set(),
                riskScore: 0,
            };
        }
        const data = ipData[ip];
        data.lastSeen = now;
        data.pktCount++;
    }

    // ==================== IOC MANAGEMENT ====================

    function addIoc(type, value, reason, firstSeen) {
        const key = type + ':' + value;
        if (iocIndex[key] !== undefined) {
            // Update existing IOC
            iocEntries[iocIndex[key]].pktCount++;
            return;
        }

        const entry = {
            type: type,
            value: value,
            reason: reason,
            firstSeen: firstSeen,
            pktCount: 1,
        };
        iocIndex[key] = iocEntries.length;
        iocEntries.push(entry);
    }

    // ==================== GEO-IP CLASSIFICATION ====================

    function classifyIp(ip) {
        if (!ip || classifiedIps[ip]) return;

        let classification;

        if (isLoopback(ip)) {
            classification = 'loopback';
        } else if (isMulticast(ip)) {
            classification = 'multicast';
        } else if (isPrivate(ip)) {
            classification = 'private';
        } else {
            classification = 'public';
        }

        classifiedIps[ip] = classification;
        geoCounters[classification]++;
    }

    function isLoopback(ip) {
        return ip === '127.0.0.1' || ip === '::1' || ip.startsWith('127.');
    }

    function isMulticast(ip) {
        if (ip.startsWith('ff')) return true;   // IPv6 multicast
        const firstOctet = parseInt(ip.split('.')[0], 10);
        return firstOctet >= 224 && firstOctet <= 239;
    }

    function isPrivate(ip) {
        if (ip.startsWith('10.')) return true;
        if (ip.startsWith('172.')) {
            const second = parseInt(ip.split('.')[1], 10);
            return second >= 16 && second <= 31;
        }
        if (ip.startsWith('192.168.')) return true;
        if (ip.startsWith('fc') || ip.startsWith('fd')) return true;    // IPv6 ULA
        if (ip.startsWith('fe80')) return true;                          // IPv6 link-local
        return false;
    }

    // ==================== RENDERING: MITRE ATT&CK GRID ====================

    function renderMitreGrid() {
        const container = document.getElementById('ti-mitre-grid');
        if (!container) return;

        let html = '<div class="ti-mitre-grid-inner">';

        for (const tactic of TACTICS) {
            html += '<div class="ti-mitre-tactic-col">';
            html += '<div class="ti-mitre-tactic-header">' + esc(tactic.name) + '</div>';

            const techniques = TECHNIQUES.filter(t => t.tactic === tactic.id);
            for (const tech of techniques) {
                const isObserved = observedTechniques.has(tech.id);
                const cls = isObserved ? 'ti-mitre-tech ti-mitre-tech-active' : 'ti-mitre-tech';
                html += '<div class="' + cls + '" title="' + esc(tech.id + ' — ' + tech.name) + '">';
                html += '<span class="ti-mitre-tech-id">' + esc(tech.id) + '</span>';
                html += '<span class="ti-mitre-tech-name">' + esc(tech.name) + '</span>';
                html += '</div>';
            }

            html += '</div>';
        }

        html += '</div>';
        container.innerHTML = html;
    }

    // ==================== RENDERING: IOC LIST ====================

    function renderIocList() {
        const container = document.getElementById('ti-ioc-list');
        if (!container) return;

        if (iocEntries.length === 0) {
            container.innerHTML = '<div class="ti-empty-state">No indicators of compromise detected</div>';
            return;
        }

        // Show most recent first, cap at 200
        const entries = iocEntries.slice().reverse().slice(0, 200);

        let html = '<table class="ti-ioc-table">';
        html += '<thead><tr>';
        html += '<th>Type</th>';
        html += '<th>Value</th>';
        html += '<th>Reason</th>';
        html += '<th>First Seen</th>';
        html += '<th>Count</th>';
        html += '</tr></thead>';
        html += '<tbody>';

        for (const entry of entries) {
            const icon = iocTypeIcon(entry.type);
            const timeStr = formatTime(entry.firstSeen);
            html += '<tr class="ti-ioc-row ti-ioc-type-' + esc(entry.type) + '">';
            html += '<td class="ti-ioc-type-cell"><span class="ti-ioc-icon">' + icon + '</span> ' + esc(entry.type) + '</td>';
            html += '<td class="ti-ioc-value" title="' + esc(entry.value) + '">' + esc(entry.value) + '</td>';
            html += '<td class="ti-ioc-reason">' + esc(entry.reason) + '</td>';
            html += '<td class="ti-ioc-time">' + esc(timeStr) + '</td>';
            html += '<td class="ti-ioc-count">' + entry.pktCount + '</td>';
            html += '</tr>';
        }

        html += '</tbody></table>';
        container.innerHTML = html;
    }

    function iocTypeIcon(type) {
        switch (type) {
            case 'ip':     return '&#128267;';  // IP address icon (key)
            case 'domain': return '&#127760;';  // globe
            case 'port':   return '&#128268;';  // link
            default:       return '&#128196;';  // document
        }
    }

    // ==================== RENDERING: RISK TABLE ====================

    function renderRiskTable() {
        const container = document.getElementById('ti-risk-table');
        if (!container) return;

        // Collect IPs that have alerts (risk > 0)
        const riskyIps = [];
        for (const ip in ipData) {
            const data = ipData[ip];
            if (data.alerts.length > 0) {
                riskyIps.push({
                    ip: ip,
                    riskScore: data.riskScore,
                    alertCount: data.alerts.length,
                    attackTypes: [...data.attackTypes].join(', '),
                    lastActivity: data.lastSeen,
                });
            }
        }

        if (riskyIps.length === 0) {
            container.innerHTML = '<div class="ti-empty-state">No risky hosts detected</div>';
            return;
        }

        // Sort by risk score descending
        riskyIps.sort((a, b) => b.riskScore - a.riskScore);

        // Cap at 100 entries
        const display = riskyIps.slice(0, 100);

        let html = '<table class="ti-risk-score-table">';
        html += '<thead><tr>';
        html += '<th>IP</th>';
        html += '<th>Risk Score</th>';
        html += '<th>Alert Count</th>';
        html += '<th>Attack Types</th>';
        html += '<th>Last Activity</th>';
        html += '</tr></thead>';
        html += '<tbody>';

        for (const entry of display) {
            const riskClass = riskColorClass(entry.riskScore);
            const timeStr = formatTime(entry.lastActivity);
            html += '<tr class="ti-risk-row">';
            html += '<td class="ti-risk-ip">' + esc(entry.ip) + '</td>';
            html += '<td class="ti-risk-score ' + riskClass + '">';
            html += '<div class="ti-risk-bar-track"><div class="ti-risk-bar-fill ' + riskClass + '" style="width:' + entry.riskScore + '%"></div></div>';
            html += '<span class="ti-risk-score-num">' + entry.riskScore + '</span>';
            html += '</td>';
            html += '<td class="ti-risk-alert-count">' + entry.alertCount + '</td>';
            html += '<td class="ti-risk-attack-types" title="' + esc(entry.attackTypes) + '">' + esc(formatAttackTypes(entry.attackTypes)) + '</td>';
            html += '<td class="ti-risk-time">' + esc(timeStr) + '</td>';
            html += '</tr>';
        }

        html += '</tbody></table>';
        container.innerHTML = html;
    }

    function riskColorClass(score) {
        if (score <= 25) return 'ti-risk-green';
        if (score <= 50) return 'ti-risk-yellow';
        if (score <= 75) return 'ti-risk-orange';
        return 'ti-risk-red';
    }

    function formatAttackTypes(typesStr) {
        if (!typesStr) return '--';
        // Replace underscores with spaces and capitalize
        return typesStr.split(', ').map(t => {
            return t.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
        }).join(', ');
    }

    // ==================== RENDERING: GEO-IP SUMMARY ====================

    function renderGeoSummary() {
        const container = document.getElementById('ti-geo-summary');
        if (!container) return;

        const total = geoCounters.private + geoCounters.public + geoCounters.multicast + geoCounters.loopback;

        let html = '<div class="ti-geo-cards">';

        html += geoCard('Private IPs', geoCounters.private, total, 'ti-geo-private');
        html += geoCard('Public IPs', geoCounters.public, total, 'ti-geo-public');
        html += geoCard('Multicast', geoCounters.multicast, total, 'ti-geo-multicast');
        html += geoCard('Loopback', geoCounters.loopback, total, 'ti-geo-loopback');

        html += '</div>';
        container.innerHTML = html;
    }

    function geoCard(label, count, total, cls) {
        const pct = total > 0 ? Math.round(count / total * 100) : 0;
        return '<div class="ti-geo-card ' + cls + '">' +
            '<div class="ti-geo-card-count">' + count + '</div>' +
            '<div class="ti-geo-card-label">' + esc(label) + '</div>' +
            '<div class="ti-geo-card-pct">' + pct + '%</div>' +
            '</div>';
    }

    // ==================== CLEAR ====================

    function clear() {
        // Reset all state
        for (const key in ipData) delete ipData[key];
        for (const key in dnsQueries) delete dnsQueries[key];
        for (const key in portActivity) delete portActivity[key];
        iocEntries.length = 0;
        for (const key in iocIndex) delete iocIndex[key];
        observedTechniques.clear();
        geoCounters.private = 0;
        geoCounters.public = 0;
        geoCounters.multicast = 0;
        geoCounters.loopback = 0;
        for (const key in classifiedIps) delete classifiedIps[key];

        dirty = false;

        // Re-render empty state
        renderMitreGrid();
        renderIocList();
        renderRiskTable();
        renderGeoSummary();
    }

    // ==================== HELPERS ====================

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

    function extractDnsDomain(text) {
        if (!text) return '';
        // DNS info patterns: "Standard query A example.com" or domain embedded in detail
        const parts = text.split(/\s+/);
        for (let i = parts.length - 1; i >= 0; i--) {
            if (parts[i].includes('.') && parts[i].length > 3 && /^[a-zA-Z0-9._-]+$/.test(parts[i])) {
                return parts[i];
            }
        }
        return '';
    }

    function formatTime(ts) {
        if (!ts) return '--';
        const d = new Date(ts);
        if (isNaN(d.getTime())) return '--';
        return d.toLocaleTimeString();
    }

    function esc(s) {
        if (!s) return '';
        return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    return { init, addPacket, addAlert, clear };
})();
