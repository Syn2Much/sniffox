// filters.js — Client-side display filter parsing and evaluation
'use strict';

const Filters = (() => {
    // Compile a filter string into a function: (packet) => bool
    // Returns null if filter is empty (show all).
    //
    // Supported syntax:
    //   tcp, udp, dns, arp, icmp, http, ipv6     — protocol match
    //   tls, dhcp, ntp, icmpv6, vlan             — expanded protocol match
    //   ip.src==ADDR or ip.src=ADDR               — source address match
    //   ip.dst==ADDR or ip.dst=ADDR               — destination address match
    //   ip==ADDR or ip=ADDR                       — match src OR dst (strip port)
    //   port==N or port=N                         — info/addr contains :N
    //   tls.sni==hostname                         — TLS SNI filter
    //   flow==N                                   — match by flow ID
    //   stream==N                                 — match by stream ID
    //   inbound / incoming                        — dst is a local address
    //   outbound / outgoing                       — src is a local address
    //   local                                     — both src and dst are local
    //   external                                  — at least one side is non-local
    //   broadcast                                 — dst is broadcast/multicast
    //   unicast                                   — dst is not broadcast/multicast
    //   FREETEXT                                  — substring match across fields
    //   expr && expr, expr || expr                — logical combination
    //   !expr                                     — negation

    // Local IP addresses — populated by app.js when interfaces are received
    const localAddrs = new Set();

    function setLocalAddresses(addrs) {
        localAddrs.clear();
        if (addrs) {
            addrs.forEach(a => localAddrs.add(a));
        }
        // Always include common loopback
        localAddrs.add('127.0.0.1');
        localAddrs.add('::1');
    }

    function isLocalAddr(addr) {
        if (!addr) return false;
        const ip = stripPort(addr);
        return localAddrs.has(ip);
    }

    function isBroadcast(addr) {
        if (!addr) return false;
        const ip = stripPort(addr);
        // IPv4 broadcast
        if (ip === '255.255.255.255') return true;
        if (ip.endsWith('.255')) return true;
        if (ip === '0.0.0.0') return true;
        // Multicast IPv4 (224.0.0.0 - 239.255.255.255)
        const first = parseInt(ip.split('.')[0], 10);
        if (first >= 224 && first <= 239) return true;
        // IPv6 multicast (ff00::/8)
        if (ip.toLowerCase().startsWith('ff')) return true;
        return false;
    }

    function compile(filterText) {
        if (!filterText || !filterText.trim()) return null;
        const text = filterText.trim();
        try {
            const fn = parseOr(text, 0);
            return fn.func;
        } catch (e) {
            const lower = text.toLowerCase();
            return (pkt) => matchSubstring(pkt, lower);
        }
    }

    function matchSubstring(pkt, lower) {
        return (
            (pkt.srcAddr && pkt.srcAddr.toLowerCase().includes(lower)) ||
            (pkt.dstAddr && pkt.dstAddr.toLowerCase().includes(lower)) ||
            (pkt.protocol && pkt.protocol.toLowerCase().includes(lower)) ||
            (pkt.info && pkt.info.toLowerCase().includes(lower))
        );
    }

    function parseOr(text, pos) {
        let left = parseAnd(text, pos);
        let rest = text.slice(left.end).trimStart();
        while (rest.startsWith('||')) {
            const right = parseAnd(text, text.length - rest.length + 2);
            const lf = left.func, rf = right.func;
            left = { func: (pkt) => lf(pkt) || rf(pkt), end: right.end };
            rest = text.slice(left.end).trimStart();
        }
        return left;
    }

    function parseAnd(text, pos) {
        let left = parseNot(text, pos);
        let rest = text.slice(left.end).trimStart();
        while (rest.startsWith('&&')) {
            const right = parseNot(text, text.length - rest.length + 2);
            const lf = left.func, rf = right.func;
            left = { func: (pkt) => lf(pkt) && rf(pkt), end: right.end };
            rest = text.slice(left.end).trimStart();
        }
        return left;
    }

    function parseNot(text, pos) {
        const rest = text.slice(pos).trimStart();
        const newPos = text.length - rest.length;
        if (rest.startsWith('!')) {
            const inner = parseNot(text, newPos + 1);
            const inf = inner.func;
            return { func: (pkt) => !inf(pkt), end: inner.end };
        }
        return parseAtom(text, newPos);
    }

    function parseAtom(text, pos) {
        const rest = text.slice(pos).trimStart();
        const newPos = text.length - rest.length;

        if (rest.startsWith('(')) {
            const inner = parseOr(text, newPos + 1);
            const afterInner = text.slice(inner.end).trimStart();
            const endPos = afterInner.startsWith(')') ? text.length - afterInner.length + 1 : inner.end;
            return { func: inner.func, end: endPos };
        }

        const tokenMatch = rest.match(/^[^&|)]+/);
        if (!tokenMatch) {
            return { func: () => true, end: newPos };
        }

        const token = tokenMatch[0].trim();
        const end = newPos + tokenMatch[0].length;

        // Protocol keywords (expanded)
        const protocols = [
            'tcp', 'udp', 'dns', 'arp', 'icmp', 'http', 'ipv6', 'ipv4', 'ethernet',
            'tls', 'dhcp', 'ntp', 'icmpv6', 'vlan',
            'igmp', 'gre', 'sctp', 'stp', 'ssh', 'quic', 'mqtt', 'sip', 'modbus', 'rdp'
        ];
        const lowerToken = token.toLowerCase();
        if (protocols.includes(lowerToken)) {
            return {
                func: (pkt) => pkt.protocol && pkt.protocol.toLowerCase() === lowerToken,
                end
            };
        }

        // Direction keywords
        if (lowerToken === 'inbound' || lowerToken === 'incoming' || lowerToken === 'in') {
            return {
                func: (pkt) => isLocalAddr(pkt.dstAddr) && !isLocalAddr(pkt.srcAddr),
                end
            };
        }
        if (lowerToken === 'outbound' || lowerToken === 'outgoing' || lowerToken === 'out') {
            return {
                func: (pkt) => isLocalAddr(pkt.srcAddr) && !isLocalAddr(pkt.dstAddr),
                end
            };
        }
        if (lowerToken === 'local' || lowerToken === 'internal') {
            return {
                func: (pkt) => isLocalAddr(pkt.srcAddr) && isLocalAddr(pkt.dstAddr),
                end
            };
        }
        if (lowerToken === 'external' || lowerToken === 'remote') {
            return {
                func: (pkt) => !isLocalAddr(pkt.srcAddr) || !isLocalAddr(pkt.dstAddr),
                end
            };
        }
        if (lowerToken === 'broadcast' || lowerToken === 'multicast') {
            return {
                func: (pkt) => isBroadcast(pkt.dstAddr),
                end
            };
        }
        if (lowerToken === 'unicast') {
            return {
                func: (pkt) => !isBroadcast(pkt.dstAddr),
                end
            };
        }

        // flow==N — filter by flow ID
        const flowMatch = token.match(/^flow\s*={1,2}\s*(\d+)$/i);
        if (flowMatch) {
            const flowId = parseInt(flowMatch[1], 10);
            return {
                func: (pkt) => pkt.flowId === flowId,
                end
            };
        }

        // stream==N — filter by stream ID
        const streamMatch = token.match(/^stream\s*={1,2}\s*(\d+)$/i);
        if (streamMatch) {
            const streamId = parseInt(streamMatch[1], 10);
            return {
                func: (pkt) => pkt.streamId === streamId,
                end
            };
        }

        // tls.sni==hostname — filter by TLS SNI
        const sniMatch = token.match(/^tls\.sni\s*={1,2}\s*(.+)$/i);
        if (sniMatch) {
            const hostname = sniMatch[1].trim().toLowerCase();
            return {
                func: (pkt) => pkt.info && pkt.info.toLowerCase().includes(hostname) && pkt.protocol && pkt.protocol.toLowerCase() === 'tls',
                end
            };
        }

        // ip==ADDR (match either src or dst, stripping port)
        const ipMatch = token.match(/^ip\s*={1,2}\s*(.+)$/i);
        if (ipMatch) {
            const addr = ipMatch[1].trim();
            return {
                func: (pkt) => stripPort(pkt.srcAddr) === addr || stripPort(pkt.dstAddr) === addr,
                end
            };
        }

        // ip.src==ADDR
        const srcMatch = token.match(/^ip\.src\s*={1,2}\s*(.+)$/i);
        if (srcMatch) {
            const addr = srcMatch[1].trim();
            return { func: (pkt) => stripPort(pkt.srcAddr) === addr || pkt.srcAddr === addr, end };
        }

        // ip.dst==ADDR
        const dstMatch = token.match(/^ip\.dst\s*={1,2}\s*(.+)$/i);
        if (dstMatch) {
            const addr = dstMatch[1].trim();
            return { func: (pkt) => stripPort(pkt.dstAddr) === addr || pkt.dstAddr === addr, end };
        }

        // port==N
        const portMatch = token.match(/^port\s*={1,2}\s*(\d+)$/i);
        if (portMatch) {
            const port = portMatch[1];
            const portSuffix = ':' + port;
            return {
                func: (pkt) =>
                    (pkt.info && pkt.info.includes(portSuffix)) ||
                    (pkt.srcAddr && pkt.srcAddr.endsWith(portSuffix)) ||
                    (pkt.dstAddr && pkt.dstAddr.endsWith(portSuffix)),
                end
            };
        }

        // Fallback: substring match
        return {
            func: (pkt) => matchSubstring(pkt, lowerToken),
            end
        };
    }

    function stripPort(addr) {
        if (!addr) return '';
        const i = addr.lastIndexOf(':');
        return i > 0 ? addr.substring(0, i) : addr;
    }

    return { compile, setLocalAddresses, isLocalAddr };
})();
