// filters.js — Client-side display filter parsing and evaluation
'use strict';

const Filters = (() => {
    // Compile a filter string into a function: (packet) => bool
    // Returns null if filter is empty (show all).
    //
    // Supported syntax:
    //   tcp, udp, dns, arp, icmp, http, ipv6     — protocol match
    //   ip.src==ADDR or ip.src=ADDR               — source address match
    //   ip.dst==ADDR or ip.dst=ADDR               — destination address match
    //   ip==ADDR or ip=ADDR                       — match src OR dst (strip port)
    //   port==N or port=N                         — info/addr contains :N
    //   FREETEXT                                  — substring match across fields
    //   expr && expr, expr || expr                — logical combination
    //   !expr                                     — negation

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

        // Protocol keywords
        const protocols = ['tcp', 'udp', 'dns', 'arp', 'icmp', 'http', 'ipv6', 'ipv4', 'ethernet'];
        const lowerToken = token.toLowerCase();
        if (protocols.includes(lowerToken)) {
            return {
                func: (pkt) => pkt.protocol && pkt.protocol.toLowerCase() === lowerToken,
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

    return { compile };
})();
