import {connect} from "cloudflare:sockets";
const uuid = "d342d11e-d424-4583-b36e-524ab1f0afa4";
const bufferSize = 256 * 1024;
const startThreshold = 50 * 1024 * 1024;
const maxChunkLen = 64 * 1024;
const flushTime = 4;
const proxyStrategyOrder = ["socks", "http", "https", "turn", "turns"];
const dohEndpoint = "https://cloudflare-dns.com/dns-query";
const finallyProxyHost = "proxy.zjcloud.us.ci";
const uuidBytes = Uint8Array.from(uuid.replace(/-/g, "").match(/../g), hex => parseInt(hex, 16));
const textEncoder = new TextEncoder, textDecoder = new TextDecoder;
const html = `<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx/1.25.3</center></body></html>`;
const binaryAddrToString = (addrType, addrBytes) => {
    if (addrType === 3) return textDecoder.decode(addrBytes);
    if (addrType === 1) return `${addrBytes[0]}.${addrBytes[1]}.${addrBytes[2]}.${addrBytes[3]}`;
    let ipv6 = (addrBytes[0] << 8 | addrBytes[1]).toString(16);
    for (let i = 1; i < 8; i++) ipv6 += ":" + (addrBytes[i * 2] << 8 | addrBytes[i * 2 + 1]).toString(16);
    return `[${ipv6}]`
};
const parseHostPort = (addr, defaultPort) => {
    let host = addr, port = defaultPort, idx;
    if (addr.charCodeAt(0) === 91) {
        if ((idx = addr.indexOf("]:")) !== -1) {
            host = addr.substring(0, idx + 1);
            port = addr.substring(idx + 2)
        }
    } else if ((idx = addr.indexOf(".tp")) !== -1 && addr.lastIndexOf(":") === -1) {port = addr.substring(idx + 3, addr.indexOf(".", idx + 3))} else if ((idx = addr.lastIndexOf(":")) !== -1) {
        host = addr.substring(0, idx);
        port = addr.substring(idx + 1)
    }
    return [host, (port = parseInt(port), isNaN(port) ? defaultPort : port)]
};
const parseAuthString = authParam => {
    let username, password, hostStr;
    const atIndex = authParam.lastIndexOf("@");
    if (atIndex === -1) {hostStr = authParam} else {
        const cred = authParam.substring(0, atIndex);
        hostStr = authParam.substring(atIndex + 1);
        const colonIndex = cred.indexOf(":");
        if (colonIndex === -1) {username = cred} else {
            username = cred.substring(0, colonIndex);
            password = cred.substring(colonIndex + 1)
        }
    }
    const [hostname, port] = parseHostPort(hostStr, 1080);
    return {username: username, password: password, hostname: hostname, port: port}
};
const createConnect = (hostname, port, socketOptions, socket = connect({hostname: hostname, port: port}, socketOptions)) => socket.opened.then(() => socket);
const connectViaSocksProxy = async (a, p, h, b) => {
    const s = await createConnect(h.hostname, h.port);
    const w = s.writable.getWriter(), r = s.readable.getReader();
    await w.write(new Uint8Array([5, 2, 0, 2]));
    const {value: v} = await r.read();
    if (!v || v[0] !== 5 || v[1] === 255) return null;
    if (v[1] === 2) {
        if (!h.username) return null;
        const u = textEncoder.encode(h.username), q = textEncoder.encode(h.password || "");
        const ul = u.length, ql = q.length, x = new Uint8Array(3 + ul + ql);
        x[0] = 1, x[1] = ul, x.set(u, 2), x[2 + ul] = ql, x.set(q, 3 + ul);
        await w.write(x);
        const {value: y} = await r.read();
        if (!y || y[0] !== 1 || y[1] !== 0) return null
    } else if (v[1] !== 0) {return null}
    const d = a === 3, x = new Uint8Array(6 + b.length + (d ? 1 : 0));
    x[0] = 5, x[1] = 1, x[2] = 0, x[3] = a;
    d ? (x[4] = b.length, x.set(b, 5)) : x.set(b, 4);
    x[x.length - 2] = p >> 8, x[x.length - 1] = p & 255;
    await w.write(x);
    const {value: y} = await r.read();
    if (!y || y[1] !== 0) return null;
    w.releaseLock(), r.releaseLock();
    return s
};
const staticHeaders = `User-Agent:Mozilla/5.0(X11;Linux x86_64)AppleWebKit/537.36\r\nProxy-Connection:Keep-Alive\r\nConnection:Keep-Alive\r\n\r\n`;
const encodedStaticHeaders = textEncoder.encode(staticHeaders);
const connectViaHttpProxy = async (a, p, h, b, t = false) => {
    const {username: u, password: q, hostname: n, port: o} = h;
    const so = t ? {secureTransport: "on", allowHalfOpen: false} : undefined;
    const s = await createConnect(n, o, so), w = s.writable.getWriter();
    const x = binaryAddrToString(a, b);
    let d = `CONNECT ${x}:${p} HTTP/1.1\r\nHost:${x}:${p}\r\n`;
    if (u) d += `Proxy-Authorization:Basic ${btoa(`${u}:${q || ""}`)}\r\n`;
    const f = new Uint8Array(d.length * 3 + encodedStaticHeaders.length), {written: z} = textEncoder.encodeInto(d, f);
    f.set(encodedStaticHeaders, z);
    await w.write(f.subarray(0, z + encodedStaticHeaders.length));
    w.releaseLock();
    const r = s.readable.getReader(), b2 = new Uint8Array(512);
    let i = 0, c = false;
    while (i < b2.length) {
        const {value: v, done: e} = await r.read();
        if (e || i + v.length > b2.length) return null;
        const q = i;
        b2.set(v, i), i += v.length;
        if (!c && i >= 12) {
            if (b2[9] !== 50) return null;
            c = true
        }
        let j = Math.max(15, q - 3);
        while ((j = b2.indexOf(13, j)) !== -1 && j <= i - 4) {
            if (b2[j + 1] === 10 && b2[j + 2] === 13 && b2[j + 3] === 10) {
                r.releaseLock();
                return s
            }
            j++
        }
    }
    return null
};
const magic = new Uint8Array([33, 18, 164, 66]);
const cat = (...a) => {
    let len = 0, i = 0, o = 0;
    for (; i < a.length; i++) len += a[i].length;
    const r = new Uint8Array(len);
    for (i = 0; i < a.length; i++) {
        r.set(a[i], o);
        o += a[i].length
    }
    return r
};
const stunAttr = (t, v) => {
    const l = v.length, b = new Uint8Array(4 + l + (4 - l % 4) % 4);
    b[0] = t >> 8, b[1] = t & 255, b[2] = l >> 8, b[3] = l & 255, b.set(v, 4);
    return b
};
const stunMsg = (t, tid, a) => {
    const bd = cat(...a), l = bd.length, h = new Uint8Array(20 + l);
    h[0] = t >> 8, h[1] = t & 255, h[2] = l >> 8, h[3] = l & 255, h.set(magic, 4), h.set(tid, 8), h.set(bd, 20);
    return h
};
const xorPeer = (ip, port) => {
    const b = new Uint8Array(8);
    b[1] = 1;
    const xp = port ^ 8466;
    b[2] = xp >> 8, b[3] = xp & 255;
    let p = 0, num = 0;
    for (let i = 0; i < ip.length; i++) {
        const c = ip.charCodeAt(i);
        if (c === 46) {
            b[4 + p] = num ^ magic[p++];
            num = 0
        } else {num = num * 10 + (c - 48)}
    }
    b[4 + p] = num ^ magic[p];
    return b
};
const parseStun = d => {
    if (d.length < 20 || magic.some((v, i) => d[4 + i] !== v)) return null;
    const ml = d[2] << 8 | d[3], attrs = {};
    for (let o = 20; o + 4 <= 20 + ml;) {
        const t = d[o] << 8 | d[o + 1], l = d[o + 2] << 8 | d[o + 3];
        if (o + 4 + l > d.length) break;
        attrs[t] = d.subarray(o + 4, o + 4 + l);
        o += 4 + l + (4 - l % 4) % 4
    }
    return {type: d[0] << 8 | d[1], attrs: attrs, tid: d.slice(8, 20)}
};
const parseErr = d => d?.length >= 4 ? (d[2] & 7) * 100 + d[3] : 0;
const addIntegrity = async (m, cryptoKey) => {
    const l = m.length, c = new Uint8Array(l + 24);
    c.set(m);
    const nl = (m[2] << 8 | m[3]) + 24;
    c[2] = nl >> 8, c[3] = nl & 255;
    const sig = new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, c.subarray(0, l)));
    c[l] = 0, c[l + 1] = 8, c[l + 2] = 0, c[l + 3] = 20, c.set(sig, l + 4);
    return c
};
const readStun = async (rd, buf) => {
    let chunks = buf && buf.length ? [buf] : [];
    let total = buf ? buf.length : 0;
    const pull = async () => {
        const {done: done, value: value} = await rd.read();
        if (done) throw new Error;
        chunks.push(value);
        total += value.length
    };
    const getB = () => {
        if (chunks.length === 1) return chunks[0];
        const b = new Uint8Array(total);
        let o = 0;
        for (let i = 0; i < chunks.length; i++) {
            b.set(chunks[i], o);
            o += chunks[i].length
        }
        chunks = [b];
        return b
    };
    try {
        while (total < 20) await pull();
        let b = getB();
        if (b[4] !== 33 || b[5] !== 18 || b[6] !== 164 || b[7] !== 66) return null;
        const n = 20 + (b[2] << 8 | b[3]);
        if (n > 8192) return null;
        while (total < n) await pull();
        b = getB();
        return [parseStun(b.subarray(0, n)), total > n ? b.subarray(n) : null]
    } catch {return null}
};
const md5 = async s => new Uint8Array(await crypto.subtle.digest("MD5", textEncoder.encode(s)));
const connectViaTurnProxy = async ({hostname: h, port: p, username: u, password: w}, {addrType: a, port: t, addrBytes: b}, z = false) => {
    let ip = binaryAddrToString(a, b);
    if (a === 3) {ip = dnsAResult(ip).catch(() => null)} else if (a === 4) {return null}
    let c = null, d = null, dp = null;
    let cw = null, cr = null, ce = null, cl = false;
    const close = () => {
        cl = true;
        [c, d].forEach(s => {try {s?.close()} catch {}});
        [cr, cw].forEach(l => {try {l?.releaseLock()} catch {}})
    };
    const cc = () => {
        const so = z ? {secureTransport: "on", allowHalfOpen: false} : undefined;
        const s = connect({hostname: h, port: p}, so);
        return createConnect(h, p, so, s).catch(e => {
            try {s.close()} catch {}
            throw e
        })
    };
    const nt = () => crypto.getRandomValues(new Uint8Array(12));
    const st = (x, y) => x?.length === y?.length && x.every((v, i) => v === y[i]);
    const tk = x => {
        let k = "";
        for (let i = 0; i < x.length; i++) k += x[i].toString(16).padStart(2, "0");
        return k
    };
    const rm = async (rd, et, buf = null, pend = null) => {
        const ek = tk(et), v = pend?.get(ek);
        if (v) {
            pend.delete(ek);
            return [v, buf]
        }
        let ex = buf;
        for (; ;) {
            const res = await readStun(rd, ex);
            if (!res) throw new Error;
            const [m, n] = res;
            ex = n;
            if (st(m.tid, et)) return [m, ex];
            if (pend) pend.set(tk(m.tid), m)
        }
    };
    const cp = new Map;
    const rc = async et => {
        const [m, ex] = await rm(cr, et, ce, cp);
        ce = ex;
        return m
    };
    let ck = null, aa = [];
    const sign = m => ck ? addIntegrity(m, ck) : m;
    try {
        const ct = cc();
        dp = cc().then(s => {
            d = s;
            if (cl) try {s.close()} catch {}
            return s
        });
        dp.catch(() => {});
        c = await ct;
        cw = c.writable.getWriter(), cr = c.readable.getReader();
        let tid = nt();
        await cw.write(stunMsg(3, tid, [stunAttr(25, new Uint8Array([6, 0, 0, 0]))]));
        let r = await rc(tid);
        if (!r) throw new Error;
        const ta = await ip;
        if (!ta) throw new Error;
        const peer = stunAttr(18, xorPeer(ta, t));
        let pt = null, xt = null, pm = null, cm = null;
        if (r.type === 275 && u && parseErr(r.attrs[9]) === 401) {
            const realm = textDecoder.decode(r.attrs[20] ?? []), nonce = r.attrs[21] ?? [];
            const kb = await md5(`${u}:${realm}:${w}`);
            ck = await crypto.subtle.importKey("raw", kb, {name: "HMAC", hash: "SHA-1"}, false, ["sign"]);
            aa = [stunAttr(6, textEncoder.encode(u)), stunAttr(20, textEncoder.encode(realm)), stunAttr(21, nonce)];
            const at = nt();
            pt = nt(), xt = nt();
            const [am, pmsg, xmsg] = await Promise.all([sign(stunMsg(3, at, [stunAttr(25, new Uint8Array([6, 0, 0, 0])), ...aa])), sign(stunMsg(8, pt, [peer, ...aa])), sign(stunMsg(10, xt, [peer, ...aa]))]);
            pm = pmsg, cm = xmsg;
            await cw.write(cat(am, pm, cm));
            r = await rc(at)
        } else if (r.type === 259) {
            pt = nt(), xt = nt();
            [pm, cm] = await Promise.all([sign(stunMsg(8, pt, [peer, ...aa])), sign(stunMsg(10, xt, [peer, ...aa]))]);
            await cw.write(cat(pm, cm))
        } else {throw new Error}
        if (r?.type !== 259) throw new Error;
        r = await rc(pt);
        if (r?.type !== 264) throw new Error;
        r = await rc(xt);
        if (r?.type !== 266 || !r.attrs[42]) throw new Error;
        await dp;
        const dw = d.writable.getWriter(), dr = d.readable.getReader();
        tid = nt();
        await dw.write(await sign(stunMsg(11, tid, [stunAttr(42, r.attrs[42]), ...aa])));
        let ex;
        [r, ex] = await rm(dr, tid);
        if (r?.type !== 267) throw new Error;
        dr.releaseLock(), dw.releaseLock();
        return {readable: d.readable, writable: d.writable, close: close, extra: ex}
    } catch {
        close();
        return null
    }
};
const parseProtocolChunk = chunk => {
    const len = chunk.length;
    const result = {success: false, needMore: false, handshake: null, parsedRequest: null};
    let isVL = false;
    if (len >= 17) {
        isVL = true;
        for (let i = 0; i < 16; i++) {
            if (chunk[i + 1] !== uuidBytes[i]) {
                isVL = false;
                break
            }
        }
    }
    if (isVL) {
        if (len < 18) return result.needMore = true, result;
        const offset = 19 + chunk[17];
        if (len < offset + 4) return result.needMore = true, result;
        let addrType = chunk[offset + 2];
        if (addrType !== 1) addrType += 1;
        const addrLen = addrType === 3 ? offset + 3 < len ? chunk[offset + 3] : null : addrType === 1 ? 4 : addrType === 4 ? 16 : -1;
        if (addrLen === null) return result.needMore = true, result;
        if (addrLen > 0) {
            const addrOffset = addrType === 3 ? offset + 4 : offset + 3;
            const dataOffset = addrOffset + addrLen;
            if (len < dataOffset) return result.needMore = true, result;
            const port = chunk[offset] << 8 | chunk[offset + 1];
            result.handshake = new Uint8Array([chunk[0], 0]);
            result.success = true;
            result.parsedRequest = {addrType: addrType, addrBytes: chunk.subarray(addrOffset, addrOffset + addrLen), dataOffset: dataOffset, port: port, isDns: port === 53};
            return result
        }
    }
    return len < 17 ? (result.needMore = true, result) : result
};
const dohJsonOptions = {headers: {Accept: "application/dns-json"}}, dohHeaders = {"content-type": "application/dns-message"};
const dohDnsResolve = async (hostname, recordType) => {
    try {
        const response = await fetch(`${dohEndpoint}?name=${encodeURIComponent(hostname)}&type=${recordType}`, dohJsonOptions);
        if (!response.ok) return null;
        const dnsResult = await response.json();
        const answer = dnsResult.Answer || dnsResult.answer;
        if (!answer || answer.length === 0) return null;
        return answer
    } catch {return null}
};
const dnsAResult = async hostname => {
    const answer = await dohDnsResolve(hostname, "A");
    if (!answer) return null;
    let ip = null;
    for (let i = 0, len = answer.length; i < len; i++) if (answer[i].type === 1 && answer[i].data) {
        ip = answer[i].data;
        break
    }
    return ip
};
const dohDnsHandler = async payload => {
    if (payload.byteLength < 2) return null;
    const dnsQueryData = payload.subarray(2);
    let dnsQueryResult;
    try {
        const resp = await fetch(dohEndpoint, {method: "POST", headers: dohHeaders, body: dnsQueryData});
        if (!resp.ok) return null;
        dnsQueryResult = await resp.arrayBuffer()
    } catch {return null}
    const udpSize = dnsQueryResult.byteLength;
    const packet = new Uint8Array(2 + udpSize);
    packet[0] = udpSize >> 8 & 255, packet[1] = udpSize & 255;
    packet.set(new Uint8Array(dnsQueryResult), 2);
    return packet
};
const txtdnsResult = async txtdns => {
    const answer = await dohDnsResolve(txtdns, "TXT");
    if (!answer) return null;
    let txtData, i = 0, len = answer.length;
    for (; i < len; i++) if (answer[i].type === 16) {
        txtData = answer[i].data;
        break
    }
    if (!txtData) return null;
    if (txtData.charCodeAt(0) === 34 && txtData.charCodeAt(txtData.length - 1) === 34) txtData = txtData.slice(1, -1);
    const raw = txtData.split(/,|\\010|\n/), prefixes = [];
    for (i = 0, len = raw.length; i < len; i++) {
        const s = raw[i].trim();
        if (s) prefixes.push(s)
    }
    return prefixes.length ? prefixes : null
};
const proxyIpRegex = /william|fxpip|hhtxt/;
const connectProxyIp = async (param, txt) => {
    if (txt || proxyIpRegex.test(param)) {
        const resolvedIps = await txtdnsResult(param);
        if (!resolvedIps || resolvedIps.length === 0) return null;
        const [host, port] = parseHostPort(resolvedIps[Math.random() * resolvedIps.length | 0], 443);
        return createConnect(host, port)
    }
    const [host, port] = parseHostPort(param, 443);
    return createConnect(host, port)
};
const strategyExecutorMap = new Map([
    [0, async ({addrType, port, addrBytes}) => createConnect(binaryAddrToString(addrType, addrBytes), port)],
    [1, async ({addrType, port, addrBytes}, param) => connectViaSocksProxy(addrType, port, param, addrBytes)],
    [2, async ({addrType, port, addrBytes}, param) => connectViaHttpProxy(addrType, port, param, addrBytes)],
    [6, async ({addrType, port, addrBytes}, param) => connectViaHttpProxy(addrType, port, param, addrBytes, true)],
    [5, async (parsedRequest, param) => connectViaTurnProxy(param, parsedRequest)],
    [7, async (parsedRequest, param) => connectViaTurnProxy(param, parsedRequest, true)],
    [3, async (_parsedRequest, param, txt) => connectProxyIp(param, txt)]
]);
const paramRegex = /(speed|gs5|s5all|ghttp|httpall|ghttps|httpsall|gturn|turnall|gturns|turnsall|s5|socks|http|https|turn|turns|txtip|ip)(?:=|:\/\/|%3A%2F%2F)([^&]+)|(proxyall|globalproxy|global)/gi;
const establishTcpConnection = async (parsedRequest, request) => {
    let u = request.url, clean = u.slice(u.indexOf("/", 10) + 1), l = clean.length, list = [], speed;
    const c = clean.charCodeAt(l - 1);
    if (c === 47 || c === 61) clean = clean.slice(0, l - 1);
    const colo = request.cf?.colo;
    const coloProxyHost = colo ? `${colo.toLowerCase()}.proxy.zjcloud.us.ci` : finallyProxyHost;
    if (clean.length < 6) {list.push({type: 0}, {type: 3, param: coloProxyHost}, {type: 3, param: finallyProxyHost})} else {
        const p = Object.create(null);
        paramRegex.lastIndex = 0;
        let m;
        while (m = paramRegex.exec(clean)) {p[(m[1] || m[3]).toLowerCase()] = m[2] ? m[2].charCodeAt(m[2].length - 1) === 61 ? m[2].slice(0, -1) : m[2] : true}
        if (p.speed) speed = p.speed;
        const s5 = p.gs5 || p.s5all || p.s5 || p.socks, http = p.ghttp || p.httpall || p.http, https = p.ghttps || p.httpsall || p.https, turn = p.gturn || p.turnall || p.turn, turns = p.gturns || p.turnsall || p.turns;
        const proxyAll = !!(p.gs5 || p.s5all || p.ghttp || p.httpall || p.ghttps || p.httpsall || p.gturn || p.turnall || p.gturns || p.turnsall || p.proxyall || p.globalproxy || p.global);
        if (!proxyAll) list.push({type: 0});
        const add = (v, t, txt) => {
            if (!v) return;
            const parts = decodeURIComponent(v).split(",").filter(Boolean);
            for (let i = 0; i < parts.length; i++) list.push(txt ? {type: t, param: parts[i], txt: txt} : {type: t, param: t === 1 || t === 2 || t === 5 || t === 6 || t === 7 ? parseAuthString(parts[i]) : parts[i]})
        };
        for (let i = 0; i < proxyStrategyOrder.length; i++) {
            const k = proxyStrategyOrder[i];
            add(k === "socks" ? s5 : k === "http" ? http : k === "https" ? https : k === "turn" ? turn : turns, k === "socks" ? 1 : k === "http" ? 2 : k === "https" ? 6 : k === "turn" ? 5 : 7)
        }
        if (proxyAll) {if (!list.length) list.push({type: 0})} else {
            add(p.ip, 3), add(p.txtip, 3, true);
            list.push({type: 3, param: coloProxyHost}, {type: 3, param: finallyProxyHost})
        }
    }
    for (let i = 0; i < list.length; i++) {
        try {
            const exec = strategyExecutorMap.get(list[i].type);
            const socket = await (exec?.(parsedRequest, list[i].param, list[i].txt));
            if (socket) return {socket: socket, speed: speed}
        } catch {}
    }
    return null
};
const manualPipe = async (readable, writable, close, speed) => {
    const n = parseFloat(speed), speedLimit = n > 0;
    let pipeBufferSize = bufferSize, pipeFlushTime = flushTime, pipeStartThreshold = startThreshold;
    if (speedLimit) {
        pipeStartThreshold = n > 256 ? Number.MAX_SAFE_INTEGER : n * 1048576;
        let bestSize = pipeBufferSize, bestTime = Infinity, bestDiff = Infinity;
        for (let size = 262144; size <= 524288; size += 65536) {
            const timeMs = Math.max(2, Math.round(size * 1e3 / pipeStartThreshold)), diff = Math.abs(size * 1e3 / timeMs - pipeStartThreshold);
            if (diff < bestDiff || diff === bestDiff && timeMs < bestTime) bestSize = size, bestTime = timeMs, bestDiff = diff
        }
        pipeBufferSize = bestSize, pipeFlushTime = bestTime
    }
    const safeBufferSize = pipeBufferSize - maxChunkLen, fastFlushOffset = maxChunkLen << 1;
    let bufferView = new Uint8Array(pipeBufferSize), spareBuffer = new ArrayBuffer(maxChunkLen);
    let offset = 0, totalBytes = 0, time = 0, timerId = null, resume = null, isReading = false, needsFlush = false, protectFlush = false;
    let fastFlush = true;
    const flushBuffer = () => {
        if (isReading) return needsFlush = true;
        fastFlush = offset < fastFlushOffset;
        if (offset > 0) (writable.send(bufferView.subarray(0, offset)), offset = 0);
        needsFlush = false, protectFlush = false, timerId && (clearTimeout(timerId), timerId = null), resume?.(), resume = null
    };
    const reader = readable.getReader({mode: "byob"});
    try {
        while (true) {
            const useSpare = offset > 0 && protectFlush;
            let readBuffer = bufferView.buffer, readOffset = offset;
            isReading = offset > 0;
            useSpare && (readBuffer = spareBuffer, readOffset = 0, isReading = false);
            const {done: done, value: value} = await reader.read(new Uint8Array(readBuffer, readOffset, maxChunkLen));
            isReading = false;
            useSpare ? (bufferView.set(value, offset), spareBuffer = value.buffer) : bufferView = new Uint8Array(value.buffer);
            if (done) break;
            const chunkLen = value.byteLength;
            if (!chunkLen) {
                needsFlush && flushBuffer();
                continue
            }
            offset += chunkLen, totalBytes += chunkLen;
            if (needsFlush || chunkLen < 2048) {flushBuffer()} else {
                if (fastFlush || chunkLen < 28672) {
                    if (!speedLimit) totalBytes = 0;
                    time = 2
                } else if (totalBytes > pipeStartThreshold) time = pipeFlushTime;
                timerId ||= setTimeout(flushBuffer, time), protectFlush = chunkLen < maxChunkLen;
                offset > safeBufferSize && (totalBytes > pipeStartThreshold ? await new Promise(r => resume = r) : flushBuffer())
            }
        }
    } catch {offset = 0, close?.()} finally {isReading = false, flushBuffer()}
};
const createAsyncMicrotaskQueue = (consume, close) => {
    const queue = new Array(2048);
    let head = 0, tail = 0, size = 0, coalesceBuffer = null, drainActive = false, closed = false;
    const closeQueue = () => {
        if (closed) return;
        closed = true;
        for (let i = 0; i < 2048; i++) queue[i] = null;
        close?.()
    };
    const shift = () => {
        const chunk = queue[head];
        queue[head] = null, head = head + 1 & 2047, size--;
        return chunk
    };
    const drainQueue = async () => {
        if (closed) return;
        try {
            while (size > 0 && !closed) {
                if (!enqueue.writer) {
                    await consume(shift());
                    continue
                }
                let chunk = queue[head];
                if (chunk.byteLength >= maxChunkLen) {
                    await enqueue.writer.write(shift());
                    continue
                }
                let mergedLength = 0;
                coalesceBuffer ||= new Uint8Array(maxChunkLen);
                while (size > 0 && mergedLength + queue[head].byteLength <= maxChunkLen) {chunk = shift(), coalesceBuffer.set(chunk, mergedLength), mergedLength += chunk.byteLength}
                if (mergedLength > 0) await enqueue.writer.write(coalesceBuffer.subarray(0, mergedLength))
            }
        } catch {closeQueue()} finally {drainActive = false}
    };
    const enqueue = chunk => {
        if (closed) return;
        chunk = chunk.constructor === Uint8Array ? chunk : new Uint8Array(chunk);
        if (enqueue.writer && !chunk.byteLength) return;
        if (size === 2048) return closeQueue();
        queue[tail] = chunk, tail = tail + 1 & 2047, size++;
        if (!drainActive) drainActive = true, queueMicrotask(drainQueue)
    };
    return enqueue
};
const handleSession = async (chunk, state, request, writable, close, isEarlyData = false) => {
    state.needMore = false;
    const parsed = parseProtocolChunk(chunk);
    if (parsed.handshake) writable.send(parsed.handshake);
    if (!parsed.success) return parsed.needMore ? state.needMore = true : close();
    const parsedRequest = parsed.parsedRequest;
    const payload = chunk.subarray(parsedRequest.dataOffset);
    if (parsedRequest.isDns) {
        const dnsPack = await dohDnsHandler(payload);
        if (dnsPack?.byteLength) writable.send(dnsPack);
        if (!isEarlyData) return close()
    } else {
        const tcpResult = await establishTcpConnection(parsedRequest, request);
        if (!tcpResult) return close();
        state.tcpSocket = tcpResult.socket;
        const tcpWriter = state.tcpSocket.writable.getWriter();
        if (payload.byteLength) tcpWriter.write(payload);
        state.tcpWriter ||= createAsyncMicrotaskQueue(null, close);
        state.tcpWriter.writer = tcpWriter;
        if (state.tcpSocket.extra?.length) await writable.send(state.tcpSocket.extra);
        if (state.xwebPipeTo) return;
        manualPipe(state.tcpSocket.readable, writable, close, tcpResult.speed)
    }
};
const handleWebSocketConn = async (webSocket, request) => {
    const refererHeader = request.headers.get("Referer");
    const protocolHeader = refererHeader || request.headers.get("sec-websocket-protocol");
    let earlyDataHeader = null;
    if (refererHeader) {earlyDataHeader = protocolHeader.slice(request.headers.get("host").length)} else if (protocolHeader) {earlyDataHeader = protocolHeader}
    const earlyData = earlyDataHeader ? Uint8Array.fromBase64(earlyDataHeader, {alphabet: "base64url"}) : null;
    const state = {tcpWriter: null, tcpSocket: null};
    const close = () => {
        try {state.tcpSocket?.close()} catch {}
        try {webSocket.close(1011, "WebSocket is closed")} catch {}
    };
    const processingQueue = createAsyncMicrotaskQueue(chunk => handleSession(chunk, state, request, webSocket, close, earlyData !== null), close);
    state.tcpWriter = processingQueue;
    if (earlyData) processingQueue(earlyData);
    webSocket.addEventListener("message", event => processingQueue(event.data));
    webSocket.addEventListener("error", close)
};
const xwebHeaders = {"Content-Type": "application/octet-stream", "grpc-status": "0", "X-Accel-Buffering": "no", "Cache-Control": "no-store"};
const handleXwebPost = async request => {
    const reader = request.body?.getReader({mode: "byob"});
    if (!reader) return new Response(null, {status: 400});
    const state = {tcpWriter: null, tcpSocket: null, needMore: false, xwebPipeTo: true};
    const bridge = new IdentityTransformStream, responseWriter = bridge.writable.getWriter();
    let xwebBuffer = new ArrayBuffer(8192), used = 0;
    const close = () => {if (state.xwebPipeTo) responseWriter.close().catch(() => {})};
    const writable = {send(chunk) {if (chunk?.byteLength) return responseWriter.write(chunk)}};
    (async () => {
        while (true) {
            const {done, value} = await reader.read(new Uint8Array(xwebBuffer, used, used === 0 ? 8192 : 4096));
            if (done) return close();
            xwebBuffer = value.buffer, used += value.byteLength;
            const payload = new Uint8Array(xwebBuffer, 0, used);
            if (state.tcpWriter) {
                await state.tcpWriter(payload.slice());
                used = 0;
            } else {
                state.needMore = false;
                await handleSession(payload, state, request, writable, close);
                if (state.tcpSocket && state.xwebPipeTo) {
                    state.xwebPipeTo = false, responseWriter.releaseLock();
                    state.tcpSocket.readable.pipeTo(bridge.writable).catch(close);
                }
                if (!state.needMore) used = 0;
            }
        }
    })().catch(close);
    return new Response(bridge.readable, {headers: xwebHeaders})
};
export default {
    async fetch(request) {
        if (request.method === "POST" && request.headers.get("content-type") === "application/grpc-web") return handleXwebPost(request);
        if (request.headers.get("Upgrade") === "websocket") {
            const {0: clientSocket, 1: webSocket} = new WebSocketPair;
            webSocket.accept({allowHalfOpen: true}), webSocket.binaryType = "arraybuffer";
            handleWebSocketConn(webSocket, request);
            return new Response(null, {status: 101, webSocket: clientSocket})
        }
        return new Response(html, {status: 200, headers: {"Content-Type": "text/html; charset=UTF-8"}})
    }
};