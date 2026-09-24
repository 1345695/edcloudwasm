import {connect} from 'cloudflare:sockets';
const uuid = 'd342d11e-d424-4583-b36e-524ab1f0afa4';
//**警告**:trojan使用的sha224密钥，需要自己计算，当前设置为密码666的密钥
//**警告**:trojan使用的sha224密钥，需要自己计算，当前设置为密码666的密钥
//**警告**:trojan使用的sha224密钥，需要自己计算，当前设置为密码666的密钥
//**警告**:trojan使用的sha224密钥计算网址：https://www.lzltool.com/data-sha224
const passWordSha224 = '509eece82eb6910bebef9af9496092d3244b6c0d69ef3aaa4b12c565';
// URL路径添加 speed=N 可限制下行速度，单位为 MB/s，例如 /?speed=50。
const bufferSize = 256 * 1024;
const startThreshold = 50 * 1024 * 1024;
const maxChunkLen = 64 * 1024;
const flushTime = 4;
let concurrency = 4;
const urlParamCacheLimit = 20;
const proxyStrategyOrder = ['socks', 'http', 'https'];
const dohEndpoints = ['https://cloudflare-dns.com/dns-query', 'https://dns.google/dns-query'];
const dohNatEndpoints = ['https://cloudflare-dns.com/dns-query', 'https://dns.google/resolve'];
const finallyProxyHost = 'proxy.zjcloud.us.ci';
const traceUrl = 'http://cp.cloudflare.com/cdn-cgi/trace', proxySuffix = '.proxy.zjcloud.us.ci';
let currentColo = null, pendingPromise = null;
const getCurrentColo = () => {
    if (currentColo !== null) return currentColo;
    if (pendingPromise !== null) return pendingPromise;
    return pendingPromise = fetch(traceUrl, {signal: AbortSignal.timeout(200)}).then(r => r.text()).then(t => {
        const i = t.indexOf("colo=");
        return currentColo = i !== -1 ? t.slice(i + 5, i + 8) + proxySuffix : finallyProxyHost
    }).catch(() => currentColo = finallyProxyHost).finally(() => {pendingPromise = null})
};
const _h = c => (c > 64 ? (c & 7) + 9 : c & 15);
const _b = p => (_h(uuid.charCodeAt(p)) << 4) | _h(uuid.charCodeAt(p + 1));
const U0 = _b(0), U1 = _b(2), U2 = _b(4), U3 = _b(6), U4 = _b(9), U5 = _b(11), U6 = _b(14), U7 = _b(16), U8 = _b(19), U9 = _b(21), U10 = _b(24), U11 = _b(26), U12 = _b(28), U13 = _b(30), U14 = _b(32), U15 = _b(34);
const _c = i => passWordSha224.charCodeAt(i);
const H0 = _c(0), H1 = _c(1), H2 = _c(2), H3 = _c(3), H4 = _c(4), H5 = _c(5), H6 = _c(6), H7 = _c(7), H8 = _c(8), H9 = _c(9), H10 = _c(10), H11 = _c(11), H12 = _c(12), H13 = _c(13),
    H14 = _c(14), H15 = _c(15), H16 = _c(16), H17 = _c(17), H18 = _c(18), H19 = _c(19), H20 = _c(20), H21 = _c(21), H22 = _c(22), H23 = _c(23), H24 = _c(24), H25 = _c(25), H26 = _c(26), H27 = _c(27),
    H28 = _c(28), H29 = _c(29), H30 = _c(30), H31 = _c(31), H32 = _c(32), H33 = _c(33), H34 = _c(34), H35 = _c(35), H36 = _c(36), H37 = _c(37), H38 = _c(38), H39 = _c(39), H40 = _c(40), H41 = _c(41),
    H42 = _c(42), H43 = _c(43), H44 = _c(44), H45 = _c(45), H46 = _c(46), H47 = _c(47), H48 = _c(48), H49 = _c(49), H50 = _c(50), H51 = _c(51), H52 = _c(52), H53 = _c(53), H54 = _c(54), H55 = _c(55);
const textEncoder = new TextEncoder, textDecoder = new TextDecoder;
const binaryAddrToString = (addrType, addrBytes) => {
    if (addrType === 3) return textDecoder.decode(addrBytes);
    if (addrType === 1) return `${addrBytes[0]}.${addrBytes[1]}.${addrBytes[2]}.${addrBytes[3]}`;
    let ipv6 = ((addrBytes[0] << 8) | addrBytes[1]).toString(16);
    for (let i = 1; i < 8; i++) ipv6 += ':' + ((addrBytes[i * 2] << 8) | addrBytes[i * 2 + 1]).toString(16);
    return `[${ipv6}]`;
};
const parseHostPort = (addr, defaultPort) => {
    let host = addr, port = defaultPort, idx;
    if (addr.charCodeAt(0) === 91) {
        if ((idx = addr.indexOf(']:')) !== -1) {
            host = addr.substring(0, idx + 1);
            port = addr.substring(idx + 2);
        }
    } else if ((idx = addr.indexOf('.tp')) !== -1 && addr.lastIndexOf(':') === -1) {
        port = addr.substring(idx + 3, addr.indexOf('.', idx + 3));
    } else if ((idx = addr.lastIndexOf(':')) !== -1) {
        host = addr.substring(0, idx);
        port = addr.substring(idx + 1);
    }
    return [host, (port = parseInt(port), isNaN(port) ? defaultPort : port)];
};
const parseAuthString = (authParam) => {
    let username, password, hostStr;
    const atIndex = authParam.lastIndexOf('@');
    if (atIndex === -1) {hostStr = authParam} else {
        const cred = authParam.substring(0, atIndex);
        hostStr = authParam.substring(atIndex + 1);
        const colonIndex = cred.indexOf(':');
        if (colonIndex === -1) {username = cred} else {
            username = cred.substring(0, colonIndex);
            password = cred.substring(colonIndex + 1);
        }
    }
    const [hostname, port] = parseHostPort(hostStr, 1080);
    return {username, password, hostname, port};
};
const createConnect = (hostname, port, socketOptions, socket = connect({hostname, port}, socketOptions)) => socket.opened.then(() => socket);
const dohHeaders = {'content-type': 'application/dns-message', 'accept': 'application/dns-message'}, dohJsonHeaders = {headers: {'accept': 'application/dns-json'}};
const concurrentDnsResolve = async (hostname, recordType) => {
    const q = '?name=' + hostname + '&type=' + recordType;
    const res = await Promise.any([
        fetch(dohNatEndpoints[0] + q, dohJsonHeaders).then(r => r.ok ? r.json() : Promise.reject()),
        fetch(dohNatEndpoints[1] + q, dohJsonHeaders).then(r => r.ok ? r.json() : Promise.reject())
    ]).catch(() => null);
    return res?.Answer || res?.answer || null;
};
const raceAny = promises => {
    let settled = false;
    const len = promises.length, wrapped = new Array(len);
    for (let i = 0; i < len; i++) {
        wrapped[i] = promises[i].then(res => {
            if (!res || settled) {
                res?.close();
                throw null;
            }
            settled = true;
            return res;
        });
    }
    return Promise.any(wrapped);
};
const concurrentConnect = (hostname, port, limit = concurrency, socketOptions) => {
    if (limit <= 1) return createConnect(hostname, port, socketOptions);
    const attempts = new Array(limit);
    for (let i = 0; i < limit; i++) attempts[i] = createConnect(hostname, port, socketOptions);
    return raceAny(attempts);
};
const connectViaSocksProxy = async (targetAddrType, targetPortNum, socksAuth, addrBytes, limit) => {
    const socksSocket = await concurrentConnect(socksAuth.hostname, socksAuth.port, limit);
    const writer = socksSocket.writable.getWriter();
    const reader = socksSocket.readable.getReader();
    await writer.write(new Uint8Array([5, 2, 0, 2]));
    const {value: authResponse} = await reader.read();
    if (!authResponse || authResponse[0] !== 5 || authResponse[1] === 0xFF) return null;
    if (authResponse[1] === 2) {
        if (!socksAuth.username) return null;
        const userBytes = textEncoder.encode(socksAuth.username);
        const passBytes = textEncoder.encode(socksAuth.password || '');
        const uLen = userBytes.length, pLen = passBytes.length, authReq = new Uint8Array(3 + uLen + pLen)
        authReq[0] = 1, authReq[1] = uLen, authReq.set(userBytes, 2), authReq[2 + uLen] = pLen, authReq.set(passBytes, 3 + uLen);
        await writer.write(authReq);
        const {value: authResult} = await reader.read();
        if (!authResult || authResult[0] !== 1 || authResult[1] !== 0) return null;
    } else if (authResponse[1] !== 0) {return null}
    const isDomain = targetAddrType === 3, socksReq = new Uint8Array(6 + addrBytes.length + (isDomain ? 1 : 0));
    socksReq[0] = 5, socksReq[1] = 1, socksReq[2] = 0, socksReq[3] = targetAddrType;
    isDomain ? (socksReq[4] = addrBytes.length, socksReq.set(addrBytes, 5)) : socksReq.set(addrBytes, 4);
    socksReq[socksReq.length - 2] = targetPortNum >> 8, socksReq[socksReq.length - 1] = targetPortNum & 0xff;
    await writer.write(socksReq);
    const {value: finalResponse} = await reader.read();
    if (!finalResponse || finalResponse[1] !== 0) return null;
    writer.releaseLock(), reader.releaseLock();
    return socksSocket;
};
const staticHeaders = `User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36\r\nProxy-Connection: Keep-Alive\r\nConnection: Keep-Alive\r\n\r\n`;
const encodedStaticHeaders = textEncoder.encode(staticHeaders);
const connectViaHttpProxy = async (targetAddrType, targetPortNum, httpAuth, addrBytes, limit, useTls = false) => {
    const {username, password, hostname, port} = httpAuth;
    const connectOptions = useTls ? {secureTransport: 'on', allowHalfOpen: false} : undefined;
    const proxySocket = await concurrentConnect(hostname, port, limit, connectOptions);
    const writer = proxySocket.writable.getWriter();
    const httpHost = binaryAddrToString(targetAddrType, addrBytes);
    let dynamicHeaders = `CONNECT ${httpHost}:${targetPortNum} HTTP/1.1\r\nHost: ${httpHost}:${targetPortNum}\r\n`;
    if (username) dynamicHeaders += `Proxy-Authorization: Basic ${btoa(`${username}:${password || ''}`)}\r\n`;
    const fullHeaders = new Uint8Array(dynamicHeaders.length * 3 + encodedStaticHeaders.length);
    const {written} = textEncoder.encodeInto(dynamicHeaders, fullHeaders);
    fullHeaders.set(encodedStaticHeaders, written);
    await writer.write(fullHeaders.subarray(0, written + encodedStaticHeaders.length));
    writer.releaseLock();
    const reader = proxySocket.readable.getReader();
    const buffer = new Uint8Array(512);
    let bytesRead = 0, statusChecked = false;
    while (bytesRead < buffer.length) {
        const {value, done} = await reader.read();
        if (done || bytesRead + value.length > buffer.length) return null;
        const prevBytesRead = bytesRead;
        buffer.set(value, bytesRead);
        bytesRead += value.length;
        if (!statusChecked && bytesRead >= 12) {
            if (buffer[9] !== 50) return null;
            statusChecked = true;
        }
        let i = Math.max(15, prevBytesRead - 3);
        while ((i = buffer.indexOf(13, i)) !== -1 && i <= bytesRead - 4) {
            if (buffer[i + 1] === 10 && buffer[i + 2] === 13 && buffer[i + 3] === 10) {
                reader.releaseLock();
                return proxySocket;
            }
            i++;
        }
    }
    return null;
};
const parseProtocolChunk = (chunk) => {
    const len = chunk.length;
    const result = {success: false, needMore: false, handshake: null, parsedRequest: null};
    if (len >= 17 &&
        chunk[1] === U0 && chunk[2] === U1 && chunk[3] === U2 && chunk[4] === U3 && chunk[5] === U4 && chunk[6] === U5 && chunk[7] === U6 && chunk[8] === U7 &&
        chunk[9] === U8 && chunk[10] === U9 && chunk[11] === U10 && chunk[12] === U11 && chunk[13] === U12 && chunk[14] === U13 && chunk[15] === U14 && chunk[16] === U15
    ) {
        if (len < 18) return result.needMore = true, result;
        const offset = 19 + chunk[17];
        if (len < offset + 4) return result.needMore = true, result;
        let addrType = chunk[offset + 2];
        if (addrType !== 1) addrType += 1;
        const addrLen = addrType === 3 ? (offset + 3 < len ? chunk[offset + 3] : null) : addrType === 1 ? 4 : addrType === 4 ? 16 : -1;
        if (addrLen === null) return result.needMore = true, result;
        if (addrLen > 0) {
            const addrOffset = addrType === 3 ? offset + 4 : offset + 3;
            const dataOffset = addrOffset + addrLen;
            if (len < dataOffset) return result.needMore = true, result;
            const port = (chunk[offset] << 8) | chunk[offset + 1];
            result.handshake = new Uint8Array([chunk[0], 0]);
            result.success = true;
            result.parsedRequest = {addrType, addrBytes: chunk.subarray(addrOffset, addrOffset + addrLen), dataOffset, port, isDns: port === 53};
            return result;
        }
    }
    if (len >= 56 &&
        chunk[0] === H0 && chunk[1] === H1 && chunk[2] === H2 && chunk[3] === H3 && chunk[4] === H4 && chunk[5] === H5 && chunk[6] === H6 && chunk[7] === H7 &&
        chunk[8] === H8 && chunk[9] === H9 && chunk[10] === H10 && chunk[11] === H11 && chunk[12] === H12 && chunk[13] === H13 && chunk[14] === H14 && chunk[15] === H15 &&
        chunk[16] === H16 && chunk[17] === H17 && chunk[18] === H18 && chunk[19] === H19 && chunk[20] === H20 && chunk[21] === H21 && chunk[22] === H22 && chunk[23] === H23 &&
        chunk[24] === H24 && chunk[25] === H25 && chunk[26] === H26 && chunk[27] === H27 && chunk[28] === H28 && chunk[29] === H29 && chunk[30] === H30 && chunk[31] === H31 &&
        chunk[32] === H32 && chunk[33] === H33 && chunk[34] === H34 && chunk[35] === H35 && chunk[36] === H36 && chunk[37] === H37 && chunk[38] === H38 && chunk[39] === H39 &&
        chunk[40] === H40 && chunk[41] === H41 && chunk[42] === H42 && chunk[43] === H43 && chunk[44] === H44 && chunk[45] === H45 && chunk[46] === H46 && chunk[47] === H47 &&
        chunk[48] === H48 && chunk[49] === H49 && chunk[50] === H50 && chunk[51] === H51 && chunk[52] === H52 && chunk[53] === H53 && chunk[54] === H54 && chunk[55] === H55
    ) {
        if (len < 60) return result.needMore = true, result;
        const addrType = chunk[59];
        const addrLen = addrType === 3 ? (60 < len ? chunk[60] : null) : addrType === 1 ? 4 : addrType === 4 ? 16 : -1;
        if (addrLen === null) return result.needMore = true, result;
        if (addrLen > 0) {
            const addrOffset = addrType === 3 ? 61 : 60;
            const dataOffset = addrOffset + addrLen + 4;
            if (len < dataOffset) return result.needMore = true, result;
            const portOffset = addrOffset + addrLen;
            const port = (chunk[portOffset] << 8) | chunk[portOffset + 1];
            result.success = true;
            result.parsedRequest = {addrType, addrBytes: chunk.subarray(addrOffset, addrOffset + addrLen), dataOffset, port, isDns: port === 53};
            return result;
        }
    }
    return len < 56 ? (result.needMore = true, result) : result;
};
const dohDnsHandler = async (payload) => {
    if (payload.byteLength < 2) return null;
    const dnsQueryData = payload.subarray(2);
    const resp = await Promise.any(dohEndpoints.map(endpoint =>
        fetch(endpoint, {method: 'POST', headers: dohHeaders, body: dnsQueryData}).then(response => {
            if (!response.ok) throw new Error();
            return response;
        })
    ));
    const dnsQueryResult = await resp.arrayBuffer();
    const udpSize = dnsQueryResult.byteLength;
    const packet = new Uint8Array(2 + udpSize);
    packet[0] = (udpSize >> 8) & 0xff, packet[1] = udpSize & 0xff;
    packet.set(new Uint8Array(dnsQueryResult), 2);
    return packet;
};
const txtdnsResult = async (txtdns) => {
    const answer = await concurrentDnsResolve(txtdns, 'TXT');
    if (!answer) return null;
    let txtData, i = 0, len = answer.length;
    for (; i < len; i++) if (answer[i].type === 16) {
        txtData = answer[i].data;
        break;
    }
    if (!txtData) return null;
    if (txtData.charCodeAt(0) === 34 && txtData.charCodeAt(txtData.length - 1) === 34) txtData = txtData.slice(1, -1);
    const raw = txtData.split(/,|\\010|\n/), prefixes = [];
    for (i = 0, len = raw.length; i < len; i++) {
        const s = raw[i].trim();
        if (s) prefixes.push(s);
    }
    return prefixes.length ? prefixes : null;
};
const proxyIpRegex = /william|fxpip|hhtxt/;
const connectProxyIp = async (param, limit, txt) => {
    if (param === undefined) param = await getCurrentColo() || finallyProxyHost;
    if (txt || proxyIpRegex.test(param)) {
        let resolvedIps = await txtdnsResult(param);
        if (!resolvedIps || resolvedIps.length === 0) return null;
        if (resolvedIps.length > limit) {
            for (let i = resolvedIps.length - 1; i > 0; i--) {
                const j = (Math.random() * (i + 1)) | 0;
                [resolvedIps[i], resolvedIps[j]] = [resolvedIps[j], resolvedIps[i]];
            }
            resolvedIps = resolvedIps.slice(0, limit);
        }
        const connectionPromises = resolvedIps.map(ip => {
            const [host, port] = parseHostPort(ip, 443);
            return createConnect(host, port);
        });
        return raceAny(connectionPromises).catch(() => null);
    }
    const [host, port] = parseHostPort(param, 443);
    return concurrentConnect(host, port, limit);
};
const strategyExecutorMap = new Map([
    [0, ({addrType, port, addrBytes}, _param, limit) => concurrentConnect(binaryAddrToString(addrType, addrBytes), port, limit)],
    [1, async ({addrType, port, addrBytes}, param, limit, _txt) => connectViaSocksProxy(addrType, port, param, addrBytes, limit)],
    [2, async ({addrType, port, addrBytes}, param, limit, _txt) => connectViaHttpProxy(addrType, port, param, addrBytes, limit)],
    [6, async ({addrType, port, addrBytes}, param, limit, _txt) => connectViaHttpProxy(addrType, port, param, addrBytes, limit, true)],
    [3, async (_parsedRequest, param, limit, txt) => connectProxyIp(param, limit, txt)]
]);
const concurrentStrategyExec = (parsedRequest, params, exec, limit, txt) => {
    const attempts = params.map(param => Promise.resolve().then(() => exec(parsedRequest, param, limit, txt)));
    return raceAny(attempts);
};
const paramRegex = /(speed|gs5|s5all|ghttp|httpall|ghttps|httpsall|s5|socks|http|https|txtip|ip)(?:=|:\/\/|%3A%2F%2F)([^&]+)|(proxyall|globalproxy|global)/gi;
const urlListCacheDict = new Map(), urlListCacheKeys = new Array(urlParamCacheLimit);
let urlListCacheIndex = 0;
const establishTcpConnection = async (parsedRequest, request) => {
    let u = request.url, clean = u.slice(u.indexOf('/', 10) + 1), l = clean.length, list = [], speed;
    const c = clean.charCodeAt(l - 1);
    if (c === 47 || c === 61) clean = clean.slice(0, l - 1);
    const cachedResult = urlListCacheDict.get(clean);
    if (cachedResult !== undefined) {
        list = cachedResult.list, speed = cachedResult.speed;
    } else {
        if (clean.length < 6) {
            list.push({type: 0}, {type: 3}, {type: 3, param: finallyProxyHost});
        } else {
            const p = Object.create(null);
            paramRegex.lastIndex = 0;
            let m;
            while ((m = paramRegex.exec(clean))) {p[(m[1] || m[3]).toLowerCase()] = m[2] ? (m[2].charCodeAt(m[2].length - 1) === 61 ? m[2].slice(0, -1) : m[2]) : true}
            if (p.speed) speed = p.speed;
            const s5 = p.gs5 || p.s5all || p.s5 || p.socks, http = p.ghttp || p.httpall || p.http, https = p.ghttps || p.httpsall || p.https;
            const proxyAll = !!(p.gs5 || p.s5all || p.ghttp || p.httpall || p.ghttps || p.httpsall || p.proxyall || p.globalproxy || p.global);
            if (!proxyAll) list.push({type: 0});
            const add = (v, t, txt) => {
                if (!v) return;
                const parts = decodeURIComponent(v).split(',').filter(Boolean);
                if (txt) {
                    for (let i = 0; i < parts.length; i++) list.push({type: t, param: parts[i], txt});
                } else if (parts.length) {
                    const parsedParams = parts.map(part => {
                        if (t === 1 || t === 2 || t === 6) return parseAuthString(part);
                        return part;
                    });
                    list.push({type: t, param: parsedParams, concurrent: true});
                }
            };
            for (let i = 0; i < proxyStrategyOrder.length; i++) {
                const k = proxyStrategyOrder[i];
                add(k === 'socks' ? s5 : k === 'http' ? http : https, k === 'socks' ? 1 : k === 'http' ? 2 : 6);
            }
            if (proxyAll) {
                if (!list.length) list.push({type: 0});
            } else {
                add(p.ip, 3), add(p.txtip, 3, true);
                list.push({type: 3}, {type: 3, param: finallyProxyHost});
            }
        }
        const oldKey = urlListCacheKeys[urlListCacheIndex];
        if (oldKey !== undefined) urlListCacheDict.delete(oldKey);
        urlListCacheKeys[urlListCacheIndex] = clean;
        urlListCacheDict.set(clean, {list, speed});
        urlListCacheIndex = (urlListCacheIndex + 1) % urlParamCacheLimit;
    }
    for (let i = 0; i < list.length; i++) {
        try {
            const exec = strategyExecutorMap.get(list[i].type);
            const sub = (list[i]['concurrent'] && Array.isArray(list[i].param)) ? Math.max(1, Math.floor(concurrency / list[i].param.length)) : undefined;
            // @ts-ignore
            const socket = await (list[i]['concurrent'] && Array.isArray(list[i].param) ? concurrentStrategyExec(parsedRequest, list[i].param, exec, sub, list[i].txt) : exec(parsedRequest, list[i].param, undefined, list[i].txt));
            if (socket) return {socket, speed};
        } catch {}
    }
    return null;
};
const manualPipe = async (readable, writable, close, speed) => {
    const n = parseFloat(speed), speedLimit = n > 0;
    let pipeBufferSize = bufferSize, pipeFlushTime = flushTime, pipeStartThreshold = startThreshold;
    if (speedLimit) {
        pipeStartThreshold = n > 256 ? Number.MAX_SAFE_INTEGER : n * 1048576;
        let bestSize = pipeBufferSize, bestTime = Infinity, bestDiff = Infinity;
        for (let size = 262144; size <= 524288; size += 65536) {
            const timeMs = Math.max(2, Math.round(size * 1000 / pipeStartThreshold)), diff = Math.abs(size * 1000 / timeMs - pipeStartThreshold);
            if (diff < bestDiff || (diff === bestDiff && timeMs < bestTime)) bestSize = size, bestTime = timeMs, bestDiff = diff;
        }
        pipeBufferSize = bestSize, pipeFlushTime = bestTime;
    }
    const safeBufferSize = pipeBufferSize - maxChunkLen, fastFlushOffset = maxChunkLen << 1;
    let bufferView = new Uint8Array(pipeBufferSize), spareBuffer = new ArrayBuffer(maxChunkLen);
    let offset = 0, totalBytes = 0, time = 0, timerId = null, resume = null, isReading = false;
    let needsFlush = false, protectFlush = false, fastFlush = true, done, value;
    const flushBuffer = () => {
        if (isReading) return needsFlush = true;
        fastFlush = offset < fastFlushOffset;
        if (offset > 0) (writable.send(bufferView.subarray(0, offset)), offset = 0);
        needsFlush = false, protectFlush = false, timerId && (clearTimeout(timerId), timerId = null), resume?.(), resume = null;
    };
    const reader = readable.getReader({mode: 'byob'});
    try {
        while (true) {
            if (offset > 0 && protectFlush) {
                ({done, value} = await reader.read(new Uint8Array(spareBuffer, 0, maxChunkLen)));
                bufferView.set(value, offset), spareBuffer = value.buffer;
            } else {
                isReading = offset > 0;
                ({done, value} = await reader.read(new Uint8Array(bufferView.buffer, offset, maxChunkLen)));
                isReading = false, bufferView = new Uint8Array(value.buffer);
            }
            if (done) break;
            const chunkLen = value.byteLength;
            if (!chunkLen) {
                needsFlush && flushBuffer();
                continue;
            }
            offset += chunkLen, totalBytes += chunkLen;
            if (needsFlush) {
                flushBuffer();
            } else {
                if (fastFlush || chunkLen < 28672) {
                    if (!speedLimit) totalBytes = 0;
                    time = 2;
                } else if (totalBytes > pipeStartThreshold) time = pipeFlushTime;
                timerId ||= setTimeout(flushBuffer, time), protectFlush = chunkLen < maxChunkLen;
                offset > safeBufferSize && (totalBytes > pipeStartThreshold ? await new Promise(r => resume = r) : flushBuffer());
            }
        }
    } catch {offset = 0, close?.()} finally {isReading = false, flushBuffer()}
};
const createBufferedTcpWriter = (tcpWriter, close) => {
    const buffer = new Uint8Array(32768);
    let offset = 0, timerId = null, closed = false;
    const closeWriter = () => {
        if (closed) return;
        closed = true;
        timerId && (clearTimeout(timerId), timerId = null);
        close?.();
    };
    const safeWrite = data => {try {tcpWriter.write(data)} catch {closeWriter()}};
    const flush = () => {
        timerId && (clearTimeout(timerId), timerId = null);
        if (!offset || closed) return;
        const len = offset;
        offset = 0, safeWrite(buffer.subarray(0, len));
    };
    return chunk => {
        if (closed) return;
        const data = chunk.constructor === Uint8Array ? chunk : new Uint8Array(chunk), len = data.byteLength;
        if (!len) return;
        offset + len > 32768 && flush(), buffer.set(data, offset), offset += len, offset === 32768 ? flush() : (timerId && clearTimeout(timerId), timerId = setTimeout(flush, 2));
    };
};
const createAsyncMicrotaskQueue = (consume, close) => {
    const queue = new Array(256).fill(null);
    let head = 0, tail = 0, size = 0, drainActive = false, closed = false;
    const closeQueue = () => {
        if (closed) return;
        closed = true;
        for (let i = 0; i < 256; i++) queue[i] = null;
        close?.();
    };
    const drainQueue = async () => {
        if (closed) return;
        try {
            while (size > 0 && !closed) {
                const chunk = queue[head];
                queue[head] = null, head = (head + 1) & 255, size--;
                await consume(chunk);
            }
        } catch {closeQueue()} finally {drainActive = false}
    };
    return chunk => {
        if (closed) return;
        if (size === 256) return closeQueue();
        queue[tail] = chunk, tail = (tail + 1) & 255, size++;
        if (!drainActive) drainActive = true, queueMicrotask(drainQueue);
    };
};
const handleSession = async (chunk, state, request, writable, close, isEarlyData = false) => {
    state.needMore = false;
    const parsed = parseProtocolChunk(chunk);
    if (parsed.handshake) writable.send(parsed.handshake);
    if (!parsed.success) return parsed.needMore ? (state.needMore = true) : close();
    const parsedRequest = parsed.parsedRequest;
    const payload = chunk.subarray(parsedRequest.dataOffset);
    if (parsedRequest.isDns) {
        const dnsPack = await dohDnsHandler(payload);
        if (dnsPack?.byteLength) writable.send(dnsPack);
        if (!isEarlyData) return close();
    } else {
        const tcpResult = await establishTcpConnection(parsedRequest, request);
        if (!tcpResult) return close();
        state.tcpSocket = tcpResult.socket;
        const tcpWriter = state.tcpSocket.writable.getWriter();
        state.rawTcpWriter = tcpWriter;
        if (payload.byteLength) tcpWriter.write(payload);
        if (state.xwebPipeTo) return state.tcpWriter = (chunk) => tcpWriter.write(chunk);
        state.tcpWriter = createBufferedTcpWriter(tcpWriter, close);
        manualPipe(state.tcpSocket.readable, writable, close, tcpResult.speed);
    }
};
const handleWebSocketConn = async (webSocket, request) => {
    const refererHeader = request.headers.get("Referer");
    const protocolHeader = refererHeader || request.headers.get("sec-websocket-protocol");
    let earlyDataHeader = null;
    if (refererHeader) {earlyDataHeader = protocolHeader.slice(request.headers.get("host").length)} else if (protocolHeader) {earlyDataHeader = protocolHeader}
    // @ts-ignore
    const earlyData = earlyDataHeader ? Uint8Array.fromBase64(earlyDataHeader, {alphabet: "base64url"}) : null;
    const state = {tcpWriter: null, tcpSocket: null};
    let processingQueue = null;
    const close = () => {webSocket.close(1011, 'WebSocket is closed')};
    const process = (chunk) => {
        if (state.tcpWriter) return state.tcpWriter(chunk);
        return handleSession(earlyData ? chunk : new Uint8Array(chunk), state, request, webSocket, close, earlyData !== null);
    };
    processingQueue = createAsyncMicrotaskQueue(process, close);
    if (earlyData) processingQueue(earlyData);
    webSocket.addEventListener("message", event => (state.tcpWriter || processingQueue)(event.data));
    webSocket.addEventListener("error", close);
};
const xwebHeaders = {'Content-Type': 'application/octet-stream', 'grpc-status': '0', 'X-Accel-Buffering': 'no', 'Cache-Control': 'no-store'};
const handleXwebPost = async (request) => {
    const reader = request.body?.getReader({mode: 'byob'});
    if (!reader) return new Response(null, {status: 400});
    const state = {tcpWriter: null, tcpSocket: null, needMore: false, xwebPipeTo: true};
    const bridge = new IdentityTransformStream({highWaterMark: 1024 * 1024}), upBridge = new IdentityTransformStream({highWaterMark: 1024 * 1024 * 1024}), responseWriter = bridge.writable.getWriter();
    const close = () => {if (state.xwebPipeTo) state.xwebPipeTo = false, reader.cancel().catch(() => {}), responseWriter.close().catch(() => {})};
    const writable = {send(chunk) {if (chunk?.byteLength) return responseWriter.write(chunk)}};
    (async () => {
        let bufferView = new Uint8Array(32768), spareBuffer = new ArrayBuffer(8192), used = 0, uploaded = 0, timerId = null, done, value;
        const flush = () => {
            if (used > 0 && state.tcpWriter && bufferView) (state.tcpWriter(bufferView.subarray(0, used)), used = 0);
            timerId && (clearTimeout(timerId), timerId = null);
        };
        try {
            while (true) {
                if (used > 0 && state.tcpWriter) {
                    ({done, value} = await reader.read(new Uint8Array(spareBuffer, 0, 8192)));
                    bufferView.set(value, used), spareBuffer = value.buffer;
                } else {
                    ({done, value} = await reader.read(new Uint8Array(bufferView.buffer, used, 8192)));
                    bufferView = new Uint8Array(value.buffer);
                }
                if (done) break;
                const chunkLen = value.byteLength;
                if (!chunkLen) continue;
                used += chunkLen;
                if (state.tcpWriter) {
                    if (++uploaded >= 8000) {
                        flush();
                        await state.rawTcpWriter.ready;
                        reader.releaseLock(), state.rawTcpWriter.releaseLock(), state.xwebPipeTo = false, bufferView = null, spareBuffer = null;
                        request.body.pipeThrough(upBridge).pipeTo(state.tcpSocket.writable);
                        break;
                    }
                    used > 24576 ? flush() : (timerId && clearTimeout(timerId), timerId = setTimeout(flush, 2));
                } else {
                    state.needMore = false;
                    await handleSession(bufferView.subarray(0, used), state, request, writable, close);
                    if (state.tcpSocket && state.xwebPipeTo && !state.downstreamPiped) {
                        state.downstreamPiped = true, responseWriter.releaseLock();
                        state.tcpSocket.readable.pipeTo(bridge.writable);
                    }
                    if (!state.needMore) used = 0;
                }
            }
        } catch {used = 0, close()} finally {flush()}
    })().catch(close);
    return new Response(bridge.readable, {headers: xwebHeaders});
};
export default {
    async fetch(request) {
        if (request.method === 'POST' && request.headers.get('content-type')?.startsWith('application/grpc')) return handleXwebPost(request);
        if (request.headers.get('Upgrade') === 'websocket') {
            const {0: clientSocket, 1: webSocket} = new WebSocketPair();
            // @ts-ignore
            webSocket.accept({allowHalfOpen: true}), webSocket.binaryType = "arraybuffer";
            handleWebSocketConn(webSocket, request);
            return new Response(null, {status: 101, webSocket: clientSocket});
        }
        return fetch('https://1345695.github.io/index-404-html/');
    }
};
