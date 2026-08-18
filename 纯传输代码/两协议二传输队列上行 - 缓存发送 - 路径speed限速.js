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
const dnsStrategyOrder = ['ipv6', 'ipv4', 'hostname'];
const urlParamCacheLimit = 20;
const proxyStrategyOrder = ['socks', 'http', 'https'];
const dohEndpoints = ['https://cloudflare-dns.com/dns-query', 'https://dns.google/dns-query'];
const dohNatEndpoints = ['https://cloudflare-dns.com/dns-query', 'https://dns.google/resolve'];
const proxyIpAddrs = {
    US: 'us.proxy.zjcloud.us.ci',
    SJC: 'sjc.proxy.zjcloud.us.ci',
    SEA: 'sea.proxy.zjcloud.us.ci',
    LAX: 'lax.proxy.zjcloud.us.ci',
    EU: 'eu.proxy.zjcloud.us.ci',
    SIN: 'sin.proxy.zjcloud.us.ci',
    NRT: 'nrt.proxy.zjcloud.us.ci',
    TPE: 'tpe.proxy.zjcloud.us.ci',
    HKG: 'hkg.proxy.zjcloud.us.ci'
};
const finallyProxyHost = 'proxy.zjcloud.us.ci';
const coloRegions = {
    NRT: new Set(['FUK', 'ICN', 'KIX', 'NRT', 'OKA']), HKG: new Set(['HKG', 'MFM']), TPE: new Set(['KHH', 'TPE']),
    LAX: new Set(['LAX']), SEA: new Set(['SEA']), SJC: new Set(['SJC']),
    EU: new Set([
        'ACC', 'ADB', 'ALA', 'ALG', 'AMM', 'AMS', 'ARN', 'ATH', 'BAH', 'BCN', 'BEG', 'BGW', 'BOD', 'BRU', 'BTS', 'BUD', 'CAI',
        'CDG', 'CPH', 'CPT', 'DAR', 'DKR', 'DMM', 'DOH', 'DUB', 'DUR', 'DUS', 'DXB', 'EBB', 'EDI', 'EVN', 'FCO', 'FRA', 'GOT',
        'GVA', 'HAM', 'HEL', 'HRE', 'IST', 'JED', 'JIB', 'JNB', 'KBP', 'KEF', 'KWI', 'LAD', 'LED', 'LHR', 'LIS', 'LOS', 'LUX',
        'LYS', 'MAD', 'MAN', 'MCT', 'MPM', 'MRS', 'MUC', 'MXP', 'NBO', 'OSL', 'OTP', 'PMO', 'PRG', 'RIX', 'RUH', 'RUN', 'SKG',
        'SOF', 'STR', 'TBS', 'TLL', 'TLV', 'TUN', 'VIE', 'VNO', 'WAW', 'ZAG', 'ZRH']),
    SIN: new Set([
        'ADL', 'AKL', 'AMD', 'BKK', 'BLR', 'BNE', 'BOM', 'CBR', 'CCU', 'CEB', 'CGK', 'CMB', 'COK', 'DAC', 'DEL', 'HAN',
        'HYD', 'ISB', 'JHB', 'JOG', 'KCH', 'KHI', 'KTM', 'KUL', 'LHE', 'MAA', 'MEL', 'MLE', 'MNL', 'NAG', 'NOU',
        'PAT', 'PBH', 'PER', 'PNH', 'SGN', 'SIN', 'SYD', 'ULN', 'VTE'])
};
const coloToProxyMap = new Map();
for (const [region, colos] of Object.entries(coloRegions)) {for (const colo of colos) coloToProxyMap.set(colo, proxyIpAddrs[region])}
let currentColo = null;
const getCurrentColo = async () => {
    if (currentColo !== null) return currentColo;
    try {
        const text = await fetch('https://cp.cloudflare.com/cdn-cgi/trace', {
            headers: {'User-Agent': 'Mozilla/5.0'}
        }).then(r => r.text());
        const i = text.indexOf('colo=');
        currentColo = text.slice(i + 5, i + 8);
        return currentColo;
    } catch {
        currentColo = null;
        return '';
    }
};
const uuidBytes = new Uint8Array(16), hashBytes = new Uint8Array(56), offsets = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 4, 4, 4, 4];
for (let i = 0, c; i < 16; i++) uuidBytes[i] = (((c = uuid.charCodeAt(i * 2 + offsets[i])) > 64 ? c + 9 : c) & 0xF) << 4 | (((c = uuid.charCodeAt(i * 2 + offsets[i] + 1)) > 64 ? c + 9 : c) & 0xF);
for (let i = 0; i < 56; i++) hashBytes[i] = passWordSha224.charCodeAt(i);
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
const isIPv4 = (str) => {
    const len = str.length;
    if (len > 15 || len < 7) return false;
    let part = 0, dots = 0, partLen = 0, head = 0;
    for (let i = 0; i < len; i++) {
        const charCode = str.charCodeAt(i);
        if (charCode === 46) {
            if (dots === 3 || partLen === 0 || (partLen > 1 && head === 48)) return false;
            dots++, part = 0, partLen = 0;
        } else {
            const digit = (charCode - 48) >>> 0;
            if (digit > 9) return false;
            if (partLen === 0) head = charCode;
            partLen++, part = part * 10 + digit;
            if (part > 255 || partLen > 3) return false;
        }
    }
    return dots === 3 && partLen > 0 && !(partLen > 1 && head === 48);
};
const addrTypeIs = hostname => {
    const char0 = hostname.charCodeAt(0);
    return (char0 - 48) >>> 0 > 9 ? (char0 === 91 ? 4 : 3) : isIPv4(hostname) ? 1 : 3;
};
const createConnect = (hostname, port, socketOptions, socket = connect({hostname, port}, socketOptions)) => socket.opened.then(() => socket);
const dohJsonOptions = {headers: {'Accept': 'application/dns-json'}}, dohHeaders = {'content-type': 'application/dns-message'};
const concurrentDnsResolve = async (hostname, recordType) => {
    const dnsResult = await Promise.any(dohNatEndpoints.map(endpoint =>
        fetch(`${endpoint}?name=${hostname}&type=${recordType}`, dohJsonOptions).then(response => {
            if (!response.ok) throw new Error();
            return response.json();
        })
    ));
    const answer = dnsResult.Answer || dnsResult.answer;
    if (!answer || answer.length === 0) return null;
    return answer;
};
const dnsConnectCache = new Map();
const setDnsConnectCache = (hostname, result) => {
    if (!dnsConnectCache.has(hostname) && dnsConnectCache.size >= 5000) {
        let oldestKey, oldestExpires = Infinity;
        for (const [key, value] of dnsConnectCache) if (value.expires < oldestExpires) oldestKey = key, oldestExpires = value.expires;
        if (oldestKey !== undefined) dnsConnectCache.delete(oldestKey);
    }
    dnsConnectCache.set(hostname, result);
};
const dnsConnectResolve = async hostname => {
    const parseAnswer = (answer, type, wrap) => {
        const records = [], now = Date.now();
        let ttl = 0;
        if (answer) {
            for (let i = 0, len = answer.length; i < len; i++) {
                const record = answer[i];
                if (record.type === type && record.data) {
                    records.push(wrap ? `[${record.data}]` : record.data);
                    if (record.TTL > 0) ttl = ttl ? Math.min(ttl, record.TTL * 1000) : record.TTL * 1000;
                }
            }
        }
        return {records, expires: now + Math.min(ttl || 60000, 300000)};
    };
    const [aaaa, a] = await Promise.all([
        dnsStrategyOrder.includes('ipv6') ? concurrentDnsResolve(hostname, 'AAAA').catch(() => null) : Promise.resolve(null),
        dnsStrategyOrder.includes('ipv4') ? concurrentDnsResolve(hostname, 'A').catch(() => null) : Promise.resolve(null)
    ]);
    const ipv6 = parseAnswer(aaaa, 28, true), ipv4 = parseAnswer(a, 1, false);
    const hasRecord = ipv6.records.length || ipv4.records.length;
    const result = {ipv6: ipv6.records, ipv4: ipv4.records, expires: hasRecord ? Math.max(ipv6.expires, ipv4.expires) : Date.now() + 5000, refreshing: null};
    setDnsConnectCache(hostname, result);
    return result;
};
const getDnsConnectCache = hostname => {
    let cached = dnsConnectCache.get(hostname);
    const now = Date.now();
    if (!cached) return dnsConnectResolve(hostname);
    if (cached.expires > now) return cached;
    cached.refreshing ||= dnsConnectResolve(hostname).catch(() => null).finally(() => {
        const current = dnsConnectCache.get(hostname);
        if (current) current.refreshing = null;
    });
    return cached;
};
const getTxtDnsCache = txtdns => {
    const key = `TXT:${txtdns}`;
    let cached = dnsConnectCache.get(key);
    const now = Date.now(), resolve = async () => {
        const answer = await concurrentDnsResolve(txtdns, 'TXT').catch(() => null);
        const result = {answer, expires: Date.now() + (answer ? 60000 : 5000), refreshing: null};
        setDnsConnectCache(key, result);
        return result;
    };
    if (!cached) return resolve();
    if (cached.expires > now) return cached;
    cached.refreshing ||= resolve().catch(() => null).finally(() => {
        const current = dnsConnectCache.get(key);
        if (current) current.refreshing = null;
    });
    return cached.answer ? cached : cached.refreshing;
};
const shuffleCandidates = (ipv6 = [], ipv4 = [], hostname) => {
    const shuffle = records => {
        records = records.slice();
        for (let i = records.length - 1; i > 0; i--) {
            const j = (Math.random() * (i + 1)) | 0;
            [records[i], records[j]] = [records[j], records[i]];
        }
        return records;
    };
    return dnsStrategyOrder.map(strategy => {
        const candidates = strategy === 'ipv6' ? ipv6 : strategy === 'ipv4' ? ipv4 : (strategy === 'hostname' && hostname) ? [hostname] : [];
        return candidates.length ? shuffle(candidates) : null;
    }).filter(Boolean);
};
const raceAny = (promises, closeFn) => {
    let settled = false, winner = null;
    const resolvedList = [];
    const wrapped = promises.map(async p => {
        const res = await p;
        if (!res) throw new Error();
        if (settled) {
            closeFn?.(res);
            throw new Error();
        }
        resolvedList.push(res);
        return res;
    });
    return Promise.any(wrapped).then(win => {
        settled = true, winner = win;
        for (const item of resolvedList) if (item !== winner) closeFn?.(item);
        return winner;
    }, err => {
        settled = true;
        for (const item of resolvedList) closeFn?.(item);
        throw err;
    });
};
const connectCandidates = (candidates, port, limit, socketOptions) => {
    if (!candidates?.length) return Promise.reject();
    if (candidates.length === 1 && limit === 1) return createConnect(candidates[0], port, socketOptions);
    const targets = (candidates.length === 1 && limit > 1)
        ? Array(limit).fill(candidates[0])
        : (limit && candidates.length > limit ? candidates.slice(0, limit) : candidates);
    const closeSocket = s => {try {s?.close?.()} catch {}};
    const attempts = targets.map(candidate => {
        const socket = connect({hostname: candidate, port}, socketOptions);
        return socket.opened.then(() => socket, err => {
            closeSocket(socket);
            throw err;
        });
    });
    return raceAny(attempts, closeSocket);
};
const connectGroups = async (groups, port, limit, socketOptions) => {
    let lastError;
    for (const candidates of groups) try {return await connectCandidates(candidates, port, limit, socketOptions)} catch (err) {lastError = err}
    throw lastError || new Error('No connect candidates');
};
const concurrentConnect = async (hostname, port, limit = concurrency, socketOptions, addrType) => {
    if (addrType !== 3) return connectCandidates([hostname], port, limit, socketOptions);
    if (dnsStrategyOrder.length === 1 && dnsStrategyOrder[0] === 'hostname') {
        return connectCandidates([hostname], port, limit, socketOptions);
    }
    const cached = await getDnsConnectCache(hostname);
    const groups = shuffleCandidates(cached.ipv6, cached.ipv4, hostname);
    try {
        return await connectGroups(groups, port, limit, socketOptions);
    } catch (err) {
        const refreshed = cached.refreshing ? await cached.refreshing : null;
        if (refreshed && refreshed !== cached) {
            const refreshedGroups = shuffleCandidates(refreshed.ipv6, refreshed.ipv4, hostname);
            return connectGroups(refreshedGroups, port, limit, socketOptions);
        }
        throw err;
    }
};
const connectViaSocksProxy = async (targetAddrType, targetPortNum, socksAuth, addrBytes, limit) => {
    const socksSocket = await concurrentConnect(socksAuth.hostname, socksAuth.port, limit, undefined, addrTypeIs(socksAuth.hostname));
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
    const proxySocket = await concurrentConnect(hostname, port, limit, connectOptions, addrTypeIs(hostname));
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
    let isVL = false;
    if (len >= 17) {
        isVL = true;
        for (let i = 0; i < 16; i++) {
            if (chunk[i + 1] !== uuidBytes[i]) {
                isVL = false;
                break;
            }
        }
    }
    if (isVL) {
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
    if (len >= 56) {
        let isTJ = true;
        for (let i = 0; i < 56; i++) {
            if (chunk[i] !== hashBytes[i]) {
                isTJ = false;
                break;
            }
        }
        if (isTJ) {
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
    const answer = (await getTxtDnsCache(txtdns))?.answer;
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
        const closeSocket = s => {try {s?.close?.()} catch {}};
        const connectionPromises = resolvedIps.map(ip => {
            const [host, port] = parseHostPort(ip, 443);
            const socket = connect({hostname: host, port});
            return socket.opened.then(() => socket, err => {
                closeSocket(socket);
                throw err;
            });
        });
        return raceAny(connectionPromises, closeSocket).catch(() => null);
    }
    const [host, port] = parseHostPort(param, 443);
    return concurrentConnect(host, port, limit, undefined, addrTypeIs(host));
};
const strategyExecutorMap = new Map([
    [0, async ({addrType, port, addrBytes}, _param, limit, _txt) => {
        const hostname = binaryAddrToString(addrType, addrBytes);
        return concurrentConnect(hostname, port, limit, undefined, addrType);
    }],
    [1, async ({addrType, port, addrBytes}, param, limit, _txt) => {
        return connectViaSocksProxy(addrType, port, param, addrBytes, limit);
    }],
    [2, async ({addrType, port, addrBytes}, param, limit, _txt) => {
        return connectViaHttpProxy(addrType, port, param, addrBytes, limit);
    }],
    [6, async ({addrType, port, addrBytes}, param, limit, _txt) => {
        return connectViaHttpProxy(addrType, port, param, addrBytes, limit, true);
    }],
    [3, async (_parsedRequest, param, limit, txt) => {
        return connectProxyIp(param, limit, txt);
    }]
]);
const concurrentStrategyExec = (parsedRequest, params, exec, limit, txt) => {
    const closeResource = s => {try {s?.close?.()} catch {}};
    const attempts = params.map(param => Promise.resolve().then(() => exec(parsedRequest, param, limit, txt)));
    return raceAny(attempts, closeResource);
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
            const coloProxy = coloToProxyMap.get(await getCurrentColo()) ?? proxyIpAddrs.US;
            list.push({type: 0}, {type: 3, param: coloProxy}, {type: 3, param: finallyProxyHost});
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
                const coloProxy = coloToProxyMap.get(await getCurrentColo()) ?? proxyIpAddrs.US;
                add(p.ip, 3), add(p.txtip, 3, true);
                list.push({type: 3, param: coloProxy}, {type: 3, param: finallyProxyHost});
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
    let offset = 0, totalBytes = 0, time = 0, timerId = null, resume = null, isReading = false, needsFlush = false, protectFlush = false;
    let fastFlush = true;
    const flushBuffer = () => {
        if (isReading) return needsFlush = true;
        fastFlush = offset < fastFlushOffset;
        if (offset > 0) {
            offset > safeBufferSize
                ? (writable.send(bufferView.subarray(0, offset)), bufferView = new Uint8Array(pipeBufferSize))
                : writable.send(bufferView.slice(0, offset));
            offset = 0;
        }
        needsFlush = false, protectFlush = false, timerId && (clearTimeout(timerId), timerId = null), resume?.(), resume = null;
    };
    const reader = readable.getReader({mode: 'byob'});
    try {
        while (true) {
            const useSpare = offset > 0 && protectFlush;
            let readBuffer = bufferView.buffer, readOffset = offset;
            isReading = offset > 0;
            useSpare && (readBuffer = spareBuffer, readOffset = 0, isReading = false);
            const {done, value} = await reader.read(new Uint8Array(readBuffer, readOffset, maxChunkLen));
            isReading = false;
            useSpare ? (bufferView.set(value, offset), spareBuffer = value.buffer) : (bufferView = new Uint8Array(value.buffer));
            if (done) break;
            const chunkLen = value.byteLength;
            if (!chunkLen) {
                needsFlush && flushBuffer();
                continue;
            }
            offset += chunkLen, totalBytes += chunkLen;
            if (needsFlush || chunkLen < 2048) {
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
const createAsyncMicrotaskQueue = (consume, close) => {
    const queue = new Array(2048);
    let head = 0, tail = 0, size = 0, coalesceBuffer = null, drainActive = false, closed = false;
    const closeQueue = () => {
        if (closed) return;
        closed = true;
        for (let i = 0; i < 2048; i++) queue[i] = null;
        close?.();
    };
    const shift = () => {
        const chunk = queue[head];
        queue[head] = null, head = (head + 1) & 2047, size--;
        return chunk;
    };
    const drainQueue = async () => {
        if (closed) return;
        try {
            while (size > 0 && !closed) {
                if (!enqueue.writer) {
                    await consume(shift());
                    continue;
                }
                let chunk = queue[head];
                if (chunk.byteLength >= maxChunkLen) {
                    await enqueue.writer.write(shift());
                    continue;
                }
                let mergedLength = 0;
                coalesceBuffer ||= new Uint8Array(maxChunkLen);
                while (size > 0 && mergedLength + queue[head].byteLength <= maxChunkLen) {
                    chunk = shift(), coalesceBuffer.set(chunk, mergedLength), mergedLength += chunk.byteLength;
                }
                if (mergedLength > 0) await enqueue.writer.write(coalesceBuffer.subarray(0, mergedLength));
            }
        } catch {closeQueue()} finally {drainActive = false}
    };
    const enqueue = chunk => {
        if (closed) return;
        chunk = chunk.constructor === Uint8Array ? chunk : new Uint8Array(chunk);
        if (enqueue.writer && !chunk.byteLength) return;
        if (size === 2048) return closeQueue();
        queue[tail] = chunk, tail = (tail + 1) & 2047, size++;
        if (!drainActive) drainActive = true, queueMicrotask(drainQueue);
    };
    return enqueue;
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
        if (payload.byteLength) tcpWriter.write(payload);
        state.tcpWriter ||= createAsyncMicrotaskQueue(null, close);
        state.tcpWriter.writer = tcpWriter;
        if (state.xwebPipeTo) return;
        manualPipe(state.tcpSocket.readable, writable, close, tcpResult.speed);
    }
};
const handleWebSocketConn = async (webSocket, request) => {
    const refererHeader = request.headers.get('Referer');
    const protocolHeader = refererHeader || request.headers.get('sec-websocket-protocol');
    let earlyDataHeader = null;
    if (refererHeader) {
        earlyDataHeader = protocolHeader.slice(request.headers.get('host').length);
    } else if (protocolHeader) {
        earlyDataHeader = protocolHeader;
    }
    // @ts-ignore
    const earlyData = earlyDataHeader ? Uint8Array.fromBase64(earlyDataHeader, {alphabet: 'base64url'}) : null;
    const state = {tcpWriter: null, tcpSocket: null};
    const close = () => {
        try {state.tcpSocket?.close()} catch {}
        try {webSocket.close(1011, 'WebSocket is closed')} catch {}
    };
    const processingQueue = createAsyncMicrotaskQueue(chunk => handleSession(chunk, state, request, webSocket, close, earlyData !== null), close);
    state.tcpWriter = processingQueue;
    if (earlyData) processingQueue(earlyData);
    webSocket.addEventListener("message", event => processingQueue(event.data));
    webSocket.addEventListener("error", close);
};
const xwebHeaders = {'Content-Type': 'application/octet-stream', 'grpc-status': '0', 'X-Accel-Buffering': 'no', 'Cache-Control': 'no-store'};
const handleXwebPost = async (request) => {
    const reader = request.body?.getReader({mode: 'byob'});
    if (!reader) return new Response(null, {status: 400});
    const state = {tcpWriter: null, tcpSocket: null, needMore: false, xwebPipeTo: true};
    const bridge = new IdentityTransformStream(), responseWriter = bridge.writable.getWriter();
    let xwebBuffer = new ArrayBuffer(8192), used = 0;
    const close = () => {
        try {state.tcpSocket?.close()} catch {}
        if (state.xwebPipeTo) responseWriter.close().catch(() => {});
    };
    const writable = {send(chunk) {if (chunk?.byteLength) return responseWriter.write(chunk)}};
    (async () => {
        while (true) {
            if (used > 0) {
                const payload = new Uint8Array(xwebBuffer, 0, used);
                state.tcpWriter ? await state.tcpWriter(payload.slice()) : (state.needMore = false, await handleSession(payload, state, request, writable, close));
                if (state.tcpSocket && state.xwebPipeTo) {
                    state.xwebPipeTo = false;
                    responseWriter.releaseLock();
                    state.tcpSocket.readable.pipeTo(bridge.writable).catch(close);
                }
                if (!state.needMore) {
                    used = 0;
                    continue;
                }
            }
            const {done, value} = await reader.read(new Uint8Array(xwebBuffer, used, used === 0 ? 8192 : 4096));
            if (done) return close();
            xwebBuffer = value.buffer;
            used += value.byteLength;
        }
    })().catch(close);
    return new Response(bridge.readable, {headers: xwebHeaders});
};
export default {
    async fetch(request) {
        if (request.method === 'POST' && request.headers.get('content-type') === 'application/grpc-web') return handleXwebPost(request);
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
