// 代码基本都抄的CM和AK大佬和天书大佬的项目，在此感谢各位大佬的无私奉献。
import {connect} from 'cloudflare:sockets';
const defaultUuid = ''; // 可在环境变量配置，变量名称为UUID，两个地方都不写为不验证uuid
const defaultPassword = ''; // 可在环境变量配置，变量名称为PASSWORD，两个地方都不写为不验证密码
const socks5AndHttpUser = ''; // 可在环境变量配置，变量名称为S5HTTPUSER，两个地方都不写为不验证密码
const socks5AndHttpPass = ''; // 可在环境变量配置，变量名称为S5HTTPPASS，两个地方都不写为不验证密码
const ssAeadPassword = ''; // 可在环境变量配置，变量名称为SSPASS
// ---------------------------------------------------------------------------------
// 理论最低带宽计算公式 (Theoretical Max Bandwidth Calculation):
//    - 速度上限 (Mbps) = (bufferSize (字节) / flushTime (毫秒)) * 0.008
//    - 示例: (512 * 1024 字节 / 10 毫秒) * 0.008 ≈ 419 Mbps
//    - 在此模式下，这两个参数共同构成了一个精确的速度限制器。
// 为有效降低下载大文件可能爆内存的风险，需要自行根据网络单线程速度计算参数。
// ---------------------------------------------------------------------------------
/** 缓冲区最大大小。*/
/**- **警告**: 大小为maxChunkLen的整数倍使用率最高，不然会有空间浪费。*/
const bufferSize = 256 * 1024;         // 256KB
/** 开启限速缓存模式的大包流量阈值。*/
const startThreshold = 50 * 1024 * 1024; //50MB
/** 从TCP读取的数据块最大大小，改小会成倍增加传输相同流量的cpu开销，同时会因为写满而增加数据进入缓冲区限速的概率*/
/**- **警告**: 大小必须为2的幂，设置到大于64KB后只会写满写64KB*/
/**- **警告**: 免费worker设置64KB时传输相同流量cpu开销最低。*/
const maxChunkLen = 64 * 1024;        // 64KB
/** 进入缓冲模式时的缓冲区发送的触发时间。*/
const flushTime = 4;                 // 4ms
// ---------------------------------------------------------------------------------
/** SS AEAD加密时每批并发处理的payload分片数量，length加密开销低，会随payload一起提交。*/
const ssAeadEncryptCount = 16;
// ---------------------------------------------------------------------------------
/**- **警告**: worker最大支持6，超过6没意义*/
let concurrency = 4;//socket获取并发数
// ---------------------------------------------------------------------------------
const urlParamCacheLimit = 20;//URL参数解析结果缓存条数
// ---------------------------------------------------------------------------------
//五者的socket获取顺序，全局模式下为这五个的顺序，非全局为：直连>socks>http>https>turn>nat64>proxyip>finallyProxyHost
const proxyStrategyOrder = ['socks', 'http', 'https', 'turn', 'nat64'];
const sharedEchDns = 'lido.fi+https://223.5.5.5/dns-query'; //ECHDNS配置
const dohEndpoints = ['https://cloudflare-dns.com/dns-query', 'https://dns.google/dns-query'];
const dohNatEndpoints = ['https://cloudflare-dns.com/dns-query', 'https://dns.google/resolve'];
const proxyIpAddrs = {EU: 'ProxyIP.DE.CMLiussss.net', AS: 'ProxyIP.SG.CMLiussss.net', JP: 'ProxyIP.JP.CMLiussss.net', US: 'ProxyIP.US.CMLiussss.net'};//分区域proxyip
const finallyProxyHost = 'ProxyIP.CMLiussss.net';//兜底proxyip
// 订阅和面板使用的优选ip地址，可支持ip:port#name格式
const ipListAll = ["172.64.154.125", "104.18.39.123", "172.64.145.18", "104.18.42.218", "104.18.33.131", "172.64.145.38", "172.64.145.202", "104.18.42.151"];
const coloRegions = {
    JP: new Set(['FUK', 'ICN', 'KIX', 'NRT', 'OKA']),
    EU: new Set([
        'ACC', 'ADB', 'ALA', 'ALG', 'AMM', 'AMS', 'ARN', 'ATH', 'BAH', 'BCN', 'BEG', 'BGW', 'BOD', 'BRU', 'BTS', 'BUD', 'CAI',
        'CDG', 'CPH', 'CPT', 'DAR', 'DKR', 'DMM', 'DOH', 'DUB', 'DUR', 'DUS', 'DXB', 'EBB', 'EDI', 'EVN', 'FCO', 'FRA', 'GOT',
        'GVA', 'HAM', 'HEL', 'HRE', 'IST', 'JED', 'JIB', 'JNB', 'KBP', 'KEF', 'KWI', 'LAD', 'LED', 'LHR', 'LIS', 'LOS', 'LUX',
        'LYS', 'MAD', 'MAN', 'MCT', 'MPM', 'MRS', 'MUC', 'MXP', 'NBO', 'OSL', 'OTP', 'PMO', 'PRG', 'RIX', 'RUH', 'RUN', 'SKG',
        'SOF', 'STR', 'TBS', 'TLL', 'TLV', 'TUN', 'VIE', 'VNO', 'WAW', 'ZAG', 'ZRH']),
    AS: new Set([
        'ADL', 'AKL', 'AMD', 'BKK', 'BLR', 'BNE', 'BOM', 'CBR', 'CCU', 'CEB', 'CGK', 'CMB', 'COK', 'DAC', 'DEL', 'HAN', 'HKG',
        'HYD', 'ISB', 'JHB', 'JOG', 'KCH', 'KHH', 'KHI', 'KTM', 'KUL', 'LHE', 'MAA', 'MEL', 'MFM', 'MLE', 'MNL', 'NAG', 'NOU',
        'PAT', 'PBH', 'PER', 'PNH', 'SGN', 'SIN', 'SYD', 'TPE', 'ULN', 'VTE'])
};
const coloToProxyMap = new Map();
for (const [region, colos] of Object.entries(coloRegions)) {for (const colo of colos) coloToProxyMap.set(colo, proxyIpAddrs[region])}
const textEncoder = new TextEncoder(), textDecoder = new TextDecoder();
import wasmModule from './protocol.wasm';
const instance = new WebAssembly.Instance(wasmModule);
const {
    memory, getUuidPtr, getResultPtr, getDataPtr, getHttpAuthPtr, getSocks5AuthPtr, setHttpAuthLenWasm, setSocks5AuthLenWasm, parseProtocolWasm, parseUrlWasm,
    initCredentialsWasm, getPanelHtmlPtr, getPanelHtmlLen, getErrorHtmlPtr, getErrorHtmlLen, getTemplateWasm, getSecretStringWasm
} = instance.exports;
const wasmMem = new Uint8Array(memory.buffer);
const wasmRes = new Int32Array(memory.buffer, getResultPtr(), 34);
const dataPtr = getDataPtr();
let isInitialized = false, rawHtml = null, rawErrorHtml = null, config = null, cachedTemplates = null, strList = null, userAgentSuffix = null;
const decompressWasm = async (ptrFn, lenFn) => {
    const ptr = ptrFn(), len = lenFn();
    const compressedData = wasmMem.subarray(ptr, ptr + len);
    const ds = new DecompressionStream("gzip");
    const writer = ds.writable.getWriter();
    writer.write(compressedData);
    writer.close();
    return await new Response(ds.readable).text();
};
const getEnv = (env) => {
    if (config) return config;
    config = {
        uuid: (env.UUID || defaultUuid).trim(),
        password: (env.PASSWORD || defaultPassword).trim(),
        user: (env.S5HTTPUSER || socks5AndHttpUser).trim(),
        pass: (env.S5HTTPPASS || socks5AndHttpPass).trim(),
        sspass: (env.SSPASS || ssAeadPassword).trim()
    };
    return config;
};
const initializeWasm = (env) => {
    const {uuid, password, user, pass} = getEnv(env);
    const cleanUuid = uuid.replace(/-/g, "");
    if (cleanUuid.length === 32) {
        wasmRes[0] = 1;
        const uuidBytes = new Uint8Array(16);
        for (let i = 0, c; i < 16; i++) {uuidBytes[i] = (((c = cleanUuid.charCodeAt(i * 2)) > 64 ? c + 9 : c) & 0xF) << 4 | (((c = cleanUuid.charCodeAt(i * 2 + 1)) > 64 ? c + 9 : c) & 0xF)}
        wasmMem.set(uuidBytes, getUuidPtr());
    }
    if (password.length > 0) {
        wasmRes[1] = 1;
        const passBytes = textEncoder.encode(password);
        wasmMem.set(passBytes, dataPtr);
        initCredentialsWasm(passBytes.length);
    }
    if (user && pass) {
        const authBytes = textEncoder.encode(btoa(`${user}:${pass}`));
        wasmMem.set(authBytes, getHttpAuthPtr());
        setHttpAuthLenWasm(authBytes.length);
        const userBytes = textEncoder.encode(user);
        const passBytes = textEncoder.encode(pass);
        const socks5Pkg = new Uint8Array(3 + userBytes.length + passBytes.length);
        socks5Pkg[0] = 1, socks5Pkg[1] = userBytes.length, socks5Pkg.set(userBytes, 2), socks5Pkg[2 + userBytes.length] = passBytes.length, socks5Pkg.set(passBytes, 3 + userBytes.length);
        wasmMem.set(socks5Pkg, getSocks5AuthPtr());
        setSocks5AuthLenWasm(socks5Pkg.length);
    }
    cachedTemplates = new Array(13);
    const subUuid = uuid || crypto.randomUUID();
    const subPassword = password || crypto.randomUUID();
    globalThis.subUuid = subUuid;
    const getSecret = (idx) => {
        const len = getSecretStringWasm(idx);
        return textDecoder.decode(wasmMem.subarray(dataPtr, dataPtr + len));
    };
    strList = new Array(20);
    for (let i = 0; i < 20; i++) {strList[i] = getSecret(i)}
    const edge = strList[2];
    userAgentSuffix = edge + strList[3] + edge + strList[4];
    for (let i = 0; i < 13; i++) {
        const len = getTemplateWasm(i);
        const tmpl = textDecoder.decode(wasmMem.subarray(dataPtr, dataPtr + len));
        const baseTmpl = tmpl.replaceAll("{{ECHDNS}}", encodeURIComponent(sharedEchDns));
        cachedTemplates[i] = i < 7 ? baseTmpl.replaceAll("{{UUID}}", subUuid) : baseTmpl.replaceAll("{{PASSWORD}}", subPassword);
    }
    isInitialized = true;
};
const binaryAddrToString = (addrType, addrBytes) => {
    if (addrType === 3) return textDecoder.decode(addrBytes);
    if (addrType === 1) return `${addrBytes[0]}.${addrBytes[1]}.${addrBytes[2]}.${addrBytes[3]}`;
    let ipv6 = ((addrBytes[0] << 8) | addrBytes[1]).toString(16);
    for (let i = 1; i < 8; i++) ipv6 += ':' + ((addrBytes[i * 2] << 8) | addrBytes[i * 2 + 1]).toString(16);
    return `[${ipv6}]`;
};
const emptyU8 = new Uint8Array(0), ssSubkeyInfo = textEncoder.encode('ss-subkey');
const incNonce = (nonce) => {
    for (let i = 0; i < 12; i++) {
        nonce[i] = (nonce[i] + 1) & 0xff;
        if (nonce[i] !== 0) break;
    }
};
let ssMasterKeyPromise, ssHkdfKeyPromise;
const createSsAeadCtx = async (salt = crypto.getRandomValues(new Uint8Array(16))) => {
    const hkdfKey = await (ssHkdfKeyPromise ||= (async () => {
        const masterKey = await (ssMasterKeyPromise ||= (async () => {
            const pwd = textEncoder.encode(config.sspass);
            const out = new Uint8Array(16);
            let prev = emptyU8, offset = 0;
            while (offset < 16) {
                const input = new Uint8Array(prev.length + pwd.length);
                if (prev.length) input.set(prev, 0);
                input.set(pwd, prev.length);
                prev = new Uint8Array(await crypto.subtle.digest('MD5', input));
                const copyLen = Math.min(prev.length, 16 - offset);
                out.set(prev.subarray(0, copyLen), offset);
                offset += copyLen;
            }
            return out;
        })());
        return crypto.subtle.importKey('raw', masterKey, 'HKDF', false, ['deriveKey']);
    })());
    return {
        salt,
        key: await crypto.subtle.deriveKey({name: 'HKDF', hash: 'SHA-1', salt, info: ssSubkeyInfo}, hkdfKey, {name: 'AES-GCM', length: 128}, false, ['encrypt', 'decrypt']),
        nonce: new Uint8Array(12),
        pendingBuf: new Uint8Array(0),
        pendingStart: 0,
        pendingEnd: 0,
        nextPayloadLen: -1,
        nextNeed: 0
    };
};
const ssAeadDecryptFeed = async (ctx, chunk, onPlain) => {
    if (chunk?.length) {
        const chunkLen = chunk.length;
        const pendingLen = ctx.pendingEnd - ctx.pendingStart;
        if (!pendingLen) {
            if (chunkLen > ctx.pendingBuf.length) ctx.pendingBuf = new Uint8Array(chunkLen);
            ctx.pendingBuf.set(chunk, 0);
            ctx.pendingStart = 0;
            ctx.pendingEnd = chunkLen;
        } else {
            if (ctx.pendingBuf.length - ctx.pendingEnd < chunkLen) {
                if (ctx.pendingStart > 0) {
                    ctx.pendingBuf.copyWithin(0, ctx.pendingStart, ctx.pendingEnd);
                    ctx.pendingEnd = pendingLen;
                    ctx.pendingStart = 0;
                }
                if (ctx.pendingBuf.length - ctx.pendingEnd < chunkLen) {
                    const nextCap = pendingLen + chunkLen;
                    const nextBuf = new Uint8Array(nextCap);
                    nextBuf.set(ctx.pendingBuf.subarray(ctx.pendingStart, ctx.pendingEnd), 0);
                    ctx.pendingBuf = nextBuf;
                    ctx.pendingStart = 0;
                    ctx.pendingEnd = pendingLen;
                }
            }
            ctx.pendingBuf.set(chunk, ctx.pendingEnd);
            ctx.pendingEnd += chunkLen;
        }
    }
    const out = onPlain ? null : [];
    let total = 0, pendingStart = ctx.pendingStart, pendingEnd = ctx.pendingEnd;
    const pendingBuf = ctx.pendingBuf;
    while (true) {
        const pendingLen = pendingEnd - pendingStart;
        if (ctx.nextPayloadLen < 0) {
            if (pendingLen < 18) break;
            let lenPlain;
            try {
                lenPlain = new Uint8Array(await crypto.subtle.decrypt({name: 'AES-GCM', iv: ctx.nonce, tagLength: 128}, ctx.key, pendingBuf.subarray(pendingStart, pendingStart + 18)));
            } catch {throw new Error('ss length decrypt failed')}
            incNonce(ctx.nonce);
            const payloadLen = (lenPlain[0] << 8) | lenPlain[1];
            if (payloadLen > 16383) throw new Error('ss payload too large');
            ctx.nextPayloadLen = payloadLen;
            ctx.nextNeed = 18 + payloadLen + 16;
        }
        if (pendingLen < ctx.nextNeed) break;
        let payload;
        try {
            payload = new Uint8Array(await crypto.subtle.decrypt({name: 'AES-GCM', iv: ctx.nonce, tagLength: 128}, ctx.key, pendingBuf.subarray(pendingStart + 18, pendingStart + ctx.nextNeed)));
        } catch {throw new Error('ss payload decrypt failed')}
        incNonce(ctx.nonce);
        pendingStart += ctx.nextNeed;
        ctx.nextPayloadLen = -1;
        ctx.nextNeed = 0;
        if (onPlain) {
            await onPlain(payload);
        } else {
            out.push(payload), total += payload.length;
        }
    }
    if (pendingStart === pendingEnd) {
        ctx.pendingStart = 0;
        ctx.pendingEnd = 0;
    } else {
        ctx.pendingStart = pendingStart;
        ctx.pendingEnd = pendingEnd;
    }
    if (onPlain || out.length === 0) return emptyU8;
    if (out.length === 1) return out[0];
    const merged = new Uint8Array(total);
    for (let i = 0, o = 0; i < out.length; i++) {
        merged.set(out[i], o);
        o += out[i].length;
    }
    return merged;
};
const ssAeadEncryptChunks = async (ctx, data) => {
    if (!data?.length) return emptyU8;
    const dataLen = data.length;
    const out = new Uint8Array(dataLen + Math.ceil(dataLen / 16383) * 34);
    const {key, nonce} = ctx;
    const subtle = crypto.subtle;
    let outOffset = 0;
    for (let base = 0; base < dataLen; base += 16383 * ssAeadEncryptCount) {
        const batchEnd = Math.min(base + 16383 * ssAeadEncryptCount, dataLen);
        const tasks = [];
        for (let offset = base; offset < batchEnd; offset += 16383) {
            const end = offset + 16383 < dataLen ? offset + 16383 : dataLen;
            const p = offset === 0 && end === dataLen ? data : data.subarray(offset, end), l = end - offset;
            const lenBuf = new Uint8Array([l >> 8, l & 0xff]);
            const lenIv = nonce.slice();
            incNonce(nonce);
            const dataIv = nonce.slice();
            incNonce(nonce);
            tasks.push((async () => {
                const lenCipher = await subtle.encrypt({name: 'AES-GCM', iv: lenIv, tagLength: 128}, key, lenBuf);
                const dataCipher = await subtle.encrypt({name: 'AES-GCM', iv: dataIv, tagLength: 128}, key, p);
                return {l, lenCipher, dataCipher};
            })());
        }
        const results = await Promise.all(tasks);
        for (let i = 0; i < results.length; i++) {
            const {l, lenCipher, dataCipher} = results[i];
            out.set(new Uint8Array(lenCipher), outOffset);
            outOffset += 18;
            out.set(new Uint8Array(dataCipher), outOffset);
            outOffset += l + 16;
        }
    }
    return out;
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
const parseSubNode = (entry, defaultPort = 443) => {
    const raw = (entry || '').trim();
    if (!raw) return null;
    const hashIndex = raw.indexOf('#');
    const endpoint = hashIndex === -1 ? raw : raw.slice(0, hashIndex).trim();
    const customName = hashIndex === -1 ? '' : raw.slice(hashIndex + 1).trim();
    const [ip, portNum] = parseHostPort(endpoint || raw, defaultPort);
    return {ip, port: String(portNum), name: customName || ip};
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
const addrTypeIs = (hostname) => {
    const char0 = hostname.charCodeAt(0);
    return (char0 - 48) >>> 0 > 9 ? (char0 === 91 ? 4 : 3) : isIPv4(hostname) ? 1 : 3;
};
const createConnect = (hostname, port, socketOptions, socket = connect({hostname, port}, socketOptions)) => socket.opened.then(() => socket);
const concurrentConnect = (hostname, port, limit = concurrency, socketOptions) => {
    if (limit === 1) return createConnect(hostname, port, socketOptions);
    let settled = false, winner = null;
    const sockets = new Array(limit);
    const closeSocket = socket => {try {socket?.close()} catch {}};
    const attempts = Array.from({length: limit}, (_, i) => {
        const socket = connect({hostname, port}, socketOptions);
        sockets[i] = socket;
        return createConnect(hostname, port, socketOptions, socket).then(openedSocket => {
            if (settled && openedSocket !== winner) closeSocket(openedSocket);
            return openedSocket;
        });
    });
    return Promise.any(attempts).then(socket => {
        settled = true, winner = socket;
        for (const other of sockets) if (other !== socket) closeSocket(other);
        return socket;
    }, err => {
        settled = true;
        for (const socket of sockets) closeSocket(socket);
        throw err;
    });
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
const {TlsClient} = (() => {
    const e = 769, t = 771, n = 772, r = 20, i = 21, s = 22, a = 23, h = 1, c = 2, o = 4, l = 8, f = 11, u = 12, y = 13, p = 14, w = 15, d = 16, g = 20, k = 24, v = 0, A = 10, S = 11, m = 13, b = 16, C = 43, H = 45, T = 51, E = 0, L = new TextEncoder, K = new TextDecoder, P = new Uint8Array(0), U = new Map(Object.entries({
        TLS_AES_128_GCM_SHA256: {id: 4865, keyLen: 16, ivLen: 12, hash: "SHA-256", tls13: !0},
        TLS_AES_256_GCM_SHA384: {id: 4866, keyLen: 32, ivLen: 12, hash: "SHA-384", tls13: !0},
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: {id: 49199, keyLen: 16, ivLen: 4, hash: "SHA-256", kex: "ECDHE"},
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: {id: 49200, keyLen: 32, ivLen: 4, hash: "SHA-384", kex: "ECDHE"},
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: {id: 49195, keyLen: 16, ivLen: 4, hash: "SHA-256", kex: "ECDHE"},
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: {id: 49196, keyLen: 32, ivLen: 4, hash: "SHA-384", kex: "ECDHE"}
    }).map(([, e]) => [e.id, e])), I = new Map([[29, "X25519"], [23, "P-256"]]), x = [2052, 2053, 2054, 2055, 2056, 2057, 2058, 2059, 1027, 1283, 1539, 1025, 1281, 1537, 513, 515], _ = (...e) => {
        const t = e => {
            const n = [];
            for (const r of e) r instanceof Uint8Array ? n.push(...r) : Array.isArray(r) ? n.push(...t(r)) : "number" == typeof r && n.push(r);
            return n
        };
        return new Uint8Array(t(e))
    }, B = e => [e >> 8 & 255, 255 & e], R = (e, t) => e[t] << 8 | e[t + 1], M = (e, t) => e[t] << 16 | e[t + 1] << 8 | e[t + 2], W = (...e) => {
        const t = e.filter(e => e && e.length > 0), n = t.reduce((e, t) => e + t.length, 0), r = new Uint8Array(n);
        let i = 0;
        for (const e of t) r.set(e, i), i += e.length;
        return r
    }, D = e => crypto.getRandomValues(new Uint8Array(e)), N = (e, t) => {
        if (!e || !t || e.length !== t.length) return !1;
        let n = 0;
        for (let r = 0; r < e.length; r++) n |= e[r] ^ t[r];
        return 0 === n
    }, q = e => "SHA-512" === e ? 64 : "SHA-384" === e ? 48 : 32;
    async function $(e, t, n) {
        const r = await crypto.subtle.importKey("raw", t, {name: "HMAC", hash: e}, !1, ["sign"]);
        return new Uint8Array(await crypto.subtle.sign("HMAC", r, n))
    }
    async function G(e, t) {return new Uint8Array(await crypto.subtle.digest(e, t))}
    async function V(e, t, n, r, i = "SHA-256") {
        const s = W(L.encode(t), n);
        let a = new Uint8Array(0), h = s;
        for (; a.length < r;) {
            h = await $(i, e, h);
            const t = await $(i, e, W(h, s));
            a = W(a, t)
        }
        return a.slice(0, r)
    }
    async function X(e, t, n) {return t && t.length || (t = new Uint8Array(q(e))), $(e, t, n)}
    async function O(e, t, n, r, i) {
        const s = L.encode("tls13 " + n);
        return async function (e, t, n, r) {
            const i = q(e), s = Math.ceil(r / i);
            let a = new Uint8Array(0), h = new Uint8Array(0);
            for (let r = 1; r <= s; r++) h = await $(e, t, W(h, n, [r])), a = W(a, h);
            return a.slice(0, r)
        }(e, t, _(B(i), s.length, s, r.length, r), i)
    }
    async function F(e = "P-256") {
        if ("X25519" === e) {
            const e = await crypto.subtle.generateKey({name: "X25519"}, !0, ["deriveBits"]);
            return {kp: e, pk: new Uint8Array(await crypto.subtle.exportKey("raw", e.publicKey))}
        }
        const t = await crypto.subtle.generateKey({name: "ECDH", namedCurve: e}, !0, ["deriveBits"]);
        return {kp: t, pk: new Uint8Array(await crypto.subtle.exportKey("raw", t.publicKey))}
    }
    async function Y(e, t, n = "P-256") {
        if ("X25519" === n) {
            const n = await crypto.subtle.importKey("raw", t, {name: "X25519"}, !1, []);
            return new Uint8Array(await crypto.subtle.deriveBits({name: "X25519", public: n}, e, 256))
        }
        const r = await crypto.subtle.importKey("raw", t, {name: "ECDH", namedCurve: n}, !1, []), i = "P-384" === n ? 384 : "P-521" === n ? 528 : 256;
        return new Uint8Array(await crypto.subtle.deriveBits({name: "ECDH", public: r}, e, i))
    }
    async function j(e, t, n, r) {
        const i = await crypto.subtle.importKey("raw", e, {name: "AES-GCM"}, !1, ["encrypt"]);
        return new Uint8Array(await crypto.subtle.encrypt({name: "AES-GCM", iv: t, additionalData: r, tagLength: 128}, i, n))
    }
    async function z(e, t, n, r) {
        const i = await crypto.subtle.importKey("raw", e, {name: "AES-GCM"}, !1, ["decrypt"]);
        return new Uint8Array(await crypto.subtle.decrypt({name: "AES-GCM", iv: t, additionalData: r, tagLength: 128}, i, n))
    }
    function ie(e, n, r = t) {return _(e, B(r), B(n.length), n)}
    function se(e, t) {return _(e, (e => [e >> 16 & 255, e >> 8 & 255, 255 & e])(t.length), t)}
    class ae {
        constructor() {this.b = new Uint8Array(0)}
        feed(e) {this.b = W(this.b, e)}
        next() {
            if (this.b.length < 5) return null;
            const e = this.b[0], t = R(this.b, 1), n = R(this.b, 3);
            if (n > 18432) throw 0;
            if (this.b.length < 5 + n) return null;
            const r = this.b.slice(5, 5 + n);
            return this.b = this.b.slice(5 + n), {type: e, version: t, length: n, fragment: r}
        }
    }
    class he {
        constructor() {this.b = new Uint8Array(0)}
        feed(e) {this.b = W(this.b, e)}
        next() {
            if (this.b.length < 4) return null;
            const e = this.b[0], t = M(this.b, 1);
            if (this.b.length < 4 + t) return null;
            const n = this.b.slice(4, 4 + t), r = this.b.slice(0, 4 + t);
            return this.b = this.b.slice(4 + t), {type: e, length: t, body: n, raw: r}
        }
    }
    function ce(e) {
        let t = 0;
        const r = R(e, t);
        t += 2;
        const i = e.slice(t, t + 32);
        t += 32;
        const s = e[t++], a = e.slice(t, t + s);
        t += s;
        const h = R(e, t);
        t += 2;
        const c = e[t++];
        let o = r, l = null, cookie = null;
        if (t < e.length) {
            const n = R(e, t);
            t += 2;
            const r = t + n;
            for (; t + 4 <= r;) {
                const n = R(e, t);
                t += 2;
                const r = R(e, t);
                t += 2;
                const i = e.slice(t, t + r);
                if (t += r, n === C && r >= 2) {o = R(i, 0)} else if (n === T && r >= 2) {
                    const e = R(i, 0), t = r >= 4 ? R(i, 2) : 0;
                    l = {group: e, key: t ? i.slice(4, 4 + t) : P}
                } else if (44 === n && r >= 2) {cookie = i}
            }
        }
        const u = new Uint8Array([207, 33, 173, 116, 229, 154, 97, 17, 190, 29, 140, 2, 30, 101, 184, 145, 194, 162, 17, 22, 122, 187, 140, 94, 7, 158, 9, 226, 200, 168, 51, 156]);
        return {version: r, sr: i, sid: a, cs: h, comp: c, sv: o, ks: l, cookie, isHRR: N(i, u), isTls13: o === n}
    }
    function oe(e) {
        let t = 0;
        t++;
        const n = R(e, t);
        t += 2;
        const r = e[t++];
        return {nc: n, spk: e.slice(t, t + r)}
    }
    const F0 = e => {
        if (e = String(e ?? "").trim(), "[" === e[0] && "]" === e[e.length - 1] && (e = e.slice(1, -1)), !e || e.includes(":")) return "";
        const t = e.split(".");
        if (4 !== t.length) return e;
        for (const n of t) {
            if ("" === n || n.length > 3) return e;
            let t = 0;
            for (let r = 0; r < n.length; r++) {
                const i = n.charCodeAt(r) - 48;
                if (i < 0 || i > 9) return e;
                t = 10 * t + i
            }
            if (t > 255) return e
        }
        return ""
    }, Z0 = e => e && 1 === e[0] && 112 === e[1];
    function ue(e, n, r, {cookie: cookie = null, sessionId: sid = P, groups: supportedGroups = null} = {}) {
        n = F0(n);
        const c = [4865, 4866, 49199, 49200, 49195, 49196];
        const o = _(...c.flatMap(B)), l = [_(255, 1, 0, 1, 0)];
        if (n) {
            const e = L.encode(n), t = _(0, B(e.length), e);
            l.push(_(B(v), B(t.length + 2), B(t.length), t))
        }
        l.push(_(B(S), 0, 2, 1, 0));
        const groups = supportedGroups?.filter(e => I.has(e)) || [];
        if (!groups.length) r?.x25519 && groups.push(29), r?.p256 && groups.push(23), r instanceof Uint8Array && groups.push(23);
        if (!groups.length) throw 0;
        const groupBytes = _(...groups.flatMap(B));
        l.push(_(B(A), B(groupBytes.length + 2), B(groupBytes.length), groupBytes));
        const f = _(...x.flatMap(B));
        l.push(_(B(m), B(f.length + 2), B(f.length), f));
        cookie?.length && l.push(_(B(44), B(cookie.length), cookie));
        if (r) {
            let e;
            if (l.push(_(B(C), 0, 5, 4, 3, 4, 3, 3)), l.push(_(B(H), 0, 2, 1, 1)), r?.x25519 && r?.p256) {e = W(_(0, 29, B(r.x25519.length), r.x25519), _(0, 23, B(r.p256.length), r.p256))} else if (r?.x25519) {e = _(0, 29, B(r.x25519.length), r.x25519)} else if (r?.p256) {e = _(0, 23, B(r.p256.length), r.p256)} else {
                if (!(r instanceof Uint8Array)) throw 0;
                e = _(0, 23, B(r.length), r)
            }
            l.push(_(B(T), B(e.length + 2), B(e.length), e))
        }
        const y = W(...l);
        return se(h, _(B(t), e, sid.length, sid, B(o.length), o, 1, 0, B(y.length), y))
    }
    const ye = e => {
        const t = new Uint8Array(8);
        return new DataView(t.buffer).setBigUint64(0, e, !1), t
    }, pe = (e, t) => {
        const n = e.slice(), r = ye(t);
        for (let e = 0; e < 8; e++) n[n.length - 8 + e] ^= r[e];
        return n
    }, we = (e, t, n, r) => Promise.all([O(e, t, "key", P, n), O(e, t, "iv", P, r)]), de = e => {
        let t = e.length - 1;
        for (; t >= 0 && 0 === e[t];) t--;
        if (t < 0) throw 0;
        return {data: e.slice(0, t), type: e[t]}
    }, ge = 0xffffffffffffffffn;
    class TlsClient {
        constructor(e, t = {}) {this.sk = e, this.sn = t.serverName || "", this.cr = D(32), this.sid = D(32), this.sr = null, this.hk = [], this.hc = !1, this.cs = null, this.cc = null, this.is13 = !1, this.ms = null, this.hs = null, this.cwk = null, this.swk = null, this.cwi = null, this.swi = null, this.chk = null, this.shk = null, this.chi = null, this.shi = null, this.cak = null, this.sak = null, this.cai = null, this.sai = null, this.cats = null, this.sats = null, this.csn = 0n, this.ssn = 0n, this.rp = new ae, this.hp = new he, this.kps = new Map, this.ekp = null, this.pq = [], this.rr = [], this.closed = !1, this.closing = !1, this.failed = !1, this.wq = Promise.resolve(), this.cp = null, this.rb = new Uint8Array(65536)}
        rh(e) {this.hk.push(e)}
        ts() {return 1 === this.hk.length ? this.hk[0] : W(...this.hk)}
        gfc(e) {return U.get(e) || null}
        fc() {
            if (this.csn > ge) throw 0;
            return this.csn++
        }
        fs() {
            if (this.ssn > ge) throw 0;
            return this.ssn++
        }
        fail() {
            this.failed = !0, this.closed = !0;
            try {this.sk.close()} catch {}
        }
        async rc(e, b) {
            let t;
            const n = b ? e.read(b) : e.read(), r = await Promise.race([n, new Promise(e => t = setTimeout(e, 3e4, 0))]).finally(() => clearTimeout(t));
            if (r) return r;
            try {await e.cancel("err")} catch {}
            try {await n} catch {}
            throw 0
        }
        async pr(e, t, n) {
            for (; ;) {
                let r;
                for (; r = this.rp.next();) if (await t(r)) return;
                const {value: i, done: s} = await this.rc(e);
                if (s) throw 0;
                this.rp.feed(i)
            }
        }
        async ph(e, t, n) {
            for (let e; e = this.hp.next();) if (await t(e)) return;
            return this.pr(e, async e => {
                if (e.type === i) {
                    if (Z0(e.fragment)) return;
                    throw 0
                }
                if (e.type === s) {
                    this.hp.feed(e.fragment);
                    for (let e; e = this.hp.next();) if (await t(e)) return 1
                }
            }, n)
        }
        clearHandshakeState() {
            this.cr = this.sid = this.sr = this.hk = this.ms = this.hs = this.chk = this.shk = this.chi = this.shi = this.ekp = null;
            this.kps?.clear(), this.kps = null
        }
        async handshake() {
            const [t, n] = await Promise.allSettled([F("P-256"), F("X25519")]);
            this.kps = new Map, "fulfilled" === t.status && this.kps.set(23, t.value), "fulfilled" === n.status && this.kps.set(29, n.value);
            if (!this.kps.size) throw 0;
            this.ekp = (this.kps.get(23) || this.kps.get(29)).kp;
            const r = this.sk.readable.getReader(), a = this.sk.writable.getWriter();
            try {
                const shares = {x25519: this.kps.get(29)?.pk, p256: this.kps.get(23)?.pk};
                const supportedGroups = [29, 23].filter(e => this.kps.has(e));
                const h = ue(this.cr, this.sn, shares, {sessionId: this.sid, groups: supportedGroups});
                this.rh(h), await a.write(ie(s, h, e));
                let o = await this.rsh(r);
                if (o.isHRR) {
                    const group = o.ks?.group;
                    if (!I.has(group)) throw 0;
                    const kp = await F(I.get(group));
                    this.kps.set(group, kp), this.ekp = kp.kp;
                    const digest = await G(this.cc.hash, h);
                    this.hk = [se(254, digest), this.hk[this.hk.length - 1]];
                    const retryShares = 29 === group ? {x25519: kp.pk} : {p256: kp.pk};
                    const retry = ue(this.cr, this.sn, retryShares, {cookie: o.cookie, sessionId: this.sid, groups: supportedGroups});
                    this.rh(retry), await a.write(ie(s, retry, e)), o = await this.rsh(r);
                    if (o.isHRR) throw 0
                }
                if (o.ks?.group && this.kps.has(o.ks.group)) {
                    const e = this.kps.get(o.ks.group);
                    this.ekp = e.kp
                }
                o.isTls13 ? await this.h13(r, a, o) : await this.h12(r, a), this.hc = !0, this.clearHandshakeState()
            } finally {r.releaseLock(), a.releaseLock()}
        }
        async rsh(e) {
            for (; ;) {
                const {value: t, done: n} = await this.rc(e);
                if (n) throw 0;
                let r;
                for (this.rp.feed(t); r = this.rp.next();) {
                    if (r.type === i) {
                        if (Z0(r.fragment)) continue;
                        throw 0
                    }
                    if (r.type !== s) continue;
                    let e;
                    for (this.hp.feed(r.fragment); e = this.hp.next();) {
                        if (e.type !== c) continue;
                        this.rh(e.raw);
                        const t = ce(e.body), n = this.gfc(t.cs);
                        if (!n || t.comp || t.isTls13 !== !!n.tls13 || !t.isTls13 && t.sv !== 771) throw 0;
                        return this.sr = t.sr, this.cs = t.cs, this.cc = n, this.is13 = t.isTls13, t
                    }
                }
            }
        }
        async h12(e, t) {
            let n = null, a = !1, certRequested = !1;
            if (await this.ph(e, async e => {
                switch (e.type) {
                    case f: {
                        this.rh(e.raw);
                        break
                    }
                    case u:
                        this.rh(e.raw), n = oe(e.body);
                        break;
                    case p:
                        return this.rh(e.raw), a = !0, 1;
                    case y:
                        this.rh(e.raw), certRequested = !0;
                        break;
                    default:
                        this.rh(e.raw)
                }
            }, "err"), !a) {throw 0}
            if (!n) throw 0;
            const h = I.get(n.nc);
            if (!h) throw 0;
            const c = this.kps.get(n.nc);
            if (!c) throw 0;
            if (certRequested) {
                const emptyCert = se(f, _(0, 0, 0));
                this.rh(emptyCert), await t.write(ie(s, emptyCert))
            }
            const o = await Y(c.kp.privateKey, n.spk, h), l = se(d, _(c.pk.length, c.pk));
            this.rh(l);
            const w = this.cc.hash;
            this.ms = await V(o, "master secret", W(this.cr, this.sr), 48, w);
            const k = this.cc.keyLen, v = this.cc.ivLen, A = await V(this.ms, "key expansion", W(this.sr, this.cr), 2 * k + 2 * v, w);
            this.cwk = A.slice(0, k), this.swk = A.slice(k, 2 * k), this.cwi = A.slice(2 * k, 2 * k + v), this.swi = A.slice(2 * k + v, 2 * k + 2 * v), await t.write(ie(s, l)), await t.write(ie(r, _(1)));
            const S = await V(this.ms, "client finished", await G(w, this.ts()), 12, w), m = se(g, S);
            this.rh(m), await t.write(ie(s, await this.e12(m, s)));
            let b = !1;
            await this.pr(e, async e => {
                if (e.type === i) {
                    if (Z0(e.fragment)) return;
                    throw 0
                }
                if (e.type === r) return void (b = !0);
                if (e.type !== s || !b) return;
                const t = await this.d12(e.fragment, s);
                if (t[0] !== g) return;
                const n = M(t, 1), a = t.slice(4, 4 + n), h = await V(this.ms, "server finished", await G(w, this.ts()), 12, w);
                if (!N(a, h)) throw 0;
                return 1
            }, "err")
        }
        async h13(e, t, n) {
            const h = I.get(n.ks?.group);
            if (!h || !n.ks?.key?.length) throw 0;
            const c = this.cc.hash, o = q(c), u = this.cc.keyLen, p = this.cc.ivLen, d = await Y(this.ekp.privateKey, n.ks.key, h), k = await X(c, null, new Uint8Array(o)), v = await O(c, k, "derived", await G(c, P), o);
            this.hs = await X(c, v, d);
            const A = await G(c, this.ts()), S = await O(c, this.hs, "c hs traffic", A, o), m = await O(c, this.hs, "s hs traffic", A, o);
            [this.chk, this.chi] = await we(c, S, u, p), [this.shk, this.shi] = await we(c, m, u, p);
            const b = await O(c, m, "finished", P, o);
            let C = !1, certRequested = !1;
            const H = async e => {
                switch (e.type) {
                    case l: {
                        this.rh(e.raw);
                        break
                    }
                    case f: {
                        this.rh(e.raw);
                        break
                    }
                    case y:
                        this.rh(e.raw), certRequested = !0;
                        break;
                    case w:
                        this.rh(e.raw);
                        break;
                    case g: {
                        const t = await $(c, b, await G(c, this.ts()));
                        if (!N(t, e.body)) throw 0;
                        this.rh(e.raw), C = !0;
                        break
                    }
                    default:
                        this.rh(e.raw)
                }
            };
            await this.pr(e, async e => {
                if (e.type === r || e.type === s) return;
                if (e.type === i) {
                    if (Z0(e.fragment)) return;
                    throw 0
                }
                if (e.type !== a) return;
                const {data: t, type: n} = await this.d13h(e.fragment), h = t;
                if (n === s) {
                    this.hp.feed(h);
                    for (let e; e = this.hp.next();) if (await H(e), C) return 1
                }
            }, "err");
            const T = await G(c, this.ts()), E = await O(c, this.hs, "derived", await G(c, P), o), L = await X(c, E, new Uint8Array(o)), K = await O(c, L, "c ap traffic", T, o), U = await O(c, L, "s ap traffic", T, o);
            this.cats = K, this.sats = U, [this.cak, this.cai] = await we(c, K, u, p), [this.sak, this.sai] = await we(c, U, u, p);
            let clientCert = P;
            if (certRequested) clientCert = se(f, _(0, 0, 0, 0)), this.rh(clientCert);
            const x = await O(c, S, "finished", P, o), _ = await $(c, x, await G(c, this.ts())), B = se(g, _);
            this.rh(B), await t.write(ie(a, await this.e13h(W(clientCert, B, [s])))), this.csn = 0n, this.ssn = 0n
        }
        async e12(e, n, r = this.fc()) {
            const i = ye(r), s = W(i, [n], B(t), B(e.length));
            const a = i;
            return W(a, await j(this.cwk, W(this.cwi, a), e, s))
        }
        async d12(e, n, r = this.fs()) {
            const i = ye(r);
            const s = e.slice(0, 8), a = e.slice(8);
            return z(this.swk, W(this.swi, s), a, W(i, [n], B(t), B(a.length - 16)))
        }
        async e13h(e) {
            const t = pe(this.chi, this.fc()), n = _(a, 3, 3, B(e.length + 16));
            return j(this.chk, t, e, n)
        }
        async d13h(e) {
            const t = pe(this.shi, this.fs()), n = _(a, 3, 3, B(e.length)), r = await z(this.shk, t, e, n);
            return de(r)
        }
        async e13(e, n = this.fc(), r = a) {
            const t = W(e, [r]), i = pe(this.cai, n), s = _(a, 3, 3, B(t.length + 16));
            return j(this.cak, i, t, s)
        }
        async d13(e, n = this.fs(), r = this.sak, i = this.sai) {
            const s = pe(i, n), h = _(a, 3, 3, B(e.length)), c = await z(r, s, e, h);
            return de(c)
        }
        write(e) {
            if (!this.hc || this.failed || this.closing) return Promise.reject(0);
            const t = this.wq.then(() => this._write(e)), n = t.catch(e => {
                this.fail();
                throw e
            });
            return this.wq = n.catch(() => {}), n
        }
        async _write(e) {
            if (this.failed || this.closing) throw 0;
            const t = this.sk.writable.getWriter();
            try {
                if (e.length <= 16384) {
                    await t.write(ie(a, this.is13 ? await this.e13(e) : await this.e12(e, a)));
                } else {
                    for (let n = 0; n < e.length;) {
                        const r = [];
                        for (let i = 0; i < 8 && n < e.length; i++, n += 16384) {
                            const i = e.subarray(n, Math.min(n + 16384, e.length)), s = this.fc();
                            r.push(this.is13 ? this.e13(i, s).then(e => ie(a, e)) : this.e12(i, a, s).then(e => ie(a, e)))
                        }
                        await t.write(W(...await Promise.all(r)))
                    }
                }
            } finally {t.releaseLock();}
        }
        read() {
            if (this.failed) return Promise.reject(0);
            return this._read().catch(e => {
                this.fail();
                throw e
            })
        }
        async _read() {
            for (; ;) {
                if (this.pq.length) return this.pq.shift();
                if (this.closed) return null;
                const e = [];
                let n;
                for (; e.length < 8 && (n = this.rr.length ? this.rr.shift() : this.rp.next());) {
                    if (this.is13) {
                        if (n.type === r) continue;
                        if (n.type !== a) throw 0
                    } else if (n.type !== a && n.type !== i && n.type !== s) throw 0;
                    e.push(n)
                }
                if (e.length) {
                    if (!this.is13) {
                        const t = this.ssn;
                        if (t + BigInt(e.length - 1) > ge) throw 0;
                        const n = await Promise.all(e.map((e, n) => this.d12(e.fragment, e.type, t + BigInt(n))));
                        this.ssn = t + BigInt(e.length);
                        for (let t = 0; t < n.length; t++) this.pt(n[t], e[t].type)
                    } else {
                        const t = this.ssn, n = this.sak, r = this.sai;
                        if (t + BigInt(e.length - 1) > ge) throw 0;
                        let i;
                        try {
                            i = await Promise.all(e.map((e, i) => this.d13(e.fragment, t + BigInt(i), n, r)));
                        } catch {
                            i = null
                        }
                        if (i) {
                            for (let n = 0; n < i.length; n++) {
                                this.ssn = t + BigInt(n + 1);
                                const r = await this.p13(i[n]);
                                if (null !== r) {
                                    n + 1 < e.length && this.rr.unshift(...e.slice(n + 1));
                                    const t = 1 === r ? this.qku() : null;
                                    await this.usr();
                                    t && await t;
                                    break
                                }
                            }
                        } else {
                            for (let n = 0; n < e.length; n++) {
                                const r = await this.d13(e[n].fragment, this.ssn);
                                this.ssn++;
                                const i = await this.p13(r);
                                if (null !== i) {
                                    n + 1 < e.length && this.rr.unshift(...e.slice(n + 1));
                                    const t = 1 === i ? this.qku() : null;
                                    await this.usr();
                                    t && await t;
                                    break
                                }
                            }
                        }
                    }
                    if (this.pq.length) return this.pq.shift();
                    if (this.closed) return null;
                    continue
                }
                if (this.closed) return null;
                const t = this.sk.readable.getReader({mode: "byob"});
                try {
                    const {value: e, done: n} = await this.rc(t, this.rb);
                    if (n) return null;
                    if (e.length > 49152) {
                        this.rp.feed(e.subarray());
                        this.rb = new Uint8Array(65536);
                    } else {
                        this.rp.feed(e.slice());
                        this.rb = new Uint8Array(e.buffer);
                    }
                } finally {t.releaseLock()}
            }
        }
        pt(e, t) {
            if (t === a) {
                this.pq.push(e);
            } else if (t === i) {
                this.pa(e);
            } else if (t === s) {
                let t;
                for (this.hp.feed(e); t = this.hp.next();) {}
            }
        }
        pa(e) {
            this.closed = !0, this.close()
        }
        async p13({data: e, type: t}) {
            if (t === a) return this.pq.push(e), null;
            if (t === i) return this.pa(e), null;
            if (t !== s) return null;
            let n, r = null;
            for (this.hp.feed(e); n = this.hp.next();) {
                if (n.type === o) continue;
                if (n.type === k) {
                    if (1 !== n.body.length || n.body[0] > 1 || null !== r) continue;
                    r = n.body[0]
                }
            }
            return r
        }
        async usr() {
            const e = this.cc.hash, t = q(e);
            this.sats = await O(e, this.sats, "traffic upd", P, t), [this.sak, this.sai] = await we(e, this.sats, this.cc.keyLen, this.cc.ivLen), this.ssn = 0n
        }
        qku() {
            const e = this.wq.then(() => this.sku()), t = e.catch(e => {
                this.fail();
                throw e
            });
            return this.wq = t.catch(() => {}), t
        }
        async sku() {
            if (this.failed || this.closing) throw 0;
            const e = this.sk.writable.getWriter();
            try {
                const t = se(k, _(0));
                await e.write(ie(a, await this.e13(t, this.fc(), s)))
            } finally {e.releaseLock()}
            const t = this.cc.hash, n = q(t);
            this.cats = await O(t, this.cats, "traffic upd", P, n), [this.cak, this.cai] = await we(t, this.cats, this.cc.keyLen, this.cc.ivLen), this.csn = 0n
        }
        close() {
            if (this.cp) return this.cp;
            if (this.failed || !this.hc) {
                try {this.sk.close()} catch {}
                return this.cp = Promise.resolve()
            }
            this.closing = !0;
            const e = this.wq.then(async () => {
                const e = this.sk.writable.getWriter();
                try {
                    const t = _(1, E), n = this.is13 ? await this.e13(t, this.fc(), i) : await this.e12(t, i);
                    await e.write(ie(this.is13 ? a : i, n))
                } finally {e.releaseLock()}
            });
            return this.cp = e.catch(() => {}).finally(() => {
                this.closed = !0;
                try {this.sk.close()} catch {}
            }), this.wq = this.cp, this.cp
        }
    }
    return {TlsClient};
})();
const tlsStreamAdapter = (tls, initial = new Uint8Array(0)) => ({
    readable: {
        getReader() {
            let leftOver = initial;
            return {
                async read(view) {
                    if (leftOver.length) {
                        const len = Math.min(leftOver.length, view.byteLength);
                        view.set(leftOver.subarray(0, len));
                        leftOver = leftOver.subarray(len);
                        return {done: false, value: new Uint8Array(view.buffer, view.byteOffset, len)};
                    }
                    const data = await tls.read();
                    if (!data) return {done: true};
                    const len = Math.min(data.length, view.byteLength);
                    view.set(data.subarray(0, len));
                    if (data.length > len) leftOver = data.subarray(len);
                    return {done: false, value: new Uint8Array(view.buffer, view.byteOffset, len)};
                },
                releaseLock() {}
            };
        }
    },
    writable: new WritableStream({write(chunk) {return tls.write(chunk)}, close() {tls.close()}, abort() {tls.close()}})
});
const staticHeaders = `User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36\r\nProxy-Connection: Keep-Alive\r\nConnection: Keep-Alive\r\n\r\n`;
const encodedStaticHeaders = textEncoder.encode(staticHeaders);
const connectViaHttpProxy = async (targetAddrType, targetPortNum, httpAuth, addrBytes, limit, useTls = false) => {
    const {username, password, hostname, port} = httpAuth;
    let proxySocket, tlsClient = null, isCustomTls = false;
    const proxyIsIp = addrTypeIs(hostname) !== 3;
    if (useTls && proxyIsIp) {
        isCustomTls = true;
        proxySocket = await concurrentConnect(hostname, port, limit, {allowHalfOpen: false});
    } else {
        try {
            proxySocket = await concurrentConnect(hostname, port, limit, useTls ? {secureTransport: 'on', allowHalfOpen: false} : undefined);
        } catch {
            if (!useTls) return null;
            isCustomTls = true;
            proxySocket = await concurrentConnect(hostname, port, limit, {allowHalfOpen: false});
        }
    }
    if (isCustomTls) {
        try {
            tlsClient = new TlsClient(proxySocket, {serverName: proxyIsIp ? "" : hostname});
            await tlsClient.handshake();
        } catch {
            try {proxySocket.close()} catch {}
            return null;
        }
    }
    const httpHost = binaryAddrToString(targetAddrType, addrBytes);
    let dynamicHeaders = `CONNECT ${httpHost}:${targetPortNum} HTTP/1.1\r\nHost: ${httpHost}:${targetPortNum}\r\n`;
    if (username) dynamicHeaders += `Proxy-Authorization: Basic ${btoa(`${username}:${password || ''}`)}\r\n`;
    const fullHeaders = new Uint8Array(dynamicHeaders.length * 3 + encodedStaticHeaders.length);
    const {written} = textEncoder.encodeInto(dynamicHeaders, fullHeaders);
    fullHeaders.set(encodedStaticHeaders, written);
    const reqData = fullHeaders.subarray(0, written + encodedStaticHeaders.length);
    try {
        if (isCustomTls) {
            await tlsClient.write(reqData);
        } else {
            const writer = proxySocket.writable.getWriter();
            await writer.write(reqData);
            writer.releaseLock();
        }
    } catch {
        isCustomTls ? tlsClient.close() : proxySocket.close();
        return null;
    }
    const buffer = new Uint8Array(4096);
    let bytesRead = 0, statusChecked = false;
    const reader = isCustomTls ? null : proxySocket.readable.getReader();
    try {
        while (bytesRead < buffer.length) {
            const res = isCustomTls ? {value: await tlsClient.read()} : await reader.read();
            const value = res.value;
            if (!value) return null;
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
                    if (!isCustomTls) reader.releaseLock();
                    return isCustomTls ? tlsStreamAdapter(tlsClient, buffer.subarray(i + 4, bytesRead)) : proxySocket;
                }
                i++;
            }
        }
    } catch {}
    isCustomTls ? tlsClient.close() : proxySocket.close();
    return null;
};
const magic = new Uint8Array([0x21, 0x12, 0xA4, 0x42]);
const cat = (...a) => {
    let len = 0, i = 0, o = 0;
    for (; i < a.length; i++) len += a[i].length;
    const r = new Uint8Array(len);
    for (i = 0; i < a.length; i++) {
        r.set(a[i], o);
        o += a[i].length;
    }
    return r;
};
const stunAttr = (t, v) => {
    const l = v.length, b = new Uint8Array(4 + l + (4 - l % 4) % 4);
    b[0] = t >> 8, b[1] = t & 0xff, b[2] = l >> 8, b[3] = l & 0xff, b.set(v, 4);
    return b;
};
const stunMsg = (t, tid, a) => {
    const bd = cat(...a), l = bd.length, h = new Uint8Array(20 + l);
    h[0] = t >> 8, h[1] = t & 0xff, h[2] = l >> 8, h[3] = l & 0xff, h.set(magic, 4), h.set(tid, 8), h.set(bd, 20);
    return h;
};
const xorPeer = (ip, port) => {
    const b = new Uint8Array(8);
    b[1] = 1;
    const xp = port ^ 0x2112;
    b[2] = xp >> 8, b[3] = xp & 0xff;
    let p = 0, num = 0;
    for (let i = 0; i < ip.length; i++) {
        const c = ip.charCodeAt(i);
        if (c === 46) {
            b[4 + p] = num ^ magic[p++];
            num = 0;
        } else {num = num * 10 + (c - 48)}
    }
    b[4 + p] = num ^ magic[p];
    return b;
};
const parseStun = d => {
    if (d.length < 20 || magic.some((v, i) => d[4 + i] !== v)) return null;
    const ml = (d[2] << 8) | d[3], attrs = {};
    for (let o = 20; o + 4 <= 20 + ml;) {
        const t = (d[o] << 8) | d[o + 1], l = (d[o + 2] << 8) | d[o + 3];
        if (o + 4 + l > d.length) break;
        attrs[t] = d.subarray(o + 4, o + 4 + l);
        o += 4 + l + (4 - l % 4) % 4;
    }
    return {type: (d[0] << 8) | d[1], attrs};
};
const parseErr = d => d?.length >= 4 ? (d[2] & 7) * 100 + d[3] : 0;
const addIntegrity = async (m, cryptoKey) => {
    const l = m.length, c = new Uint8Array(l + 24);
    c.set(m);
    const nl = (m[2] << 8 | m[3]) + 24;
    c[2] = nl >> 8, c[3] = nl & 0xff;
    const sig = new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, c.subarray(0, l)));
    c[l] = 0x00, c[l + 1] = 0x08, c[l + 2] = 0x00, c[l + 3] = 0x14, c.set(sig, l + 4);
    return c;
};
const readStun = async (rd, buf) => {
    let chunks = buf && buf.length ? [buf] : [];
    let total = buf ? buf.length : 0;
    const pull = async () => {
        const {done, value} = await rd.read();
        if (done) throw 0;
        chunks.push(value);
        total += value.length;
    };
    const getB = () => {
        if (chunks.length === 1) return chunks[0];
        const b = new Uint8Array(total);
        let o = 0;
        for (let i = 0; i < chunks.length; i++) {
            b.set(chunks[i], o);
            o += chunks[i].length;
        }
        chunks = [b];
        return b;
    };
    try {
        while (total < 20) await pull();
        let b = getB();
        if (b[4] !== 0x21 || b[5] !== 0x12 || b[6] !== 0xA4 || b[7] !== 0x42) return null;
        const n = 20 + ((b[2] << 8) | b[3]);
        if (n > 8192) return null;
        while (total < n) await pull();
        b = getB();
        return [parseStun(b.subarray(0, n)), total > n ? b.subarray(n) : null];
    } catch {return null}
};
const md5 = async s => new Uint8Array(await crypto.subtle.digest('MD5', textEncoder.encode(s)));
const connectViaTurnProxy = async ({hostname, port, username, password}, targetIp, targetPort, useTls = false) => {
    let ctrl = null, data = null, dataPromise = null, ctrlTls = null, dataTls = null;
    const proxyIsIp = addrTypeIs(hostname) !== 3;
    const close = () => [ctrl, data, ctrlTls, dataTls].forEach(s => {try {s?.close()} catch {}});
    const createConn = async () => {
        let sock, tls = null, isCustom = false;
        if (useTls && proxyIsIp) {
            isCustom = true;
            sock = await createConnect(hostname, port, {allowHalfOpen: false});
        } else {
            try {
                sock = await createConnect(hostname, port, useTls ? {secureTransport: 'on', allowHalfOpen: false} : undefined);
            } catch {
                if (!useTls) throw 0;
                isCustom = true;
                sock = await createConnect(hostname, port, {allowHalfOpen: false});
            }
        }
        if (isCustom) {
            tls = new TlsClient(sock, {serverName: proxyIsIp ? "" : hostname});
            await tls.handshake();
        }
        return {sock, tls, isCustom};
    };
    try {
        const cRes = await createConn();
        ctrl = cRes.sock;
        ctrlTls = cRes.tls;
        const cIsCustom = cRes.isCustom;
        const cw = cIsCustom ? {write: c => ctrlTls.write(c), releaseLock: () => {}} : ctrl.writable.getWriter();
        const cr = cIsCustom ? {
            read: async () => {
                const v = await ctrlTls.read();
                return v ? {value: v, done: false} : {done: true};
            },
            releaseLock: () => {}
        } : ctrl.readable.getReader();
        const tidBuf = new Uint8Array(12), tid = () => crypto.getRandomValues(tidBuf), tp = new Uint8Array([6, 0, 0, 0]);
        await cw.write(stunMsg(0x003, tid(), [stunAttr(0x019, tp)]));
        let [r, ex] = await readStun(cr);
        if (!r) throw 0;
        let cryptoKey = null, aa = [];
        const sign = m => cryptoKey ? addIntegrity(m, cryptoKey) : m;
        const peer = stunAttr(0x012, xorPeer(targetIp, targetPort));
        if (r.type === 0x113 && username && parseErr(r.attrs[0x009]) === 401) {
            const realm = textDecoder.decode(r.attrs[0x014] ?? []), nonce = r.attrs[0x015] ?? [];
            const keyBytes = await md5(`${username}:${realm}:${password}`);
            cryptoKey = await crypto.subtle.importKey('raw', keyBytes, {name: 'HMAC', hash: 'SHA-1'}, false, ['sign']);
            aa = [stunAttr(0x006, textEncoder.encode(username)), stunAttr(0x014, textEncoder.encode(realm)), stunAttr(0x015, nonce)];
            const [am, pm, cm] = await Promise.all([
                sign(stunMsg(0x003, tid(), [stunAttr(0x019, tp), ...aa])),
                sign(stunMsg(0x008, tid(), [peer, ...aa])),
                sign(stunMsg(0x00A, tid(), [peer, ...aa]))
            ]);
            await cw.write(cat(am, pm, cm));
            dataPromise = createConn();
            [r, ex] = await readStun(cr, ex);
            if (r?.type !== 0x103) throw 0;
        } else if (r.type === 0x103) {
            const [pm, cm] = await Promise.all([
                sign(stunMsg(0x008, tid(), [peer, ...aa])),
                sign(stunMsg(0x00A, tid(), [peer, ...aa]))
            ]);
            await cw.write(cat(pm, cm));
            dataPromise = createConn();
        } else {throw 0}
        [r, ex] = await readStun(cr, ex);
        if (r?.type !== 0x108) throw 0;
        [r] = await readStun(cr, ex);
        if (r?.type !== 0x10A || !r.attrs[0x02A]) throw 0;
        const dRes = await dataPromise;
        data = dRes.sock;
        dataTls = dRes.tls;
        const dIsCustom = dRes.isCustom;
        const dw = dIsCustom ? {write: c => dataTls.write(c), releaseLock: () => {}} : data.writable.getWriter();
        const dr = dIsCustom ? {
            read: async () => {
                const v = await dataTls.read();
                return v ? {value: v, done: false} : {done: true};
            },
            releaseLock: () => {}
        } : data.readable.getReader();
        await dw.write(await sign(stunMsg(0x00B, tid(), [stunAttr(0x02A, r.attrs[0x02A]), ...aa])));
        let extra;
        [r, extra] = await readStun(dr);
        if (r?.type !== 0x10B) throw 0;
        if (!cIsCustom) cr.releaseLock(), cw.releaseLock();
        if (!dIsCustom) dr.releaseLock(), dw.releaseLock();
        const tlsStream = dIsCustom ? tlsStreamAdapter(dataTls) : null;
        const readable = tlsStream ? tlsStream.readable : data.readable;
        const writable = tlsStream ? tlsStream.writable : data.writable;
        return {readable, writable, close, extra};
    } catch {
        close();
        return null;
    }
};
const ipv4ToNat64Ipv6 = (ipv4Address, nat64Prefixes) => {
    const parts = ipv4Address.split('.');
    let hexStr = "";
    for (let i = 0; i < 4; i++) {
        let h = (parts[i] | 0).toString(16);
        hexStr += (h.length === 1 ? "0" + h : h);
        if (i === 1) hexStr += ":";
    }
    return `[${nat64Prefixes}${hexStr}]`;
};
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
const createDnsWriter = (state, writable, close, closeAfterResponse) => {
    let pending = emptyU8, closed = false;
    const sendDnsResponse = async (dnsPack) => {
        if (state.ssOutbound) {
            if (state.ssResponseSalt) {
                writable.send(state.ssResponseSalt);
                state.ssResponseSalt = null;
            }
            const encryptedDns = await ssAeadEncryptChunks(state.ssOutbound, dnsPack);
            if (encryptedDns.byteLength) writable.send(encryptedDns);
        } else {
            writable.send(dnsPack);
        }
    };
    return async (chunk) => {
        if (closed || !chunk?.byteLength) return;
        chunk = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
        let buf = chunk;
        if (pending.byteLength) {
            buf = new Uint8Array(pending.byteLength + chunk.byteLength);
            buf.set(pending);
            buf.set(chunk, pending.byteLength);
            pending = emptyU8;
        }
        let offset = 0;
        while (buf.byteLength - offset >= 2) {
            const dnsLen = (buf[offset] << 8) | buf[offset + 1];
            const end = offset + 2 + dnsLen;
            if (buf.byteLength < end) break;
            const dnsPack = await dohDnsHandler(buf.subarray(offset, end));
            if (dnsPack?.byteLength) await sendDnsResponse(dnsPack);
            offset = end;
            if (closeAfterResponse) {
                closed = true;
                close();
                return;
            }
        }
        if (offset < buf.byteLength) pending = buf.slice(offset);
    };
};
const connectNat64 = async (addrType, port, nat64Auth, addrBytes, proxyAll, limit, isHttp) => {
    const nat64Prefixes = nat64Auth.charCodeAt(0) === 91 ? nat64Auth.slice(1, -1) : nat64Auth;
    if (!proxyAll) return concurrentConnect(`[${nat64Prefixes}6815:3598]`, port, limit);
    const hostname = binaryAddrToString(addrType, addrBytes);
    if (isHttp) addrType = addrTypeIs(hostname);
    if (addrType === 3) {
        const answer = await concurrentDnsResolve(hostname, 'A');
        const aRecord = answer?.find(record => record.type === 1);
        return aRecord ? concurrentConnect(ipv4ToNat64Ipv6(aRecord.data, nat64Prefixes), port, limit) : null;
    }
    if (addrType === 1) return concurrentConnect(ipv4ToNat64Ipv6(hostname, nat64Prefixes), port, limit);
    return concurrentConnect(hostname, port, limit);
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
        let settled = false, winner = null;
        const sockets = new Array(resolvedIps.length);
        const closeSocket = socket => {try {socket?.close()} catch {}};
        const connectionPromises = resolvedIps.map((ip, i) => {
            const [host, port] = parseHostPort(ip, 443);
            const socket = connect({hostname: host, port});
            sockets[i] = socket;
            return createConnect(host, port, undefined, socket).then(openedSocket => {
                if (settled && openedSocket !== winner) closeSocket(openedSocket);
                return openedSocket;
            });
        });
        return await Promise.any(connectionPromises).then(socket => {
            settled = true, winner = socket;
            for (const other of sockets) if (other !== socket) closeSocket(other);
            return socket;
        }, err => {
            settled = true;
            for (const socket of sockets) closeSocket(socket);
            throw err;
        });
    }
    const [host, port] = parseHostPort(param, 443);
    return concurrentConnect(host, port, limit);
};
const strategyExecutorMap = new Map([
    [0, async ({addrType, port, addrBytes}, _param, _limit, _txt) => {
        const hostname = binaryAddrToString(addrType, addrBytes);
        return concurrentConnect(hostname, port);
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
    }],
    [4, async ({addrType, port, addrBytes, isHttp}, param, limit, _txt) => {
        const {nat64Auth, proxyAll} = param;
        return connectNat64(addrType, port, nat64Auth, addrBytes, proxyAll, limit, isHttp);
    }],
    [5, async ({addrType, port, addrBytes, isHttp}, param, _limit, _txt) => {
        let targetIp = binaryAddrToString(addrType, addrBytes);
        if (isHttp) addrType = addrTypeIs(targetIp);
        if (addrType === 3) {
            const answer = await concurrentDnsResolve(targetIp, 'A');
            const aRecord = answer?.find(record => record.type === 1);
            if (!aRecord) return null;
            targetIp = aRecord.data;
        } else if (addrType === 4) {return null}
        return connectViaTurnProxy(param, targetIp, port);
    }],
    [7, async ({addrType, port, addrBytes, isHttp}, param, _limit, _txt) => {
        let targetIp = binaryAddrToString(addrType, addrBytes);
        if (isHttp) addrType = addrTypeIs(targetIp);
        if (addrType === 3) {
            const answer = await concurrentDnsResolve(targetIp, 'A');
            const aRecord = answer?.find(record => record.type === 1);
            if (!aRecord) return null;
            targetIp = aRecord.data;
        } else if (addrType === 4) {return null}
        return connectViaTurnProxy(param, targetIp, port, true);
    }]
]);
const getUrlParam = (offset, len) => {
    if (len <= 0) return null;
    return textDecoder.decode(wasmMem.subarray(dataPtr + offset, dataPtr + offset + len));
};
const urlListCacheDict = new Map(), urlListCacheKeys = new Array(urlParamCacheLimit);
let urlListCacheIndex = 0;
const establishTcpConnection = async (parsedRequest, request) => {
    let u = request.url, clean = u.slice(u.indexOf('/', 10) + 1), l = clean.length, list = [], speed;
    if (l > 3 && clean.charCodeAt(l - 4) === 47 && clean.charCodeAt(l - 3) === 84 && clean.charCodeAt(l - 2) === 117 && clean.charCodeAt(l - 1) === 110) {
        clean = clean.slice(0, l - 4);
    } else {
        const c = clean.charCodeAt(l - 1);
        if (c === 47 || c === 61) clean = clean.slice(0, l - 1);
    }
    const cachedResult = urlListCacheDict.get(clean);
    if (cachedResult !== undefined) {
        list = cachedResult.list, speed = cachedResult.speed;
    } else {
        if (clean.length < 6 || clean.length > 1024) {
            list.push({type: 0}, {type: 3, param: coloToProxyMap.get(request.cf?.colo) ?? proxyIpAddrs.US}, {type: 3, param: finallyProxyHost});
        } else {
            const urlBytes = textEncoder.encode(clean);
            wasmMem.set(urlBytes, dataPtr);
            parseUrlWasm(urlBytes.length);
            const r = wasmRes;
            const s5Val = getUrlParam(r[15], r[16]), httpVal = getUrlParam(r[17], r[18]), nat64Val = getUrlParam(r[19], r[20]), turnVal = getUrlParam(r[24], r[25]), ipVal = getUrlParam(r[21], r[22]), httpsVal = getUrlParam(r[26], r[27]), txtipVal = getUrlParam(r[28], r[29]), turnsVal = getUrlParam(r[32], r[33]);
            speed = getUrlParam(r[30], r[31]);
            const proxyAll = r[23] === 1;
            !proxyAll && list.push({type: 0});
            const add = (v, t, txt) => {
                if (!v) return;
                const parts = decodeURIComponent(v).split(',').filter(Boolean);
                if (txt) {
                    for (let i = 0; i < parts.length; i++) list.push({type: t, param: parts[i], txt});
                } else if (parts.length) {
                    const parsedParams = parts.map(part => {
                        if (t === 4) return {nat64Auth: part, proxyAll};
                        if (t === 1 || t === 2 || t === 5 || t === 6 || t === 7) return parseAuthString(part);
                        return part;
                    });
                    list.push({type: t, param: parsedParams, concurrent: true});
                }
            };
            for (const k of proxyStrategyOrder) k === 'socks' ? add(s5Val, 1) : k === 'http' ? add(httpVal, 2) : k === 'https' ? add(httpsVal, 6) : k === 'turn' ? add(turnVal, 5) : k === 'turns' ? add(turnsVal, 7) : add(nat64Val, 4);
            if (proxyAll) {
                !list.length && list.push({type: 0});
            } else {
                add(ipVal, 3), add(txtipVal, 3, true);
                list.push({type: 3, param: coloToProxyMap.get(request.cf?.colo) ?? proxyIpAddrs.US}, {type: 3, param: finallyProxyHost});
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
            const sub = (list[i].concurrent && Array.isArray(list[i].param)) ? Math.max(1, Math.floor(concurrency / list[i].param.length)) : undefined;
            const socket = await (list[i].concurrent && Array.isArray(list[i].param) ? Promise.any(list[i].param.map(ip => exec(parsedRequest, ip, sub, list[i].txt))) : exec(parsedRequest, list[i].param, undefined, list[i].txt));
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
const createBufferedTcpWriter = (tcpWriter, close) => {
    const queue = new Array(2048);
    let head = 0, tail = 0, size = 0, coalesceBuffer = null, drainActive = false, closed = false;
    const closeWriter = () => {
        if (closed) return;
        closed = true;
        for (let i = 0; i < 2048; i++) queue[i] = null;
        close?.();
    };
    const drainQueue = async () => {
        if (closed) return;
        try {
            while (size > 0 && !closed) {
                let chunk = queue[head];
                if (chunk.byteLength >= maxChunkLen) {
                    queue[head] = null, head = (head + 1) & 2047, size--;
                    await tcpWriter.write(chunk);
                    continue;
                }
                let mergedLength = 0;
                coalesceBuffer ||= new Uint8Array(maxChunkLen);
                while (size > 0) {
                    chunk = queue[head];
                    if (mergedLength + chunk.byteLength > maxChunkLen) break;
                    coalesceBuffer.set(chunk, mergedLength), mergedLength += chunk.byteLength;
                    queue[head] = null, head = (head + 1) & 2047, size--;
                }
                if (mergedLength > 0) await tcpWriter.write(coalesceBuffer.subarray(0, mergedLength));
            }
        } catch {closeWriter()} finally {drainActive = false}
    };
    return chunk => {
        if (closed) return;
        const data = chunk.constructor === Uint8Array ? chunk : new Uint8Array(chunk);
        if (!data.byteLength) return;
        if (size === 2048) return closeWriter();
        queue[tail] = data, tail = (tail + 1) & 2047, size++;
        if (!drainActive) drainActive = true, queueMicrotask(drainQueue);
    };
};
const createAsyncMicrotaskQueue = (consume, close) => {
    const queue = new Array(1024);
    let head = 0, tail = 0, size = 0, drainActive = false, closed = false;
    const closeQueue = () => {
        if (closed) return;
        closed = true;
        for (let i = 0; i < 1024; i++) queue[i] = null;
        close?.();
    };
    const drainQueue = async () => {
        if (closed) return;
        try {
            while (size > 0 && !closed) {
                const chunk = queue[head];
                queue[head] = null, head = (head + 1) & 1023, size--;
                await consume(chunk);
            }
        } catch {closeQueue()} finally {drainActive = false}
    };
    return chunk => {
        if (closed) return;
        if (size === 1024) return closeQueue();
        queue[tail] = chunk, tail = (tail + 1) & 1023, size++;
        if (!drainActive) drainActive = true, queueMicrotask(drainQueue);
    };
};
const handleSession = async (chunk, state, request, writable, close, isEarlyData = false) => {
    const allowNeedMore = state.allowNeedMore === true;
    if (allowNeedMore) state.needMore = false;
    let parsedRequest, payload, isSs = false;
    const ssEnabled = !state.disableSsAead && !!config?.sspass && !state.tcpWriter && state.socks5State === 0;
    const parseLen = Math.min(chunk.length, 1024);
    wasmMem.set(chunk.subarray(0, parseLen), dataPtr);
    const success = parseProtocolWasm(parseLen, state.socks5State);
    const r = wasmRes;
    const hLen = r[12];
    if (hLen > 0) writable.send(wasmMem.slice(dataPtr, dataPtr + hLen));
    if (!success) {
        if (r[4] > 0) return state.socks5State = r[4];
        if (allowNeedMore && r[14] === 1) return state.needMore = true;
        if (ssEnabled && chunk.length >= 34) {
            try {
                const decryptCtx = await createSsAeadCtx(chunk.subarray(0, 16));
                const plain = await ssAeadDecryptFeed(decryptCtx, chunk.subarray(16));
                const plainLen = plain.length;
                if (plainLen > 0) {
                    const addrType = plain[0];
                    const addrLen = addrType === 3 ? (plainLen > 1 ? plain[1] : null) : addrType === 1 ? 4 : addrType === 4 ? 16 : -1;
                    if (addrLen !== null && addrLen > 0) {
                        const addrOffset = addrType === 3 ? 2 : 1;
                        const dataOffset = addrOffset + addrLen + 2;
                        if (plainLen >= dataOffset) {
                            const portOffset = dataOffset - 2;
                            const port = (plain[portOffset] << 8) | plain[portOffset + 1];
                            parsedRequest = {addrType, addrBytes: plain.subarray(addrOffset, addrOffset + addrLen), dataOffset, port, isDns: port === 53};
                            const encryptCtx = await createSsAeadCtx();
                            isSs = true;
                            payload = plain.subarray(dataOffset);
                            state.ssInbound = decryptCtx;
                            state.ssOutbound = encryptCtx;
                            state.ssResponseSalt = encryptCtx.salt;
                        }
                    }
                }
            } catch {}
        }
        if (!isSs) return close();
    } else {
        state.socks5State = 0;
        parsedRequest = {addrType: r[5], port: r[6], dataOffset: r[7], isDns: r[8] === 1, addrBytes: chunk.subarray(r[9], r[9] + r[10]), isHttp: r[11] === 3};
        payload = chunk.subarray(parsedRequest.dataOffset);
    }
    if (parsedRequest.isDns) {
        const dnsWriter = createDnsWriter(state, writable, close, !(isEarlyData && payload.byteLength));
        state.tcpWriter = (isSs || state.ssOutbound) ? async (c) => {
            await ssAeadDecryptFeed(state.ssInbound, c instanceof Uint8Array ? c : new Uint8Array(c), dnsWriter);
        } : dnsWriter;
        return await dnsWriter(payload);
    } else {
        const tcpResult = await establishTcpConnection(parsedRequest, request);
        if (!tcpResult) return close();
        state.tcpSocket = tcpResult.socket;
        const tcpWriter = state.tcpSocket.writable.getWriter();
        const bufferedTcpWriter = createBufferedTcpWriter(tcpWriter, close);
        if (payload.byteLength) tcpWriter.write(payload);
        if (isSs || state.ssOutbound) {
            state.tcpWriter = async (c) => {
                await ssAeadDecryptFeed(state.ssInbound, c instanceof Uint8Array ? c : new Uint8Array(c), async plain => {
                    if (plain.byteLength) bufferedTcpWriter(plain);
                });
            };
            state.ssResponseSalt?.length && writable.send(state.ssResponseSalt);
            state.ssResponseSalt = null;
            (async () => {
                const ssSendQueue = createAsyncMicrotaskQueue(async (chunk) => {
                    const encrypted = await ssAeadEncryptChunks(state.ssOutbound, chunk);
                    encrypted.byteLength && writable.send(encrypted);
                }, close);
                state.tcpSocket.extra?.length && ssSendQueue(state.tcpSocket.extra);
                await manualPipe(state.tcpSocket.readable, {
                    send: (chunk) => {
                        chunk?.byteLength && ssSendQueue(chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk));
                    }
                }, close, tcpResult.speed);
            })().catch(close);
        } else {
            state.tcpWriter = bufferedTcpWriter;
            if (state.tcpSocket.extra?.length) writable.send(state.tcpSocket.extra);
            manualPipe(state.tcpSocket.readable, writable, close, tcpResult.speed);
        }
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
    const state = {socks5State: 0, tcpWriter: null, tcpSocket: null, ssInbound: null, ssOutbound: null, ssResponseSalt: null};
    let processingQueue = null;
    const close = () => {
        try {state.tcpSocket?.close()} catch {}
        try {webSocket.close(1011, 'WebSocket is closed')} catch {}
    };
    const process = (chunk) => {
        if (state.tcpWriter) return state.tcpWriter(chunk);
        return handleSession(earlyData ? chunk : new Uint8Array(chunk), state, request, webSocket, close, earlyData !== null);
    };
    processingQueue = createAsyncMicrotaskQueue(process, close);
    if (earlyData) processingQueue(earlyData);
    webSocket.addEventListener("message", event => (state.tcpWriter || processingQueue)(event.data));
    webSocket.addEventListener("error", close);
    webSocket.addEventListener("close", close);
};
const grpcHeaders = {'Content-Type': 'application/grpc', 'X-Accel-Buffering': 'no', 'Cache-Control': 'no-store'};
const xhttpHeaders = {'Content-Type': 'application/octet-stream', 'grpc-status': '0', 'X-Accel-Buffering': 'no', 'Cache-Control': 'no-store'};
const handleGrpcPost = async (request, reader, buffer, used) => {
    const state = {socks5State: 0, tcpWriter: null, tcpSocket: null, ssInbound: null, ssOutbound: null, ssResponseSalt: null};
    let close = () => {};
    return new Response(new ReadableStream({
        start(controller) {
            close = () => {
                try {state.tcpSocket?.close()} catch {}
                try {controller.close()} catch {}
            };
            const writable = {
                send: (chunk) => {
                    const len = chunk.byteLength;
                    if (!len) return;
                    let varintLen = 1;
                    for (let v = len >>> 7; v; v >>>= 7) varintLen++;
                    const totalPayloadLen = 1 + varintLen + len;
                    const grpcFrame = new Uint8Array(5 + totalPayloadLen);
                    grpcFrame[0] = 0;
                    grpcFrame[1] = totalPayloadLen >>> 24;
                    grpcFrame[2] = totalPayloadLen >>> 16;
                    grpcFrame[3] = totalPayloadLen >>> 8;
                    grpcFrame[4] = totalPayloadLen;
                    grpcFrame[5] = 0x0A;
                    let p = 6, v = len;
                    while (v > 127) {
                        grpcFrame[p++] = (v & 0x7F) | 0x80;
                        v >>>= 7;
                    }
                    grpcFrame[p++] = v;
                    grpcFrame.set(chunk, p);
                    controller.enqueue(grpcFrame);
                }
            };
            (async () => {
                let grpcBuffer = new ArrayBuffer(73728), offset = 0;
                if (used) new Uint8Array(grpcBuffer, 0, used).set(buffer);
                while (true) {
                    const bufToProcess = new Uint8Array(grpcBuffer, 0, used), bufLen = bufToProcess.byteLength;
                    offset = 0;
                    while (bufLen - offset >= 5) {
                        const grpcLen = ((bufToProcess[offset + 1] << 24) >>> 0) | (bufToProcess[offset + 2] << 16) | (bufToProcess[offset + 3] << 8) | bufToProcess[offset + 4];
                        const frameSize = 5 + grpcLen;
                        if (bufLen - offset >= frameSize) {
                            const grpcData = bufToProcess.slice(offset + 5, offset + frameSize);
                            offset += frameSize;
                            let p = grpcData[0] === 0x0A ? 1 : 0;
                            while (p && grpcData[p++] & 0x80) ;
                            const payload = p === 0 ? grpcData : grpcData.subarray(p);
                            state.tcpWriter ? await state.tcpWriter(payload) : await handleSession(payload, state, request, writable, close);
                        } else {break}
                    }
                    if (offset < bufLen) {
                        used = bufLen - offset;
                        new Uint8Array(grpcBuffer).copyWithin(0, offset, bufLen);
                    } else {used = 0}
                    const {done, value} = await reader.read(new Uint8Array(grpcBuffer, used, 8192));
                    if (done) break;
                    grpcBuffer = value.buffer;
                    used += value.byteLength;
                }
            })().catch(close);
        }
    }), {headers: grpcHeaders});
};
const handleXhttpPost = async (request, reader, xhttpBuffer, used) => {
    const state = {socks5State: 0, tcpWriter: null, tcpSocket: null, needMore: false, allowNeedMore: true, disableSsAead: true};
    let close = () => {};
    return new Response(new ReadableStream({
        start(controller) {
            close = () => {
                try {state.tcpSocket?.close()} catch {}
                try {controller.close()} catch {}
            };
            const writable = {send: (chunk) => controller.enqueue(chunk)};
            (async () => {
                while (true) {
                    if (used > 0) {
                        const payload = new Uint8Array(xhttpBuffer, 0, used);
                        state.tcpWriter ? await state.tcpWriter(payload) : (state.needMore = false, await handleSession(payload, state, request, writable, close));
                        if (!state.needMore) {
                            used = 0;
                            continue;
                        }
                    }
                    const {done, value} = await reader.read(new Uint8Array(xhttpBuffer, used, used === 0 ? 8192 : 4096));
                    if (done) break;
                    xhttpBuffer = value.buffer;
                    used += value.byteLength;
                }
            })().catch(close);
        }
    }), {headers: xhttpHeaders});
};
const getErrorResponse = async (status = 200) => {
    if (!rawErrorHtml) rawErrorHtml = await decompressWasm(getErrorHtmlPtr, getErrorHtmlLen);
    return new Response(rawErrorHtml, {status, headers: {'Content-Type': 'text/html; charset=UTF-8'}});
};
const getSub = async (request, url, uuid) => {
    if (uuid && url.searchParams.get('uuid') !== uuid) return await getErrorResponse(404);
    const ua = (request.headers.get('User-Agent') || '').toLowerCase();
    const proxyPath = url.searchParams.get('path') || '';
    const host = url.hostname;
    const hasVL = url.searchParams.get('vl') === '1';
    const hasTR = url.searchParams.get('tj') === '1';
    const hasWS = url.searchParams.get('ws') === '1';
    const hasXhttp = url.searchParams.get('xhttp') === '1';
    const hasGRPC = url.searchParams.get('grpc') === '1';
    const hasECH = url.searchParams.get('ech') === '1';
    const hasWsNoTLS = url.searchParams.get('wstls') === '0' || url.searchParams.get('wsnotls') === '1';
    const encPath = encodeURIComponent(proxyPath);
    const parts = [];
    const processTemplate = (index, defaultPort = 443) => {
        if (cachedTemplates[index]) {
            const tmpl = cachedTemplates[index].replaceAll("{{HOST}}", host).replaceAll("{{PATH}}", encPath);
            ipListAll.forEach(entry => {
                const node = parseSubNode(entry, defaultPort);
                if (!node) return;
                parts.push(tmpl.replaceAll("{{IP}}", node.ip).replaceAll("{{port}}", node.port).replaceAll("{{name}}", node.name));
            });
        }
    };
    const addNodes = (base, allowWsNoTLS) => {
        const wsNoTLS = allowWsNoTLS && hasWsNoTLS;
        const xhttpBase = base + (allowWsNoTLS ? 3 : 2);
        const grpcBase = base + (allowWsNoTLS ? 5 : 4);
        if (hasWS) processTemplate(base + (wsNoTLS ? 2 : hasECH ? 1 : 0), wsNoTLS ? 80 : 443);
        if (hasXhttp) processTemplate(xhttpBase + (hasECH ? 1 : 0));
        if (hasGRPC) processTemplate(grpcBase + (hasECH ? 1 : 0));
    };
    if (hasVL) addNodes(0, true);
    if (hasTR) addNodes(7, false);
    const finalLinks = parts.join("\n");
    const base64Links = btoa(unescape(encodeURIComponent(finalLinks)));
    if (ua.includes(strList[18])) return new Response(base64Links, {headers: {'Content-Type': 'text/plain; charset=utf-8'}});
    if (url.searchParams.get('format') === 'raw') return new Response(finalLinks, {headers: {'Content-Type': 'text/plain; charset=utf-8'}});
    const target = (url.searchParams.has(strList[5]) || ua.includes(strList[5]) || ua.includes(strList[15]) || ua.includes(strList[16])) ? strList[5]
        : (url.searchParams.has(strList[11]) || url.searchParams.has(strList[6]) || ua.includes(strList[12]) || ua.includes(strList[6])) ? strList[6]
            : (url.searchParams.has(strList[13]) || ua.includes(strList[13])) ? strList[7]
                : (url.searchParams.has(strList[8]) || ua.includes(strList[14])) ? strList[8]
                    : (url.searchParams.has(strList[9]) || ua.includes(strList[9])) ? strList[9]
                        : (url.searchParams.has(strList[10]) || ua.includes(strList[10])) ? strList[10] : '';
    if (target) {
        const baseUrl = `${url.protocol}//${url.host}${url.pathname}?uuid=${globalThis.subUuid}&format=raw&path=${encPath}&vl=${hasVL ? 1 : 0}&tj=${hasTR ? 1 : 0}&ws=${hasWS ? 1 : 0}&wstls=${hasWsNoTLS ? 0 : 1}&xhttp=${hasXhttp ? 1 : 0}&grpc=${hasGRPC ? 1 : 0}&ech=${hasECH ? 1 : 0}`;
        const convertUrl = `${strList[0]}/sub?target=${target}&url=${encodeURIComponent(baseUrl)}&insert=false&config=${encodeURIComponent(strList[1])}&emoji=true&scv=true`;
        try {
            const response = await fetch(convertUrl, {
                headers: {'User-Agent': strList[19] + ' for ' + target + ' ' + userAgentSuffix}
            });
            if (response.ok) {
                return new Response(await response.text(), {
                    headers: {
                        'Content-Type': target === strList[5] ? 'application/x-yaml; charset=utf-8' : 'text/plain; charset=utf-8',
                        'Content-Disposition': `attachment; filename*=utf-8''${encodeURIComponent(strList[17])}`,
                        'Subscription-Userinfo': 'upload=0; download=0; total=1125899906842624; expire=253402271999',
                        'Profile-Update-Interval': '6'
                    }
                });
            }
        } catch {}
    }
    return new Response(base64Links, {headers: {'Content-Type': 'text/plain; charset=utf-8', 'Subscription-Userinfo': 'upload=0; download=0; total=1125899906842624; expire=253402271999'}});
};
export default {
    async fetch(request, env) {
        if (!isInitialized) initializeWasm(env);
        if (request.method === 'POST' && request.headers.get('content-type') === 'application/grpc-web') {
            const reader = request.body?.getReader({mode: 'byob'});
            if (!reader) return new Response(null, {status: 400});
            let postBuffer = new ArrayBuffer(8192), used = 0, buffer = new Uint8Array();
            while (buffer.length === 0 || (buffer[0] === 0 && buffer.length < 6)) {
                const {done, value} = await reader.read(new Uint8Array(postBuffer, used, 4096));
                if (done || !value?.byteLength) break;
                postBuffer = value.buffer;
                used += value.byteLength;
                buffer = new Uint8Array(postBuffer, 0, used);
            }
            if (buffer.length === 0) {
                reader.releaseLock();
                return new Response(null, {status: 400});
            }
            const isGrpc = !request.headers.get('Referer') && buffer.length >= 6 && buffer[0] === 0 && buffer[5] === 0x0A;
            return isGrpc ? handleGrpcPost(request, reader, buffer, used) : handleXhttpPost(request, reader, postBuffer, used);
        }
        if (request.headers.get('Upgrade') === 'websocket') {
            const {0: clientSocket, 1: webSocket} = new WebSocketPair();
            webSocket.accept({allowHalfOpen: true}), webSocket.binaryType = "arraybuffer";
            handleWebSocketConn(webSocket, request);
            return new Response(null, {status: 101, webSocket: clientSocket});
        }
        const url = new URL(request.url);
        const {uuid, password, user, pass, sspass} = getEnv(env);
        if (url.pathname === '/sub') return await getSub(request, url, uuid);
        if (url.pathname === `/${uuid}` || url.pathname === `/${password}`) {
            if (!rawHtml) {
                rawHtml = await decompressWasm(getPanelHtmlPtr, getPanelHtmlLen);
                const map = {UUID: uuid, PASS: password, HTTPPASS: `${user}:${pass}`, SSPASS: sspass, IPLIST: JSON.stringify(ipListAll), ECHDNS: encodeURIComponent(sharedEchDns)};
                rawHtml = rawHtml.replace(/{{(UUID|PASS|HTTPPASS|SSPASS|IPLIST|ECHDNS)}}/g, (_, k) => map[k]);
            }
            return new Response(rawHtml, {headers: {'Content-Type': 'text/html; charset=UTF-8'}});
        }
        return await getErrorResponse();
    }
};
