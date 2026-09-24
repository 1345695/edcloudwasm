/*
// 代码基本都抄的CM和和AK大佬和天书大佬的项目，在此感谢各位大佬的无私奉献。
// 支持xhttp和websocket，trojan和vless和ss和socks5和http协议入站,ss协议无密码，ss和socks5和http协议只能纯手搓，socks5协议不能在路径使用ed=2560参数
// ws模式的vless导入链接：vless://{这里写uuid}@104.16.40.11:2053?encryption=none&security=tls&sni={这里写域名}&alpn=http%2F1.1&fp=chrome&type=ws&host={这里写域名}#vless
// ws模式的trojan导入链接：trojan://{这里写密码}@104.16.40.11:2053?security=tls&sni={这里写域名}&alpn=http%2F1.1&fp=chrome&allowInsecure=1&type=ws&host={这里写域名}#trojan
// xhttp模式的vless导入链接：vless://{这里写uuid}@104.16.40.11:2053?encryption=none&security=tls&sni={这里写域名}&alpn=h2&fp=chrome&allowInsecure=1&type=xhttp&host={这里写域名}&mode=stream-one#vless-xhttp
// xhttp模式的trojan导入链接：trojan://passwd@104.16.40.11:2053?security=tls&sni=sni&alpn=h2&fp=chrome&allowInsecure=1&type=xhttp&host=host&path=%2F&mode=stream-one#trojan-xhttp
// 复制协议开头的导入链接导入再手动修改即可
 * ========================== URL路径参数速查表 =================================================================================
 * 多个参数用 & 连接, 示例: /?s5=host:port&ip=1.2.3.4:443   注: s5/http/https/sstp/turn/turns/nat64/ip 均支持逗号分隔多个地址以实现并发连接
 * s5/gs5/socks/s5all         - 直连失败SOCKS5代理 / 全局SOCKS5        示例: s5=user1:pass1@host1:port1,user2:pass2@host2:port2
 * http/ghttp/httpall         - 直连失败HTTP代理 / 全局HTTP            示例: http=user1:pass1@host1:port1,user2:pass2@host2:port2
 * https/ghttps/httpsall      - 直连失败HTTPS代理 / 全局HTTPS          示例: https=user1:pass1@host1:port1,user2:pass2@host2:port2
 * nat64/gnat64/nat64all      - 直连失败NAT64转换 / 全局NAT64          示例: nat64=64:ff9b::,64:ff9b:1::
 * turn/gturn/turnall         - 直连失败TURN代理 / 全局TURN            示例: turn=user1:pass1@host1:port1,user2:pass2@host2:port2
 * turns/gturns/turnsall      - 直连失败TURNS代理 / 全局TURNS          示例: turns=user1:pass1@host1:port1,user2:pass2@host2:port2
 * sstp/gsstp/sstpall         - 直连失败SSTP代理 / 全局SSTP            示例: sstp=user1:pass1@host1:443,user2:pass2@host2:443
 * ip/txtip/proxyip           - 直连失败时的备用IP                     示例: ip=1.2.3.4:443,5.6.7.8:443
 * proxyall/globalproxy/global - 全局代理标志,无s5/http/https参数时纯直连 示例: proxyall=1
 * speed                      - 下行限速,单位默认MB/s，大于256时解除限速  示例: speed=50 表示50MB/s
 * ==========================================================================================================================*/
import {connect} from 'cloudflare:sockets';
//**警告**:不看开头注释直接把域名地址扔浏览器里会收获彩蛋一枚
const uuid = 'd342d11e-d424-4583-b36e-524ab1f0afa4';//vless使用的uuid
//**警告**:trojan使用的sha224密钥，需要自己计算，当前设置为密码666的密钥
//**警告**:trojan使用的sha224密钥，需要自己计算，当前设置为密码666的密钥
//**警告**:trojan使用的sha224密钥，需要自己计算，当前设置为密码666的密钥
//**警告**:trojan使用的sha224密钥计算网址：https://www.lzltool.com/data-sha224
const passWordSha224 = '509eece82eb6910bebef9af9496092d3244b6c0d69ef3aaa4b12c565';
const socks5AndHttpUser = 'admin';     //socsk5和http协议用户名，设置为空即为无密码验证，需要客户端也为空
const socks5AndHttpPass = '123456';    //socsk5和http协议密码，设置为空即为无密码验证，需要客户端也为空
const ssAeadPassword = '123456';       // ss协议 aes-128-gcm 密码（notls）
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
const flushTime = 4;                  // 4ms
// ---------------------------------------------------------------------------------
/** SS AEAD加密时每批并发处理的payload分片数量，length加密开销低，会随payload一起提交。*/
const ssAeadEncryptCount = 16;
// ---------------------------------------------------------------------------------
/** TCPsocket并发获取，可提高tcp连接成功率*/
/**- **警告**: snippets只能设置为1，worker最大支持6，超过6没意义*/
let concurrency = 4;//socket获取并发数
const enableSniSniff = false;//域名嗅探开关(支持ss vless trojan)
// ---------------------------------------------------------------------------------
const urlParamCacheLimit = 20;//URL参数解析结果缓存条数
// ---------------------------------------------------------------------------------
//出站socket获取顺序，全局模式下按数组顺序，非全局为：直连>socks>http>https>sstp>turn>turns>nat64>proxyip>finallyProxyHost
/**- **警告**: snippets只支持最大两次connect，所以snippets全局nat64不能使用域名访问，snippets访问cf失败的备用只有第一个有效*/
const proxyStrategyOrder = ['socks', 'http', 'https', 'sstp', 'turn', 'turns', 'nat64'];
const dohEndpoints = ['https://cloudflare-dns.com/dns-query', 'https://dns.google/dns-query'];
const dohNatEndpoints = ['https://cloudflare-dns.com/dns-query', 'https://dns.google/resolve'];
const finallyProxyHost = 'proxy.zjcloud.us.ci';//兜底proxyip
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
const textEncoder = new TextEncoder(), textDecoder = new TextDecoder(), socks5req = new Uint8Array([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
let socks5Pkg, httpAuthValue;
const httpRes200 = textEncoder.encode("HTTP/1.1 200 Connection Established\r\n\r\n"), httpRes407 = textEncoder.encode("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\n\r\n");
if (socks5AndHttpUser && socks5AndHttpPass) {
    httpAuthValue = textEncoder.encode(btoa(`${socks5AndHttpUser}:${socks5AndHttpPass}`));
    const userBytes = textEncoder.encode(socks5AndHttpUser), passBytes = textEncoder.encode(socks5AndHttpPass);
    socks5Pkg = new Uint8Array(3 + userBytes.length + passBytes.length);
    socks5Pkg[0] = 1, socks5Pkg[1] = userBytes.length, socks5Pkg.set(userBytes, 2), socks5Pkg[2 + userBytes.length] = passBytes.length, socks5Pkg.set(passBytes, 3 + userBytes.length);
}
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
            const pwd = textEncoder.encode(ssAeadPassword);
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
        onPlain ? await onPlain(payload) : (out.push(payload), total += payload.length);
    }
    pendingStart === pendingEnd ? (ctx.pendingStart = 0, ctx.pendingEnd = 0) : (ctx.pendingStart = pendingStart, ctx.pendingEnd = pendingEnd);
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
const parseAuthString = (authParam, defaultPort = 1080) => {
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
    const [hostname, port] = parseHostPort(hostStr, defaultPort);
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
const {TlsClient} = (() => {
    const b = crypto.subtle, V = new TextEncoder, g = new Uint8Array(0), f = s => [s >> 8, s & 255], A = (s, t) => s[t] << 8 | s[t + 1], E = (...s) => {
            const t = a => {
                let i = 0;
                for (let c = 0; c < a.length; c++) {
                    const l = a[c];
                    i += l instanceof Uint8Array ? l.length : Array.isArray(l) ? t(l) : 1
                }
                return i
            }, e = new Uint8Array(t(s));
            let r = 0;
            const n = a => {
                for (let i = 0; i < a.length; i++) {
                    const c = a[i];
                    c instanceof Uint8Array ? (e.set(c, r), r += c.length) : Array.isArray(c) ? n(c) : e[r++] = c
                }
            };
            return n(s), e
        }, d = (...s) => {
            const t = new Uint8Array(s.reduce((r, n) => r + (n?.length || 0), 0));
            let e = 0;
            for (const r of s) r?.length && (t.set(r, e), e += r.length);
            return t
        }, D = s => s === "SHA-384" ? 48 : 32, G = s => s?.[0] === 1 && s[1] === 112, X = async (s, t, e) => new Uint8Array(await b.sign("HMAC", t.type ? t : await b.importKey("raw", t, {name: "HMAC", hash: s}, !1, ["sign"]), e)), K = async (s, t) => new Uint8Array(await b.digest(s, t)), W = (s, t) => b.importKey("raw", s, {name: "AES-GCM"}, !1, [t]), J = async (s, t, e, r) => new Uint8Array(await b.encrypt({name: "AES-GCM", iv: t, additionalData: r}, s, e)),
        N = async (s, t, e, r) => new Uint8Array(await b.decrypt({name: "AES-GCM", iv: t, additionalData: r}, s, e)), P = (s, t, e = 771, r = t.length) => {
            const n = new Uint8Array(5 + r);
            return n[0] = s, n[1] = e >> 8, n[2] = e & 255, n[3] = r >> 8, n[4] = r & 255, n.set(t, 5), n
        }, $ = (s, t = 23) => {
            let e = 0;
            for (let a = 0; a < s.length; a++) e += 5 + s[a].length;
            const r = new Uint8Array(e);
            let n = 0;
            for (let a = 0; a < s.length; a++) {
                const i = s[a], c = i.length;
                r[n] = t, r[n + 1] = 3, r[n + 2] = 3, r[n + 3] = c >> 8, r[n + 4] = c & 255, r.set(i, n + 5), n += 5 + c
            }
            return r
        }, L = (s, t, e = t.length) => {
            const r = new Uint8Array(4 + e);
            return r[0] = s, r[1] = e >> 16 & 255, r[2] = e >> 8 & 255, r[3] = e & 255, r.set(t, 4), r
        }, R = s => new Uint8Array([23, 3, 3, s >> 8, s & 255]), z = (s, t, e) => X(s, t?.length ? t : new Uint8Array(D(s)), e), F = async (s, t, e, r, n = "SHA-256") => {
            const a = d(V.encode(t), e), i = s.type ? s : await b.importKey("raw", s, {name: "HMAC", hash: n}, !1, ["sign"]);
            let c = g, l = a;
            for (; c.length < r;) l = await X(n, i, l), c = d(c, await X(n, i, d(l, a)));
            return c.slice(0, r)
        }, q = async (s, t, e, r, n) => {
            const a = typeof e == "string" ? V.encode("tls13 " + e) : e, i = D(s), c = a.length, l = r.length, h = new Uint8Array(4 + c + l);
            h[0] = n >> 8, h[1] = n & 255, h[2] = c, h.set(a, 3), h[3 + c] = l, l && h.set(r, 4 + c);
            const w = t.type ? t : await b.importKey("raw", t, {name: "HMAC", hash: s}, !1, ["sign"]);
            let k = g, p = g;
            for (let U = 1; U <= Math.ceil(n / i); U++) {
                const v = new Uint8Array(p.length + h.length + 1);
                p.length && v.set(p), v.set(h, p.length), v[p.length + h.length] = U, p = await X(s, w, v), k = d(k, p)
            }
            return k.slice(0, n)
        }, Q = async (s = "P-256") => {
            const t = s === "X25519", e = await b.generateKey(t ? {name: s} : {name: "ECDH", namedCurve: s}, !0, ["deriveBits"]);
            return {kp: e, pk: new Uint8Array(await b.exportKey("raw", e.publicKey))}
        }, Y = async (s, t, e = "P-256") => {
            const r = e === "X25519", n = await b.importKey("raw", t, r ? {name: e} : {name: "ECDH", namedCurve: e}, !1, []);
            return new Uint8Array(await b.deriveBits({name: r ? e : "ECDH", public: n}, s, 256))
        }, tt = (s, t, e, {sessionId: r = g} = {}) => {
            const n = E(...[4865, 4866, 49199, 49200, 49195, 49196].flatMap(f)), a = [E(255, 1, 0, 1, 0)];
            if (t) {
                const l = V.encode(t);
                a.push(E(0, 0, f(l.length + 5), f(l.length + 3), 0, f(l.length), l))
            }
            const i = d(E(0, 29, f(e.x25519.length), e.x25519), E(0, 23, f(e.p256.length), e.p256));
            a.push(E(f(11), 0, 2, 1, 0), E(f(10), 0, 6, 0, 4, 0, 29, 0, 23), E(f(13), 0, 34, 0, 32, ...[2052, 2053, 2054, 2055, 2056, 2057, 2058, 2059, 1027, 1283, 1539, 1025, 1281, 1537, 513, 515].flatMap(f)), E(f(43), 0, 5, 4, 3, 4, 3, 3), E(f(51), f(i.length + 2), f(i.length), i));
            const c = d(...a);
            return L(1, E(f(771), s, r.length, r, f(n.length), n, 1, 0, f(c.length), c))
        }, T = async (s, t, e, r, n) => {
            const a = t.type ? t : await b.importKey("raw", t, {name: "HMAC", hash: s}, !1, ["sign"]), [i, c] = await Promise.all([q(s, a, "key", g, e), q(s, a, "iv", g, r)]);
            return [await W(i, n), c]
        }, Z = s => {
            let t = s.length - 1;
            for (; t >= 0 && !s[t];) t--;
            if (t < 0) throw new Error;
            return {data: s.subarray(0, t), type: s[t]}
        }, B = (s, t) => {
            const e = s.slice(), r = t >>> 0, n = t / 4294967296 >>> 0, a = e.length - 8;
            return e[a] ^= n >>> 24, e[a + 1] ^= n >>> 16, e[a + 2] ^= n >>> 8, e[a + 3] ^= n, e[a + 4] ^= r >>> 24, e[a + 5] ^= r >>> 16, e[a + 6] ^= r >>> 8, e[a + 7] ^= r, e
        };
    class _ {
        constructor(t, e, r) {this.b = new Uint8Array(t), this.h = this.t = 0, this.l = e, this.g = r}
        feed(t) {
            const e = this;
            if (e.t + t.length > e.b.length) {
                const r = e.t - e.h, n = r + t.length > e.b.length, a = n ? new Uint8Array(Math.max(e.b.length * 2, r + t.length)) : e.b;
                n ? a.set(e.b.subarray(e.h, e.t)) : a.copyWithin(0, e.h, e.t), e.b = a, e.t = r, e.h = 0
            }
            e.b.set(t, e.t), e.t += t.length
        }
        next() {
            const t = this;
            if (t.t - t.h < t.l) return null;
            const e = t.g(t.b, t.h);
            if (t.l === 5 && e > 18432) throw new Error;
            if (t.t - t.h < t.l + e) return null;
            const r = t.b.subarray(t.h, t.h += t.l + e), n = r.subarray(t.l);
            return t.h === t.t && (t.h = t.t = 0), {type: r[0], version: t.l === 5 ? A(r, 1) : 0, length: e, body: n, fragment: n, raw: r}
        }
    }
    class et {
        constructor(t, e = {}) {
            const r = this;
            r.sk = t, r.sn = e.serverName || "", r.cr = crypto.getRandomValues(new Uint8Array(32)), r.id = crypto.getRandomValues(new Uint8Array(32)), r.hb = new Uint8Array(8192), r.hl = 0, r.cn = 0, r.qn = 0, r.rp = new _(32768, 5, (n, a) => A(n, a + 3)), r.hp = new _(4096, 4, (n, a) => n[a + 1] << 16 | A(n, a + 2)), r.kp = new Map, r.pq = [], r.wq = Promise.resolve(), r.rb = new Uint8Array(65536), r.rd = null, r.wr = null, r.fl = !1, r.cl = !1, r.cg = !1, r.hc = !1, r.cp = null, r.i3 = !1, r.cs = null, r.cc = null, r.sr = null, r.hs = null, r.ch = null, r.ci = null, r.sh = null, r.si = null, r.ak = null, r.ai = null, r.bk = null, r.bi = null, r.ms = null, r.ck = null, r.wk = null, r.cv = null, r.wv = null, r.as = null, r.bs = null
        }
        rh(t) {
            const e = this;
            if (e.hl + t.length > e.hb.length) {
                const r = new Uint8Array(Math.max(e.hb.length * 2, e.hl + t.length));
                r.set(e.hb.subarray(0, e.hl)), e.hb = r
            }
            e.hb.set(t, e.hl), e.hl += t.length
        }
        ts() {return this.hb.subarray(0, this.hl)}
        fc() {return this.cn++}
        fs() {return this.qn++}
        fail() {
            const t = this;
            t.fl = t.cl = !0;
            try {t.sk?.close()} catch {}
            try {t.rd?.cancel()} catch {}
            try {t.wr?.abort()} catch {}
        }
        async rc() {
            const t = this, e = await t.rd.read(t.rb);
            if (!e) throw new Error;
            return !e.done && e.value && (t.rb = new Uint8Array(e.value.buffer)), e
        }
        async pr(t) {
            const e = this;
            for (; ;) {
                for (let a; a = e.rp.next();) if (await t(a)) return;
                const {value: r, done: n} = await e.rc();
                if (n) throw new Error;
                e.rp.feed(r)
            }
        }
        async handshake() {
            const t = this, [e, r] = await Promise.all([Q("P-256"), Q("X25519")]);
            t.kp = new Map([[23, e], [29, r]]), t.rd = t.sk.readable.getReader({mode: "byob"}), t.wr = t.sk.writable.getWriter();
            try {
                const n = tt(t.cr, t.sn, {p256: e.pk, x25519: r.pk}, {sessionId: t.id});
                t.rh(n), await t.wr.write(P(22, n, 769));
                const a = await t.rsh();
                if (a.isTls13) {
                    const i = a.ks?.group === 29 ? "X25519" : a.ks?.group === 23 ? "P-256" : null, c = t.kp.get(a.ks?.group);
                    if (!i || !a.ks?.key?.length || !c) throw new Error;
                    const l = t.cc.hash, h = D(l), {keyLen: w, ivLen: k} = t.cc, p = await Y(c.kp.privateKey, a.ks.key, i), U = await q(l, await z(l, null, new Uint8Array(h)), "derived", await K(l, g), h);
                    t.hs = await z(l, U, p);
                    const v = await K(l, t.ts()), y = await q(l, t.hs, "c hs traffic", v, h), C = await q(l, t.hs, "s hs traffic", v, h);
                    [t.ch, t.ci] = await T(l, y, w, k, "encrypt"), [t.sh, t.si] = await T(l, C, w, k, "decrypt");
                    let m = !1;
                    await t.pr(async u => {
                        if (u.type === 20 || u.type === 22) return;
                        if (u.type === 21) {
                            if (G(u.fragment)) return;
                            throw new Error
                        }
                        if (u.type !== 23) return;
                        const {data: rt, type: nt} = Z(await N(t.sh, B(t.si, t.fs()), u.fragment, R(u.fragment.length)));
                        if (nt === 22) {
                            t.hp.feed(rt);
                            for (let I; I = t.hp.next();) if (t.rh(I.raw), I.type === 13) m = !0; else if (I.type === 20) return 1
                        }
                    });
                    const M = await K(l, t.ts()), x = await q(l, t.hs, "derived", await K(l, g), h), H = await z(l, x, new Uint8Array(h));
                    t.as = await q(l, H, "c ap traffic", M, h), t.bs = await q(l, H, "s ap traffic", M, h), [t.ak, t.ai] = await T(l, t.as, w, k, "encrypt"), [t.bk, t.bi] = await T(l, t.bs, w, k, "decrypt");
                    let S = g;
                    m && (S = L(11, new Uint8Array(4)), t.rh(S));
                    const O = await q(l, y, "finished", g, h), j = L(20, await X(l, O, await K(l, t.ts())));
                    t.rh(j);
                    const o = d(S, j, new Uint8Array([22]));
                    await t.wr.write(d(P(20, new Uint8Array([1])), P(23, await J(t.ch, B(t.ci, t.fc()), o, R(o.length + 16))))), t.cn = t.qn = 0
                } else {
                    let i = null, c = !1, l = !1;
                    const h = async o => {
                        if (t.rh(o.raw), o.type === 12) {
                            i = {nc: A(o.body, 1), spk: o.body.subarray(4, 4 + o.body[3])};
                        } else {
                            if (o.type === 14) return c = !0, 1;
                            o.type === 13 && (l = !0)
                        }
                    };
                    let w = !1;
                    for (let o; o = t.hp.next();) if (await h(o)) {
                        w = !0;
                        break
                    }
                    if (!w) {
                        for (let o; o = t.rp.next();) if (o.type === 22) {
                            t.hp.feed(o.fragment);
                            for (let u; u = t.hp.next();) if (await h(u)) {
                                w = !0;
                                break
                            }
                            if (w) break
                        }
                    }
                    if (w || await t.pr(async o => {
                        if (o.type === 21) {
                            if (G(o.fragment)) return;
                            throw new Error
                        }
                        if (o.type === 20) throw new Error;
                        if (o.type === 22) {
                            t.hp.feed(o.fragment);
                            for (let u; u = t.hp.next();) if (await h(u)) return 1
                        }
                    }), !c || !i) {
                        throw new Error;
                    }
                    const k = i.nc === 29 ? "X25519" : i.nc === 23 ? "P-256" : null, p = t.kp.get(i.nc);
                    if (!k || !p) throw new Error;
                    let U = g;
                    if (l) {
                        const o = L(11, new Uint8Array(3));
                        t.rh(o), U = P(22, o)
                    }
                    const v = await Y(p.kp.privateKey, i.spk, k), y = L(16, d(new Uint8Array([p.pk.length]), p.pk));
                    t.rh(y);
                    const C = t.cc.hash;
                    t.ms = await F(v, "master secret", d(t.cr, t.sr), 48, C);
                    const {keyLen: m, ivLen: M} = t.cc, x = await F(t.ms, "key expansion", d(t.sr, t.cr), 2 * m + 2 * M, C);
                    [t.ck, t.wk] = await Promise.all([W(x.subarray(0, m), "encrypt"), W(x.subarray(m, 2 * m), "decrypt")]), t.cv = x.subarray(2 * m, 2 * m + M), t.wv = x.subarray(2 * m + M, 2 * m + 2 * M);
                    const H = await F(t.ms, "client finished", await K(C, t.ts()), 12, C), S = L(20, H);
                    t.rh(S);
                    const O = await t.e12(S, 22);
                    await t.wr.write(d(U, P(22, y), P(20, new Uint8Array([1])), P(22, O)));
                    let j = !1;
                    await t.pr(async o => {
                        if (o.type === 21) {
                            if (G(o.fragment)) return;
                            throw new Error
                        }
                        if (o.type === 20) return void (j = !0);
                        if (o.type === 22 && j) {
                            t.hp.feed(await t.d12(o.fragment, 22));
                            for (let u; u = t.hp.next();) if (u.type === 20) return 1
                        }
                    })
                }
                t.hc = !0, t.cr = t.id = t.sr = t.ms = t.hs = t.ch = t.sh = t.ci = t.si = null, t.kp.clear(), t.kp = null
            } finally {
                if (!t.hc || t.fl) {
                    try {t.rd?.releaseLock()} catch {}
                    try {t.wr?.releaseLock()} catch {}
                }
            }
        }
        async rsh() {
            const t = this;
            for (; ;) {
                const {value: e, done: r} = await t.rc();
                if (r) throw new Error;
                t.rp.feed(e);
                for (let n; n = t.rp.next();) {
                    if (n.type === 21) {
                        if (G(n.fragment)) continue;
                        throw new Error
                    }
                    if (n.type !== 20 && n.type === 22) {
                        t.hp.feed(n.fragment);
                        for (let a; a = t.hp.next();) {
                            if (a.type !== 2) continue;
                            t.rh(a.raw);
                            let i = 2;
                            const c = A(a.body, 0), l = a.body.slice(i, i += 32), h = a.body[i++], w = a.body.subarray(i, i += h), k = A(a.body, i);
                            i += 2;
                            const p = a.body[i++];
                            let U = c, v = null;
                            if (i < a.body.length) {
                                const m = i + 2 + A(a.body, i);
                                for (i += 2; i + 4 <= m;) {
                                    const M = A(a.body, i), x = A(a.body, i + 2), H = a.body.subarray(i += 4, i += x);
                                    M === 43 && x >= 2 ? U = A(H, 0) : M === 51 && x >= 2 && (v = {group: A(H, 0), key: x >= 4 ? H.subarray(4, 4 + A(H, 2)) : g})
                                }
                            }
                            const y = {version: c, sr: l, sid: w, cs: k, comp: p, sv: U, ks: v, isTls13: U === 772}, C = y.cs === 4866 || y.cs === 49200 || y.cs === 49196;
                            if (!C && y.cs !== 4865 && y.cs !== 49199 && y.cs !== 49195 || p !== 0 || y.cs < 49e3 !== y.isTls13 || !y.isTls13 && y.sv !== 771) throw new Error;
                            return t.sr = y.sr, t.cs = y.cs, t.cc = {keyLen: C ? 32 : 16, ivLen: y.isTls13 ? 12 : 4, hash: C ? "SHA-384" : "SHA-256", tls13: y.isTls13}, t.i3 = y.isTls13, y
                        }
                    }
                }
            }
        }
        async e12(t, e, r = this.fc()) {
            const n = new Uint8Array(13), a = r >>> 0, i = r / 4294967296 >>> 0;
            n[0] = i >>> 24, n[1] = i >>> 16, n[2] = i >>> 8, n[3] = i, n[4] = a >>> 24, n[5] = a >>> 16, n[6] = a >>> 8, n[7] = a, n[8] = e, n[9] = 3, n[10] = 3, n[11] = t.length >> 8, n[12] = t.length & 255;
            const c = n.subarray(0, 8), l = new Uint8Array(12);
            l.set(this.cv), l.set(c, 4);
            const h = await J(this.ck, l, t, n), w = new Uint8Array(8 + h.length);
            return w.set(c), w.set(h, 8), w
        }
        async d12(t, e, r = this.fs()) {
            const n = t.subarray(0, 8), a = t.subarray(8), i = new Uint8Array(12);
            i.set(this.wv), i.set(n, 4);
            const c = new Uint8Array(13), l = a.length - 16, h = r >>> 0, w = r / 4294967296 >>> 0;
            return c[0] = w >>> 24, c[1] = w >>> 16, c[2] = w >>> 8, c[3] = w, c[4] = h >>> 24, c[5] = h >>> 16, c[6] = h >>> 8, c[7] = h, c[8] = e, c[9] = 3, c[10] = 3, c[11] = l >> 8, c[12] = l & 255, N(this.wk, i, a, c)
        }
        async e13(t, e = this.fc(), r = 23) {
            const n = new Uint8Array(t.length + 1);
            return n.set(t), n[t.length] = r, J(this.ak, B(this.ai, e), n, R(n.length + 16))
        }
        async d13(t, e = this.fs(), r = this.bk, n = this.bi) {return Z(await N(r, B(n, e), t, R(t.length)))}
        write(t) {
            const e = this;
            if (!e.hc || e.fl || e.cg) return Promise.reject(new Error);
            const r = t instanceof Uint8Array ? t.slice() : new Uint8Array(t);
            if (!r.length) return Promise.resolve();
            const n = e.wq.then(async () => {
                if (e.fl || e.cg) throw new Error;
                if (r.length <= 16384) return e.wr.write(P(23, e.i3 ? await e.e13(r) : await e.e12(r, 23)));
                for (let i = 0; i < r.length;) {
                    const c = [];
                    for (let l = 0; l < 8 && i < r.length; l++, i += 16384) {
                        const h = r.subarray(i, Math.min(i + 16384, r.length)), w = e.fc();
                        c.push(e.i3 ? e.e13(h, w) : e.e12(h, 23, w))
                    }
                    await e.wr.write($(await Promise.all(c)))
                }
            }), a = n.catch(i => {throw e.fail(), i});
            return e.wq = a.catch(() => {}), a
        }
        read() {
            const t = this;
            return t.fl || !t.hc ? Promise.reject(new Error) : (async () => {
                for (; ;) {
                    if (t.pq.length) return t.pq.length === 1 ? t.pq.pop() : d(...t.pq.splice(0));
                    if (t.cl) return null;
                    const e = [];
                    for (let a; e.length < 8 && (a = t.rp.next());) if (!(t.i3 ? a.type === 20 : ![21, 22, 23].includes(a.type))) {
                        if (t.i3 && a.type !== 23) throw new Error;
                        e.push(a)
                    }
                    if (e.length) {
                        if (t.i3) {
                            const a = t.qn, i = t.bk, c = t.bi;
                            let l;
                            try {l = await Promise.all(e.map((h, w) => t.d13(h.fragment, a + w, i, c)))} catch {}
                            if (l) {
                                t.qn = a + l.length;
                                for (const h of l) await t.p13(h)
                            } else {
                                for (let h = 0; h < e.length; h++) await t.p13(await t.d13(e[h].fragment, t.qn++))
                            }
                        } else {
                            const a = t.qn, i = await Promise.all(e.map((c, l) => t.d12(c.fragment, c.type, a + l)));
                            t.qn = a + e.length;
                            for (let c = 0; c < i.length; c++) {
                                const l = i[c], h = e[c].type;
                                if (h === 23) t.pq.push(l); else if (h === 21) t.pa(l); else if (h === 22) for (t.hp.feed(l); t.hp.next();) ;
                            }
                        }
                        if (t.pq.length) return t.pq.length === 1 ? t.pq.pop() : d(...t.pq.splice(0));
                        if (t.cl) return null;
                        continue
                    }
                    if (t.cl) return null;
                    const {value: r, done: n} = await t.rc();
                    if (n) return null;
                    t.rp.feed(r)
                }
            })().catch(e => {throw t.fail(), e})
        }
        pa(t) {
            const e = this;
            if (e.cl = !0, t && t.length >= 2) {
                const r = t[0], n = t[1];
                if (r === 2 || r === 1 && n !== 0) throw e.fail(), new Error
            }
            e.close()
        }
        async p13({data: t, type: e}) {
            if (e === 23) {
                this.pq.push(t);
            } else if (e === 21) {
                this.pa(t);
            } else if (e === 22) {
                this.hp.feed(t);
                for (let r; r = this.hp.next();) r.type === 24 && (await this.uv(), r.body[0] === 1 && await this.su(0))
            }
        }
        async uk() {
            const t = this, e = t.cc.hash, r = D(e), {keyLen: n, ivLen: a} = t.cc;
            t.as = await q(e, t.as, "traffic upd", g, r), [t.ak, t.ai] = await T(e, t.as, n, a, "encrypt"), t.cn = 0
        }
        async uv() {
            const t = this, e = t.cc.hash, r = D(e), {keyLen: n, ivLen: a} = t.cc;
            t.bs = await q(e, t.bs, "traffic upd", g, r), [t.bk, t.bi] = await T(e, t.bs, n, a, "decrypt"), t.qn = 0
        }
        su(t = 0) {
            const e = this;
            if (!e.hc || e.fl || e.cg) return Promise.reject(new Error);
            const r = e.wq.then(async () => {
                if (e.fl || e.cg) throw new Error;
                const a = L(24, new Uint8Array([t]));
                await e.wr.write(P(23, await e.e13(a, e.fc(), 22))), await e.uk()
            }), n = r.catch(a => {throw e.fail(), a});
            return e.wq = n.catch(() => {}), n
        }
        close() {
            const t = this;
            return t.cp ? t.cp : t.fl || !t.hc ? (t.sk?.close(), t.cp = Promise.resolve()) : (t.cg = !0, t.wq = t.cp = t.wq.then(async () => {
                const e = new Uint8Array([1, 0]), r = t.i3 ? await t.e13(e, t.fc(), 21) : await t.e12(e, 21);
                await t.wr.write(P(t.i3 ? 23 : 21, r))
            }).catch(() => {}).finally(() => {t.cl = !0, t.sk?.close()}))
        }
    }
    return {TlsClient: et}
})();
const tlsStreamAdapter = (tls, initial = new Uint8Array(0)) => {
    let leftOver = initial?.byteLength ? initial : null, reading = null, closed = false, tlsClosed = false;
    const close = () => {
        if (tlsClosed) return;
        tlsClosed = true, closed = true;
        try {tls.close()} catch {}
    };
    const readNext = async () => leftOver ? (d => (leftOver = null, d))(leftOver) : tls.read();
    const readable = new ReadableStream({
        type: 'bytes', autoAllocateChunkSize: 65536,
        async pull(c) {
            if (closed) return;
            try {
                reading ||= readNext().finally(() => reading = null);
                const data = await reading;
                if (!data?.byteLength) {
                    closed = true;
                    try {c.close()} catch {}
                    return void c.byobRequest?.respond(0);
                }
                const v = data instanceof Uint8Array ? data : new Uint8Array(data), req = c.byobRequest;
                if (req) {
                    const l = Math.min(v.byteLength, req.view.byteLength);
                    req.view.set(v.subarray(0, l)), leftOver = l < v.byteLength ? v.subarray(l) : null, req.respond(l);
                } else {c.enqueue(v)}
            } catch {
                closed = true;
                try {c.close()} catch {}
                close();
            }
        }, cancel: close
    }, {highWaterMark: 1048576});
    const writable = new WritableStream({write: c => tls.write(c), close, abort: close});
    return {readable, writable, close};
};
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
const sstpEmpty = new Uint8Array(0), sstpMss = 1400, sstpTcpWindowScale = 6, sstpTcpReceiveWindow = 4 * 1024 * 1024;
const sstpU16 = (b, o) => (b[o] << 8) | b[o + 1];
const sstpU32 = (b, o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
const sstpRandomBytes = length => crypto.getRandomValues(new Uint8Array(length));
const sstpRandom16 = () => sstpU16(sstpRandomBytes(2), 0);
const sstpRandom32 = () => sstpU32(sstpRandomBytes(4), 0);
const sstpIpv4Bytes = ip => isIPv4(ip) ? new Uint8Array(ip.split('.').map(Number)) : null;
const sstpChecksum = (data, offset, length) => {
    let sum = 0;
    for (let i = offset; i < offset + length - 1; i += 2) sum += sstpU16(data, i);
    if (length & 1) sum += data[offset + length - 1] << 8;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >>> 16);
    return (~sum) & 0xffff;
};
const createSstpSession = (username, password) => {
    const userBytes = textEncoder.encode(username), passBytes = textEncoder.encode(password);
    if (!userBytes.length || !passBytes.length || userBytes.length > 255 || passBytes.length > 255) throw new Error('Invalid SSTP credentials');
    let buffered = sstpEmpty, packetId = 1, socket = null, reader = null, writer = null, serverHost = '', serverPort = 443;
    let readBuffer = new ArrayBuffer(65536), writeQueue = Promise.resolve(), closed = false;
    const readMore = async () => {
        if (closed || !reader) throw new Error('SSTP socket is closed');
        const saved = buffered.length ? new Uint8Array(buffered) : null;
        const {value, done} = await reader.read(new Uint8Array(readBuffer));
        if (done || !value?.byteLength) throw new Error('SSTP socket ended');
        readBuffer = value.buffer;
        buffered = saved ? cat(saved, value) : value;
    };
    const readBytes = async length => {
        while (buffered.length < length) await readMore();
        const value = buffered.subarray(0, length);
        buffered = buffered.subarray(length);
        return value;
    };
    const readLine = async () => {
        for (; ;) {
            const index = buffered.indexOf(10);
            if (index !== -1) {
                const line = textDecoder.decode(buffered.subarray(0, index)).replace(/\r$/, '');
                buffered = buffered.subarray(index + 1);
                return line;
            }
            if (buffered.length > 16384) throw new Error('SSTP HTTP header is too large');
            await readMore();
        }
    };
    const readPacket = async (timeoutMs = 10000) => {
        let timer;
        const packet = (async () => {
            const header = await readBytes(4);
            const length = sstpU16(header, 2) & 0x0fff;
            if (header[0] !== 0x10 || length < 4) throw new Error('Invalid SSTP packet');
            return {ctrl: (header[1] & 1) !== 0, body: length === 4 ? sstpEmpty : await readBytes(length - 4)};
        })();
        try {
            return await Promise.race([packet, new Promise((_, reject) => timer = setTimeout(() => reject(new Error('SSTP read timeout')), timeoutMs))]);
        } finally {clearTimeout(timer)}
    };
    const dataPacket = frame => {
        const length = 6 + frame.length, packet = new Uint8Array(length);
        packet.set([0x10, 0, ((length >> 8) & 0x0f) | 0x80, length & 0xff, 0xff, 0x03]);
        packet.set(frame, 6);
        return packet;
    };
    const controlPacket = (messageType, attrs = []) => {
        const attrsLength = attrs.reduce((sum, attr) => sum + 4 + attr.data.length, 0), packet = new Uint8Array(8 + attrsLength), view = new DataView(packet.buffer);
        packet[0] = 0x10, packet[1] = 1;
        view.setUint16(2, packet.length | 0x8000), view.setUint16(4, messageType), view.setUint16(6, attrs.length);
        attrs.reduce((offset, attr) => {
            packet[offset + 1] = attr.id;
            view.setUint16(offset + 2, 4 + attr.data.length);
            packet.set(attr.data, offset + 4);
            return offset + 4 + attr.data.length;
        }, 8);
        return packet;
    };
    const pppPacket = (protocol, code, id, options = []) => {
        const optionsLength = options.reduce((sum, option) => sum + 2 + option.data.length, 0), frame = new Uint8Array(6 + optionsLength), view = new DataView(frame.buffer);
        view.setUint16(0, protocol), frame[2] = code, frame[3] = id, view.setUint16(4, 4 + optionsLength);
        options.reduce((offset, option) => {
            frame[offset] = option.type, frame[offset + 1] = 2 + option.data.length;
            frame.set(option.data, offset + 2);
            return offset + 2 + option.data.length;
        }, 6);
        return frame;
    };
    const papPacket = id => {
        const pppLength = 6 + userBytes.length + passBytes.length, frame = new Uint8Array(2 + pppLength), view = new DataView(frame.buffer);
        view.setUint16(0, 0xc023), frame[2] = 1, frame[3] = id, view.setUint16(4, pppLength);
        frame[6] = userBytes.length, frame.set(userBytes, 7), frame[7 + userBytes.length] = passBytes.length, frame.set(passBytes, 8 + userBytes.length);
        return frame;
    };
    const parsePpp = data => {
        let offset = data.length >= 2 && data[0] === 0xff && data[1] === 3 ? 2 : 0;
        if (data.length - offset < 4) return null;
        const protocol = sstpU16(data, offset);
        if (protocol === 0x0021) return {protocol, ip: data.subarray(offset + 2)};
        return data.length - offset >= 6 ? {protocol, code: data[offset + 2], id: data[offset + 3], payload: data.subarray(offset + 6), raw: data.subarray(offset)} : null;
    };
    const parseOptions = data => {
        const options = [];
        for (let offset = 0; offset + 2 <= data.length;) {
            const type = data[offset], length = data[offset + 1];
            if (length < 2 || offset + length > data.length) break;
            options.push({type, data: data.subarray(offset + 2, offset + length)});
            offset += length;
        }
        return options;
    };
    const write = data => {
        const operation = writeQueue.then(() => {
            if (closed || !writer) throw new Error('SSTP socket is closed');
            return writer.write(data);
        });
        writeQueue = operation.catch(() => {});
        return operation;
    };
    const handleControl = async body => {
        if (body.length < 2) return;
        const messageType = sstpU16(body, 0);
        if (messageType === 8) {
            await write(controlPacket(9));
        } else if (messageType === 6) {
            await write(controlPacket(7));
            throw new Error('SSTP disconnected');
        } else if (messageType === 5 || messageType === 7) throw new Error('SSTP aborted');
    };
    const connectSstp = async (hostname, port) => {
        socket = connect({hostname, port}, {secureTransport: 'on', allowHalfOpen: false});
        await socket.opened;
        if (closed) throw new Error('SSTP socket is closed');
        reader = socket.readable.getReader({mode: 'byob'}), writer = socket.writable.getWriter(), serverHost = hostname, serverPort = port;
    };
    const establish = async () => {
        const authority = serverPort === 443 ? serverHost : `${serverHost}:${serverPort}`;
        const http = textEncoder.encode(`SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\nHost: ${authority}\r\nContent-Length: 18446744073709551615\r\nSSTPCORRELATIONID: {${crypto.randomUUID()}}\r\n\r\n`);
        const protocolAttr = new Uint8Array(2), mru = new Uint8Array(2);
        new DataView(protocolAttr.buffer).setUint16(0, 1), new DataView(mru.buffer).setUint16(0, 1500);
        await write(cat(http, controlPacket(1, [{id: 1, data: protocolAttr}]), dataPacket(pppPacket(0xc021, 1, packetId++, [{type: 1, data: mru}]))));
        const statusLine = await readLine();
        let headersEnded = false;
        for (let i = 0; i < 64; i++) if ((await readLine()) === '') {
            headersEnded = true;
            break;
        }
        if (!headersEnded || !/^HTTP\/1\.[01] 200(?:\s|$)/i.test(statusLine)) throw new Error('SSTP HTTP handshake failed');
        let localLcpDone = false, authSent = false, ipcpSent = false, done = false, myIp = null;
        const sendAuth = async () => {
            if (!authSent) authSent = true, await write(dataPacket(papPacket(packetId++)));
        };
        const sendIpcp = async ip => {
            ipcpSent = true;
            await write(dataPacket(pppPacket(0x8021, 1, packetId++, [{type: 3, data: ip}])));
        };
        for (let attempts = 0; attempts < 40 && !done; attempts++) {
            const packet = await readPacket(15000);
            if (packet.ctrl) {
                await handleControl(packet.body);
                continue;
            }
            const ppp = parsePpp(packet.body);
            if (!ppp) continue;
            if (ppp.protocol === 0xc021) {
                if (ppp.code === 1) {
                    const ack = new Uint8Array(ppp.raw);
                    ack[2] = 2;
                    await write(dataPacket(ack));
                    if (localLcpDone) await sendAuth();
                } else if (ppp.code === 2) {
                    localLcpDone = true;
                    await sendAuth();
                }
            } else if (ppp.protocol === 0xc023) {
                if (ppp.code === 2 && !ipcpSent) {
                    await sendIpcp(new Uint8Array(4));
                } else if (ppp.code === 3) throw new Error('SSTP PAP authentication failed');
            } else if (ppp.protocol === 0x8021) {
                if (ppp.code === 1) {
                    const ack = new Uint8Array(ppp.raw);
                    ack[2] = 2;
                    await write(dataPacket(ack));
                } else if (ppp.code === 3) {
                    const option = parseOptions(ppp.payload).find(item => item.type === 3 && item.data.length === 4);
                    if (option) {
                        myIp = Array.from(option.data).join('.');
                        await sendIpcp(new Uint8Array(option.data));
                    }
                } else if (ppp.code === 2) {
                    const option = parseOptions(ppp.payload).find(item => item.type === 3 && item.data.length === 4);
                    if (option) myIp = Array.from(option.data).join('.');
                    done = true;
                }
            }
        }
        if (!myIp || !sstpIpv4Bytes(myIp)) throw new Error('SSTP did not assign an IPv4 address');
        return myIp;
    };
    const close = () => {
        if (closed) return;
        closed = true;
        try {reader?.cancel()?.catch?.(() => {})} catch {}
        try {writer?.abort?.()?.catch?.(() => {})} catch {}
        try {socket?.close()} catch {}
    };
    return {connect: connectSstp, establish, readPacket, parsePpp, dataPacket, controlPacket, handleControl, write, close, get bufferedLength() {return buffered.length}};
};
const createSstpTcp = (sstp, sourceIp, targetIp, targetPort) => {
    const sourceBytes = sstpIpv4Bytes(sourceIp), targetBytes = sstpIpv4Bytes(targetIp);
    if (!sourceBytes || !targetBytes) throw new Error('SSTP TCP requires IPv4');
    const sourcePort = 10000 + sstpRandom16() % 50000, ipTemplate = new Uint8Array(20), pseudoHeader = new Uint8Array(12 + 20 + sstpMss);
    let sequence = sstpRandom32(), acknowledgement = 0, peerWindowScale = 0;
    ipTemplate.set([0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6]), ipTemplate.set(sourceBytes, 12), ipTemplate.set(targetBytes, 16);
    pseudoHeader.set(sourceBytes), pseudoHeader.set(targetBytes, 4), pseudoHeader[9] = 6;
    const frame = (flags, payload = sstpEmpty) => {
        const syn = (flags & 0x02) !== 0, tcpOptions = syn ? new Uint8Array([2, 4, sstpMss >> 8, sstpMss & 0xff, 3, 3, sstpTcpWindowScale, 1]) : sstpEmpty;
        const tcpHeaderLength = 20 + tcpOptions.length, tcpLength = tcpHeaderLength + payload.length, ipLength = 20 + tcpLength, packetLength = 8 + ipLength, packet = new Uint8Array(packetLength), view = new DataView(packet.buffer);
        packet.set([0x10, 0, ((packetLength >> 8) & 0x0f) | 0x80, packetLength & 0xff, 0xff, 3, 0, 0x21]), packet.set(ipTemplate, 8);
        view.setUint16(10, ipLength), view.setUint16(12, sstpRandom16()), view.setUint16(18, sstpChecksum(packet, 8, 20));
        view.setUint16(28, sourcePort), view.setUint16(30, targetPort), view.setUint32(32, sequence), view.setUint32(36, acknowledgement);
        packet[40] = (tcpHeaderLength / 4) << 4, packet[41] = flags;
        view.setUint16(42, syn ? 65535 : Math.min(65535, Math.ceil(sstpTcpReceiveWindow / (1 << peerWindowScale))));
        if (tcpOptions.length) packet.set(tcpOptions, 48);
        if (payload.length) packet.set(payload, 28 + tcpHeaderLength);
        pseudoHeader[10] = tcpLength >> 8, pseudoHeader[11] = tcpLength & 0xff, pseudoHeader.set(packet.subarray(28, 28 + tcpLength), 12);
        view.setUint16(44, sstpChecksum(pseudoHeader, 0, 12 + tcpLength));
        return packet;
    };
    const match = ip => {
        if (ip.length < 40 || (ip[0] >> 4) !== 4 || ip[9] !== 6) return null;
        const ipHeaderLength = (ip[0] & 0x0f) * 4;
        if (ipHeaderLength < 20 || ip.length < ipHeaderLength + 20) return null;
        for (let i = 0; i < 4; i++) if (ip[12 + i] !== targetBytes[i] || ip[16 + i] !== sourceBytes[i]) return null;
        if (sstpU16(ip, ipHeaderLength) !== targetPort || sstpU16(ip, ipHeaderLength + 2) !== sourcePort) return null;
        const tcpHeaderLength = ((ip[ipHeaderLength + 12] >> 4) & 0x0f) * 4, dataOffset = ipHeaderLength + tcpHeaderLength;
        if (tcpHeaderLength < 20 || dataOffset > ip.length) return null;
        let windowScale = null;
        for (let offset = ipHeaderLength + 20; offset < dataOffset;) {
            const type = ip[offset];
            if (type === 0) break;
            if (type === 1) {
                offset++;
                continue;
            }
            if (offset + 1 >= dataOffset) break;
            const length = ip[offset + 1];
            if (length < 2 || offset + length > dataOffset) break;
            if (type === 3 && length === 3) windowScale = Math.min(ip[offset + 2], 14);
            offset += length;
        }
        return {flags: ip[ipHeaderLength + 13], sequence: sstpU32(ip, ipHeaderLength + 4), dataOffset, windowScale};
    };
    const handshake = async () => {
        await sstp.write(frame(0x02));
        sequence = (sequence + 1) >>> 0;
        for (let attempts = 0; attempts < 30; attempts++) {
            const packet = await sstp.readPacket(15000);
            if (packet.ctrl) {
                await sstp.handleControl(packet.body);
                continue;
            }
            const ppp = sstp.parsePpp(packet.body);
            if (!ppp || ppp.protocol !== 0x0021) continue;
            const matched = match(ppp.ip);
            if (!matched) continue;
            if (matched.flags & 0x04) throw new Error('SSTP target reset TCP handshake');
            if ((matched.flags & 0x12) === 0x12) {
                peerWindowScale = matched.windowScale ?? 0;
                acknowledgement = (matched.sequence + 1) >>> 0;
                await sstp.write(frame(0x10));
                return;
            }
        }
        throw new Error('SSTP TCP handshake timed out');
    };
    return {frame, match, handshake, get sequence() {return sequence}, set sequence(value) {sequence = value}, get acknowledgement() {return acknowledgement}, set acknowledgement(value) {acknowledgement = value}};
};
const resolveSstpTargetIpv4 = async ({addrType, addrBytes, isHttp}) => {
    const targetIp = binaryAddrToString(addrType, addrBytes);
    if (isHttp) addrType = addrTypeIs(targetIp);
    if (addrType === 1) return targetIp;
    if (addrType !== 3) return null;
    return (await concurrentDnsResolve(targetIp, 'A'))?.find(r => r.type === 1)?.data ?? null;
};
const connectViaSstpProxy = async (sstpAuth, parsedRequest) => {
    if (!sstpAuth || parsedRequest.addrType === 4) return null;
    const {hostname, port} = sstpAuth;
    if (!hostname || !(port > 0 && port <= 65535)) return null;
    const hasCredentials = !!sstpAuth.username && !!sstpAuth.password;
    const username = hasCredentials ? sstpAuth.username : 'vpn', password = hasCredentials ? sstpAuth.password : 'vpn';
    let closed = false, controller = null;
    const sstp = createSstpSession(username, password), close = () => {
        if (closed) return;
        closed = true, sstp.close();
    };
    try {
        const targetIpPromise = resolveSstpTargetIpv4(parsedRequest);
        await sstp.connect(hostname, port);
        const [sourceIp, targetIp] = await Promise.all([sstp.establish(), targetIpPromise]);
        if (!targetIp) throw new Error('SSTP target has no IPv4 address');
        const tcp = createSstpTcp(sstp, sourceIp, targetIp, parsedRequest.port);
        await tcp.handshake();
        const readable = new ReadableStream({
            type: 'bytes',
            start(streamController) {controller = streamController},
            cancel: close
        });
        (async () => {
            let pending = [], pendingLength = 0;
            const flush = () => {
                if (!pendingLength || closed) return;
                controller.enqueue(pending.length === 1 ? pending[0] : cat(...pending));
                pending = [], pendingLength = 0;
                sstp.write(tcp.frame(0x10)).catch(close);
            };
            try {
                for (; ;) {
                    const packet = await sstp.readPacket(60000);
                    if (packet.ctrl) {
                        await sstp.handleControl(packet.body);
                        continue;
                    }
                    const ppp = sstp.parsePpp(packet.body);
                    if (!ppp || ppp.protocol !== 0x0021) continue;
                    const matched = tcp.match(ppp.ip);
                    if (!matched) continue;
                    if (matched.flags & 0x04) throw new Error('SSTP target reset connection');
                    if (matched.dataOffset < ppp.ip.length) {
                        const data = ppp.ip.subarray(matched.dataOffset);
                        if (data.length) {
                            tcp.acknowledgement = (matched.sequence + data.length) >>> 0;
                            pending.push(new Uint8Array(data)), pendingLength += data.length;
                        }
                    }
                    if (matched.flags & 0x01) {
                        flush();
                        tcp.acknowledgement = (tcp.acknowledgement + 1) >>> 0;
                        await sstp.write(tcp.frame(0x11));
                        return;
                    }
                    if (sstp.bufferedLength < 4 || pendingLength >= 32768) flush();
                }
            } catch {} finally {
                try {pendingLength && flush()} catch {}
                try {controller.close()} catch {}
                close();
            }
        })();
        const writable = new WritableStream({
            async write(chunk) {
                if (closed) throw new Error('SSTP connection is closed');
                const data = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
                if (data.length <= sstpMss) {
                    const frame = tcp.frame(0x18, data);
                    tcp.sequence = (tcp.sequence + data.length) >>> 0;
                    await sstp.write(frame);
                    return;
                }
                const frames = [];
                for (let offset = 0; offset < data.length; offset += sstpMss) {
                    const segment = data.subarray(offset, Math.min(offset + sstpMss, data.length));
                    frames.push(tcp.frame(0x18, segment));
                    tcp.sequence = (tcp.sequence + segment.length) >>> 0;
                }
                await sstp.write(cat(...frames));
            },
            close() {return closed ? undefined : sstp.write(tcp.frame(0x11)).catch(close)},
            abort: close
        });
        return {readable, writable, close};
    } catch {
        close();
        return null;
    }
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
    return {type: (d[0] << 8) | d[1], attrs, tid: d.slice(8, 20)};
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
        if (done) throw new Error();
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
const connectViaTurnProxy = async ({hostname, port, username, password}, {addrType, port: targetPort, addrBytes, isHttp}, useTls = false) => {
    let targetIp = binaryAddrToString(addrType, addrBytes);
    if (isHttp) addrType = addrTypeIs(targetIp);
    if (addrType === 3) {
        targetIp = concurrentDnsResolve(targetIp, 'A').then(ans => ans?.find(r => r.type === 1)?.data ?? null).catch(() => null);
    } else if (addrType === 4) {return null}
    let ctrl = null, data = null, dataPromise = null, ctrlTls = null, dataTls = null, cw = null, cr = null, ctrlExtra = null, closed = false, refreshTimer = null;
    const proxyIsIp = addrTypeIs(hostname) !== 3;
    const close = () => {
        closed = true;
        if (refreshTimer !== null) clearTimeout(refreshTimer), refreshTimer = null;
        [ctrl, data, ctrlTls, dataTls].forEach(s => {try {s?.close()} catch {}});
        [cr, cw].forEach(lock => {try {lock?.releaseLock()} catch {}});
    };
    const createConn = async () => {
        let sock = null, tls = null, isCustom = false;
        try {
            if (useTls && proxyIsIp) {
                isCustom = true;
                sock = await concurrentConnect(hostname, port, 2, {allowHalfOpen: false});
            } else {
                try {
                    sock = await concurrentConnect(hostname, port, 2, useTls ? {secureTransport: 'on', allowHalfOpen: false} : undefined);
                } catch {
                    if (!useTls) throw new Error();
                    isCustom = true;
                    sock = await concurrentConnect(hostname, port, 2, {allowHalfOpen: false});
                }
            }
            if (isCustom) {
                tls = new TlsClient(sock, {serverName: proxyIsIp ? "" : hostname});
                await tls.handshake();
            }
            return {sock, tls, isCustom};
        } catch (e) {
            try {await tls?.close()} catch {}
            try {sock?.close()} catch {}
            throw e;
        }
    };
    const newTid = () => crypto.getRandomValues(new Uint8Array(12));
    const sameTid = (a, b) => a?.length === b?.length && a.every((v, i) => v === b[i]);
    const tidKey = tid => {
        let key = '';
        for (let i = 0; i < tid.length; i++) key += tid[i].toString(16).padStart(2, '0');
        return key;
    };
    const readMatching = async (rd, expectedTid, buffered = null, pending = null) => {
        const expectedKey = tidKey(expectedTid), cached = pending?.get(expectedKey);
        if (cached) {
            pending.delete(expectedKey);
            return [cached, buffered];
        }
        let extra = buffered;
        for (; ;) {
            const result = await readStun(rd, extra);
            if (!result) throw new Error();
            const [msg, next] = result;
            extra = next;
            if (sameTid(msg.tid, expectedTid)) return [msg, extra];
            if (pending) pending.set(tidKey(msg.tid), msg);
        }
    };
    const ctrlPending = new Map();
    const readControl = async expectedTid => {
        const [msg, extra] = await readMatching(cr, expectedTid, ctrlExtra, ctrlPending);
        ctrlExtra = extra;
        return msg;
    };
    const u32 = value => new Uint8Array([(value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255]);
    const readU32 = value => value?.length >= 4 ? value[0] * 0x1000000 + value[1] * 0x10000 + value[2] * 0x100 + value[3] : 0;
    let cryptoKey = null, aa = [], authRealm = '';
    const sign = m => cryptoKey ? addIntegrity(m, cryptoKey) : m;
    const updateAuth = async response => {
        const nonce = response?.attrs?.[0x015]?.slice();
        if (!username || !nonce?.length) return false;
        const realm = response.attrs?.[0x014]?.length ? textDecoder.decode(response.attrs[0x014]) : authRealm;
        if (!realm) return false;
        if (realm !== authRealm || !cryptoKey) {
            const keyBytes = await md5(`${username}:${realm}:${password}`);
            cryptoKey = await crypto.subtle.importKey('raw', keyBytes, {name: 'HMAC', hash: 'SHA-1'}, false, ['sign']);
        }
        authRealm = realm, aa = [stunAttr(0x006, textEncoder.encode(username)), stunAttr(0x014, textEncoder.encode(authRealm)), stunAttr(0x015, nonce)];
        return true;
    };
    const controlRequest = async (type, attrs, expectedType) => {
        for (let attempt = 0; attempt < 2; attempt++) {
            if (closed) throw new Error();
            const tid = newTid();
            await cw.write(await sign(stunMsg(type, tid, [...attrs, ...aa])));
            const response = await readControl(tid);
            if (response?.type === expectedType) return response;
            const errCode = parseErr(response?.attrs?.[0x009]);
            if ((errCode === 401 || errCode === 438) && await updateAuth(response)) continue;
            throw new Error();
        }
        throw new Error();
    };
    try {
        const ctrlPromise = createConn();
        dataPromise = createConn().then(res => {
            data = res.sock, dataTls = res.tls;
            if (closed) {
                try {res.tls?.close()} catch {}
                try {res.sock?.close()} catch {}
            }
            return res;
        });
        dataPromise.catch(() => {});
        const cRes = await ctrlPromise;
        ctrl = cRes.sock, ctrlTls = cRes.tls;
        const cIsCustom = cRes.isCustom;
        cw = cIsCustom ? {write: c => ctrlTls.write(c), releaseLock: () => {}} : ctrl.writable.getWriter();
        cr = cIsCustom ? {
            read: async () => {
                const v = await ctrlTls.read();
                return v ? {value: v, done: false} : {done: true};
            },
            releaseLock: () => {}
        } : ctrl.readable.getReader();
        let tid = newTid();
        await cw.write(stunMsg(0x003, tid, [stunAttr(0x019, new Uint8Array([6, 0, 0, 0]))]));
        let r = await readControl(tid);
        if (!r) throw new Error();
        const targetAddress = await targetIp;
        if (!targetAddress) throw new Error();
        const peer = stunAttr(0x012, xorPeer(targetAddress, targetPort));
        let permissionTid = null, connectTid = null, pm = null, cm = null;
        if (r.type === 0x113 && username && parseErr(r.attrs[0x009]) === 401) {
            const realm = textDecoder.decode(r.attrs[0x014] ?? []), nonce = r.attrs[0x015] ?? [], keyBytes = await md5(`${username}:${realm}:${password}`);
            cryptoKey = await crypto.subtle.importKey('raw', keyBytes, {name: 'HMAC', hash: 'SHA-1'}, false, ['sign']), authRealm = realm;
            aa = [stunAttr(0x006, textEncoder.encode(username)), stunAttr(0x014, textEncoder.encode(realm)), stunAttr(0x015, nonce)];
            const allocateTid = newTid();
            permissionTid = newTid(), connectTid = newTid();
            const [am, permissionMsg, connectMsg] = await Promise.all([sign(stunMsg(0x003, allocateTid, [stunAttr(0x019, new Uint8Array([6, 0, 0, 0])), ...aa])), sign(stunMsg(0x008, permissionTid, [peer, ...aa])), sign(stunMsg(0x00A, connectTid, [peer, ...aa]))]);
            pm = permissionMsg, cm = connectMsg;
            await cw.write(cat(am, pm, cm));
            r = await readControl(allocateTid);
        } else if (r.type === 0x103) {
            permissionTid = newTid(), connectTid = newTid();
            [pm, cm] = await Promise.all([sign(stunMsg(0x008, permissionTid, [peer, ...aa])), sign(stunMsg(0x00A, connectTid, [peer, ...aa]))]);
            await cw.write(cat(pm, cm));
        } else {throw new Error()}
        if (r?.type !== 0x103) throw new Error();
        let allocTtl = readU32(r.attrs?.[0x00D]) || 600;
        r = await readControl(permissionTid);
        if (r?.type !== 0x108) throw new Error();
        r = await readControl(connectTid);
        if (r?.type !== 0x10A || !r.attrs[0x02A]) throw new Error();
        const dRes = await dataPromise, dIsCustom = dRes.isCustom, dw = dIsCustom ? {write: c => dataTls.write(c), releaseLock: () => {}} : data.writable.getWriter();
        const dr = dIsCustom ? {
            read: async () => {
                const v = await dataTls.read();
                return v ? {value: v, done: false} : {done: true};
            },
            releaseLock: () => {}
        } : data.readable.getReader();
        tid = newTid();
        await dw.write(await sign(stunMsg(0x00B, tid, [stunAttr(0x02A, r.attrs[0x02A]), ...aa])));
        let extra;
        [r, extra] = await readMatching(dr, tid);
        if (r?.type !== 0x10B) throw new Error();
        if (!dIsCustom) dr.releaseLock(), dw.releaseLock();
        const tlsStream = dIsCustom ? tlsStreamAdapter(dataTls) : null, readable = tlsStream ? tlsStream.readable : data.readable, writable = tlsStream ? tlsStream.writable : data.writable;
        let retryCount = 0;
        const renew = async () => {
            if (closed) return;
            try {
                const refreshRes = await controlRequest(0x004, [stunAttr(0x00D, u32(allocTtl))], 0x104), newAllocTtl = readU32(refreshRes.attrs?.[0x00D]);
                if (newAllocTtl === 0) throw new Error();
                if (newAllocTtl > 0) allocTtl = newAllocTtl;
                retryCount = 0;
                if (!closed) refreshTimer = setTimeout(renew, Math.min(300000, Math.max(5000, Math.floor(allocTtl * 500))));
            } catch {
                if (closed) return;
                retryCount++, retryCount <= 3 ? refreshTimer = setTimeout(renew, retryCount * 2000) : close();
            }
        };
        if (!closed) refreshTimer = setTimeout(renew, Math.min(300000, Math.max(5000, Math.floor(allocTtl * 500))));
        return {readable, writable, close, extra};
    } catch {
        close();
        return null;
    }
};
const extractSniBytes = (data) => {
    if (!data || data.length === 0) return null;
    if (data[0] !== 0x16) return null;
    if (data.length < 5) return {needMore: true};
    const recordLen = (data[3] << 8) | data[4];
    if (data.length < 5 + recordLen) return {needMore: true};
    if (data[5] !== 0x01) return null;
    let offset = 43;
    if (offset >= data.length) return {needMore: true};
    offset += 1 + data[offset];
    if (offset + 2 > data.length) return {needMore: true};
    offset += 2 + ((data[offset] << 8) | data[offset + 1]);
    if (offset >= data.length) return {needMore: true};
    offset += 1 + data[offset];
    if (offset + 2 > data.length) return null;
    const extLen = (data[offset] << 8) | data[offset + 1];
    offset += 2;
    const extEnd = offset + extLen;
    if (extEnd > data.length) return {needMore: true};
    while (offset + 4 <= extEnd) {
        const extType = (data[offset] << 8) | data[offset + 1], len = (data[offset + 2] << 8) | data[offset + 3];
        offset += 4;
        if (extType === 0x0000) {
            let sniOffset = offset + 2;
            const sniEnd = offset + len;
            while (sniOffset + 3 <= sniEnd) {
                const nameType = data[sniOffset], nameLen = (data[sniOffset + 1] << 8) | data[sniOffset + 2];
                sniOffset += 3;
                if (nameType === 0x00) {
                    if (sniOffset + nameLen <= sniEnd) return {offset: sniOffset, len: nameLen};
                    return {needMore: true};
                }
                sniOffset += nameLen;
            }
        }
        offset += len;
    }
    return null;
};
const parseProtocolChunk = (chunk, socks5State) => {
    const len = chunk.length;
    const result = {success: false, needMore: false, nextSocksState: 0, handshake: null, parsedRequest: null};
    if (socks5State === 1) {
        const authLen = socks5Pkg?.length || 0;
        if (len < authLen) return result.needMore = true, result;
        let match = len === authLen;
        for (let i = 0; match && i < authLen; i++) if (chunk[i] !== socks5Pkg[i]) match = false;
        return result.handshake = new Uint8Array([1, match ? 0 : 1]), result.nextSocksState = match ? 2 : 0, result;
    }
    if (socks5State === 2) {
        if (len < 4) return result.needMore = true, result;
        if (chunk[0] !== 5 || chunk[1] !== 1) return result;
        let addrType = chunk[3];
        const addrLen = addrType === 3 ? (4 < len ? chunk[4] : null) : addrType === 1 ? 4 : addrType === 4 ? 16 : -1;
        if (addrLen === null) return result.needMore = true, result;
        if (!(addrLen > 0)) return result;
        const addrOffset = addrType === 3 ? 5 : 4, dataOffset = addrOffset + addrLen + 2;
        if (len < dataOffset) return result.needMore = true, result;
        const portOffset = dataOffset - 2, port = (chunk[portOffset] << 8) | chunk[portOffset + 1];
        result.handshake = socks5req, result.success = true, result.parsedRequest = {addrType, addrBytes: chunk.subarray(addrOffset, addrOffset + addrLen), dataOffset, port, isDns: port === 53};
        return result;
    }
    if (chunk[0] === 5) {
        if (len < 2) return result.needMore = true, result;
        const fullLen = 2 + chunk[1];
        if (len < fullLen) return result.needMore = true, result;
        const required = socks5Pkg ? 2 : 0;
        let supported = false;
        for (let i = 0; i < chunk[1]; i++) {
            if (chunk[2 + i] === required) {
                supported = true;
                break;
            }
        }
        return result.handshake = new Uint8Array([5, supported ? required : 0xFF]), result.nextSocksState = supported ? (required === 2 ? 1 : 2) : 0, result;
    }
    if (chunk[0] === 67) {
        if (len < 48) return result.needMore = true, result;
        if (chunk[1] === 79) {
            if (chunk[len - 4] !== 13 || chunk[len - 3] !== 10 || chunk[len - 2] !== 13 || chunk[len - 1] !== 10) return result.needMore = true, result;
            const secondSpace = chunk.indexOf(32, 8);
            if (secondSpace !== -1) {
                if (httpAuthValue) {
                    let matchAuth = false;
                    const searchLimit = len > 1024 ? 1024 : len;
                    for (let p = secondSpace + 30; p + httpAuthValue.length + 6 < searchLimit; p++) {
                        if (chunk[p] === 66 && chunk[p + 1] === 97 && chunk[p + 2] === 115 && chunk[p + 3] === 105 && chunk[p + 4] === 99 && chunk[p + 5] === 32) {
                            matchAuth = true;
                            for (let j = 0; j < httpAuthValue.length; j++) {
                                if (chunk[p + 6 + j] !== httpAuthValue[j]) {
                                    matchAuth = false;
                                    break;
                                }
                            }
                            if (matchAuth) break;
                        }
                    }
                    if (!matchAuth) return result.handshake = httpRes407, result;
                }
                let lastColon = -1;
                for (let i = secondSpace - 3; i >= 8; i--) {
                    if (chunk[i] === 58) {
                        lastColon = i;
                        break;
                    }
                }
                if (lastColon > 8) {
                    let port = 0;
                    for (let i = lastColon + 1, digit; i < secondSpace && (digit = chunk[i] - 48) >= 0 && digit <= 9; i++) port = port * 10 + digit;
                    result.handshake = httpRes200, result.success = true, result.parsedRequest = {addrType: 3, addrBytes: chunk.subarray(8, lastColon), dataOffset: len, port, isDns: port === 53, isHttp: true};
                    return result;
                }
            }
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
        let addrType = chunk[59];
        let addrLen = addrType === 3 ? (60 < len ? chunk[60] : null) : addrType === 1 ? 4 : addrType === 4 ? 16 : -1;
        if (addrLen === null) return result.needMore = true, result;
        if (addrLen > 0) {
            let addrOffset = addrType === 3 ? 61 : 60;
            const dataOffset = addrOffset + addrLen + 4;
            if (len < dataOffset) return result.needMore = true, result;
            const portOffset = addrOffset + addrLen, port = (chunk[portOffset] << 8) | chunk[portOffset + 1];
            if (enableSniSniff && addrType !== 3 && len >= dataOffset) {
                const sniRes = extractSniBytes(chunk.subarray(dataOffset));
                if (sniRes?.needMore) return result.needMore = true, result;
                sniRes?.len && (addrType = 3, addrOffset = dataOffset + sniRes.offset, addrLen = sniRes.len);
            }
            result.success = true, result.parsedRequest = {addrType, addrBytes: chunk.subarray(addrOffset, addrOffset + addrLen), dataOffset, port, isDns: port === 53};
            return result;
        }
    }
    if (len >= 17 &&
        chunk[1] === U0 && chunk[2] === U1 && chunk[3] === U2 && chunk[4] === U3 && chunk[5] === U4 && chunk[6] === U5 && chunk[7] === U6 && chunk[8] === U7 &&
        chunk[9] === U8 && chunk[10] === U9 && chunk[11] === U10 && chunk[12] === U11 && chunk[13] === U12 && chunk[14] === U13 && chunk[15] === U14 && chunk[16] === U15
    ) {
        if (len < 18) return result.needMore = true, result;
        const offset = 19 + chunk[17];
        if (len < offset + 4) return result.needMore = true, result;
        let addrType = chunk[offset + 2];
        if (addrType !== 1) addrType += 1;
        let addrLen = addrType === 3 ? (offset + 3 < len ? chunk[offset + 3] : null) : addrType === 1 ? 4 : addrType === 4 ? 16 : -1;
        if (addrLen === null) return result.needMore = true, result;
        if (addrLen > 0) {
            let addrOffset = addrType === 3 ? offset + 4 : offset + 3;
            const dataOffset = addrOffset + addrLen;
            if (len < dataOffset) return result.needMore = true, result;
            const port = (chunk[offset] << 8) | chunk[offset + 1];
            if (enableSniSniff && addrType !== 3 && len >= dataOffset) {
                const sniRes = extractSniBytes(chunk.subarray(dataOffset));
                if (sniRes?.needMore) return result.needMore = true, result;
                sniRes?.len && (addrType = 3, addrOffset = dataOffset + sniRes.offset, addrLen = sniRes.len);
            }
            result.handshake = new Uint8Array([chunk[0], 0]), result.success = true, result.parsedRequest = {addrType, addrBytes: chunk.subarray(addrOffset, addrOffset + addrLen), dataOffset, port, isDns: port === 53};
            return result;
        }
    }
    if (chunk[0] === 1 || chunk[0] === 3 || chunk[0] === 4) {
        if (len < 2) return result.needMore = true, result;
        let addrType = chunk[0];
        let addrLen = addrType === 3 ? (1 < len ? chunk[1] : null) : addrType === 1 ? 4 : addrType === 4 ? 16 : -1;
        if (addrLen === null) return result.needMore = true, result;
        if (addrLen > 0) {
            let addrOffset = addrType === 3 ? 2 : 1;
            const dataOffset = addrOffset + addrLen + 2;
            if (len < dataOffset) return result.needMore = true, result;
            const portOffset = dataOffset - 2, port = (chunk[portOffset] << 8) | chunk[portOffset + 1];
            if (enableSniSniff && addrType !== 3 && len >= dataOffset) {
                const sniRes = extractSniBytes(chunk.subarray(dataOffset));
                if (sniRes?.needMore) return result.needMore = true, result;
                sniRes?.len && (addrType = 3, addrOffset = dataOffset + sniRes.offset, addrLen = sniRes.len);
            }
            result.success = true, result.parsedRequest = {addrType, addrBytes: chunk.subarray(addrOffset, addrOffset + addrLen), dataOffset, port, isDns: port === 53};
            return result;
        }
    }
    if (chunk[0] !== 1 && chunk[0] !== 3 && chunk[0] !== 4 && len < 56) return result.needMore = true, result;
    return result;
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
        const ip = (await concurrentDnsResolve(hostname, 'A'))?.find(r => r.type === 1)?.data;
        return ip ? concurrentConnect(ipv4ToNat64Ipv6(ip, nat64Prefixes), port, limit) : null;
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
    [3, async (_parsedRequest, param, limit, txt) => connectProxyIp(param, limit, txt)],
    [4, async ({addrType, port, addrBytes, isHttp}, param, limit, _txt) => connectNat64(addrType, port, param.nat64Auth, addrBytes, param.proxyAll, limit, isHttp)],
    [5, async (parsedRequest, param, _limit, _txt) => connectViaTurnProxy(param, parsedRequest)],
    [7, async (parsedRequest, param, _limit, _txt) => connectViaTurnProxy(param, parsedRequest, true)],
    [8, async (parsedRequest, param, _limit, _txt) => connectViaSstpProxy(param, parsedRequest)]
]);
const concurrentStrategyExec = (parsedRequest, params, exec, limit, txt) => {
    const attempts = params.map(param => Promise.resolve().then(() => exec(parsedRequest, param, limit, txt)));
    return raceAny(attempts);
};
const paramRegex = /(speed|gs5|s5all|ghttp|httpall|ghttps|httpsall|gnat64|nat64all|gturn|turnall|gturns|turnsall|gsstp|sstpall|sstp|s5|socks|http|https|nat64|turn|turns|txtip|ip)(?:=|:\/\/|%3A%2F%2F)([^&]+)|(proxyall|globalproxy|global)/gi;
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
        if (clean.length < 6) {
            list.push({type: 0}, {type: 3}, {type: 3, param: finallyProxyHost});
        } else {
            const p = Object.create(null);
            paramRegex.lastIndex = 0;
            let m;
            while ((m = paramRegex.exec(clean))) {p[(m[1] || m[3]).toLowerCase()] = m[2] ? (m[2].charCodeAt(m[2].length - 1) === 61 ? m[2].slice(0, -1) : m[2]) : true}
            if (p.speed) speed = p.speed;
            const s5 = p.gs5 || p.s5all || p.s5 || p.socks, http = p.ghttp || p.httpall || p.http, https = p.ghttps || p.httpsall || p.https, sstp = p.gsstp || p.sstpall || p.sstp, nat64 = p.gnat64 || p.nat64all || p.nat64, turn = p.gturn || p.turnall || p.turn, turns = p.gturns || p.turnsall || p.turns;
            const proxyAll = !!(p.gs5 || p.s5all || p.ghttp || p.httpall || p.ghttps || p.httpsall || p.gsstp || p.sstpall || p.gnat64 || p.nat64all || p.gturn || p.turnall || p.gturns || p.turnsall || p.proxyall || p.globalproxy || p.global);
            if (!proxyAll) list.push({type: 0});
            const add = (v, t, txt) => {
                if (!v) return;
                const parts = decodeURIComponent(v).split(',').filter(Boolean);
                if (txt) {
                    for (let i = 0; i < parts.length; i++) list.push({type: t, param: parts[i], txt});
                } else if (parts.length) {
                    const parsedParams = parts.map(part => {
                        if (t === 4) return {nat64Auth: part, proxyAll};
                        if (t === 1 || t === 2 || t === 5 || t === 6 || t === 7) return parseAuthString(part);
                        if (t === 8) {
                            const auth = parseAuthString(part, 443);
                            return auth.username && auth.password ? auth : {...auth, username: 'vpn', password: 'vpn'};
                        }
                        return part;
                    });
                    list.push({type: t, param: parsedParams, concurrent: true});
                }
            };
            for (let i = 0; i < proxyStrategyOrder.length; i++) {
                const k = proxyStrategyOrder[i];
                add(k === 'socks' ? s5 : k === 'http' ? http : k === 'https' ? https : k === 'sstp' ? sstp : k === 'turn' ? turn : k === 'turns' ? turns : nat64, k === 'socks' ? 1 : k === 'http' ? 2 : k === 'https' ? 6 : k === 'sstp' ? 8 : k === 'turn' ? 5 : k === 'turns' ? 7 : 4);
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
    const allowNeedMore = state.allowNeedMore === true;
    if (allowNeedMore) state.needMore = false;
    let parsedRequest, payload, isSs = false;
    const ssEnabled = !state.disableSsAead && !!ssAeadPassword && !state.tcpWriter && state.socks5State === 0, parsed = parseProtocolChunk(chunk, state.socks5State);
    if (parsed.handshake) writable.send(parsed.handshake);
    if (!parsed.success) {
        if (parsed.nextSocksState > 0) return state.socks5State = parsed.nextSocksState;
        if (allowNeedMore && parsed.needMore) return state.needMore = true;
        if (ssEnabled && chunk.length >= 34) {
            try {
                const decryptCtx = await createSsAeadCtx(chunk.subarray(0, 16)), plain = await ssAeadDecryptFeed(decryptCtx, chunk.subarray(16)), plainLen = plain.length;
                if (plainLen > 0) {
                    let addrType = plain[0];
                    let addrLen = addrType === 3 ? (plainLen > 1 ? plain[1] : null) : addrType === 1 ? 4 : addrType === 4 ? 16 : -1;
                    if (addrLen !== null && addrLen > 0) {
                        let addrOffset = addrType === 3 ? 2 : 1;
                        const dataOffset = addrOffset + addrLen + 2;
                        if (plainLen >= dataOffset) {
                            const portOffset = dataOffset - 2, port = (plain[portOffset] << 8) | plain[portOffset + 1];
                            payload = plain.subarray(dataOffset);
                            if (enableSniSniff && addrType !== 3 && payload.length > 0) {
                                const sniRes = extractSniBytes(payload);
                                if (sniRes?.needMore && allowNeedMore) return state.needMore = true;
                                sniRes?.len && (addrType = 3, addrOffset = dataOffset + sniRes.offset, addrLen = sniRes.len);
                            }
                            parsedRequest = {addrType, addrBytes: plain.subarray(addrOffset, addrOffset + addrLen), dataOffset, port, isDns: port === 53};
                            const encryptCtx = await createSsAeadCtx();
                            isSs = true, state.ssInbound = decryptCtx, state.ssOutbound = encryptCtx, state.ssResponseSalt = encryptCtx.salt;
                        }
                    }
                }
            } catch {}
        }
        if (!isSs) return close();
    } else {
        state.socks5State = 0, parsedRequest = parsed.parsedRequest, payload = chunk.subarray(parsedRequest.dataOffset);
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
        state.rawTcpWriter = tcpWriter;
        const bufferedTcpWriter = state.xwebPipeTo ? (chunk) => tcpWriter.write(chunk) : createBufferedTcpWriter(tcpWriter, close);
        if (payload.byteLength) tcpWriter.write(payload);
        if (isSs || state.ssOutbound) {
            state.tcpWriter = async (c) => {
                await ssAeadDecryptFeed(state.ssInbound, c instanceof Uint8Array ? c : new Uint8Array(c), async plain => {
                    if (plain.byteLength) bufferedTcpWriter(plain);
                });
            };
            state.ssResponseSalt?.length && writable.send(state.ssResponseSalt), state.ssResponseSalt = null;
            (async () => {
                const ssSendQueue = createAsyncMicrotaskQueue(async (chunk) => {
                    const encrypted = await ssAeadEncryptChunks(state.ssOutbound, chunk);
                    encrypted.byteLength && writable.send(encrypted);
                }, close);
                state.tcpSocket.extra?.length && ssSendQueue(state.tcpSocket.extra);
                await manualPipe(state.tcpSocket.readable, {send: chunk => ssSendQueue(chunk.slice())}, close, tcpResult.speed);
            })().catch(close);
        } else {
            if (state.tcpSocket.extra?.length) await writable.send(state.tcpSocket.extra);
            state.tcpWriter = bufferedTcpWriter;
            if (state.xwebPipeTo) return;
            manualPipe(state.tcpSocket.readable, writable, close, tcpResult.speed);
        }
    }
};
const handleWebSocketConn = async (webSocket, request) => {
    const refererHeader = request.headers.get("Referer");
    const protocolHeader = refererHeader || request.headers.get("sec-websocket-protocol");
    let earlyDataHeader = null;
    if (refererHeader) {earlyDataHeader = protocolHeader.slice(request.headers.get("host").length)} else if (protocolHeader) {earlyDataHeader = protocolHeader}
    const earlyData = earlyDataHeader ? Uint8Array.fromBase64(earlyDataHeader, {alphabet: "base64url"}) : null;
    const state = {socks5State: 0, tcpWriter: null, tcpSocket: null, ssInbound: null, ssOutbound: null, ssResponseSalt: null};
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
    const state = {socks5State: 0, tcpWriter: null, tcpSocket: null, needMore: false, allowNeedMore: true, disableSsAead: true, xwebPipeTo: true};
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
