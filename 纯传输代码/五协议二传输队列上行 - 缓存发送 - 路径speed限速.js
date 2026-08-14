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
const dnsStrategyOrder = ['ipv6', 'ipv4', 'hostname'];//socket获取地址类型连接优先级（可以只指定其中一个）
// ---------------------------------------------------------------------------------
const urlParamCacheLimit = 20;//URL参数解析结果缓存条数
// ---------------------------------------------------------------------------------
//出站socket获取顺序，全局模式下按数组顺序，非全局为：直连>socks>http>https>sstp>turn>turns>nat64>proxyip>finallyProxyHost
/**- **警告**: snippets只支持最大两次connect，所以snippets全局nat64不能使用域名访问，snippets访问cf失败的备用只有第一个有效*/
const proxyStrategyOrder = ['socks', 'http', 'https', 'sstp', 'turn', 'turns', 'nat64'];
const dohEndpoints = ['https://cloudflare-dns.com/dns-query', 'https://dns.google/dns-query'];
const dohNatEndpoints = ['https://cloudflare-dns.com/dns-query', 'https://dns.google/resolve'];
const proxyIpAddrs = {EU: 'eu.proxy.58807.de5.net', AS: 'sg.proxy.58807.de5.net', JP: 'jp.proxy.58807.de5.net', US: 'us.proxy.58807.de5.net'};//分区域proxyip
const finallyProxyHost = 'proxy.58807.de5.net';//兜底proxyip
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
const uuidBytes = new Uint8Array(16), hashBytes = new Uint8Array(56), offsets = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 4, 4, 4, 4];
for (let i = 0, c; i < 16; i++) uuidBytes[i] = (((c = uuid.charCodeAt(i * 2 + offsets[i])) > 64 ? c + 9 : c) & 0xF) << 4 | (((c = uuid.charCodeAt(i * 2 + offsets[i] + 1)) > 64 ? c + 9 : c) & 0xF);
for (let i = 0; i < 56; i++) hashBytes[i] = passWordSha224.charCodeAt(i);
const [textEncoder, textDecoder, socks5req] = [new TextEncoder(), new TextDecoder(), new Uint8Array([5, 0, 0, 1, 0, 0, 0, 0, 0, 0])];
let socks5Pkg, httpAuthValue;
const httpRes200 = textEncoder.encode("HTTP/1.1 200 Connection Established\r\n\r\n"), httpRes407 = textEncoder.encode("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\n\r\n");
if (socks5AndHttpUser && socks5AndHttpPass) {
    httpAuthValue = textEncoder.encode(btoa(`${socks5AndHttpUser}:${socks5AndHttpPass}`));
    const userBytes = textEncoder.encode(socks5AndHttpUser), passBytes = textEncoder.encode(socks5AndHttpPass);
    socks5Pkg = new Uint8Array(3 + userBytes.length + passBytes.length);
    socks5Pkg[0] = 1, socks5Pkg[1] = userBytes.length, socks5Pkg.set(userBytes, 2), socks5Pkg[2 + userBytes.length] = passBytes.length, socks5Pkg.set(passBytes, 3 + userBytes.length);
}
const html = `<body style=margin:0;overflow:hidden;background:#000><canvas id=c style=width:100vw;height:100vh><script>var C=document.getElementById("c"),g=C.getContext("webgl"),t=0,P,R,F,U,O,X,Y,L,T,b=.4,K="float L(vec3 v){vec3 a=v;float b,c,d;for(int i=0;i<5;i++){b=length(a);c=atan(a.y,a.x)*10.;d=acos(a.z/b)*10.;b=pow(b,8.);a=vec3(b*sin(d)*cos(c),b*sin(d)*sin(c),b*cos(d))+v;if(b>6.)break;}return 4.-dot(a,a);}",VS="attribute vec4 p;varying vec3 d,ld;uniform vec3 r,f,u;uniform float x,y;void main(){gl_Position=p;d=f+r*p.x*x+u*p.y*y;ld=vec3(p.x*x,p.y*y,-1.);}",FS="precision highp float;float L(vec3 v);uniform vec3 r,f,u,o;uniform float t;varying vec3 d,ld;uniform float l;void main(){vec3 tc=vec3(0);for(int i=0;i<4;i++){vec2 of=vec2(mod(float(i),2.),floor(float(i)/2.))*.5;vec3 rd=normalize(d+r*of.x*.001+u*of.y*.001),c=vec3(0);float s=.002*l,r1,r2,r3;for(int k=2;k<1200;k++){float ds=s*float(k);vec3 p=o+rd*ds;if(L(p)>0.){r1=s*float(k-1);r2=ds;for(int j=0;j<24;j++){r3=(r1+r2)*.5;if(L(o+rd*r3)>0.)r2=r3;else r1=r3;}vec3 v=o+rd*r3,nw;float e=r3*1e-4;nw=normalize(vec3(L(v-r*e)-L(v+r*e),L(v-u*e)-L(v+u*e),L(v+f*e)-L(v-f*e)));vec3 rf=reflect(normalize(ld),nw);float d2=dot(v,v),lt=pow(max(0.,dot(rf,vec3(.276,.92,.276))),4.)*.45+max(0.,dot(nw,vec3(.276,.92,.276)))*.25+.3;c=(sin(d2*5.+t+vec3(0,2,4))*.5+.5)*lt;break;}}tc+=c;}gl_FragColor=vec4(pow(tc*.25,vec3(.7)),1);}";function i(){var s=g.createProgram(),v=g.createShader(35633),f=g.createShader(35632);g.shaderSource(v,VS),g.compileShader(v),g.shaderSource(f,FS+K),g.compileShader(f),g.attachShader(s,v),g.attachShader(s,f),g.linkProgram(s),g.useProgram(s),P=g.getAttribLocation(s,"p"),R=g.getUniformLocation(s,"r"),F=g.getUniformLocation(s,"f"),U=g.getUniformLocation(s,"u"),O=g.getUniformLocation(s,"o"),X=g.getUniformLocation(s,"x"),Y=g.getUniformLocation(s,"y"),L=g.getUniformLocation(s,"l"),T=g.getUniformLocation(s,"t"),g.bindBuffer(34962,g.createBuffer()),g.bufferData(34962,new Float32Array([-1,-1,0,1,-1,0,1,1,0,-1,-1,0,1,1,0,-1,1,0]),35044),g.vertexAttribPointer(P,3,5126,!1,0,0),g.enableVertexAttribArray(P)}function w(){t+=.02,innerWidth*devicePixelRatio!=C.width&&(C.width=innerWidth*(d=devicePixelRatio||1),C.height=innerHeight*d,g.viewport(0,0,C.width,C.height));var v=C.width/C.height;g.uniform1f(X,v>1?v:1),g.uniform1f(Y,v>1?1:1/v),g.uniform1f(L,1.6),g.uniform1f(T,t),g.uniform3f(O,1.6*Math.cos(t*.5)*Math.cos(b),1.6*Math.sin(b),1.6*Math.sin(t*.5)*Math.cos(b)),g.uniform3f(R,Math.sin(t*.5),0,-Math.cos(t*.5)),g.uniform3f(U,-Math.sin(b)*Math.cos(t*.5),Math.cos(b),-Math.sin(b)*Math.sin(t*.5)),g.uniform3f(F,-Math.cos(t*.5)*Math.cos(b),-Math.sin(b),-Math.sin(t*.5)*Math.cos(b)),g.drawArrays(4,0,6),requestAnimationFrame(w)}i(),w()</script>`;
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
const addrTypeIs = (hostname) => {
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
const shuffleDnsCandidates = (ipv6 = [], ipv4 = [], hostname) => {
    const shuffle = records => {
        records = records.slice();
        for (let i = records.length - 1; i > 0; i--) {
            const j = (Math.random() * (i + 1)) | 0;
            [records[i], records[j]] = [records[j], records[i]];
        }
        return records;
    };
    return dnsStrategyOrder.flatMap(strategy =>
        strategy === 'ipv6' ? shuffle(ipv6) :
            strategy === 'ipv4' ? shuffle(ipv4) :
                (strategy === 'hostname' && hostname) ? [hostname] : []
    );
};
const connectCandidates = (candidates, port, limit, socketOptions) => {
    if (candidates.length === 1) {
        if (limit === 1) return createConnect(candidates[0], port, socketOptions);
        candidates = Array(limit).fill(candidates[0]);
    }
    let settled = false, winner = null;
    let next = 0, failed = 0;
    const sockets = new Set();
    const closeSocket = socket => {try {socket?.close()} catch {}};
    return new Promise((resolve, reject) => {
        const launch = () => {
            if (settled) return;
            if (failed >= candidates.length) {
                settled = true;
                for (const socket of sockets) closeSocket(socket);
                return reject(new Error());
            }
            while (sockets.size < limit && next < candidates.length) {
                const candidate = candidates[next++], socket = connect({hostname: candidate, port}, socketOptions);
                sockets.add(socket);
                createConnect(candidate, port, socketOptions, socket).then(openedSocket => {
                    if (settled) return closeSocket(openedSocket);
                    settled = true, winner = openedSocket;
                    for (const other of sockets) if (other !== winner) closeSocket(other);
                    resolve(openedSocket);
                }, () => {
                    sockets.delete(socket), closeSocket(socket), failed++;
                    launch();
                });
            }
        };
        launch();
    });
};
const concurrentConnect = async (hostname, port, limit = concurrency, socketOptions, addrType) => {
    if (addrType !== 3) return connectCandidates([hostname], port, limit, socketOptions);
    if (dnsStrategyOrder.length === 1 && dnsStrategyOrder[0] === 'hostname') {
        return connectCandidates([hostname], port, limit, socketOptions);
    }
    const cached = await getDnsConnectCache(hostname);
    const candidates = shuffleDnsCandidates(cached.ipv6, cached.ipv4, hostname);
    try {
        return await connectCandidates(candidates, port, limit, socketOptions);
    } catch (err) {
        const refreshed = cached.refreshing ? await cached.refreshing : null;
        if (refreshed && refreshed !== cached) {
            const refreshedCandidates = shuffleDnsCandidates(refreshed.ipv6, refreshed.ipv4, hostname);
            return connectCandidates(refreshedCandidates, port, limit, socketOptions);
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
const {TlsClient} = (() => {
    const e = 769, t = 771, n = 772, r = 20, i = 21, s = 22, a = 23, h = 1, c = 2, o = 4, l = 8, f = 11, u = 12, y = 13, p = 14, w = 15, d = 16, g = 20, v = 0, A = 10, S = 11, m = 13, C = 43, H = 45, T = 51, E = 0, L = new TextEncoder, P = new Uint8Array(0),
        U = new Map([[4865, {id: 4865, keyLen: 16, ivLen: 12, hash: "SHA-256", tls13: !0}], [4866, {id: 4866, keyLen: 32, ivLen: 12, hash: "SHA-384", tls13: !0}], [49199, {id: 49199, keyLen: 16, ivLen: 4, hash: "SHA-256", kex: "ECDHE"}], [49200, {id: 49200, keyLen: 32, ivLen: 4, hash: "SHA-384", kex: "ECDHE"}], [49195, {id: 49195, keyLen: 16, ivLen: 4, hash: "SHA-256", kex: "ECDHE"}], [49196, {id: 49196, keyLen: 32, ivLen: 4, hash: "SHA-384", kex: "ECDHE"}]]),
        I = new Map([[29, "X25519"], [23, "P-256"]]), x = [2052, 2053, 2054, 2055, 2056, 2057, 2058, 2059, 1027, 1283, 1539, 1025, 1281, 1537, 513, 515];
    const _ = (...e) => {
        const calc = a => {
            let l = 0;
            for (const x of a) {if (x instanceof Uint8Array) l += x.length; else if (Array.isArray(x)) l += calc(x); else if (typeof x === "number") l += 1}
            return l
        };
        const res = new Uint8Array(calc(e));
        let off = 0;
        const fill = a => {for (const x of a) {if (x instanceof Uint8Array) {res.set(x, off), off += x.length} else if (Array.isArray(x)) {fill(x)} else if (typeof x === "number") {res[off++] = x}}};
        fill(e);
        return res
    };
    const B = e => [e >> 8 & 255, 255 & e], R = (e, t) => e[t] << 8 | e[t + 1], M = (e, t) => e[t] << 16 | e[t + 1] << 8 | e[t + 2], W = (...e) => {
        const t = e.filter(e => e && e.length > 0), n = t.reduce((e, t) => e + t.length, 0), r = new Uint8Array(n);
        let i = 0;
        for (const e of t) r.set(e, i), i += e.length;
        return r
    }, D = e => crypto.getRandomValues(new Uint8Array(e)), q = e => "SHA-384" === e ? 48 : 32;
    const LB = {key: L.encode("tls13 key"), iv: L.encode("tls13 iv"), derived: L.encode("tls13 derived"), finished: L.encode("tls13 finished"), chs: L.encode("tls13 c hs traffic"), shs: L.encode("tls13 s hs traffic"), cap: L.encode("tls13 c ap traffic"), sap: L.encode("tls13 s ap traffic")};
    async function $(e, t, n) {
        const r = t.type === "secret" ? t : await crypto.subtle.importKey("raw", t, {name: "HMAC", hash: e}, !1, ["sign"]);
        return new Uint8Array(await crypto.subtle.sign("HMAC", r, n))
    }
    async function G(e, t) {return new Uint8Array(await crypto.subtle.digest(e, t))}
    async function V(e, t, n, r, i = "SHA-256") {
        const s = W(L.encode(t), n);
        let a = new Uint8Array(0), h = s;
        const k = e.type === "secret" ? e : await crypto.subtle.importKey("raw", e, {name: "HMAC", hash: i}, !1, ["sign"]);
        for (; a.length < r;) {
            h = await $(i, k, h);
            const t = await $(i, k, W(h, s));
            a = W(a, t)
        }
        return a.slice(0, r)
    }
    async function X(e, t, n) {return t && t.length || (t = new Uint8Array(q(e))), $(e, t, n)}
    async function O(e, t, n, r, i) {
        const s = typeof n === "string" ? LB[n] || L.encode("tls13 " + n) : n, hl = q(e), blocks = Math.ceil(i / hl), info = _(B(i), s.length, s, r.length, r);
        let a = new Uint8Array(0), h = new Uint8Array(0);
        const k = t.type === "secret" ? t : await crypto.subtle.importKey("raw", t, {name: "HMAC", hash: e}, !1, ["sign"]);
        for (let j = 1; j <= blocks; j++) h = await $(e, k, W(h, info, [j])), a = W(a, h);
        return a.slice(0, i)
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
        const r = await crypto.subtle.importKey("raw", t, {name: "ECDH", namedCurve: n}, !1, []);
        return new Uint8Array(await crypto.subtle.deriveBits({name: "ECDH", public: r}, e, 256))
    }
    async function J(e, t) {return crypto.subtle.importKey("raw", e, {name: "AES-GCM"}, !1, [t])}
    async function j(e, t, n, r) {return new Uint8Array(await crypto.subtle.encrypt({name: "AES-GCM", iv: t, additionalData: r, tagLength: 128}, e, n))}
    async function z(e, t, n, r) {return new Uint8Array(await crypto.subtle.decrypt({name: "AES-GCM", iv: t, additionalData: r, tagLength: 128}, e, n))}
    function ie(e, n, r = t) {
        const out = new Uint8Array(5 + n.length);
        out[0] = e, out[1] = r >> 8, out[2] = 255 & r, out[3] = n.length >> 8, out[4] = 255 & n.length, out.set(n, 5);
        return out
    }
    function se(e, t) {
        const out = new Uint8Array(4 + t.length);
        out[0] = e, out[1] = t.length >> 16 & 255, out[2] = t.length >> 8 & 255, out[3] = 255 & t.length, out.set(t, 4);
        return out
    }
    class ae {
        constructor() {this.b = new Uint8Array(32768), this.h = 0, this.t = 0}
        feed(e) {
            if (this.t + e.length > this.b.length) {
                if (this.t - this.h + e.length > this.b.length) {
                    const nb = new Uint8Array(Math.max(this.b.length * 2, this.t - this.h + e.length));
                    nb.set(this.b.subarray(this.h, this.t), 0), this.b = nb
                } else {this.b.copyWithin(0, this.h, this.t)}
                this.t -= this.h, this.h = 0
            }
            this.b.set(e, this.t), this.t += e.length
        }
        next() {
            if (this.t - this.h < 5) return null;
            const e = this.b[this.h], t = R(this.b, this.h + 1), n = R(this.b, this.h + 3);
            if (n > 18432) throw new Error;
            if (this.t - this.h < 5 + n) return null;
            const r = this.b.subarray(this.h + 5, this.h + 5 + n);
            this.h += 5 + n;
            if (this.h === this.t) this.h = this.t = 0;
            return {type: e, version: t, length: n, fragment: r}
        }
    }
    class he {
        constructor() {this.b = new Uint8Array(4096), this.h = 0, this.t = 0}
        feed(e) {
            if (this.t + e.length > this.b.length) {
                if (this.t - this.h + e.length > this.b.length) {
                    const nb = new Uint8Array(Math.max(this.b.length * 2, this.t - this.h + e.length));
                    nb.set(this.b.subarray(this.h, this.t), 0), this.b = nb
                } else {this.b.copyWithin(0, this.h, this.t)}
                this.t -= this.h, this.h = 0
            }
            this.b.set(e, this.t), this.t += e.length
        }
        next() {
            if (this.t - this.h < 4) return null;
            const e = this.b[this.h], t = M(this.b, this.h + 1);
            if (this.t - this.h < 4 + t) return null;
            const n = this.b.subarray(this.h + 4, this.h + 4 + t), r = this.b.subarray(this.h, this.h + 4 + t);
            this.h += 4 + t;
            if (this.h === this.t) this.h = this.t = 0;
            return {type: e, length: t, body: n, raw: r}
        }
    }
    const Z0 = e => e && 1 === e[0] && 112 === e[1];
    function ue(e, n, r, {sessionId: id = P} = {}) {
        const c = [4865, 4866, 49199, 49200, 49195, 49196], o = _(...c.flatMap(B)), l = [_(255, 1, 0, 1, 0)];
        if (n) {
            const e = L.encode(n), t = _(0, B(e.length), e);
            l.push(_(B(v), B(t.length + 2), B(t.length), t))
        }
        l.push(_(B(S), 0, 2, 1, 0));
        const gb = _(0, 29, 0, 23);
        l.push(_(B(A), B(gb.length + 2), B(gb.length), gb));
        const f = _(...x.flatMap(B));
        l.push(_(B(m), B(f.length + 2), B(f.length), f)), l.push(_(B(C), 0, 5, 4, 3, 4, 3, 3)), l.push(_(B(H), 0, 2, 1, 1));
        const ks = W(_(0, 29, B(r.x25519.length), r.x25519), _(0, 23, B(r.p256.length), r.p256));
        l.push(_(B(T), B(ks.length + 2), B(ks.length), ks));
        const y = W(...l);
        return se(h, _(B(t), e, id.length, id, B(o.length), o, 1, 0, B(y.length), y))
    }
    const we = async (e, t, n, r, i) => {
        const k = t.type === "secret" ? t : await crypto.subtle.importKey("raw", t, {name: "HMAC", hash: e}, !1, ["sign"]), [s, a] = await Promise.all([O(e, k, "key", P, n), O(e, k, "iv", P, r)]);
        return [await J(s, i), a]
    }, de = e => {
        let t = e.length - 1;
        for (; t >= 0 && 0 === e[t];) t--;
        if (t < 0) throw new Error;
        return {data: e.subarray(0, t), type: e[t]}
    };
    const mkIv = (iv, seq) => {
        const out = iv.slice();
        for (let i = 0; i < 8; i++) out[out.length - 1 - i] ^= Number(seq >> BigInt(8 * i) & 0xffn);
        return out
    };
    class TlsClient {
        constructor(e, t = {}) {this.sk = e, this.sn = t.serverName || "", this.cr = D(32), this.id = D(32), this.sr = null, this.hb = new Uint8Array(8192), this.hl = 0, this.hc = !1, this.cs = null, this.cc = null, this.i3 = !1, this.ms = null, this.hs = null, this.ck = null, this.wk = null, this.cv = null, this.wv = null, this.ch = null, this.sh = null, this.ci = null, this.si = null, this.ak = null, this.bk = null, this.ai = null, this.bi = null, this.cn = 0n, this.qn = 0n, this.rp = new ae, this.hp = new he, this.kp = new Map, this.pq = [], this.cl = !1, this.cg = !1, this.fl = !1, this.wq = Promise.resolve(), this.cp = null, this.rb = new Uint8Array(65536), this.rd = null, this.wr = null}
        rh(e) {
            if (this.hl + e.length > this.hb.length) {
                const nb = new Uint8Array(Math.max(this.hb.length * 2, this.hl + e.length));
                nb.set(this.hb.subarray(0, this.hl), 0);
                this.hb = nb
            }
            this.hb.set(e, this.hl), this.hl += e.length
        }
        ts() {return this.hb.subarray(0, this.hl)}
        fc() {return this.cn++}
        fs() {return this.qn++}
        fail() {this.fl = !0, this.cl = !0, this.sk?.close()}
        async rc() {
            const r = await this.rd.read(this.rb);
            if (r) {
                if (!r.done && r.value) this.rb = new Uint8Array(r.value.buffer);
                return r
            }
            throw new Error
        }
        async pr(t) {
            for (; ;) {
                let r;
                for (; r = this.rp.next();) if (await t(r)) return;
                const {value: i, done: s} = await this.rc();
                if (s) throw new Error;
                this.rp.feed(i)
            }
        }
        async handshake() {
            const [t, n] = await Promise.all([F("P-256"), F("X25519")]);
            this.kp = new Map([[23, t], [29, n]]), this.rd = this.sk.readable.getReader({mode: "byob"}), this.wr = this.sk.writable.getWriter();
            try {
                const x = {p256: t.pk, x25519: n.pk}, h = ue(this.cr, this.sn, x, {sessionId: this.id});
                this.rh(h), await this.wr.write(ie(s, h, e));
                let o = await this.rsh();
                if (o.isTls13) {
                    const _n = o, _h = I.get(_n.ks?.group);
                    if (!_h || !_n.ks?.key?.length) throw new Error;
                    const _ep = this.kp.get(_n.ks.group);
                    if (!_ep) throw new Error;
                    const _c = this.cc.hash, _o2 = q(_c), _u = this.cc.keyLen, _p = this.cc.ivLen, _d = await Y(_ep.kp.privateKey, _n.ks.key, _h), _k = await X(_c, null, new Uint8Array(_o2)), _v = await O(_c, _k, "derived", await G(_c, P), _o2);
                    this.hs = await X(_c, _v, _d);
                    const _A = await G(_c, this.ts()), _S = await O(_c, this.hs, "chs", _A, _o2), _m = await O(_c, this.hs, "shs", _A, _o2);
                    [this.ch, this.ci] = await we(_c, _S, _u, _p, "encrypt"), [this.sh, this.si] = await we(_c, _m, _u, _p, "decrypt");
                    let _C = !1, _rq = !1;
                    const _H = async e => {
                        this.rh(e.raw);
                        if (e.type === y) _rq = !0; else if (e.type === g) _C = !0
                    };
                    await this.pr(async e => {
                        if (e.type === r || e.type === s) return;
                        if (e.type === i) {
                            if (Z0(e.fragment)) return;
                            throw new Error
                        }
                        if (e.type !== a) return;
                        const d13h_t = mkIv(this.si, this.fs()), d13h_n = new Uint8Array([a, 3, 3, e.fragment.length >> 8, 255 & e.fragment.length]), d13h_r = await z(this.sh, d13h_t, e.fragment, d13h_n), {data: _t5, type: _n5} = de(d13h_r);
                        if (_n5 === s) {
                            this.hp.feed(_t5);
                            for (let _e3; _e3 = this.hp.next();) if (await _H(_e3), _C) return 1
                        }
                    });
                    const _T = await G(_c, this.ts()), _E = await O(_c, this.hs, "derived", await G(_c, P), _o2), _L = await X(_c, _E, new Uint8Array(_o2)), _K = await O(_c, _L, "cap", _T, _o2), _U = await O(_c, _L, "sap", _T, _o2);
                    [this.ak, this.ai] = await we(_c, _K, _u, _p, "encrypt"), [this.bk, this.bi] = await we(_c, _U, _u, _p, "decrypt");
                    let _ct = P;
                    if (_rq) _ct = se(f, _(0, 0, 0, 0)), this.rh(_ct);
                    const _x2 = await O(_c, _S, "finished", P, _o2), __2 = await $(_c, _x2, await G(_c, this.ts())), _B2 = se(g, __2);
                    this.rh(_B2);
                    const e13h_arg = W(_ct, _B2, [s]), e13h_t = mkIv(this.ci, this.fc()), e13h_n = new Uint8Array([a, 3, 3, e13h_arg.length + 16 >> 8, 255 & e13h_arg.length + 16]);
                    await this.wr.write(ie(a, await j(this.ch, e13h_t, e13h_arg, e13h_n))), this.cn = 0n, this.qn = 0n
                } else {
                    let _n = null, _a2 = !1, _rq = !1;
                    const _t = async e => {
                        switch (e.type) {
                            case f:
                                this.rh(e.raw);
                                break;
                            case u: {
                                this.rh(e.raw);
                                let _t2 = 1;
                                const _n2 = R(e.body, _t2);
                                _t2 += 2;
                                const _r2 = e.body[_t2++];
                                _n = {nc: _n2, spk: e.body.subarray(_t2, _t2 + _r2)};
                                break
                            }
                            case p:
                                return this.rh(e.raw), _a2 = !0, 1;
                            case y:
                                this.rh(e.raw), _rq = !0;
                                break;
                            default:
                                this.rh(e.raw)
                        }
                    };
                    let _ph_done = false;
                    for (let _e; _e = this.hp.next();) if (await _t(_e)) {
                        _ph_done = true;
                        break
                    }
                    if (!_ph_done) {
                        await this.pr(async _e => {
                            if (_e.type === i) {
                                if (Z0(_e.fragment)) return;
                                throw new Error
                            }
                            if (_e.type === s) {
                                this.hp.feed(_e.fragment);
                                for (let _e2; _e2 = this.hp.next();) if (await _t(_e2)) return 1
                            }
                        })
                    }
                    if (!_a2) throw new Error;
                    if (!_n) throw new Error;
                    const _h = I.get(_n.nc);
                    if (!_h) throw new Error;
                    const _c = this.kp.get(_n.nc);
                    if (!_c) throw new Error;
                    if (_rq) {
                        const ec = se(f, _(0, 0, 0));
                        this.rh(ec), await this.wr.write(ie(s, ec))
                    }
                    const _o2 = await Y(_c.kp.privateKey, _n.spk, _h), _l = se(d, _(_c.pk.length, _c.pk));
                    this.rh(_l);
                    const _w = this.cc.hash;
                    this.ms = await V(_o2, "master secret", W(this.cr, this.sr), 48, _w);
                    const _k = this.cc.keyLen, _v = this.cc.ivLen, _A = await V(this.ms, "key expansion", W(this.sr, this.cr), 2 * _k + 2 * _v, _w);
                    [this.ck, this.wk] = await Promise.all([J(_A.subarray(0, _k), "encrypt"), J(_A.subarray(_k, 2 * _k), "decrypt")]), this.cv = _A.subarray(2 * _k, 2 * _k + _v), this.wv = _A.subarray(2 * _k + _v, 2 * _k + 2 * _v), await this.wr.write(ie(s, _l)), await this.wr.write(ie(r, _(1)));
                    const _S = await V(this.ms, "client finished", await G(_w, this.ts()), 12, _w), _m = se(g, _S);
                    this.rh(_m), await this.wr.write(ie(s, await this.e12(_m, s)));
                    let _b = !1;
                    await this.pr(async e => {
                        if (e.type === i) {
                            if (Z0(e.fragment)) return;
                            throw new Error
                        }
                        if (e.type === r) return void (_b = !0);
                        if (e.type !== s || !_b) return;
                        const _t3 = await this.d12(e.fragment, s);
                        if (_t3[0] === g) return 1
                    })
                }
                this.hc = !0, this.cr = this.id = this.sr = this.ms = this.hs = this.ch = this.sh = this.ci = this.si = null, this.kp.clear(), this.kp = null
            } finally {
                if (!this.hc || this.fl) {
                    try {this.rd?.releaseLock()} catch {}
                    try {this.wr?.releaseLock()} catch {}
                }
            }
        }
        async rsh() {
            for (; ;) {
                const {value: t, done: n} = await this.rc();
                if (n) throw new Error;
                let r;
                for (this.rp.feed(t); r = this.rp.next();) {
                    if (r.type === i) {
                        if (Z0(r.fragment)) continue;
                        throw new Error
                    }
                    if (r.type !== s) continue;
                    let e;
                    for (this.hp.feed(r.fragment); e = this.hp.next();) {
                        if (e.type !== c) continue;
                        this.rh(e.raw);
                        let _t = 0;
                        const _r = R(e.body, _t);
                        _t += 2;
                        const _i = e.body.subarray(_t, _t + 32);
                        _t += 32;
                        const _s = e.body[_t++], _a = e.body.subarray(_t, _t + _s);
                        _t += _s;
                        const _h = R(e.body, _t);
                        _t += 2;
                        const _c = e.body[_t++];
                        let _o = _r, _l = null;
                        if (_t < e.body.length) {
                            const n2 = R(e.body, _t);
                            _t += 2;
                            const r2 = _t + n2;
                            for (; _t + 4 <= r2;) {
                                const n3 = R(e.body, _t);
                                _t += 2;
                                const r3 = R(e.body, _t);
                                _t += 2;
                                const i2 = e.body.subarray(_t, _t + r3);
                                if (_t += r3, n3 === C && r3 >= 2) {_o = R(i2, 0)} else if (n3 === T && r3 >= 2) {
                                    const e2 = R(i2, 0), t2 = r3 >= 4 ? R(i2, 2) : 0;
                                    _l = {group: e2, key: t2 ? i2.subarray(4, 4 + t2) : P}
                                }
                            }
                        }
                        const t2 = {version: _r, sr: _i, sid: _a, cs: _h, comp: _c, sv: _o, ks: _l, isTls13: _o === 772}, n4 = U.get(t2.cs) || null;
                        if (!n4 || t2.comp || t2.isTls13 !== !!n4.tls13 || !t2.isTls13 && t2.sv !== 771) throw new Error;
                        return this.sr = t2.sr, this.cs = t2.cs, this.cc = n4, this.i3 = t2.isTls13, t2
                    }
                }
            }
        }
        async e12(e, n, r = this.fc()) {
            const exp = new Uint8Array(8);
            new DataView(exp.buffer).setBigUint64(0, r, !1);
            const aad = new Uint8Array(13);
            aad.set(exp, 0), aad[8] = n, aad[9] = 3, aad[10] = 3, aad[11] = e.length >> 8, aad[12] = 255 & e.length;
            const iv = new Uint8Array(this.cv.length + 8);
            iv.set(this.cv, 0), iv.set(exp, this.cv.length);
            const ct = await j(this.ck, iv, e, aad), out = new Uint8Array(8 + ct.length);
            out.set(exp, 0), out.set(ct, 8);
            return out
        }
        async d12(e, n, r = this.fs()) {
            const exp = new Uint8Array(8);
            new DataView(exp.buffer).setBigUint64(0, r, !1);
            const seqIv = e.subarray(0, 8), ct = e.subarray(8), aad = new Uint8Array(13);
            aad.set(exp, 0), aad[8] = n, aad[9] = 3, aad[10] = 3, aad[11] = ct.length - 16 >> 8, aad[12] = 255 & ct.length - 16;
            const iv = new Uint8Array(this.wv.length + 8);
            iv.set(this.wv, 0), iv.set(seqIv, this.wv.length);
            return z(this.wk, iv, ct, aad)
        }
        async e13(e, n = this.fc(), r = a) {
            const t = new Uint8Array(e.length + 1);
            t.set(e, 0), t[e.length] = r;
            const iv = mkIv(this.ai, n), aad = new Uint8Array([a, 3, 3, t.length + 16 >> 8, 255 & t.length + 16]);
            return j(this.ak, iv, t, aad)
        }
        async d13(e, n = this.fs(), r = this.bk, i = this.bi) {
            const iv = mkIv(i, n), aad = new Uint8Array([a, 3, 3, e.length >> 8, 255 & e.length]), c = await z(r, iv, e, aad);
            return de(c)
        }
        write(e) {
            if (!this.hc || this.fl || this.cg) return Promise.reject(new Error);
            const t = this.wq.then(async () => {
                if (this.fl || this.cg) throw new Error;
                if (e.length <= 16384) {await this.wr.write(ie(a, this.i3 ? await this.e13(e) : await this.e12(e, a)))} else {
                    for (let n = 0; n < e.length;) {
                        const r = [];
                        for (let i = 0; i < 8 && n < e.length; i++, n += 16384) {
                            const i2 = e.subarray(n, Math.min(n + 16384, e.length)), s2 = this.fc();
                            r.push(this.i3 ? this.e13(i2, s2).then(e => ie(a, e)) : this.e12(i2, a, s2).then(e => ie(a, e)))
                        }
                        await this.wr.write(W(...await Promise.all(r)))
                    }
                }
            }), n = t.catch(e => {
                this.fail();
                throw e
            });
            return this.wq = n.catch(() => {}), n
        }
        read() {
            if (this.fl || !this.hc) return Promise.reject(new Error);
            return (async () => {
                for (; ;) {
                    if (this.pq.length) {
                        const res = this.pq.length === 1 ? this.pq[0] : W(...this.pq);
                        this.pq = [];
                        return res
                    }
                    if (this.cl) return null;
                    const e = [];
                    let n;
                    for (; e.length < 8 && (n = this.rp.next());) {
                        if (this.i3) {
                            if (n.type === r) continue;
                            if (n.type !== a) throw new Error
                        } else if (n.type !== a && n.type !== i && n.type !== s) throw new Error;
                        e.push(n)
                    }
                    if (e.length) {
                        if (!this.i3) {
                            const t = this.qn, n = await Promise.all(e.map((e, n) => this.d12(e.fragment, e.type, t + BigInt(n))));
                            this.qn = t + BigInt(e.length);
                            for (let t = 0; t < n.length; t++) {
                                const _e = n[t], _t = e[t].type;
                                if (_t === a) {this.pq.push(_e)} else if (_t === i) {this.pa(_e)} else if (_t === s) {
                                    let t2;
                                    for (this.hp.feed(_e); t2 = this.hp.next();) {}
                                }
                            }
                        } else {
                            const t = this.qn, n = this.bk, r = this.bi;
                            let i;
                            try {i = await Promise.all(e.map((e, i) => this.d13(e.fragment, t + BigInt(i), n, r)))} catch {i = null}
                            if (i) {
                                this.qn = t + BigInt(i.length);
                                for (let n = 0; n < i.length; n++) this.p13(i[n])
                            } else {
                                for (let n = 0; n < e.length; n++) {
                                    const r = await this.d13(e[n].fragment, this.qn);
                                    this.qn++, this.p13(r)
                                }
                            }
                        }
                        if (this.pq.length) {
                            const res = this.pq.length === 1 ? this.pq[0] : W(...this.pq);
                            this.pq = [];
                            return res
                        }
                        if (this.cl) return null;
                        continue
                    }
                    if (this.cl) return null;
                    const {value: val, done: isDone} = await this.rc();
                    if (isDone) return null;
                    this.rp.feed(val)
                }
            })().catch(e => {
                this.fail();
                throw e
            })
        }
        pa(e) {this.cl = !0, this.close()}
        p13({data: e, type: t}) {if (t === a) this.pq.push(e); else if (t === i) this.pa(e)}
        close() {
            if (this.cp) return this.cp;
            if (this.fl || !this.hc) {
                this.sk?.close();
                return this.cp = Promise.resolve()
            }
            this.cg = !0;
            const e = this.wq.then(async () => {
                const t = new Uint8Array([1, E]), n = this.i3 ? await this.e13(t, this.fc(), i) : await this.e12(t, i);
                await this.wr.write(ie(this.i3 ? a : i, n))
            });
            return this.cp = e.catch(() => {}).finally(() => {this.cl = !0, this.sk?.close()}), this.wq = this.cp, this.cp
        }
    }
    return {TlsClient: TlsClient}
})();
const tlsStreamAdapter = (tls, initial = new Uint8Array(0)) => {
    let leftOver = initial, reading = null, closed = false;
    const readNext = async () => {
        if (leftOver?.byteLength) {
            const data = leftOver;
            leftOver = null;
            return data;
        }
        return await tls.read();
    };
    const readable = new ReadableStream({
        type: 'bytes',
        async pull(controller) {
            if (closed) return controller.close();
            if (!reading) {
                reading = readNext().finally(() => {reading = null});
            }
            const data = await reading;
            if (!data?.byteLength) {
                const request = controller.byobRequest;
                closed = true;
                controller.close();
                if (request) request.respond(0);
                return;
            }
            const value = data instanceof Uint8Array ? data : new Uint8Array(data);
            const request = controller.byobRequest;
            if (request) {
                const view = request.view;
                const len = Math.min(value.byteLength, view.byteLength);
                view.set(value.subarray(0, len));
                if (len < value.byteLength) leftOver = value.subarray(len);
                request.respond(len);
            } else {
                controller.enqueue(value);
            }
        },
        cancel() {
            closed = true;
            try {tls.close()} catch {}
        }
    });
    const writable = new WritableStream({
        write(chunk) {return tls.write(chunk)},
        close() {
            closed = true;
            return tls.close()
        },
        abort() {
            closed = true;
            return tls.close()
        }
    });
    return {readable, writable};
};
const staticHeaders = `User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36\r\nProxy-Connection: Keep-Alive\r\nConnection: Keep-Alive\r\n\r\n`;
const encodedStaticHeaders = textEncoder.encode(staticHeaders);
const connectViaHttpProxy = async (targetAddrType, targetPortNum, httpAuth, addrBytes, limit, useTls = false) => {
    const {username, password, hostname, port} = httpAuth;
    let proxySocket, tlsClient = null, isCustomTls = false;
    const proxyAddrType = addrTypeIs(hostname), proxyIsIp = proxyAddrType !== 3;
    if (useTls && proxyIsIp) {
        isCustomTls = true;
        proxySocket = await concurrentConnect(hostname, port, limit, {allowHalfOpen: false}, proxyAddrType);
    } else {
        try {
            proxySocket = await concurrentConnect(hostname, port, limit, useTls ? {secureTransport: 'on', allowHalfOpen: false} : undefined, proxyAddrType);
        } catch {
            if (!useTls) return null;
            isCustomTls = true;
            proxySocket = await concurrentConnect(hostname, port, limit, {allowHalfOpen: false}, proxyAddrType);
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
    const answer = await concurrentDnsResolve(targetIp, 'A');
    return answer?.find(record => record.type === 1 && isIPv4(record.data))?.data ?? null;
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
const connectViaTurnProxy = async ({hostname, port, username, password}, {addrType, port: targetPort, addrBytes, isHttp}, useTls = false) => {
    let targetIp = binaryAddrToString(addrType, addrBytes);
    if (isHttp) addrType = addrTypeIs(targetIp);
    if (addrType === 3) {
        targetIp = concurrentDnsResolve(targetIp, 'A')
            .then(answer => answer?.find(record => record.type === 1)?.data ?? null)
            .catch(() => null);
    } else if (addrType === 4) {return null}
    let ctrl = null, data = null, dataPromise = null, ctrlTls = null, dataTls = null;
    let cw = null, cr = null, ctrlExtra = null, closed = false;
    const proxyIsIp = addrTypeIs(hostname) !== 3;
    const close = () => {
        closed = true;
        [ctrl, data, ctrlTls, dataTls].forEach(s => {try {s?.close()} catch {}});
        [cr, cw].forEach(lock => {try {lock?.releaseLock()} catch {}});
    };
    const openConn = socketOptions => {
        const candidate = connect({hostname, port}, socketOptions);
        return createConnect(hostname, port, socketOptions, candidate).catch(e => {
            try {candidate.close()} catch {}
            throw e;
        });
    };
    const createConn = async () => {
        let sock = null, tls = null, isCustom = false;
        try {
            if (useTls && proxyIsIp) {
                isCustom = true;
                sock = await openConn({allowHalfOpen: false});
            } else {
                try {
                    sock = await openConn(useTls ? {secureTransport: 'on', allowHalfOpen: false} : undefined);
                } catch {
                    if (!useTls) throw 0;
                    isCustom = true;
                    sock = await openConn({allowHalfOpen: false});
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
            if (!result) throw 0;
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
    let cryptoKey = null, aa = [];
    const sign = m => cryptoKey ? addIntegrity(m, cryptoKey) : m;
    try {
        const ctrlPromise = createConn();
        dataPromise = createConn().then(res => {
            data = res.sock;
            dataTls = res.tls;
            if (closed) {
                try {res.tls?.close()} catch {}
                try {res.sock?.close()} catch {}
            }
            return res;
        });
        dataPromise.catch(() => {});
        const cRes = await ctrlPromise;
        ctrl = cRes.sock;
        ctrlTls = cRes.tls;
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
        if (!r) throw 0;
        const targetAddress = await targetIp;
        if (!targetAddress) throw 0;
        const peer = stunAttr(0x012, xorPeer(targetAddress, targetPort));
        let permissionTid = null, connectTid = null, pm = null, cm = null;
        if (r.type === 0x113 && username && parseErr(r.attrs[0x009]) === 401) {
            const realm = textDecoder.decode(r.attrs[0x014] ?? []), nonce = r.attrs[0x015] ?? [];
            const keyBytes = await md5(`${username}:${realm}:${password}`);
            cryptoKey = await crypto.subtle.importKey('raw', keyBytes, {name: 'HMAC', hash: 'SHA-1'}, false, ['sign']);
            aa = [stunAttr(0x006, textEncoder.encode(username)), stunAttr(0x014, textEncoder.encode(realm)), stunAttr(0x015, nonce)];
            const allocateTid = newTid();
            permissionTid = newTid(), connectTid = newTid();
            const [am, permissionMsg, connectMsg] = await Promise.all([
                sign(stunMsg(0x003, allocateTid, [stunAttr(0x019, new Uint8Array([6, 0, 0, 0])), ...aa])),
                sign(stunMsg(0x008, permissionTid, [peer, ...aa])),
                sign(stunMsg(0x00A, connectTid, [peer, ...aa]))
            ]);
            pm = permissionMsg, cm = connectMsg;
            await cw.write(cat(am, pm, cm));
            r = await readControl(allocateTid);
        } else if (r.type === 0x103) {
            permissionTid = newTid(), connectTid = newTid();
            [pm, cm] = await Promise.all([
                sign(stunMsg(0x008, permissionTid, [peer, ...aa])),
                sign(stunMsg(0x00A, connectTid, [peer, ...aa]))
            ]);
            await cw.write(cat(pm, cm));
        } else {throw 0}
        if (r?.type !== 0x103) throw 0;
        r = await readControl(permissionTid);
        if (r?.type !== 0x108) throw 0;
        r = await readControl(connectTid);
        if (r?.type !== 0x10A || !r.attrs[0x02A]) throw 0;
        const dRes = await dataPromise;
        const dIsCustom = dRes.isCustom;
        const dw = dIsCustom ? {write: c => dataTls.write(c), releaseLock: () => {}} : data.writable.getWriter();
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
        if (r?.type !== 0x10B) throw 0;
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
        const addrType = chunk[3];
        const addrLen = addrType === 3 ? (4 < len ? chunk[4] : null) : addrType === 1 ? 4 : addrType === 4 ? 16 : -1;
        if (addrLen === null) return result.needMore = true, result;
        if (!(addrLen > 0)) return result;
        const addrOffset = addrType === 3 ? 5 : 4;
        const dataOffset = addrOffset + addrLen + 2;
        if (len < dataOffset) return result.needMore = true, result;
        const portOffset = dataOffset - 2;
        const port = (chunk[portOffset] << 8) | chunk[portOffset + 1];
        result.handshake = socks5req;
        result.success = true;
        result.parsedRequest = {addrType, addrBytes: chunk.subarray(addrOffset, addrOffset + addrLen), dataOffset, port, isDns: port === 53};
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
                    result.handshake = httpRes200;
                    result.success = true;
                    result.parsedRequest = {addrType: 3, addrBytes: chunk.subarray(8, lastColon), dataOffset: len, port, isDns: port === 53, isHttp: true};
                    return result;
                }
            }
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
    if (chunk[0] === 1 || chunk[0] === 3 || chunk[0] === 4) {
        if (len < 2) return result.needMore = true, result;
        const addrLen = chunk[0] === 3 ? (1 < len ? chunk[1] : null) : chunk[0] === 1 ? 4 : chunk[0] === 4 ? 16 : -1;
        if (addrLen === null) return result.needMore = true, result;
        if (addrLen > 0) {
            const addrOffset = chunk[0] === 3 ? 2 : 1;
            const dataOffset = addrOffset + addrLen + 2;
            if (len < dataOffset) return result.needMore = true, result;
            const portOffset = dataOffset - 2;
            const port = (chunk[portOffset] << 8) | chunk[portOffset + 1];
            result.success = true;
            result.parsedRequest = {addrType: chunk[0], addrBytes: chunk.subarray(addrOffset, addrOffset + addrLen), dataOffset, port, isDns: port === 53};
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
    if (!proxyAll) return concurrentConnect(`[${nat64Prefixes}6815:3598]`, port, limit, undefined, 4);
    const hostname = binaryAddrToString(addrType, addrBytes);
    if (isHttp) addrType = addrTypeIs(hostname);
    if (addrType === 3) {
        const answer = await concurrentDnsResolve(hostname, 'A');
        const aRecord = answer?.find(record => record.type === 1);
        return aRecord ? concurrentConnect(ipv4ToNat64Ipv6(aRecord.data, nat64Prefixes), port, limit, undefined, 4) : null;
    }
    if (addrType === 1) return concurrentConnect(ipv4ToNat64Ipv6(hostname, nat64Prefixes), port, limit, undefined, 4);
    return concurrentConnect(hostname, port, limit, undefined, addrType);
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
    return concurrentConnect(host, port, limit, undefined, addrTypeIs(host));
};
const strategyExecutorMap = new Map([
    [0, async ({addrType, port, addrBytes, isHttp}, _param, limit, _txt) => {
        const hostname = binaryAddrToString(addrType, addrBytes);
        if (isHttp) addrType = addrTypeIs(hostname);
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
    }],
    [4, async ({addrType, port, addrBytes, isHttp}, param, limit, _txt) => {
        const {nat64Auth, proxyAll} = param;
        return connectNat64(addrType, port, nat64Auth, addrBytes, proxyAll, limit, isHttp);
    }],
    [5, async (parsedRequest, param, _limit, _txt) => {
        return connectViaTurnProxy(param, parsedRequest);
    }],
    [7, async (parsedRequest, param, _limit, _txt) => {
        return connectViaTurnProxy(param, parsedRequest, true);
    }],
    [8, async (parsedRequest, param, _limit, _txt) => {
        return connectViaSstpProxy(param, parsedRequest);
    }]
]);
const concurrentStrategyExec = (parsedRequest, params, exec, limit, txt) => {
    let settled = false, winner = null;
    const sockets = new Set(), closeSocket = socket => {try {socket?.close?.()} catch {}};
    const attempts = params.map(param => Promise.resolve().then(() => exec(parsedRequest, param, limit, txt)).then(socket => {
        if (!socket) throw 0;
        if (settled && socket !== winner) {
            closeSocket(socket);
            throw 0;
        }
        sockets.add(socket);
        return socket;
    }));
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
            list.push({type: 0}, {type: 3, param: coloToProxyMap.get(request.cf?.colo) ?? proxyIpAddrs.US}, {type: 3, param: finallyProxyHost});
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
    const ssEnabled = !state.disableSsAead && !!ssAeadPassword && !state.tcpWriter && state.socks5State === 0;
    const parsed = parseProtocolChunk(chunk, state.socks5State);
    if (parsed.handshake) writable.send(parsed.handshake);
    if (!parsed.success) {
        if (parsed.nextSocksState > 0) return state.socks5State = parsed.nextSocksState;
        if (allowNeedMore && parsed.needMore) return state.needMore = true;
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
        parsedRequest = parsed.parsedRequest;
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
            if (state.tcpSocket.extra?.length) await writable.send(state.tcpSocket.extra);
            if (state.xwebPipeTo) return;
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
    } else if (protocolHeader) earlyDataHeader = protocolHeader;
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
const xwebHeaders = {'Content-Type': 'application/octet-stream', 'grpc-status': '0', 'X-Accel-Buffering': 'no', 'Cache-Control': 'no-store'};
const handleXwebPost = async (request) => {
    const reader = request.body?.getReader({mode: 'byob'});
    if (!reader) return new Response(null, {status: 400});
    const state = {socks5State: 0, tcpWriter: null, tcpSocket: null, needMore: false, allowNeedMore: true, disableSsAead: true, xwebPipeTo: true};
    const bridge = new IdentityTransformStream(), responseWriter = bridge.writable.getWriter();
    let xwebBuffer = new ArrayBuffer(8192), used = 0, writerReleased = false;
    const close = () => {
        try {state.tcpSocket?.close()} catch {}
        if (!writerReleased) {
            writerReleased = true;
            responseWriter.abort().catch(() => {});
            responseWriter?.releaseLock();
        }
    };
    const writable = {
        send: (chunk) => {
            if (!chunk?.byteLength || writerReleased) return;
            return responseWriter.write(chunk);
        }
    };
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
        return new Response(html, {status: 200, headers: {'Content-Type': 'text/html; charset=UTF-8'}});
    }
};
