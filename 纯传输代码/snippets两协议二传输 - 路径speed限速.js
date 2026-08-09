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
const urlParamCacheLimit = 20;
const proxyStrategyOrder = ['socks', 'http', 'https'];
const dohEndpoint = 'https://cloudflare-dns.com/dns-query';
const proxyIpAddrs = {EU: 'ProxyIP.DE.CMLiussss.net', AS: 'ProxyIP.SG.CMLiussss.net', JP: 'ProxyIP.JP.CMLiussss.net', US: 'ProxyIP.US.CMLiussss.net'};
const finallyProxyHost = 'ProxyIP.CMLiussss.net';
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
const [textEncoder, textDecoder, socks5Init] = [new TextEncoder(), new TextDecoder(), new Uint8Array([5, 2, 0, 2])];
const html = `<body style=margin:0;overflow:hidden;background:#000><canvas id=c style=width:100vw;height:100vh><script>var C=document.getElementById("c"),g=C.getContext("webgl"),t=0,P,R,F,U,O,X,Y,L,T,b=.4,K="float L(vec3 v){vec3 a=v;float b,c,d;for(int i=0;i<5;i++){b=length(a);c=atan(a.y,a.x)*10.;d=acos(a.z/b)*10.;b=pow(b,8.);a=vec3(b*sin(d)*cos(c),b*sin(d)*sin(c),b*cos(d))+v;if(b>6.)break;}return 4.-dot(a,a);}",VS="attribute vec4 p;varying vec3 d,ld;uniform vec3 r,f,u;uniform float x,y;void main(){gl_Position=p;d=f+r*p.x*x+u*p.y*y;ld=vec3(p.x*x,p.y*y,-1.);}",FS="precision highp float;float L(vec3 v);uniform vec3 r,f,u,o;uniform float t;varying vec3 d,ld;uniform float l;void main(){vec3 tc=vec3(0);for(int i=0;i<4;i++){vec2 of=vec2(mod(float(i),2.),floor(float(i)/2.))*.5;vec3 rd=normalize(d+r*of.x*.001+u*of.y*.001),c=vec3(0);float s=.002*l,r1,r2,r3;for(int k=2;k<1200;k++){float ds=s*float(k);vec3 p=o+rd*ds;if(L(p)>0.){r1=s*float(k-1);r2=ds;for(int j=0;j<24;j++){r3=(r1+r2)*.5;if(L(o+rd*r3)>0.)r2=r3;else r1=r3;}vec3 v=o+rd*r3,nw;float e=r3*1e-4;nw=normalize(vec3(L(v-r*e)-L(v+r*e),L(v-u*e)-L(v+u*e),L(v+f*e)-L(v-f*e)));vec3 rf=reflect(normalize(ld),nw);float d2=dot(v,v),lt=pow(max(0.,dot(rf,vec3(.276,.92,.276))),4.)*.45+max(0.,dot(nw,vec3(.276,.92,.276)))*.25+.3;c=(sin(d2*5.+t+vec3(0,2,4))*.5+.5)*lt;break;}}tc+=c;}gl_FragColor=vec4(pow(tc*.25,vec3(.7)),1);}";function i(){var s=g.createProgram(),v=g.createShader(35633),f=g.createShader(35632);g.shaderSource(v,VS),g.compileShader(v),g.shaderSource(f,FS+K),g.compileShader(f),g.attachShader(s,v),g.attachShader(s,f),g.linkProgram(s),g.useProgram(s),P=g.getAttribLocation(s,"p"),R=g.getUniformLocation(s,"r"),F=g.getUniformLocation(s,"f"),U=g.getUniformLocation(s,"u"),O=g.getUniformLocation(s,"o"),X=g.getUniformLocation(s,"x"),Y=g.getUniformLocation(s,"y"),L=g.getUniformLocation(s,"l"),T=g.getUniformLocation(s,"t"),g.bindBuffer(34962,g.createBuffer()),g.bufferData(34962,new Float32Array([-1,-1,0,1,-1,0,1,1,0,-1,-1,0,1,1,0,-1,1,0]),35044),g.vertexAttribPointer(P,3,5126,!1,0,0),g.enableVertexAttribArray(P)}function w(){t+=.02,innerWidth*devicePixelRatio!=C.width&&(C.width=innerWidth*(d=devicePixelRatio||1),C.height=innerHeight*d,g.viewport(0,0,C.width,C.height));var v=C.width/C.height;g.uniform1f(X,v>1?v:1),g.uniform1f(Y,v>1?1:1/v),g.uniform1f(L,1.6),g.uniform1f(T,t),g.uniform3f(O,1.6*Math.cos(t*.5)*Math.cos(b),1.6*Math.sin(b),1.6*Math.sin(t*.5)*Math.cos(b)),g.uniform3f(R,Math.sin(t*.5),0,-Math.cos(t*.5)),g.uniform3f(U,-Math.sin(b)*Math.cos(t*.5),Math.cos(b),-Math.sin(b)*Math.sin(t*.5)),g.uniform3f(F,-Math.cos(t*.5)*Math.cos(b),-Math.sin(b),-Math.sin(t*.5)*Math.cos(b)),g.drawArrays(4,0,6),requestAnimationFrame(w)}i(),w()</script>`;
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
const createConnect = (hostname, port, socketOptions) => {
    const socket = connect({hostname, port}, socketOptions);
    return socket.opened.then(() => socket);
};
const connectViaSocksProxy = async (targetAddrType, targetPortNum, socksAuth, addrBytes) => {
    const socksSocket = await createConnect(socksAuth.hostname, socksAuth.port);
    const writer = socksSocket.writable.getWriter();
    const reader = socksSocket.readable.getReader();
    await writer.write(socks5Init);
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
const connectViaHttpProxy = async (targetAddrType, targetPortNum, httpAuth, addrBytes, useTls = false) => {
    const {username, password, hostname, port} = httpAuth;
    const connectOptions = useTls ? {secureTransport: 'on', allowHalfOpen: false} : undefined;
    const proxySocket = await createConnect(hostname, port, connectOptions);
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
const dohJsonOptions = {headers: {'Accept': 'application/dns-json'}}, dohHeaders = {'content-type': 'application/dns-message'};
const dohDnsResolve = async (hostname, recordType) => {
    try {
        const response = await fetch(`${dohEndpoint}?name=${encodeURIComponent(hostname)}&type=${recordType}`, dohJsonOptions);
        if (!response.ok) return null;
        const dnsResult = await response.json();
        const answer = dnsResult.Answer || dnsResult.answer;
        if (!answer || answer.length === 0) return null;
        return answer;
    } catch {
        return null;
    }
};
const dohDnsHandler = async (payload) => {
    if (payload.byteLength < 2) return null;
    const dnsQueryData = payload.subarray(2);
    let dnsQueryResult;
    try {
        const resp = await fetch(dohEndpoint, {method: 'POST', headers: dohHeaders, body: dnsQueryData});
        if (!resp.ok) return null;
        dnsQueryResult = await resp.arrayBuffer();
    } catch {
        return null;
    }
    const udpSize = dnsQueryResult.byteLength;
    const packet = new Uint8Array(2 + udpSize);
    packet[0] = (udpSize >> 8) & 0xff, packet[1] = udpSize & 0xff;
    packet.set(new Uint8Array(dnsQueryResult), 2);
    return packet;
};
const txtdnsResult = async (txtdns) => {
    const answer = await dohDnsResolve(txtdns, 'TXT');
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
const connectProxyIp = async (param, txt) => {
    if (txt || proxyIpRegex.test(param)) {
        const resolvedIps = await txtdnsResult(param);
        if (!resolvedIps || resolvedIps.length === 0) return null;
        const [host, port] = parseHostPort(resolvedIps[(Math.random() * resolvedIps.length) | 0], 443);
        return createConnect(host, port);
    }
    const [host, port] = parseHostPort(param, 443);
    return createConnect(host, port);
};
const strategyExecutorMap = new Map([
    [0, async ({addrType, port, addrBytes}) => {
        const hostname = binaryAddrToString(addrType, addrBytes);
        return createConnect(hostname, port);
    }],
    [1, async ({addrType, port, addrBytes}, param) => {
        return connectViaSocksProxy(addrType, port, param, addrBytes);
    }],
    [2, async ({addrType, port, addrBytes}, param) => {
        return connectViaHttpProxy(addrType, port, param, addrBytes);
    }],
    [6, async ({addrType, port, addrBytes}, param) => {
        return connectViaHttpProxy(addrType, port, param, addrBytes, true);
    }],
    [3, async (_parsedRequest, param, txt) => {
        return connectProxyIp(param, txt);
    }]
]);
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
            list.push({type: 0}, {type: 3, param: coloToProxyMap.get(request.cf?.colo) ?? proxyIpAddrs.US}, {type: 3, param: finallyProxyHost});
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
                for (let i = 0; i < parts.length; i++) list.push(txt ? {type: t, param: parts[i], txt} : {type: t, param: (t === 1 || t === 2 || t === 6) ? parseAuthString(parts[i]) : parts[i]});
            };
            for (let i = 0; i < proxyStrategyOrder.length; i++) {
                const k = proxyStrategyOrder[i];
                add(k === 'socks' ? s5 : k === 'http' ? http : https, k === 'socks' ? 1 : k === 'http' ? 2 : 6);
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
            const socket = await exec(parsedRequest, list[i].param, list[i].txt);
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
    if (parsed.handshake) {
        const deferVlessHandshake = state.xhttpPipeTo && parsed.success && parsed.handshake.byteLength === 2 && parsed.handshake[0] !== 5;
        deferVlessHandshake ? state.xhttpResponsePrefixes = [parsed.handshake.slice()] : writable.send(parsed.handshake);
    }
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
        if (state.xhttpPipeTo) {
            state.xhttpPayload = payload.slice();
            return;
        }
        const tcpWriter = state.tcpSocket.writable.getWriter();
        if (payload.byteLength) tcpWriter.write(payload);
        state.tcpWriter ||= createAsyncMicrotaskQueue(null, close);
        state.tcpWriter.writer = tcpWriter;
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
    webSocket.addEventListener("close", close);
};
const xhttpHeaders = {'Content-Type': 'application/octet-stream', 'grpc-status': '0', 'X-Accel-Buffering': 'no', 'Cache-Control': 'no-store'};
const pipeToWithPrefix = async (readable, writable, prefixes, options) => {
    const writer = writable.getWriter();
    try {
        const v = prefixes.filter(p => p?.byteLength);
        if (v.length === 1) {
            await writer.write(v[0]);
        } else if (v.length > 1) {
            let l = 0, o = 0;
            for (const p of v) l += p.byteLength;
            const b = new Uint8Array(l);
            for (const p of v) b.set(p, o), o += p.byteLength;
            await writer.write(b);
        }
    } catch (e) {
        try {await writer.abort(e)} catch {}
        throw e;
    } finally {try {writer.releaseLock()} catch {}}
    await readable.pipeTo(writable, options);
};
const handleXhttpPost = async (request) => {
    const reader = request.body?.getReader({mode: 'byob'});
    if (!reader) return new Response(null, {status: 400});
    const state = {tcpWriter: null, tcpSocket: null, needMore: false, xhttpPipeTo: true};
    const bridge = new IdentityTransformStream(), responseWriter = bridge.writable.getWriter();
    let xhttpBuffer = new ArrayBuffer(8192), used = 0, uploadAbort = null;
    let responseWriterReleased = false;
    const close = () => {
        try {uploadAbort?.abort(new Error('xhttp connection closed'))} catch {}
        try {state.tcpSocket?.close()} catch {}
        if (!responseWriterReleased) {
            responseWriterReleased = true;
            responseWriter.abort().catch(() => {});
            try {responseWriter.releaseLock()} catch {}
        }
    };
    const writable = {
        send: (chunk) => {
            if (!chunk?.byteLength || responseWriterReleased) return;
            return responseWriter.write(chunk);
        }
    };
    (async () => {
        while (true) {
            if (used > 0) {
                const payload = new Uint8Array(xhttpBuffer, 0, used);
                state.tcpWriter ? await state.tcpWriter(payload) : (state.needMore = false, await handleSession(payload, state, request, writable, close));
                if (state.tcpSocket) {
                    try {reader.releaseLock()} catch {}
                    uploadAbort = new AbortController();
                    if (!responseWriterReleased) {
                        responseWriterReleased = true;
                        try {responseWriter.releaseLock()} catch {}
                    }
                    const downloadPrefixes = state.xhttpResponsePrefixes ? [...state.xhttpResponsePrefixes] : [];
                    if (state.tcpSocket.extra?.byteLength) downloadPrefixes.push(state.tcpSocket.extra);
                    const upload = pipeToWithPrefix(
                        request.body,
                        state.tcpSocket.writable,
                        [state.xhttpPayload],
                        {signal: uploadAbort.signal}
                    ).catch(close);
                    const download = pipeToWithPrefix(
                        state.tcpSocket.readable,
                        bridge.writable,
                        downloadPrefixes
                    ).catch(close);
                    void download.finally(() => {
                        if (!uploadAbort.signal.aborted) uploadAbort.abort(new Error('xhttp response settled'));
                    }).catch(() => {});
                    void Promise.allSettled([upload, download]).then(close);
                    return;
                }
                if (!state.needMore) {
                    used = 0;
                    continue;
                }
            }
            const {done, value} = await reader.read(new Uint8Array(xhttpBuffer, used, used === 0 ? 8192 : 4096));
            if (done) return close();
            xhttpBuffer = value.buffer;
            used += value.byteLength;
        }
    })().catch(close);
    return new Response(bridge.readable, {headers: xhttpHeaders});
};
export default {
    async fetch(request) {
        if (request.method === 'POST' && request.headers.get('content-type') === 'application/grpc-web') return handleXhttpPost(request);
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
