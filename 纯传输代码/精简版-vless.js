import {connect} from 'cloudflare:sockets';
const uuid = 'd342d11e-d424-4583-b36e-524ab1f0afa4';
const bufferSize = 256 * 1024;
const startThreshold = 50 * 1024 * 1024;
const maxChunkLen = 64 * 1024;
const flushTime = 3;
const concurrency = 4;
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
const textDecoder = new TextDecoder;
const concurrentConnect = (hostname, port) => {
    let settled = false;
    const attempts = new Array(concurrency);
    for (let i = 0; i < concurrency; i++) {
        const socket = connect({hostname, port});
        attempts[i] = socket.opened.then(() => {
            if (settled) {
                socket.close();
                throw null;
            }
            settled = true;
            return socket;
        });
    }
    return Promise.any(attempts);
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
const handleSession = async (chunk, state, request, writable, close) => {
    state.needMore = false;
    const len = chunk.length;
    if (len < 17) return state.needMore = true;
    if (!(
        chunk[1] === U0 && chunk[2] === U1 && chunk[3] === U2 && chunk[4] === U3 && chunk[5] === U4 && chunk[6] === U5 && chunk[7] === U6 && chunk[8] === U7 &&
        chunk[9] === U8 && chunk[10] === U9 && chunk[11] === U10 && chunk[12] === U11 && chunk[13] === U12 && chunk[14] === U13 && chunk[15] === U14 && chunk[16] === U15
    )) {
        return close();
    }
    if (len < 18) return state.needMore = true;
    const offset = 19 + chunk[17];
    if (len < offset + 4) return state.needMore = true;
    const addrType = chunk[offset + 2];
    const addrLen = addrType === 2 ? (offset + 3 < len ? chunk[offset + 3] : null) : addrType === 1 ? 4 : addrType === 3 ? 16 : -1;
    if (addrLen === null) return state.needMore = true;
    if (addrLen <= 0) return close();
    const addrOffset = addrType === 2 ? offset + 4 : offset + 3;
    const dataOffset = addrOffset + addrLen;
    if (len < dataOffset) return state.needMore = true;
    writable.send(new Uint8Array([chunk[0], 0]));
    const port = (chunk[offset] << 8) | chunk[offset + 1];
    const addrBytes = chunk.subarray(addrOffset, addrOffset + addrLen);
    const payload = chunk.subarray(dataOffset);
    let hostname;
    if (addrType === 2) {
        hostname = textDecoder.decode(addrBytes);
    } else if (addrType === 1) {
        hostname = `${addrBytes[0]}.${addrBytes[1]}.${addrBytes[2]}.${addrBytes[3]}`;
    } else {
        hostname = ((addrBytes[0] << 8) | addrBytes[1]).toString(16);
        for (let i = 1; i < 8; i++) hostname += ':' + ((addrBytes[i * 2] << 8) | addrBytes[i * 2 + 1]).toString(16);
        hostname = `[${hostname}]`;
    }
    const speed = new URL(request.url).searchParams.get('speed');
    try {
        state.tcpSocket = await concurrentConnect(hostname, port);
    } catch {
        try {state.tcpSocket = await concurrentConnect(await getCurrentColo(), port)} catch {return close()}
    }
    const tcpWriter = state.tcpSocket.writable.getWriter();
    state.rawTcpWriter = tcpWriter;
    if (payload.byteLength) tcpWriter.write(payload);
    if (state.xwebPipeTo) return state.tcpWriter = (chunk) => tcpWriter.write(chunk);
    state.tcpWriter = createBufferedTcpWriter(tcpWriter, close);
    manualPipe(state.tcpSocket.readable, writable, close, speed);
};
const handleWebSocketConn = async (webSocket, request) => {
    const refererHeader = request.headers.get("Referer");
    const protocolHeader = refererHeader || request.headers.get("sec-websocket-protocol");
    let earlyDataHeader = null;
    if (refererHeader) {earlyDataHeader = protocolHeader.slice(request.headers.get("host").length)} else if (protocolHeader) {earlyDataHeader = protocolHeader}
    const earlyData = earlyDataHeader ? Uint8Array.fromBase64(earlyDataHeader, {alphabet: "base64url"}) : null;
    const state = {tcpWriter: null, tcpSocket: null};
    let processingQueue = null;
    const close = () => {webSocket.close(1011, 'WebSocket is closed')};
    const process = (chunk) => {
        if (state.tcpWriter) return state.tcpWriter(chunk);
        return handleSession(earlyData ? chunk : new Uint8Array(chunk), state, request, webSocket, close);
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