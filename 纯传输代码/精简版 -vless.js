import {connect} from 'cloudflare:sockets';
const uuid = 'd342d11e-d424-4583-b36e-524ab1f0afa4';
const bufferSize = 256 * 1024;
const startThreshold = 50 * 1024 * 1024;
const maxChunkLen = 64 * 1024;
const flushTime = 3;
const concurrency = 4;
const finallyProxyHost = 'proxy.zjcloud.us.ci';
let currentColo = null;
const getCurrentColo = async () => {
    if (currentColo !== null) return currentColo;
    try {
        const text = await fetch('https://cp.cloudflare.com/cdn-cgi/trace', {
            headers: {'User-Agent': 'Mozilla/5.0'}
        }).then(r => r.text());
        const i = text.indexOf('colo=');
        const colo = i >= 0 ? text.slice(i + 5, i + 8) : '';
        currentColo = colo ? `${colo.toLowerCase()}.proxy.zjcloud.us.ci` : finallyProxyHost;
        return currentColo;
    } catch {
        currentColo = finallyProxyHost;
        return currentColo;
    }
};
const uuidBytes = Uint8Array.from(uuid.replace(/-/g, "").match(/../g), hex => parseInt(hex, 16));
const textDecoder = new TextDecoder;
const createConnect = (hostname, port, socket = connect({hostname, port})) => socket.opened.then(() => socket);
const concurrentConnect = (hostname, port) => {
    let settled = false, winner = null;
    const sockets = new Array(concurrency);
    const closeSocket = socket => {try {socket?.close()} catch {}};
    const attempts = Array.from({length: concurrency}, (_, i) => {
        const socket = connect({hostname, port});
        sockets[i] = socket;
        return createConnect(hostname, port, socket).then(openedSocket => {
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
        if (offset > 0) (writable.send(bufferView.subarray(0, offset)), offset = 0);
        needsFlush = false, protectFlush = false, timerId && (clearTimeout(timerId), timerId = null), resume?.(), resume = null;
    };
    const reader = readable.getReader({mode: 'byob'});
    try {
        while (true) {
            let readBuffer, readOffset, useSpare = offset > 0 && protectFlush;
            useSpare
                ? (readBuffer = spareBuffer, readOffset = 0, isReading = false)
                : (readBuffer = bufferView.buffer, readOffset = offset, isReading = offset > 0);
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
const handleSession = async (chunk, state, request, writable, close) => {
    state.needMore = false;
    const len = chunk.length;
    if (len < 17) return state.needMore = true;
    for (let i = 0; i < 16; i++) if (chunk[i + 1] !== uuidBytes[i]) return close();
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
    if (payload.byteLength) tcpWriter.write(payload);
    state.tcpWriter ||= createAsyncMicrotaskQueue(null, close);
    state.tcpWriter.writer = tcpWriter;
    if (state.xwebPipeTo) return;
    manualPipe(state.tcpSocket.readable, writable, close, speed);
};
const handleWebSocketConn = async (webSocket, request) => {
    const refererHeader = request.headers.get('Referer');
    const protocolHeader = refererHeader || request.headers.get('sec-websocket-protocol');
    let earlyDataHeader = null;
    if (refererHeader) {
        earlyDataHeader = protocolHeader.slice(request.headers.get('host').length);
    } else if (protocolHeader) {earlyDataHeader = protocolHeader}
    // @ts-ignore
    const earlyData = earlyDataHeader ? Uint8Array.fromBase64(earlyDataHeader, {alphabet: 'base64url'}) : null;
    const state = {tcpWriter: null, tcpSocket: null};
    const close = () => {
        try {state.tcpSocket?.close()} catch {}
        try {webSocket.close(1011, 'WebSocket is closed')} catch {}
    };
    const processingQueue = createAsyncMicrotaskQueue(chunk => handleSession(chunk, state, request, webSocket, close), close);
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