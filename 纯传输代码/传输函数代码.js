const manualPipe = async (readable, writable, close, pipeSpeed) => {
    const n = parseFloat(pipeSpeed), speedLimit = n > 0;
    let pipeBufferSize = bufferSize, pipeFlushTime = flushTime, pipeStartThreshold = startThreshold;
    if (speedLimit) {
        pipeStartThreshold = n * 1048576;
        let bestSize = pipeBufferSize, bestTime = Infinity, bestDiff = Infinity;
        for (let size = 262144; size <= 524288; size += 65536) {
            const timeMs = Math.max(2, Math.round(size * 1000 / pipeStartThreshold)), diff = Math.abs(size * 1000 / timeMs - pipeStartThreshold);
            if (diff < bestDiff || (diff === bestDiff && timeMs < bestTime)) bestSize = size, bestTime = timeMs, bestDiff = diff;
        }
        pipeBufferSize = bestSize, pipeFlushTime = bestTime;
    }
    const safeBufferSize = pipeBufferSize - maxChunkLen, halfChunkLen = (maxChunkLen * 3) >> 2, directBufSize = halfChunkLen << 1, fastFlushOffset = maxChunkLen << 1;
    let bufferView, spareBuffer = new ArrayBuffer(maxChunkLen);
    let offset = 0, totalBytes = 0, timerId = null, resume = null, isReading = false, needsFlush = false, protectFlush = false;
    let directBuf = new Uint8Array(directBufSize), directOff = 0, directTimer = null, fastFlush = true;
    const flushDirect = () => {
        directTimer && (clearTimeout(directTimer), directTimer = null);
        if (directOff > 0) {
            directOff >= maxChunkLen
                ? (writable.send(directBuf.subarray(0, directOff)), directBuf = new Uint8Array(directBufSize))
                : writable.send(directBuf.slice(0, directOff));
        }
        directOff = 0;
    };
    const flushBuffer = () => {
        if (isReading) return needsFlush = true;
        fastFlush = speedLimit ? fastFlush : offset < fastFlushOffset;
        if (offset > 0) {
            offset > safeBufferSize
                ? (writable.send(bufferView.subarray(0, offset)), fastFlush || (bufferView = new Uint8Array(pipeBufferSize)))
                : writable.send(bufferView.slice(0, offset));
            offset = 0;
        }
        if (fastFlush) {
            if (!speedLimit) totalBytes = 0;
            directBuf ||= new Uint8Array(directBufSize), bufferView = null;
        }
        needsFlush = false, protectFlush = false, timerId && (clearTimeout(timerId), timerId = null), resume?.(), resume = null;
    };
    const reader = readable.getReader({mode: 'byob'});
    try {
        while (true) {
            if (fastFlush) {
                const {done, value} = await reader.read(new Uint8Array(spareBuffer));
                if (done) break;
                const chunkLen = value.byteLength;
                if (!chunkLen) {
                    needsFlush && flushBuffer();
                    continue;
                }
                if (chunkLen >= halfChunkLen) {
                    flushDirect(), writable.send(value), spareBuffer = new ArrayBuffer(maxChunkLen);
                } else if (directOff + chunkLen > directBufSize) {
                    flushDirect(), directBuf.set(value, 0), directOff = chunkLen, directTimer = setTimeout(flushDirect, 2), spareBuffer = value.buffer;
                } else {
                    directBuf.set(value, directOff), directOff += chunkLen, directTimer ||= setTimeout(flushDirect, 2), spareBuffer = value.buffer;
                }
                if (chunkLen < 28672) {
                    if (!speedLimit) totalBytes = 0;
                } else if ((totalBytes += chunkLen) > pipeStartThreshold) {
                    flushDirect(), fastFlush = false, bufferView = new Uint8Array(pipeBufferSize), directBuf = null;
                }
            } else {
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
                offset += chunkLen;
                if (needsFlush || chunkLen < 2048) {
                    flushBuffer();
                } else if (!speedLimit && chunkLen < 28672) {
                    flushBuffer(), fastFlush = true, totalBytes = 0, directBuf = new Uint8Array(directBufSize), bufferView = null;
                } else {
                    timerId ||= setTimeout(flushBuffer, pipeFlushTime), protectFlush = chunkLen < maxChunkLen;
                    offset > safeBufferSize && await new Promise(r => resume = r);
                }
            }
        }
    } catch {offset = 0, directOff = 0, close?.()} finally {isReading = false, flushDirect(), flushBuffer()}
};
const manualPipe = async (readable, writable, close, pipeSpeed) => {
    const n = parseFloat(pipeSpeed), speedLimit = n > 0;
    let pipeBufferSize = bufferSize, pipeFlushTime = flushTime, pipeStartThreshold = startThreshold;
    if (speedLimit) {
        pipeStartThreshold = n * 1048576;
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
const manualPipe = async (readable, writable, close) => {
    const safeBufferSize = bufferSize - maxChunkLen, fastFlushOffset = maxChunkLen << 1;
    let bufferView = new Uint8Array(bufferSize), spareBuffer = new ArrayBuffer(maxChunkLen);
    let offset = 0, totalBytes = 0, time = 0, timerId = null, resume = null, isReading = false, needsFlush = false, protectFlush = false;
    let fastFlush = true;
    const flushBuffer = () => {
        if (isReading) return needsFlush = true;
        fastFlush = offset < fastFlushOffset;
        if (offset > 0) {
            offset > safeBufferSize
                ? (writable.send(bufferView.subarray(0, offset)), bufferView = new Uint8Array(bufferSize))
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
                    totalBytes = 0, time = 2;
                } else if (totalBytes > startThreshold) time = flushTime;
                timerId ||= setTimeout(flushBuffer, time), protectFlush = chunkLen < maxChunkLen;
                offset > safeBufferSize && (totalBytes > startThreshold ? await new Promise(r => resume = r) : flushBuffer());
            }
        }
    } catch {offset = 0, close?.()} finally {isReading = false, flushBuffer()}
};
const manualPipe = async (readable, writable, close) => {
    const safeBufferSize = bufferSize - maxChunkLen;
    let bufferView = new Uint8Array(bufferSize), spareBuffer = new ArrayBuffer(maxChunkLen);
    let offset = 0, timerId = null, resume = null, isReading = false, needsFlush = false, protectFlush = false;
    const flushBuffer = () => {
        if (isReading) return needsFlush = true;
        if (offset > 0) {
            offset > safeBufferSize
                ? (writable.send(bufferView.subarray(0, offset)), bufferView = new Uint8Array(bufferSize))
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
            offset += chunkLen;
            if (needsFlush || chunkLen < 2048) {
                flushBuffer();
            } else {
                timerId ||= setTimeout(flushBuffer, 2), protectFlush = chunkLen < maxChunkLen;
                offset > safeBufferSize && flushBuffer();
            }
        }
    } catch {offset = 0, close?.()} finally {isReading = false, flushBuffer()}
};