/**
 * TLS 1.2 & TLS 1.3 轻量级客户端实现
 * - 基于标准 Web Crypto API 与 WHATWG Streams (ReadableStream / WritableStream)
 * - 支持密码套件:
 *     TLS 1.3: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
 *     TLS 1.2: ECDHE-RSA/ECDSA-AES128/256-GCM-SHA256/384
 * - 支持密钥交换曲线: X25519, Secp256r1 (P-256)
 */

const textEncoder = new TextEncoder();
const EMPTY_BUFFER = new Uint8Array(0);
// ============================================================================
// 1. 基础工具函数：字节序列化与辅助操作
// ============================================================================
/**
 * 递归展平任意嵌套的数字或 Uint8Array，生成一个连续的字节数组
 */
function concatBytes(...items) {
    const bytes = [];
    const flatten = (list) => {
        for (const item of list) {
            if (item instanceof Uint8Array) {
                bytes.push(...item);
            } else if (Array.isArray(item)) {
                flatten(item);
            } else {
                bytes.push(item);
            }
        }
    };
    flatten(items);
    return new Uint8Array(bytes);
}
/**
 * 将 16 位整数转为 2 字节的大端序 (Big-Endian) 数组
 */
const u16ToBytes = (value) => [value >> 8, value & 0xff];
/**
 * 从字节数组的指定偏移处读取 16 位大端序整数
 */
const readU16BE = (buffer, offset) => (buffer[offset] << 8) | buffer[offset + 1];
/**
 * 高性能合并多个 Uint8Array 块（单次分配内存并填充）
 */
function concatUint8Arrays(...arrays) {
    const totalLength = arrays.reduce((sum, arr) => sum + (arr?.length || 0), 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of arrays) {
        if (arr?.length) {
            result.set(arr, offset);
            offset += arr.length;
        }
    }
    return result;
}
/**
 * 根据哈希算法名称返回对应的输出摘要字节长度
 */
const getHashLength = (hashName) => (hashName === "SHA-384" ? 48 : 32);
/**
 * 检查是否为 SNI 不匹配告警 (Alert: Warning (1), Unrecognized Name (112))
 * 该告警属于非致命警告，部分服务端在收到未绑定的域名时会发出，客户端可忽略
 */
const isUnrecognizedNameAlert = (alertBytes) => alertBytes?.[0] === 1 && alertBytes[1] === 112;
// ============================================================================
// 2. Web Crypto API 封装：加解密与摘要计算
// ============================================================================
/**
 * 计算 HMAC 签名
 */
async function hmacSign(hashName, key, data) {
    const cryptoKey = key.type
        ? key
        : await crypto.subtle.importKey("raw", key, {name: "HMAC", hash: hashName}, false, ["sign"]);
    return new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, data));
}
/**
 * 计算哈希散列值 (SHA-256 / SHA-384)
 */
async function hashDigest(hashName, data) {
    return new Uint8Array(await crypto.subtle.digest(hashName, data));
}
/**
 * 导入原始 AES-GCM 密钥材料
 */
function importAesGcmKey(rawKey, usage) {
    return crypto.subtle.importKey("raw", rawKey, {name: "AES-GCM"}, false, [usage]);
}
/**
 * AES-GCM 认证加密
 */
async function aesGcmEncrypt(key, iv, plaintext, additionalData) {
    return new Uint8Array(
        await crypto.subtle.encrypt({name: "AES-GCM", iv, additionalData}, key, plaintext)
    );
}
/**
 * AES-GCM 认证解密
 */
async function aesGcmDecrypt(key, iv, ciphertext, additionalData) {
    return new Uint8Array(
        await crypto.subtle.decrypt({name: "AES-GCM", iv, additionalData}, key, ciphertext)
    );
}
/**
 * 打包 TLS 记录层 (Record Layer) 报文
 * 头部格式: [ContentType(1B), Version(2B), Length(2B)] + Payload
 * 默认版本号 0x0303 (TLS 1.2，兼容 TLS 1.3 伪装)
 */
function wrapTlsRecord(contentType, fragment, version = 0x0303, length = fragment.length) {
    const record = new Uint8Array(5 + length);
    record.set([contentType, version >> 8, version & 0xff, length >> 8, length & 0xff]);
    record.set(fragment, 5);
    return record;
}
/**
 * 打包 TLS 握手层 (Handshake Layer) 报文
 * 头部格式: [HandshakeType(1B), Length(3B uint24)] + Body
 */
function wrapHandshakeMessage(handshakeType, body, length = body.length) {
    const message = new Uint8Array(4 + length);
    message.set([handshakeType, (length >> 16) & 0xff, (length >> 8) & 0xff, length & 0xff]);
    message.set(body, 4);
    return message;
}
/**
 * TLS 1.3 记录层关联认证数据 (AAD): [0x17 (Application Data), 0x03, 0x03, Length(2B)]
 */
const createTls13Aad = (length) => new Uint8Array([23, 3, 3, length >> 8, length & 0xff]);
// ============================================================================
// 3. TLS 密码学算法：密钥交换、PRF 与 HKDF 派生
// ============================================================================
/**
 * TLS 1.2 伪随机数函数 (PRF - P_hash)
 * 用于根据预主密钥 (Pre-Master Secret) 派生 Master Secret 和工作密钥块
 */
async function prfTls12(secret, label, seed, length, hashName = "SHA-256") {
    const labelAndSeed = concatUint8Arrays(textEncoder.encode(label), seed);
    const key = secret.type
        ? secret
        : await crypto.subtle.importKey("raw", secret, {name: "HMAC", hash: hashName}, false, ["sign"]);
    let result = new Uint8Array(0);
    let a = labelAndSeed; // A(0) = seed
    while (result.length < length) {
        a = await hmacSign(hashName, key, a); // A(i) = HMAC(secret, A(i-1))
        const step = await hmacSign(hashName, key, concatUint8Arrays(a, labelAndSeed));
        result = concatUint8Arrays(result, step);
    }
    return result.slice(0, length);
}
/**
 * HKDF-Extract: 提取伪随机密钥 (PRK)
 */
function hkdfExtract(hashName, salt, ikm) {
    const saltBuffer = salt?.length ? salt : new Uint8Array(getHashLength(hashName));
    return hmacSign(hashName, saltBuffer, ikm);
}
/**
 * TLS 1.3 HKDF-Expand-Label (RFC 8446 Section 7.1)
 * 格式: [length(2B), "tls13 " + label(1B len + bytes), context(1B len + bytes)]
 */
async function hkdfExpandLabel(hashName, prk, label, context, length) {
    const labelBytes = typeof label === "string" ? textEncoder.encode("tls13 " + label) : label;
    const hashLen = getHashLength(hashName);
    const hkdfLabel = concatBytes(
        u16ToBytes(length),
        labelBytes.length,
        labelBytes,
        context.length,
        context
    );
    const key = prk.type
        ? prk
        : await crypto.subtle.importKey("raw", prk, {name: "HMAC", hash: hashName}, false, ["sign"]);
    let result = new Uint8Array(0);
    let t = new Uint8Array(0);
    const iterations = Math.ceil(length / hashLen);
    for (let i = 1; i <= iterations; i++) {
        t = await hmacSign(hashName, key, concatUint8Arrays(t, hkdfLabel, [i]));
        result = concatUint8Arrays(result, t);
    }
    return result.slice(0, length);
}
/**
 * 生成 ECDH (P-256) 或 X25519 密钥对
 */
async function generateEcdhKeyPair(namedCurve = "P-256") {
    const isX25519 = namedCurve === "X25519";
    const keyPair = await crypto.subtle.generateKey(
        isX25519 ? {name: "X25519"} : {name: "ECDH", namedCurve},
        true,
        ["deriveBits"]
    );
    const rawPublicKey = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
    return {kp: keyPair, pk: rawPublicKey};
}
/**
 * 计算 ECDH / X25519 共享秘密 (Shared Secret)
 */
async function deriveSharedSecret(privateKey, peerPublicKeyRaw, namedCurve = "P-256") {
    const isX25519 = namedCurve === "X25519";
    const peerPublicKey = await crypto.subtle.importKey(
        "raw",
        peerPublicKeyRaw,
        isX25519 ? {name: "X25519"} : {name: "ECDH", namedCurve},
        false,
        []
    );
    return new Uint8Array(
        await crypto.subtle.deriveBits(
            {name: isX25519 ? "X25519" : "ECDH", public: peerPublicKey},
            privateKey,
            256
        )
    );
}
/**
 * TLS 1.3 派生具体方向的工作密钥与基础 IV
 */
async function deriveTrafficKeys(hashName, secret, keyLen, ivLen, usage) {
    const prk = secret.type
        ? secret
        : await crypto.subtle.importKey("raw", secret, {name: "HMAC", hash: hashName}, false, ["sign"]);
    const [keyBytes, ivBytes] = await Promise.all([
        hkdfExpandLabel(hashName, prk, "key", EMPTY_BUFFER, keyLen),
        hkdfExpandLabel(hashName, prk, "iv", EMPTY_BUFFER, ivLen)
    ]);
    return [await importAesGcmKey(keyBytes, usage), ivBytes];
}
/**
 * 解析 TLS 1.3 解密后的内层明文 (InnerPlaintext)
 * 去除末尾的零填充 (Zero Padding)，提取真实的 ContentType
 */
function unpadTls13Plaintext(buffer) {
    let index = buffer.length - 1;
    while (index >= 0 && !buffer[index]) {
        index--;
    }
    if (index < 0) {
        throw new Error("Invalid TLS 1.3 padding");
    }
    return {
        data: buffer.subarray(0, index),
        type: buffer[index]
    };
}
/**
 * TLS 1.3 IV 掩码构造: 将 64 位包序号与 IV 的最后 8 个字节异或
 */
function xorIv(iv, seqNum) {
    const result = iv.slice();
    for (let i = 0; i < 8; i++) {
        result[result.length - 1 - i] ^= Number((seqNum >> BigInt(i << 3)) & 0xffn);
    }
    return result;
}
// ============================================================================
// 4. 流式数据包解析器 (带内存紧凑复用)
// ============================================================================
/**
 * 基础双指针滑动窗口缓冲区
 */
class BaseStreamBuffer {
    constructor(initialSize) {
        this.buffer = new Uint8Array(initialSize);
        this.head = 0; // 读指针
        this.tail = 0; // 写指针
    }
    feed(data) {
        if (this.tail + data.length > this.buffer.length) {
            const unreadLength = this.tail - this.head;
            const needsResize = unreadLength + data.length > this.buffer.length;
            const newBuf = needsResize
                ? new Uint8Array(Math.max(this.buffer.length * 2, unreadLength + data.length))
                : this.buffer;
            if (needsResize) {
                newBuf.set(this.buffer.subarray(this.head, this.tail));
            } else {
                newBuf.copyWithin(0, this.head, this.tail);
            }
            this.buffer = newBuf;
            this.tail = unreadLength;
            this.head = 0;
        }
        this.buffer.set(data, this.tail);
        this.tail += data.length;
    }
}
/**
 * TLS 记录层 (Record) 解析器
 */
class RecordParser extends BaseStreamBuffer {
    constructor() {
        super(32768);
    }
    next() {
        if (this.tail - this.head < 5) return null; // 头部不足 5 字节
        const type = this.buffer[this.head];
        const version = readU16BE(this.buffer, this.head + 1);
        const length = readU16BE(this.buffer, this.head + 3);
        if (length > 18432) { // 2^14 + 2048 超过 TLS 最大帧长度
            throw new Error("TLS record length exceeds maximum allowed limit");
        }
        if (this.tail - this.head < 5 + length) return null; // 负载不完整
        const fragment = this.buffer.subarray(this.head + 5, (this.head += 5 + length));
        if (this.head === this.tail) {
            this.head = this.tail = 0;
        }
        return {type, version, length, fragment};
    }
}
/**
 * TLS 握手层 (Handshake Message) 解析器
 */
class HandshakeParser extends BaseStreamBuffer {
    constructor() {
        super(4096);
    }
    next() {
        if (this.tail - this.head < 4) return null; // 头部不足 4 字节
        const type = this.buffer[this.head];
        const length = (this.buffer[this.head + 1] << 16) | readU16BE(this.buffer, this.head + 2);
        if (this.tail - this.head < 4 + length) return null;
        const body = this.buffer.subarray(this.head + 4, this.head + 4 + length);
        const raw = this.buffer.subarray(this.head, (this.head += 4 + length));
        if (this.head === this.tail) {
            this.head = this.tail = 0;
        }
        return {type, length, body, raw};
    }
}
// ============================================================================
// 5. 报文构造：ClientHello
// ============================================================================
/**
 * 构造符合 TLS 1.2 / TLS 1.3 双协议兼容的 ClientHello 报文
 */
function buildClientHello(clientRandom, serverName, keyShares, {sessionId = EMPTY_BUFFER} = {}) {
    // 支持的密码套件列表:
    // 0x1301 (TLS_AES_128_GCM_SHA256), 0x1302 (TLS_AES_256_GCM_SHA384)
    // 0xC02F, 0xC030, 0xC02B, 0xC02C (ECDHE-RSA/ECDSA GCM)
    const cipherSuites = concatBytes(...[4865, 4866, 49199, 49200, 49195, 49196].flatMap(u16ToBytes));
    const extensions = [
        // 扩展: renegotiation_info (防重协商攻击)
        concatBytes(0xff, 1, 0, 1, 0)
    ];
    // 扩展: server_name (SNI)
    if (serverName) {
        const hostBytes = textEncoder.encode(serverName);
        extensions.push(
            concatBytes(
                0, 0, // extension_type: 0 (server_name)
                u16ToBytes(hostBytes.length + 5),
                u16ToBytes(hostBytes.length + 3),
                0,    // host_name type: 0
                u16ToBytes(hostBytes.length),
                hostBytes
            )
        );
    }
    // 预计算 key_share: 同时发送 X25519 (29) 与 P-256 (23) 公钥
    const keyShareEntries = concatUint8Arrays(
        concatBytes(0, 29, u16ToBytes(keyShares.x25519.length), keyShares.x25519),
        concatBytes(0, 23, u16ToBytes(keyShares.p256.length), keyShares.p256)
    );
    extensions.push(
        // 扩展: ec_point_formats (支持 uncompressed: 0)
        concatBytes(u16ToBytes(11), 0, 2, 1, 0),
        // 扩展: supported_groups (29: X25519, 23: secp256r1)
        concatBytes(u16ToBytes(10), 0, 6, 0, 4, 0, 29, 0, 23),
        // 扩展: signature_algorithms (支持的签名组合)
        concatBytes(
            u16ToBytes(13),
            0, 34,
            0, 32,
            ...[2052, 2053, 2054, 2055, 2056, 2057, 2058, 2059, 1027, 1283, 1539, 1025, 1281, 1537, 513, 515].flatMap(u16ToBytes)
        ),
        // 扩展: supported_versions (43) -> 优先 TLS 1.3 (0x0304)，回退 TLS 1.2 (0x0303)
        concatBytes(u16ToBytes(43), 0, 5, 4, 3, 4, 3, 3),
        // 扩展: psk_key_exchange_modes (45) -> psk_dhe_ke (1)
        concatBytes(u16ToBytes(45), 0, 2, 1, 1),
        // 扩展: key_share (51)
        concatBytes(u16ToBytes(51), u16ToBytes(keyShareEntries.length + 2), u16ToBytes(keyShareEntries.length), keyShareEntries)
    );
    const serializedExtensions = concatUint8Arrays(...extensions);
    return wrapHandshakeMessage(
        1, // HandshakeType: ClientHello
        concatBytes(
            u16ToBytes(0x0303), // legacy_version: TLS 1.2
            clientRandom,
            sessionId.length,
            sessionId,
            u16ToBytes(cipherSuites.length),
            cipherSuites,
            1, 0, // legacy_compression_methods (null 压缩)
            u16ToBytes(serializedExtensions.length),
            serializedExtensions
        )
    );
}
// ============================================================================
// 6. TLS 客户端实现主体 (TlsClient)
// ============================================================================
class TlsClient {
    /**
     * @param {Object} socket 传输套接字对象，需具备 readable (ReadableStream), writable (WritableStream), close()
     * @param {Object} options 配置项: { serverName?: string }
     */
    constructor(socket, options = {}) {
        this.socket = socket;
        this.serverName = options.serverName || "";
        this.clientRandom = crypto.getRandomValues(new Uint8Array(32));
        this.sessionId = crypto.getRandomValues(new Uint8Array(32));
        this.transcriptBuffer = new Uint8Array(8192); // 握手转录哈希缓冲区
        this.transcriptLen = 0;
        this.clientSeqNum = 0n;
        this.serverSeqNum = 0n;
        this.recordParser = new RecordParser();
        this.handshakeParser = new HandshakeParser();
        this.keyPairs = new Map();
        this.packetQueue = [];
        this.writeQueue = Promise.resolve();
        this.readBuffer = new Uint8Array(65536); // BYOB 读取池
        this.reader = null;
        this.writer = null;
        this.failed = false;
        this.closed = false;
        this.closing = false;
        this.handshakeComplete = false;
        this.closePromise = null;
        this.isTls13 = false;
        this.cipherSuite = null;
        this.cipherConfig = null;
        this.serverRandom = null;
        // TLS 1.3 密钥状态
        this.handshakeSecret = null;
        this.clientHandshakeKey = null;
        this.clientHandshakeIv = null;
        this.serverHandshakeKey = null;
        this.serverHandshakeIv = null;
        this.clientAppKey = null;
        this.clientAppIv = null;
        this.serverAppKey = null;
        this.serverAppIv = null;
        // TLS 1.2 密钥状态
        this.masterSecret = null;
        this.clientWriteKey = null;
        this.serverWriteKey = null;
        this.clientWriteIv = null;
        this.serverWriteIv = null;
    }
    /**
     * 追加握手原始报文至转录缓冲区 (用于计算 Finished 校验哈希)
     */
    recordHandshake(data) {
        if (this.transcriptLen + data.length > this.transcriptBuffer.length) {
            const newBuffer = new Uint8Array(Math.max(this.transcriptBuffer.length * 2, this.transcriptLen + data.length));
            newBuffer.set(this.transcriptBuffer.subarray(0, this.transcriptLen));
            this.transcriptBuffer = newBuffer;
        }
        this.transcriptBuffer.set(data, this.transcriptLen);
        this.transcriptLen += data.length;
    }
    getTranscript() {
        return this.transcriptBuffer.subarray(0, this.transcriptLen);
    }
    nextClientSeq() {
        return this.clientSeqNum++;
    }
    nextServerSeq() {
        return this.serverSeqNum++;
    }
    /**
     * 遇到不可恢复错误时的安全释放与资源关闭
     */
    fail() {
        this.failed = this.closed = true;
        try { this.reader?.cancel(); } catch {}
        try { this.reader?.releaseLock(); } catch {}
        try { this.writer?.releaseLock(); } catch {}
        try { this.socket?.close(); } catch {}
    }
    /**
     * 从底层流中读取一个数据块 (支持 BYOB zero-copy 模式)
     */
    async readChunk() {
        const result = await this.reader.read(this.readBuffer);
        if (!result) throw new Error("Socket read returned null/undefined");
        if (!result.done && result.value) {
            this.readBuffer = new Uint8Array(result.value.buffer);
        }
        return result;
    }
    /**
     * 循环读取并分发 TLS 记录
     */
    async processRecords(onRecord) {
        while (true) {
            let record;
            while ((record = this.recordParser.next())) {
                if (await onRecord(record)) return;
            }
            const {value, done} = await this.readChunk();
            if (done) throw new Error("Connection closed during record processing");
            this.recordParser.feed(value);
        }
    }
    /**
     * 执行完整的 TLS 握手流程
     */
    async handshake() {
        // 1. 本地并发生成 P-256 和 X25519 两对秘钥
        const [p256KeyPair, x25519KeyPair] = await Promise.all([
            generateEcdhKeyPair("P-256"),
            generateEcdhKeyPair("X25519")
        ]);
        this.keyPairs = new Map([
            [23, p256KeyPair],
            [29, x25519KeyPair]
        ]);
        this.reader = this.socket.readable.getReader({mode: "byob"});
        this.writer = this.socket.writable.getWriter();
        try {
            // 2. 发送 ClientHello
            const clientHello = buildClientHello(
                this.clientRandom,
                this.serverName,
                {p256: p256KeyPair.pk, x25519: x25519KeyPair.pk},
                {sessionId: this.sessionId}
            );
            this.recordHandshake(clientHello);
            // 按照规范，握手初始阶段记录层版本包装为 0x0301 (769 即 TLS 1.0) 以实现向前兼容
            await this.writer.write(wrapTlsRecord(22, clientHello, 769));
            // 3. 读取并解析服务端的 ServerHello
            const serverHello = await this.readServerHello();
            // ----------------------------------------------------------------
            // 分支 A: TLS 1.3 握手流程
            // ----------------------------------------------------------------
            if (serverHello.isTls13) {
                const groupCurve = serverHello.ks?.group === 29 ? "X25519" : serverHello.ks?.group === 23 ? "P-256" : null;
                const localKeyPair = this.keyPairs.get(serverHello.ks?.group);
                if (!groupCurve || !serverHello.ks?.key?.length || !localKeyPair) {
                    throw new Error("Missing or invalid key_share from server");
                }
                const hash = this.cipherConfig.hash;
                const hashLen = getHashLength(hash);
                const {keyLen, ivLen} = this.cipherConfig;
                // 3.1 派生 Early Secret & Handshake Secret
                const sharedSecret = await deriveSharedSecret(localKeyPair.kp.privateKey, serverHello.ks.key, groupCurve);
                const earlySecret = await hkdfExtract(hash, null, new Uint8Array(hashLen));
                const emptyHash = await hashDigest(hash, EMPTY_BUFFER);
                const derivedEarlySecret = await hkdfExpandLabel(hash, earlySecret, "derived", emptyHash, hashLen);
                this.handshakeSecret = await hkdfExtract(hash, derivedEarlySecret, sharedSecret);
                // 3.2 派生握手阶段流量密钥 (Handshake Traffic Keys)
                const hsTranscriptHash = await hashDigest(hash, this.getTranscript());
                const clientHsSecret = await hkdfExpandLabel(hash, this.handshakeSecret, "c hs traffic", hsTranscriptHash, hashLen);
                const serverHsSecret = await hkdfExpandLabel(hash, this.handshakeSecret, "s hs traffic", hsTranscriptHash, hashLen);
                [this.clientHandshakeKey, this.clientHandshakeIv] = await deriveTrafficKeys(hash, clientHsSecret, keyLen, ivLen, "encrypt");
                [this.serverHandshakeKey, this.serverHandshakeIv] = await deriveTrafficKeys(hash, serverHsSecret, keyLen, ivLen, "decrypt");
                let finishedReceived = false;
                let certRequestReceived = false;
                // 3.3 接收并解密服务端后续握手报文 (EncryptedExtensions, Certificate, Finished 等)
                await this.processRecords(async (record) => {
                    // TLS 1.3 中 ChangeCipherSpec (20) 或未加密握手帧直接丢弃
                    if (record.type === 20 || record.type === 22) return;
                    if (record.type === 21) {
                        if (isUnrecognizedNameAlert(record.fragment)) return;
                        throw new Error("TLS alert received during handshake");
                    }
                    if (record.type !== 23) return;
                    const decrypted = await aesGcmDecrypt(
                        this.serverHandshakeKey,
                        xorIv(this.serverHandshakeIv, this.nextServerSeq()),
                        record.fragment,
                        createTls13Aad(record.fragment.length)
                    );
                    const {data, type} = unpadTls13Plaintext(decrypted);
                    if (type === 22) {
                        this.handshakeParser.feed(data);
                        let hsMsg;
                        while ((hsMsg = this.handshakeParser.next())) {
                            this.recordHandshake(hsMsg.raw);
                            if (hsMsg.type === 13) {
                                certRequestReceived = true; // 服务端要求客户端证书认证
                            } else if (hsMsg.type === 20) {
                                finishedReceived = true; // 服务端 Finished 报文
                                return 1;
                            }
                        }
                    }
                });
                // 3.4 派生应用数据流量密钥 (Application Traffic Keys)
                const finishedTranscriptHash = await hashDigest(hash, this.getTranscript());
                const derivedHsSecret = await hkdfExpandLabel(hash, this.handshakeSecret, "derived", emptyHash, hashLen);
                const masterSecret = await hkdfExtract(hash, derivedHsSecret, new Uint8Array(hashLen));
                const clientAppSecret = await hkdfExpandLabel(hash, masterSecret, "c ap traffic", finishedTranscriptHash, hashLen);
                const serverAppSecret = await hkdfExpandLabel(hash, masterSecret, "s ap traffic", finishedTranscriptHash, hashLen);
                [this.clientAppKey, this.clientAppIv] = await deriveTrafficKeys(hash, clientAppSecret, keyLen, ivLen, "encrypt");
                [this.serverAppKey, this.serverAppIv] = await deriveTrafficKeys(hash, serverAppSecret, keyLen, ivLen, "decrypt");
                // 若服务端请求证书，发送空 Certificate 消息
                let certMessage = EMPTY_BUFFER;
                if (certRequestReceived) {
                    certMessage = wrapHandshakeMessage(11, [0, 0, 0, 0]);
                    this.recordHandshake(certMessage);
                }
                // 3.5 构造并发送客户端 Finished
                const clientFinishedKey = await hkdfExpandLabel(hash, clientHsSecret, "finished", EMPTY_BUFFER, hashLen);
                const clientFinishedVerify = await hmacSign(hash, clientFinishedKey, await hashDigest(hash, this.getTranscript()));
                const clientFinishedMsg = wrapHandshakeMessage(20, clientFinishedVerify);
                this.recordHandshake(clientFinishedMsg);
                // 打包加密发送客户端 Finished
                const encryptedPayload = concatUint8Arrays(certMessage, clientFinishedMsg, [22]);
                const encryptedRecord = await aesGcmEncrypt(
                    this.clientHandshakeKey,
                    xorIv(this.clientHandshakeIv, this.nextClientSeq()),
                    encryptedPayload,
                    createTls13Aad(encryptedPayload.length + 16)
                );
                await this.writer.write(wrapTlsRecord(23, encryptedRecord));
                // 握手完成，包序号清零
                this.clientSeqNum = this.serverSeqNum = 0n;
            }
                // ----------------------------------------------------------------
                // 分支 B: TLS 1.2 握手流程
            // ----------------------------------------------------------------
            else {
                let serverKeyExchange = null;
                let serverHelloDone = false;
                let certRequestReceived = false;
                const processHandshake = async (hsMsg) => {
                    this.recordHandshake(hsMsg.raw);
                    if (hsMsg.type === 12) { // ServerKeyExchange
                        serverKeyExchange = {
                            namedCurve: readU16BE(hsMsg.body, 1),
                            serverPublicKey: hsMsg.body.subarray(4, 4 + hsMsg.body[3])
                        };
                    } else if (hsMsg.type === 14) { // ServerHelloDone
                        serverHelloDone = true;
                        return 1;
                    } else if (hsMsg.type === 13) { // CertificateRequest
                        certRequestReceived = true;
                    }
                };
                let done = false;
                let pendingMsg;
                while ((pendingMsg = this.handshakeParser.next())) {
                    if (await processHandshake(pendingMsg)) {
                        done = true;
                        break;
                    }
                }
                if (!done) {
                    await this.processRecords(async (record) => {
                        if (record.type === 21) {
                            if (isUnrecognizedNameAlert(record.fragment)) return;
                            throw new Error("TLS alert received");
                        }
                        if (record.type === 22) {
                            this.handshakeParser.feed(record.fragment);
                            let m;
                            while ((m = this.handshakeParser.next())) {
                                if (await processHandshake(m)) return 1;
                            }
                        }
                    });
                }
                if (!serverHelloDone || !serverKeyExchange) {
                    throw new Error("TLS 1.2 handshake failed: missing ServerKeyExchange or ServerHelloDone");
                }
                const namedCurve = serverKeyExchange.namedCurve === 29 ? "X25519" : serverKeyExchange.namedCurve === 23 ? "P-256" : null;
                const localKeyPair = this.keyPairs.get(serverKeyExchange.namedCurve);
                if (!namedCurve || !localKeyPair) {
                    throw new Error("Unsupported curve in ServerKeyExchange");
                }
                if (certRequestReceived) {
                    const emptyCert = wrapHandshakeMessage(11, [0, 0, 0]);
                    this.recordHandshake(emptyCert);
                    await this.writer.write(wrapTlsRecord(22, emptyCert));
                }
                // 计算 Pre-Master Secret -> Master Secret -> Key Expansion
                const preMasterSecret = await deriveSharedSecret(localKeyPair.kp.privateKey, serverKeyExchange.serverPublicKey, namedCurve);
                const clientKeyExchangeMsg = wrapHandshakeMessage(16, concatUint8Arrays([localKeyPair.pk.length], localKeyPair.pk));
                this.recordHandshake(clientKeyExchangeMsg);
                const hash = this.cipherConfig.hash;
                this.masterSecret = await prfTls12(
                    preMasterSecret,
                    "master secret",
                    concatUint8Arrays(this.clientRandom, this.serverRandom),
                    48,
                    hash
                );
                const {keyLen, ivLen} = this.cipherConfig;
                const keyBlock = await prfTls12(
                    this.masterSecret,
                    "key expansion",
                    concatUint8Arrays(this.serverRandom, this.clientRandom),
                    2 * keyLen + 2 * ivLen,
                    hash
                );
                [this.clientWriteKey, this.serverWriteKey] = await Promise.all([
                    importAesGcmKey(keyBlock.subarray(0, keyLen), "encrypt"),
                    importAesGcmKey(keyBlock.subarray(keyLen, 2 * keyLen), "decrypt")
                ]);
                this.clientWriteIv = keyBlock.subarray(2 * keyLen, 2 * keyLen + ivLen);
                this.serverWriteIv = keyBlock.subarray(2 * keyLen + ivLen, 2 * keyLen + 2 * ivLen);
                // 发送 ClientKeyExchange 与 ChangeCipherSpec
                await this.writer.write(wrapTlsRecord(22, clientKeyExchangeMsg));
                await this.writer.write(wrapTlsRecord(20, [1])); // ChangeCipherSpec (20)
                // 客户端 Finished 验证与加密发送
                const clientFinishedVerify = await prfTls12(
                    this.masterSecret,
                    "client finished",
                    await hashDigest(hash, this.getTranscript()),
                    12,
                    hash
                );
                const clientFinishedMsg = wrapHandshakeMessage(20, clientFinishedVerify);
                this.recordHandshake(clientFinishedMsg);
                await this.writer.write(wrapTlsRecord(22, await this.encryptTls12(clientFinishedMsg, 22)));
                // 等待服务端的 ChangeCipherSpec 和 Finished
                let ccsReceived = false;
                await this.processRecords(async (record) => {
                    if (record.type === 21) {
                        if (isUnrecognizedNameAlert(record.fragment)) return;
                        throw new Error("TLS alert received");
                    }
                    if (record.type === 20) {
                        ccsReceived = true;
                        return;
                    }
                    if (record.type === 22 && ccsReceived) {
                        const decrypted = await this.decryptTls12(record.fragment, 22);
                        if (decrypted[0] === 20) return 1; // 服务端 Finished (Handshake Type 20)
                    }
                });
            }
            // 握手成功：清理敏感材料释放内存
            this.handshakeComplete = true;
            this.clientRandom = this.sessionId = this.serverRandom = this.masterSecret = this.handshakeSecret = null;
            this.clientHandshakeKey = this.serverHandshakeKey = this.clientHandshakeIv = this.serverHandshakeIv = null;
            this.keyPairs.clear();
            this.keyPairs = null;
        } finally {
            if (!this.handshakeComplete || this.failed) {
                try { this.reader?.releaseLock(); } catch {}
                try { this.writer?.releaseLock(); } catch {}
            }
        }
    }
    /**
     * 等待并解析 ServerHello，确认协商的版本和密码套件
     */
    async readServerHello() {
        while (true) {
            const {value, done} = await this.readChunk();
            if (done) throw new Error("Connection closed before ServerHello");
            this.recordParser.feed(value);
            let record;
            while ((record = this.recordParser.next())) {
                if (record.type === 21) {
                    if (isUnrecognizedNameAlert(record.fragment)) continue;
                    throw new Error("TLS alert during ServerHello");
                }
                if (record.type === 22) {
                    this.handshakeParser.feed(record.fragment);
                    let hsMsg;
                    while ((hsMsg = this.handshakeParser.next())) {
                        if (hsMsg.type !== 2) continue; // 仅关注 ServerHello (Type 2)
                        this.recordHandshake(hsMsg.raw);
                        let offset = 2;
                        const legacyVersion = readU16BE(hsMsg.body, 0);
                        const serverRandom = hsMsg.body.slice(offset, (offset += 32));
                        const sessionIdLen = hsMsg.body[offset++];
                        const sessionId = hsMsg.body.subarray(offset, (offset += sessionIdLen));
                        const cipherSuite = readU16BE(hsMsg.body, offset);
                        offset += 2;
                        const compressionMethod = hsMsg.body[offset++];
                        let selectedVersion = legacyVersion;
                        let keyShare = null;
                        // 遍历解析扩展字段
                        if (offset < hsMsg.body.length) {
                            const extensionsEnd = offset + 2 + readU16BE(hsMsg.body, offset);
                            offset += 2;
                            while (offset + 4 <= extensionsEnd) {
                                const extType = readU16BE(hsMsg.body, offset);
                                const extLen = readU16BE(hsMsg.body, offset + 2);
                                const extData = hsMsg.body.subarray((offset += 4), (offset += extLen));
                                if (extType === 43 && extLen >= 2) {
                                    // supported_versions 判定真实协商版本
                                    selectedVersion = readU16BE(extData, 0);
                                } else if (extType === 51 && extLen >= 2) {
                                    // key_share 获取服务端的共享秘钥
                                    keyShare = {
                                        group: readU16BE(extData, 0),
                                        key: extLen >= 4 ? extData.subarray(4, 4 + readU16BE(extData, 2)) : EMPTY_BUFFER
                                    };
                                }
                            }
                        }
                        const isTls13 = selectedVersion === 772; // 0x0304 (TLS 1.3)
                        const isSha384 = cipherSuite === 4866 || cipherSuite === 49200 || cipherSuite === 49196;
                        // 校验密码套件有效性
                        if (
                            (!isSha384 && cipherSuite !== 4865 && cipherSuite !== 49199 && cipherSuite !== 49195) ||
                            compressionMethod !== 0 ||
                            (cipherSuite < 49000) !== isTls13 ||
                            (!isTls13 && selectedVersion !== 771)
                        ) {
                            throw new Error("Invalid or unsupported cipher suite / TLS version in ServerHello");
                        }
                        this.serverRandom = serverRandom;
                        this.cipherSuite = cipherSuite;
                        this.cipherConfig = {
                            keyLen: isSha384 ? 32 : 16,
                            ivLen: isTls13 ? 12 : 4,
                            hash: isSha384 ? "SHA-384" : "SHA-256",
                            tls13: isTls13
                        };
                        this.isTls13 = isTls13;
                        return {
                            version: legacyVersion,
                            sr: serverRandom,
                            sid: sessionId,
                            cs: cipherSuite,
                            comp: compressionMethod,
                            sv: selectedVersion,
                            ks: keyShare,
                            isTls13
                        };
                    }
                }
            }
        }
    }
    /**
     * TLS 1.2 AES-GCM 数据帧加密
     * 结构: [ExplicitNonce(8B)] + Ciphertext + Tag(16B)
     */
    async encryptTls12(plaintext, contentType, seqNum = this.nextClientSeq()) {
        const explicitNonce = new Uint8Array(8);
        new DataView(explicitNonce.buffer).setBigUint64(0, seqNum);
        const iv = concatUint8Arrays(this.clientWriteIv, explicitNonce);
        const aad = concatBytes(explicitNonce, contentType, 3, 3, u16ToBytes(plaintext.length));
        const encrypted = await aesGcmEncrypt(this.clientWriteKey, iv, plaintext, aad);
        return concatUint8Arrays(explicitNonce, encrypted);
    }
    /**
     * TLS 1.2 AES-GCM 数据帧解密
     */
    async decryptTls12(recordFragment, contentType, seqNum = this.nextServerSeq()) {
        const seqBytes = new Uint8Array(8);
        const explicitNonce = recordFragment.subarray(0, 8);
        const ciphertext = recordFragment.subarray(8);
        new DataView(seqBytes.buffer).setBigUint64(0, seqNum);
        const iv = concatUint8Arrays(this.serverWriteIv, explicitNonce);
        const aad = concatBytes(seqBytes, contentType, 3, 3, u16ToBytes(ciphertext.length - 16));
        return aesGcmDecrypt(this.serverWriteKey, iv, ciphertext, aad);
    }
    /**
     * TLS 1.3 应用数据加密
     * 明文末尾追加真实的 ContentType (23)，随后进行 AEAD 加密
     */
    async encryptTls13(plaintext, seqNum = this.nextClientSeq(), contentType = 23) {
        const innerPlaintext = new Uint8Array(plaintext.length + 1);
        innerPlaintext.set(plaintext);
        innerPlaintext[plaintext.length] = contentType;
        const iv = xorIv(this.clientAppIv, seqNum);
        const aad = createTls13Aad(innerPlaintext.length + 16);
        return aesGcmEncrypt(this.clientAppKey, iv, innerPlaintext, aad);
    }
    /**
     * TLS 1.3 应用数据解密
     */
    async decryptTls13(ciphertext, seqNum = this.nextServerSeq(), key = this.serverAppKey, iv = this.serverAppIv) {
        const decrypted = await aesGcmDecrypt(key, xorIv(iv, seqNum), ciphertext, createTls13Aad(ciphertext.length));
        return unpadTls13Plaintext(decrypted);
    }
    /**
     * 向对端发送应用层明文数据
     * 大数据自动以 16KB 分片，并以 8 包为一组并发加密提升吞吐
     */
    write(data) {
        if (!this.handshakeComplete || this.failed || this.closing) {
            return Promise.reject(new Error("Socket not ready or closing"));
        }
        const task = this.writeQueue.then(async () => {
            if (this.failed || this.closing) throw new Error("Connection failed or closing");
            const MAX_FRAGMENT_LEN = 16384; // TLS 标准最大明文片大小 (16KB)
            if (data.length <= MAX_FRAGMENT_LEN) {
                const encrypted = this.isTls13
                    ? await this.encryptTls13(data)
                    : await this.encryptTls12(data, 23);
                return this.writer.write(wrapTlsRecord(23, encrypted));
            }
            // 大包流水线加密
            for (let offset = 0; offset < data.length;) {
                const chunkPromises = [];
                for (let i = 0; i < 8 && offset < data.length; i++, offset += MAX_FRAGMENT_LEN) {
                    const chunk = data.subarray(offset, Math.min(offset + MAX_FRAGMENT_LEN, data.length));
                    const seq = this.nextClientSeq();
                    const recordPromise = (
                        this.isTls13
                            ? this.encryptTls13(chunk, seq)
                            : this.encryptTls12(chunk, 23, seq)
                    ).then((enc) => wrapTlsRecord(23, enc));
                    chunkPromises.push(recordPromise);
                }
                const records = await Promise.all(chunkPromises);
                await this.writer.write(concatUint8Arrays(...records));
            }
        });
        const chained = task.catch((err) => {
            this.fail();
            throw err;
        });
        this.writeQueue = chained.catch(() => {});
        return chained;
    }
    /**
     * 读取对端解密后的应用层数据，返回 Uint8Array，若连接已关闭则返回 null
     */
    read() {
        if (this.failed || !this.handshakeComplete) {
            return Promise.reject(new Error("Connection failed or handshake not complete"));
        }
        return (async () => {
            while (true) {
                if (this.packetQueue.length) {
                    return this.packetQueue.length === 1
                        ? this.packetQueue.pop()
                        : concatUint8Arrays(...this.packetQueue.splice(0));
                }
                if (this.closed) return null;
                // 批次提取多达 8 个数据包并发批量解密
                const batch = [];
                for (let record; batch.length < 8 && (record = this.recordParser.next());) {
                    if (!(this.isTls13 ? record.type === 20 : ![21, 22, 23].includes(record.type))) {
                        if (this.isTls13 && record.type !== 23) throw new Error("Unexpected record type in TLS 1.3");
                        batch.push(record);
                    }
                }
                if (batch.length) {
                    if (this.isTls13) {
                        const startSeq = this.serverSeqNum;
                        const key = this.serverAppKey;
                        const iv = this.serverAppIv;
                        let decryptedBatch;
                        try {
                            decryptedBatch = await Promise.all(
                                batch.map((r, idx) => this.decryptTls13(r.fragment, startSeq + BigInt(idx), key, iv))
                            );
                        } catch {}
                        if (decryptedBatch) {
                            this.serverSeqNum = startSeq + BigInt(decryptedBatch.length);
                            for (const item of decryptedBatch) this.processTls13Record(item);
                        } else {
                            // 若并发解密失败则降级为串行逐包解密
                            for (let i = 0; i < batch.length; i++) {
                                this.processTls13Record(await this.decryptTls13(batch[i].fragment, this.serverSeqNum++));
                            }
                        }
                    } else {
                        const startSeq = this.serverSeqNum;
                        const decryptedBatch = await Promise.all(
                            batch.map((r, idx) => this.decryptTls12(r.fragment, r.type, startSeq + BigInt(idx)))
                        );
                        this.serverSeqNum = startSeq + BigInt(batch.length);
                        for (let i = 0; i < decryptedBatch.length; i++) {
                            const plaintext = decryptedBatch[i];
                            const recType = batch[i].type;
                            if (recType === 23) {
                                this.packetQueue.push(plaintext);
                            } else if (recType === 21) {
                                this.processAlert(plaintext);
                            } else if (recType === 22) {
                                this.handshakeParser.feed(plaintext);
                                while (this.handshakeParser.next()) {}
                            }
                        }
                    }
                    if (this.packetQueue.length) {
                        return this.packetQueue.length === 1
                            ? this.packetQueue.pop()
                            : concatUint8Arrays(...this.packetQueue.splice(0));
                    }
                    if (this.closed) return null;
                    continue;
                }
                if (this.closed) return null;
                const {value, done} = await this.readChunk();
                if (done) return null;
                this.recordParser.feed(value);
            }
        })().catch((err) => {
            this.fail();
            throw err;
        });
    }
    /**
     * 处理 TLS 告警消息
     */
    processAlert(alertBytes) {
        this.closed = true;
        if (alertBytes && alertBytes.length >= 2) {
            const level = alertBytes[0];
            const description = alertBytes[1];
            // 致命告警 (Fatal 2) 或除正常断开 (close_notify 0) 外的警告均触发异常
            if (level === 2 || (level === 1 && description !== 0)) {
                this.fail();
                throw new Error(`TLS alert received: level ${level}, description ${description}`);
            }
        }
        this.close();
    }
    processTls13Record({data, type}) {
        if (type === 23) {
            this.packetQueue.push(data);
        } else if (type === 21) {
            this.processAlert(data);
        }
    }
    /**
     * 优雅关闭 TLS 连接 (发送 close_notify 告警)
     */
    close() {
        if (this.closePromise) return this.closePromise;
        if (this.failed || !this.handshakeComplete) {
            this.socket?.close();
            return (this.closePromise = Promise.resolve());
        }
        this.closing = true;
        this.writeQueue = this.closePromise = this.writeQueue
            .then(async () => {
                const closeNotify = new Uint8Array([1, 0]); // level: 1 (Warning), description: 0 (close_notify)
                const encrypted = this.isTls13
                    ? await this.encryptTls13(closeNotify, this.nextClientSeq(), 21)
                    : await this.encryptTls12(closeNotify, 21);
                await this.writer.write(wrapTlsRecord(this.isTls13 ? 23 : 21, encrypted));
            })
            .catch(() => {})
            .finally(() => {
                this.closed = true;
                this.socket?.close();
            });
        return this.closePromise;
    }
}
export {TlsClient};