/**
 * ============================================================================
 * TLS 1.2 & TLS 1.3 轻量级客户端实现 (Pure JavaScript / Web Crypto)
 * ============================================================================
 *
 * 本模块基于现代 Web 标准构建，不依赖 Node.js 原生的 `tls`、`net` 或 `crypto` 模块，
 * 专为 Cloudflare Workers 等边缘无服务器 (Serverless) 运行时设计；也可用于同时提供
 * W3C Web Crypto API、支持 BYOB 的 WHATWG 字节流、X25519 / P-256，以及符合本类
 * 构造函数约定的双向字节流套接字的运行时。浏览器本身通常不提供可直接使用的原始 TCP 套接字。
 *
 * 核心技术规范与协议标准依据:
 * - RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
 * - RFC 5246: The Transport Layer Security (TLS) Protocol Version 1.2
 * - RFC 5289: TLS Elliptic Curve Cipher Suites with SHA-256/384 and AES Galois Counter Mode (GCM)
 * - RFC 7748: Elliptic Curves for Security (X25519 现代高性能 Montgomery 曲线密钥协商)
 * - RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
 * - RFC 6066: Transport Layer Security (TLS) Extensions: Extension Definitions (SNI 等扩展)
 * - RFC 5746: Transport Layer Security (TLS) Renegotiation Indication Extension (安全重协商扩展)
 * - RFC 8422: Elliptic Curve Cryptography (ECC) Cipher Suites for Transport Layer Security (TLS)
 *
 * 支持的密码套件 (Cipher Suites):
 * 1. TLS 1.3 (RFC 8446 Section B.4):
 *    - 0x1301 (4865): TLS_AES_128_GCM_SHA256 (AEAD: AES-128-GCM, Hash: SHA-256)
 *    - 0x1302 (4866): TLS_AES_256_GCM_SHA384 (AEAD: AES-256-GCM, Hash: SHA-384)
 * 2. TLS 1.2 (RFC 5289 Section 3):
 *    - 0xC02F (49199): TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
 *    - 0xC030 (49200): TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
 *    - 0xC02B (49195): TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 *    - 0xC02C (49196): TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
 *
 * 支持的密钥协商命名曲线 (Supported Groups / Named Curves, RFC 8446 Section 4.2.7):
 * - X25519 (Group 29 / 0x001d) - 现代高性能 Montgomery 椭圆曲线 (Curve25519, RFC 7748)
 * - Secp256r1 / NIST P-256 (Group 23 / 0x0017) - NIST 标准 256 位 Weierstrass 椭圆曲线
 *
 * 安全边界与信任模型说明 (Security Notice & Trust Model):
 * 1. 【不认证服务端身份，也不校验服务端 Finished】:
 *    本实现会接收但不验证 X.509 证书链；TLS 1.2 中不会验证 ServerKeyExchange 签名，TLS 1.3 中不会验证
 *    CertificateVerify，并且两个版本都只识别服务端 Finished 消息类型，不会重新计算和比对其 verify_data。
 *    因此 AEAD 解密成功只表明记录与当前派生密钥一致，不能证明对端身份或排除中间人攻击。仅应在服务端
 *    认证与链路完整性已由外层可信机制保证的受控环境中使用，不能替代面向不可信网络的完整 TLS 实现。
 * 2. 【主密钥派生说明】:
 *    TLS 1.2 使用 RFC 5246 第 5 节与第 6.3 节定义的传统 Master Secret 派生方式；
 *    本实现未协商 RFC 7627 (Extended Master Secret) 扩展。
 *
 * 架构设计与性能优化要点:
 * 1. 【原生密码学加速 (Web Cryptography API)】:
 *    ECDH 密钥生成与共享秘密计算、HMAC、哈希及 AES-GCM 原语由底层 `crypto.subtle` 执行；
 *    TLS 专用的 PRF/HKDF 调度由本模块用这些原语组合。是否使用硬件加速由宿主运行时决定。
 * 2. 【WHATWG Streams & BYOB 缓冲区读取】:
 *    网络传输抽象为 ReadableStream 与 WritableStream。输入端通过 `readable.getReader({mode: "byob"})`
 *    提供并重新绑定 64KB 读取缓冲区；读取结果随后仍会复制到 `StreamParser` 的内部缓冲区。
 * 3. 【双指针滑动窗口内存紧凑复用 (StreamParser)】:
 *    内置滑动窗口解析器，通过 `head` 与 `tail` 游标维护 TCP 流式数据，以处理网络分片
 *    (拆包) 与粘包场景；仅在可用空间不足时触发 `copyWithin` 紧凑平移或动态倍增扩容。
 * 4. 【分批提交加解密】:
 *    - 写路径 (Egress): 大于 16KB 的大数据根据 RFC 规范切分为 16KB 分片，按 8 块一组利用 `Promise.all`
 *      提交加密；通过 `wrapMultipleRecords` 一次组装连续 TLS 记录帧，减少底层写入次数和额外拼接拷贝。
 *    - 读路径 (Ingress): 单批次最多提交 8 个 TLS 记录进行并发解密。
 * 5. 【序列号编码】:
 *    - 报文序列号使用 JavaScript `Number` 维护，只能精确表示到 `Number.MAX_SAFE_INTEGER`，并通过位移与除法
 *      拆分高低 32 位，避免使用 `BigInt` 或 `DataView`。
 *    - TLS 1.2 Nonce 与 13 字节 AAD 会按记录分配 TypedArray，并通过索引写入字段。
 * 6. 【长字节数组拼接】:
 *    - `concatBytes` 采用双遍遍历算法 (首遍计算总长，次遍 `.set()` 写入)，内部不会把长 TypedArray
 *      展开成函数参数；但普通数组的嵌套遍历仍然使用递归，极深嵌套仍受 JavaScript 调用栈限制。
 */
/** 全局单例 UTF-8 文本编码器，避免在热路径上频繁实例化带来不必要的内存分配与性能开销 */
const textEncoder = new TextEncoder();
/** 全局 0 长度 TypedArray 常量，用于空 Salt、空 Context 以及派生结果的初始累加值 */
const EMPTY_BUFFER = new Uint8Array(0);
/**
 * 【性能优化】: 缓存当前运行时 Web Crypto 的 SubtleCrypto 接口实例引用，
 * 减少高频加密路径上的全局命名空间属性查找开销。
 */
const cryptoSubtle = crypto.subtle;
// ============================================================================
// 1. 基础工具函数：字节序列化与辅助操作
// ============================================================================
/**
 * 递归展平任意嵌套的数值、普通数组或 Uint8Array，生成单一且连续的 Uint8Array 字节数组
 *
 * 【实现方式】:
 * 使用 `bytes.push(...item)` 展开很长的 TypedArray 可能因参数过多而抛出 `RangeError`。
 * 本函数采用双遍递归遍历，不在内部展开 TypedArray:
 * - 第一遍: 递归深度优先遍历，仅累加计算总字节长度，不执行任何内存拷贝；
 * - 第二遍: 一次性分配精确容量的 `Uint8Array`，通过 `.set()` 或索引递增原地写入。
 * 普通数组嵌套过深时，递归本身仍可能达到 JavaScript 调用栈上限。
 *
 * @param {...(number | number[] | Uint8Array | any[])} items - 待展平并拼接的嵌套数据项
 * @returns {Uint8Array} 展平并紧凑拼接后的连续字节数组
 */
function concatBytes(...items) {
    const calcLen = (list) => {
        let total = 0;
        for (let i = 0; i < list.length; i++) {
            const item = list[i];
            total += item instanceof Uint8Array ? item.length : Array.isArray(item) ? calcLen(item) : 1;
        }
        return total;
    };
    const result = new Uint8Array(calcLen(items));
    let offset = 0;
    const write = (list) => {
        for (let i = 0; i < list.length; i++) {
            const item = list[i];
            if (item instanceof Uint8Array) {
                result.set(item, offset);
                offset += item.length;
            } else if (Array.isArray(item)) {
                write(item);
            } else {
                result[offset++] = item;
            }
        }
    };
    write(items);
    return result;
}
/**
 * 将 16 位无符号整数 (uint16) 编码为 2 字节的大端序 (Big-Endian / 网络字节序) 数组
 *
 * @param {number} value - 待编码的 16 位无符号整数 (范围: 0 ~ 65535)
 * @returns {number[]} 包含 2 个字节的普通数组: [高8位 (MSB), 低8位 (LSB)]
 */
const u16ToBytes = (value) => [value >> 8, value & 0xff];
/**
 * 从字节数组的指定偏移位置读取一个 16 位大端序无符号整数 (uint16)
 *
 * @param {Uint8Array} buffer - 源字节缓冲区
 * @param {number} offset - 起始字节偏移量
 * @returns {number} 解析出的 16 位大端序整数数值 (范围: 0 ~ 65535)
 */
const readU16BE = (buffer, offset) => (buffer[offset] << 8) | buffer[offset + 1];
/**
 * 高性能合并多个 Uint8Array 块（单次内存分配并连续填充）
 *
 * 【性能优化说明】:
 * 预先统计所有非空 Uint8Array 的长度总和，单次申请对应容量的 TypedArray，
 * 依次调用 `.set()` 连续拷贝。自动忽略 `null` 或 `undefined` 片段。
 *
 * @param {...(Uint8Array | undefined | null)} arrays - 待拼接的 Uint8Array 列表
 * @returns {Uint8Array} 合并后的单一 Uint8Array 实例
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
 * 根据密码学哈希算法名称获取对应的输出摘要字节长度 (HashLen)
 *
 * - SHA-256: 32 字节 (256 位)
 * - SHA-384: 48 字节 (384 位)
 *
 * @param {("SHA-256"|"SHA-384")} hashName - 标准哈希算法名称
 * @returns {number} 哈希摘要字节长度 (32 或 48)
 */
const getHashLength = (hashName) => (hashName === "SHA-384" ? 48 : 32);
/**
 * 检查接收到的 Alert 报文是否为 Warning 级别的 SNI 不匹配告警 (unrecognized_name)
 *
 * 根据 RFC 6066 第 3 节规定，当服务端未能识别客户端所请求的 SNI 域名时，
 * 可能发送 Warning 级别的 `unrecognized_name` (112) 告警（RFC 不推荐这种 Warning 用法）；
 * 本实现选择在握手阶段忽略这一特定组合。
 *
 * @param {Uint8Array} alertBytes - 2 字节的标准 Alert 负载: [Level(1B), Description(1B)]
 * @returns {boolean} 若告警级别为 Warning (1) 且描述为 unrecognized_name (112) 则返回 true
 */
const isUnrecognizedNameAlert = (alertBytes) => alertBytes?.[0] === 1 && alertBytes[1] === 112;
// ============================================================================
// 2. Web Crypto API 封装：加解密与摘要计算
// ============================================================================
/**
 * 基于 Web Crypto API 计算 HMAC 消息认证码 (RFC 2104)
 *
 * @param {("SHA-256"|"SHA-384")} hashName - 底层哈希摘要算法名称
 * @param {Uint8Array | CryptoKey} key - HMAC 密钥材料 (原始字节数组或已导入的 CryptoKey)
 * @param {Uint8Array} data - 参与 HMAC 签名的输入数据负载
 * @returns {Promise<Uint8Array>} 计算生成的 HMAC 签名结果字节数组
 */
async function hmacSign(hashName, key, data) {
    const cryptoKey = key.type
        ? key
        : await cryptoSubtle.importKey("raw", key, {name: "HMAC", hash: hashName}, false, ["sign"]);
    return new Uint8Array(await cryptoSubtle.sign("HMAC", cryptoKey, data));
}
/**
 * 基于 Web Crypto API 计算数据的单向密码学哈希散列值 (SHA-256 / SHA-384)
 *
 * @param {("SHA-256"|"SHA-384")} hashName - 哈希算法名称 ("SHA-256" 或 "SHA-384")
 * @param {Uint8Array} data - 待计算摘要的原始数据
 * @returns {Promise<Uint8Array>} 摘要计算结果 (SHA-256 输出 32 字节, SHA-384 输出 48 字节)
 */
async function hashDigest(hashName, data) {
    return new Uint8Array(await cryptoSubtle.digest(hashName, data));
}
/**
 * 将原始对称密钥字节数组导入为 Web Crypto 的 AES-GCM CryptoKey 句柄
 *
 * @param {Uint8Array} rawKey - 16 字节 (AES-128) 或 32 字节 (AES-256) 原始对称密钥
 * @param {("encrypt"|"decrypt")} usage - 密钥用途 ("encrypt" 或 "decrypt")
 * @returns {Promise<CryptoKey>} 导入生成的不可导出 (extractable: false) CryptoKey 实例
 */
function importAesGcmKey(rawKey, usage) {
    return cryptoSubtle.importKey("raw", rawKey, {name: "AES-GCM"}, false, [usage]);
}
/**
 * 执行 AES-GCM 带关联数据的认证加密 (AEAD - Authenticated Encryption with Associated Data)
 *
 * 根据 NIST SP 800-38D 规范，AES-GCM 输出包含密文主体以及末尾追加的 16 字节 (128 位) 认证标签 (Auth Tag)。
 *
 * @param {CryptoKey} key - AES-GCM 加密密钥句柄
 * @param {Uint8Array} iv - 12 字节初始化向量 (Nonce)
 * @param {Uint8Array} plaintext - 待加密的明文数据
 * @param {Uint8Array} additionalData - 关联认证数据 (AAD)，参与完整性校验但不被加密
 * @returns {Promise<Uint8Array>} 密文与 16 字节认证标签拼接后的完整密文负载 (长度 = 明文长度 + 16)
 */
async function aesGcmEncrypt(key, iv, plaintext, additionalData) {
    return new Uint8Array(
        await cryptoSubtle.encrypt({name: "AES-GCM", iv, additionalData}, key, plaintext)
    );
}
/**
 * 执行 AES-GCM 带关联数据的认证解密 (AEAD - Authenticated Decryption)
 *
 * 验证密文末尾 16 字节的认证标签是否有效，若通过则解密出原始明文；
 * 若标签验证失败或数据被篡改，Web Crypto 的 Promise 将被拒绝；具体实现的时序特性由宿主运行时决定。
 *
 * @param {CryptoKey} key - AES-GCM 解密密钥句柄
 * @param {Uint8Array} iv - 12 字节初始化向量 (Nonce)
 * @param {Uint8Array} ciphertext - 包含末尾 16 字节认证标签的完整密文负载
 * @param {Uint8Array} additionalData - 关联认证数据 (AAD)
 * @returns {Promise<Uint8Array>} 解密恢复出的原始明文数据
 * @throws {Error|DOMException} 认证标签校验失败或密文损坏时，返回的 Promise 被拒绝
 */
async function aesGcmDecrypt(key, iv, ciphertext, additionalData) {
    return new Uint8Array(
        await cryptoSubtle.decrypt({name: "AES-GCM", iv, additionalData}, key, ciphertext)
    );
}
/**
 * 打包单个 TLS 记录层 (Record Layer) 报文帧
 *
 * TLS 1.2 记录层见 RFC 5246 第 6.2 节，TLS 1.3 记录层见 RFC 8446 第 5 节；线上记录头固定为 5 字节:
 * - Byte 0: ContentType (20: ChangeCipherSpec, 21: Alert, 22: Handshake, 23: ApplicationData)
 * - Bytes 1..2: ProtocolVersion (大端序 uint16，如 0x0303 代表 TLS 1.2，0x0301 代表 TLS 1.0)
 * - Bytes 3..4: Length (大端序 uint16，后续 Fragment 负载的字节长度)
 * - Bytes 5..5+Length-1: Fragment 有效负载
 *
 * 本函数只负责序列化，不校验 TLSPlaintext 或 TLSCiphertext 在对应协议版本下的长度上限。
 *
 * @param {number} contentType - 记录层协议类型编号 (1 字节)
 * @param {Uint8Array | number[]} fragment - 记录层承载的有效负载片段
 * @param {number} [version=0x0303] - 记录层 2 字节版本字段；0x0303 既是 TLS 1.2 版本值，也是 TLS 1.3 TLSCiphertext 的 legacy_record_version
 * @param {number} [length=fragment.length] - 负载字节长度
 * @returns {Uint8Array} 包含 5 字节头部与负载的完整 TLS 记录层字节数组
 */
function wrapTlsRecord(contentType, fragment, version = 0x0303, length = fragment.length) {
    const record = new Uint8Array(5 + length);
    record[0] = contentType;
    record[1] = version >> 8;
    record[2] = version & 0xff;
    record[3] = length >> 8;
    record[4] = length & 0xff;
    record.set(fragment, 5);
    return record;
}
/**
 * 批量打包多个密文片段为单个连续的 TLS 记录层流
 *
 * 【核心吞吐优化】:
 * 在流水线并发加密场景下，该函数先累加计算所有分片打包后的总字节长度 `sum(5 + fragment.length)`，
 * 单次申请连续 TypedArray 内存，并通过单重循环原地写入 5 字节记录层头部及密文载荷。
 * 避免先分别调用 `wrapTlsRecord`、再用 `concatUint8Arrays` 合并时产生的额外整体拷贝。
 *
 * @param {Uint8Array[]} fragments - 已加密的密文片段数组
 * @param {number} [contentType=23] - 协议内容类型 (默认 23: Application Data)
 * @returns {Uint8Array} 单次组装完毕的连续 TLS 记录层字节流；每条记录的版本字段固定为 0x0303
 */
function wrapMultipleRecords(fragments, contentType = 23) {
    let totalLen = 0;
    for (let i = 0; i < fragments.length; i++) totalLen += 5 + fragments[i].length;
    const result = new Uint8Array(totalLen);
    let offset = 0;
    for (let i = 0; i < fragments.length; i++) {
        const frag = fragments[i];
        const len = frag.length;
        result[offset] = contentType;
        result[offset + 1] = 3;
        result[offset + 2] = 3;
        result[offset + 3] = len >> 8;
        result[offset + 4] = len & 0xff;
        result.set(frag, offset + 5);
        offset += 5 + len;
    }
    return result;
}
/**
 * 打包 TLS 握手层 (Handshake Layer) 消息报文
 *
 * TLS 1.2 握手消息见 RFC 5246 第 7.4 节，TLS 1.3 握手协议见 RFC 8446 第 4 节；握手消息头固定为 4 字节:
 * - Byte 0: HandshakeType (1 字节，如 1: ClientHello, 2: ServerHello, 20: Finished 等)
 * - Bytes 1..3: Length (3 字节大端序 uint24，表示消息体字节长度)
 * - Bytes 4..4+Length-1: Handshake Body 消息体数据
 *
 * @param {number} handshakeType - 握手消息类型编号 (1 字节)
 * @param {Uint8Array | number[]} body - 握手消息体数据
 * @param {number} [length=body.length] - 消息体字节长度
 * @returns {Uint8Array} 包含 4 字节头部与消息体的完整握手消息字节数组
 */
function wrapHandshakeMessage(handshakeType, body, length = body.length) {
    const message = new Uint8Array(4 + length);
    message[0] = handshakeType;
    message[1] = (length >> 16) & 0xff;
    message[2] = (length >> 8) & 0xff;
    message[3] = length & 0xff;
    message.set(body, 4);
    return message;
}
/**
 * 构造 TLS 1.3 记录层关联认证数据 (AAD - Additional Authenticated Data)
 *
 * 根据 RFC 8446 第 5.2 节规定，TLS 1.3 记录层 AEAD 加解密的 AAD 固定为 5 字节，其结构定义为:
 * ```text
 * AAD = TLSCiphertext.opaque_type (0x17 = 23, application_data)
 *    || TLSCiphertext.legacy_record_version (0x0303 = TLS 1.2)
 *    || TLSCiphertext.length (uint16 大端序，即 InnerPlaintext 长度 + 16 字节 Tag)
 * ```
 *
 * @param {number} length - 加密后的记录层有效载荷总长度 (即内层明文长度 + 16 字节 Tag)
 * @returns {Uint8Array} 5 字节的标准 TLS 1.3 AAD 数组: `[23, 3, 3, length >> 8, length & 0xff]`
 */
function createTls13Aad(length) {
    return new Uint8Array([23, 3, 3, length >> 8, length & 0xff]);
}
// ============================================================================
// 3. TLS 密码学算法：密钥交换、PRF 与 HKDF 派生
// ============================================================================
/**
 * TLS 1.2 伪随机数函数 (PRF - Pseudo-Random Function)
 *
 * 依据 RFC 5246 第 5 节规范，TLS 1.2 采用基于 HMAC 的 P_hash 数据扩展算法:
 * ```text
 * PRF(secret, label, seed) = P_<hash>(secret, label + seed)
 *
 * P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
 *                        HMAC_hash(secret, A(2) + seed) + ...
 * 其中:
 * A(0) = seed (即 label + seed)
 * A(i) = HMAC_hash(secret, A(i-1))
 * ```
 * 该函数持续迭代生成伪随机字节序列，直至满足指定输出长度 `length`。
 *
 * @param {Uint8Array | CryptoKey} secret - 预主密钥 (Pre-Master Secret) 或主密钥 (Master Secret)
 * @param {string} label - ASCII 标签字符串 (如 "master secret", "key expansion", "client finished")
 * @param {Uint8Array} seed - 种子材料 (通常由客户端随机数和服务端随机数拼接而成)
 * @param {number} length - 期望派生的伪随机字节总长度
 * @param {("SHA-256"|"SHA-384")} [hashName="SHA-256"] - 底层哈希算法名称
 * @returns {Promise<Uint8Array>} 派生生成的伪随机字节数组 (截断至 exact length)
 */
async function prfTls12(secret, label, seed, length, hashName = "SHA-256") {
    const labelAndSeed = concatUint8Arrays(textEncoder.encode(label), seed);
    const key = secret.type
        ? secret
        : await cryptoSubtle.importKey("raw", secret, {name: "HMAC", hash: hashName}, false, ["sign"]);
    let result = EMPTY_BUFFER;
    let a = labelAndSeed;
    while (result.length < length) {
        a = await hmacSign(hashName, key, a);
        const step = await hmacSign(hashName, key, concatUint8Arrays(a, labelAndSeed));
        result = concatUint8Arrays(result, step);
    }
    return result.slice(0, length);
}
/**
 * HKDF-Extract: 提取伪随机密钥 (PRK - Pseudorandom Key)
 *
 * 依据 RFC 5869 第 2.2 节规范:
 * `PRK = HMAC-Hash(salt, IKM)`
 * 若未提供盐值 (`salt` 为 null 或空)，则自动采用长度为 HashLen 的全 0 字节填充作为默认盐值。
 *
 * @param {("SHA-256"|"SHA-384")} hashName - 底层哈希算法名称 ("SHA-256" 或 "SHA-384")
 * @param {Uint8Array | null} salt - 可选盐值材料；若缺省则自动补全为 HashLen 长度的全零数组
 * @param {Uint8Array} ikm - 输入密钥材料 (Input Keying Material)
 * @returns {Promise<Uint8Array>} 提取生成的伪随机密钥 PRK (长度为 HashLen 字节)
 */
function hkdfExtract(hashName, salt, ikm) {
    const saltBuffer = salt?.length ? salt : new Uint8Array(getHashLength(hashName));
    return hmacSign(hashName, saltBuffer, ikm);
}
/**
 * TLS 1.3 HKDF-Expand-Label (RFC 8446 Section 7.1)
 *
 * TLS 1.3 密钥调度的核心组件，依据 RFC 8446 第 7.1 节，定义了专属的 `HkdfLabel` 结构:
 * ```text
 * struct {
 *     uint16 length = length;
 *     opaque label<7..255> = "tls13 " + Label;
 *     opaque context<0..255> = Context;
 * } HkdfLabel;
 * ```
 * 将 `HkdfLabel` 作为 HKDF-Expand 的 `info` 参数，派生出指定长度的目标子密钥。
 *
 * 【性能优化说明】:
 * 直接就地预分配 `4 + labelLen + contextLen` 的连续缓冲区并手动写入大端长度与标签，
 * 避免通用 `concatBytes` 带来的二次数组组装与循环开销。
 *
 * @param {("SHA-256"|"SHA-384")} hashName - 哈希算法名称 ("SHA-256" 或 "SHA-384")
 * @param {Uint8Array | CryptoKey} prk - 伪随机主密钥 PRK
 * @param {string | Uint8Array} label - 字符串会自动追加 "tls13 " 前缀；Uint8Array 则按原样作为完整标签使用
 * @param {Uint8Array} context - 上下文哈希值 (通常为转录散列 Transcript-Hash 或空数组)
 * @param {number} length - 期望输出的派生密钥字节长度
 * @returns {Promise<Uint8Array>} 派生生成的子密钥字节数组
 */
async function hkdfExpandLabel(hashName, prk, label, context, length) {
    const labelBytes = typeof label === "string" ? textEncoder.encode("tls13 " + label) : label;
    const hashLen = getHashLength(hashName);
    const labelLen = labelBytes.length;
    const contextLen = context.length;
    // 就地组装 HkdfLabel 结构体 (2B length || 1B labelLen || label || 1B contextLen || context)
    const hkdfLabel = new Uint8Array(4 + labelLen + contextLen);
    hkdfLabel[0] = length >> 8;
    hkdfLabel[1] = length & 0xff;
    hkdfLabel[2] = labelLen;
    hkdfLabel.set(labelBytes, 3);
    hkdfLabel[3 + labelLen] = contextLen;
    if (contextLen) {
        hkdfLabel.set(context, 4 + labelLen);
    }
    const key = prk.type
        ? prk
        : await cryptoSubtle.importKey("raw", prk, {name: "HMAC", hash: hashName}, false, ["sign"]);
    let result = EMPTY_BUFFER;
    let t = EMPTY_BUFFER;
    const iterations = Math.ceil(length / hashLen);
    // HKDF-Expand 迭代扩展: T(i) = HMAC(PRK, T(i-1) + info + i)
    for (let i = 1; i <= iterations; i++) {
        const info = new Uint8Array(t.length + hkdfLabel.length + 1);
        if (t.length) info.set(t);
        info.set(hkdfLabel, t.length);
        info[t.length + hkdfLabel.length] = i;
        t = await hmacSign(hashName, key, info);
        result = concatUint8Arrays(result, t);
    }
    return result.slice(0, length);
}
/**
 * 本地生成 ECDH (P-256) 或 X25519 临时密钥对 (Ephemeral Key Pair)
 *
 * @param {("P-256"|"X25519")} [namedCurve="P-256"] - 曲线类型名称 ("P-256" 或 "X25519")
 * @returns {Promise<{kp: CryptoKeyPair, pk: Uint8Array}>} 包含原生 Web Crypto 密钥对及原始公钥字节的对象:
 *   - 对于 P-256: `pk` 为 65 字节非压缩点格式 (`0x04 || X(32B) || Y(32B)`)
 *   - 对于 X25519: `pk` 为 32 字节小端序 u 坐标 (RFC 7748)
 */
async function generateEcdhKeyPair(namedCurve = "P-256") {
    const isX25519 = namedCurve === "X25519";
    const keyPair = await cryptoSubtle.generateKey(
        isX25519 ? {name: "X25519"} : {name: "ECDH", namedCurve},
        true,
        ["deriveBits"]
    );
    const rawPublicKey = new Uint8Array(await cryptoSubtle.exportKey("raw", keyPair.publicKey));
    return {kp: keyPair, pk: rawPublicKey};
}
/**
 * 基于本端临时私钥与对端原始公钥协商计算 Diffie-Hellman 共享秘密 (Shared Secret / Z)
 *
 * @param {CryptoKey} privateKey - 本地生成的 ECDH/X25519 临时私钥句柄
 * @param {Uint8Array} peerPublicKeyRaw - 服务端返回的原始公钥字节 (P-256 65B 或 X25519 32B)
 * @param {("P-256"|"X25519")} [namedCurve="P-256"] - 椭圆曲线名称
 * @returns {Promise<Uint8Array>} 256 位 (32 字节) 的 Diffie-Hellman 共享秘密 Z
 */
async function deriveSharedSecret(privateKey, peerPublicKeyRaw, namedCurve = "P-256") {
    const isX25519 = namedCurve === "X25519";
    const peerPublicKey = await cryptoSubtle.importKey(
        "raw",
        peerPublicKeyRaw,
        isX25519 ? {name: "X25519"} : {name: "ECDH", namedCurve},
        false,
        []
    );
    return new Uint8Array(
        await cryptoSubtle.deriveBits(
            {name: isX25519 ? "X25519" : "ECDH", public: peerPublicKey},
            privateKey,
            256
        )
    );
}
/**
 * TLS 1.3 从 Traffic Secret 派生 AEAD 工作密钥与基础初始向量 (Base IV)
 *
 * 依据 RFC 8446 第 7.3 节:
 * ```text
 * [sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
 * [sender]_write_iv  = HKDF-Expand-Label(Secret, "iv",  "", iv_length)
 * ```
 *
 * @param {("SHA-256"|"SHA-384")} hashName - 哈希算法名称
 * @param {Uint8Array | CryptoKey} secret - 流量秘密源材料 (c/s hs traffic 或 c/s ap traffic)
 * @param {number} keyLen - AEAD 密钥长度 (AES-128 为 16 字节, AES-256 为 32 字节)
 * @param {number} ivLen - 初始向量长度 (TLS 1.3 GCM 固定为 12 字节)
 * @param {("encrypt"|"decrypt")} usage - 密钥用途 ("encrypt" 或 "decrypt")
 * @returns {Promise<[CryptoKey, Uint8Array]>} 数组元组: [已导入的 AES-GCM CryptoKey 句柄, 12 字节基础 IV 字节数组]
 */
async function deriveTrafficKeys(hashName, secret, keyLen, ivLen, usage) {
    const prk = secret.type
        ? secret
        : await cryptoSubtle.importKey("raw", secret, {name: "HMAC", hash: hashName}, false, ["sign"]);
    const [keyBytes, ivBytes] = await Promise.all([
        hkdfExpandLabel(hashName, prk, "key", EMPTY_BUFFER, keyLen),
        hkdfExpandLabel(hashName, prk, "iv", EMPTY_BUFFER, ivLen)
    ]);
    return [await importAesGcmKey(keyBytes, usage), ivBytes];
}
/**
 * 解析 TLS 1.3 AEAD 解密后的内部明文结构 (TLSInnerPlaintext 定义见 RFC 8446 Section 5.2，填充见 Section 5.4)
 *
 * TLS 1.3 在加密前将真实协议类型附在有效负载末尾，并允许追加任意长度的全 0 混淆填充 (Padding):
 * ```text
 * struct {
 *     opaque content[TLSPlaintext.length];
 *     ContentType type; // 真实 ContentType (非零)
 *     uint8 zeros[length_of_padding]; // 全 0 填充
 * } TLSInnerPlaintext;
 * ```
 * 本函数从尾部向前逆向扫描，跳过所有的全 0 填充字节；首个遇到的非零字节即为真实的 `ContentType`，
 * 其前面的全部字节即为对应内容类型的明文字节。
 *
 * @param {Uint8Array} buffer - AES-GCM 解密出的原始平铺字节 (TLSInnerPlaintext)
 * @returns {{data: Uint8Array, type: number}} 包含纯净有效载荷切片 (`data`) 与真实内容类型 (`type`) 的对象
 * @throws {Error} 若整个明文缓冲区全为 0（无有效 ContentType 终止标记），则抛出填充损坏异常
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
 * 计算 TLS 1.3 单包专属 Nonce (Per-Record Nonce / Masked IV)
 *
 * 依据 RFC 8446 第 5.3 节规范:
 * 记录序列号 `sequence_number` 被编码为 8 字节大端无符号整数，并在高位左填充 4 字节全零以形成 12 字节，
 * 随后与 12 字节的基础 IV (`base_iv`) 执行逐位异或运算:
 * ```text
 * nonce = base_iv ^ left_pad_zeroes(sequence_number, 12)
 * ```
 *
 * 【实现说明】:
 * 该函数通过 `iv.slice()` 分配返回缓冲区，但不创建 `DataView` 或 `BigInt`。`len - 1` 至 `len - 4`
 * 直接异或无符号低 32 位整型；
 * 若序列号超过 2^32，则提取高 32 位异或到 `len - 5` 至 `len - 8`。
 *
 * @param {Uint8Array} iv - 12 字节的基础初始向量 (Base IV)
 * @param {number} seqNum - 当前记录序列号；受 `Number` 表示限制，必须不超过 `Number.MAX_SAFE_INTEGER`
 * @returns {Uint8Array} 异或掩码计算后的 12 字节单记录 Nonce
 */
function xorIv(iv, seqNum) {
    const result = iv.slice();
    const low = seqNum >>> 0;
    const high = seqNum / 0x100000000 >>> 0;
    const i = result.length - 8;
    result[i] ^= high >>> 24;
    result[i + 1] ^= high >>> 16;
    result[i + 2] ^= high >>> 8;
    result[i + 3] ^= high;
    result[i + 4] ^= low >>> 24;
    result[i + 5] ^= low >>> 16;
    result[i + 6] ^= low >>> 8;
    result[i + 7] ^= low;
    return result;
}
// ============================================================================
// 4. 流式数据包通用解析器 (带内存紧凑复用与零拷贝切片)
// ============================================================================
/**
 * 双指针滑动窗口流式缓冲区解析器 (StreamParser)
 *
 * 专为 TCP 流式传输中的拆包 (分片未到) 与粘包 (多个报文粘连到达) 设计。
 * 内部维护 `buffer` 连续字节数组以及 `head` (未读数据起始)、`tail` (新数据写入端) 双游标。
 *
 * 【内存复用与抗碎片化机制】:
 * 1. 提取报文时调用 `.subarray()` 返回底层缓冲区的视图，避免复制报文字节；
 * 2. 写入新数据时，若尾部空间不足但前面存在已读释放空间 (`head > 0`)，
 *    优先通过高效的 `copyWithin(0, head, tail)` 将未读数据就地平移至头部紧凑复用；
 * 3. 仅当未读数据加上新数据总长真正超出容量时，才扩容到原容量的 2 倍或容纳新数据所需的更大值。
 */
class StreamParser {
    /**
     * @param {number} initialSize - 缓冲区初始分配容量 (字节)
     * @param {number} headerLen - 协议首部长度 (TLS 记录层为 5 字节，握手层为 4 字节)
     * @param {(buf: Uint8Array, offset: number) => number} getLength - 从报文首部解析负载长度的回调函数
     */
    constructor(initialSize, headerLen, getLength) {
        this.buffer = new Uint8Array(initialSize);
        this.head = 0;
        this.tail = 0;
        this.headerLen = headerLen;
        this.getLength = getLength;
    }
    /**
     * 向流解析器追加网络流入的原始字节数据块
     *
     * @param {Uint8Array} data - 新到达的原始网络数据切片
     */
    feed(data) {
        const self = this;
        if (self.tail + data.length > self.buffer.length) {
            const unread = self.tail - self.head;
            const needsResize = unread + data.length > self.buffer.length;
            const newBuf = needsResize
                ? new Uint8Array(Math.max(self.buffer.length * 2, unread + data.length))
                : self.buffer;
            if (needsResize) {
                newBuf.set(self.buffer.subarray(self.head, self.tail));
            } else {
                newBuf.copyWithin(0, self.head, self.tail);
            }
            self.buffer = newBuf;
            self.tail = unread;
            self.head = 0;
        }
        self.buffer.set(data, self.tail);
        self.tail += data.length;
    }
    /**
     * 尝试从当前缓冲区中提取下一个完整的协议报文帧
     *
     * @returns {{type: number, version: number, length: number, body: Uint8Array, fragment: Uint8Array, raw: Uint8Array} | null}
     *   若数据尚不完整 (拆包状态) 则返回 null 等待后续数据流入；若完整则返回报文对象
     * @throws {Error} 对 5 字节记录层解析器，若记录负载长度超过本实现采用的 18432 字节上限则抛出异常；该值是 TLS 1.2 的通用 TLSCiphertext 上限，宽于 TLS 1.3 的上限
     */
    next() {
        const self = this;
        if (self.tail - self.head < self.headerLen) return null;
        const length = self.getLength(self.buffer, self.head);
        if (self.headerLen === 5 && length > 18432) {
            throw new Error("TLS record length exceeds maximum allowed limit");
        }
        if (self.tail - self.head < self.headerLen + length) return null;
        const raw = self.buffer.subarray(self.head, (self.head += self.headerLen + length));
        const body = raw.subarray(self.headerLen);
        if (self.head === self.tail) {
            self.head = self.tail = 0;
        }
        return {
            type: raw[0],
            version: self.headerLen === 5 ? readU16BE(raw, 1) : 0,
            length,
            body,
            fragment: body,
            raw
        };
    }
}
// ============================================================================
// 5. 报文构造：ClientHello
// ============================================================================
/**
 * 构造同时提供 TLS 1.2 与 TLS 1.3 能力的 ClientHello 握手报文
 *
 * 依据 RFC 8446 第 4.1.2 节与附录 D.4 (中间盒兼容模式):
 * 1. 结构字段:
 *    - `legacy_version`: 0x0303 (TLS 1.2，用于兼容仅支持旧协议的中间路由器与防火墙)
 *    - `random`: 32 字节密码学安全客户端随机数
 *    - `legacy_session_id`: 携带 32 字节随机会话 ID，供服务端在兼容模式的 ServerHello 中回显；当前实现不校验该回显
 *    - `cipher_suites`: 包含 6 组现代主流 AEAD 密码套件 (TLS 1.3: 0x1301/0x1302, TLS 1.2: 0xC02F/0xC030/0xC02B/0xC02C)
 *    - `legacy_compression_methods`: 1 字节长度 1 + 0x00 (禁用压缩以防御 CRIME 侧信道攻击)
 * 2. 携带的标准扩展 (Extensions):
 *    - `renegotiation_info` (0xff01, RFC 5746): 在初始握手中发送空的 renegotiated_connection；本实现不处理后续重协商，也不验证服务端扩展
 *    - `server_name` (SNI, 0x0000, RFC 6066): 携带目标访问主机名
 *    - `ec_point_formats` (0x000b, RFC 8422): 声明仅支持非压缩椭圆曲线点格式 (0x00)
 *    - `supported_groups` (0x000a, RFC 8446): 声明支持的椭圆曲线 (X25519: 29, P-256: 23)
 *    - `signature_algorithms` (0x000d, RFC 8446): 发送 RSA-PSS、EdDSA、ECDSA、RSA-PKCS1 等算法标识；当前实现不会据此验证服务端签名
 *    - `supported_versions` (0x002b, RFC 8446): 协商协议版本 (0x0304 即 TLS 1.3, 0x0303 即 TLS 1.2)
 *    - `key_share` (0x0033, RFC 8446): 同时提供 X25519 与 P-256 的临时公钥，以降低因服务端选组而触发 HelloRetryRequest 的概率
 *
 * @param {Uint8Array} clientRandom - 客户端生成的 32 字节随机数
 * @param {string} serverName - 目标 SNI 主机名 (若为空则不附加 SNI 扩展)
 * @param {{x25519: Uint8Array, p256: Uint8Array}} keyShares - 预先生成的双曲线临时公钥
 * @param {Object} [options={}] - 可选配置项
 * @param {Uint8Array} [options.sessionId=EMPTY_BUFFER] - 兼容模式会话 ID；`handshake()` 调用时使用 32 字节随机值
 * @returns {Uint8Array} 包含 4 字节握手头的完整 ClientHello 握手报文
 */
function buildClientHello(clientRandom, serverName, keyShares, {sessionId = EMPTY_BUFFER} = {}) {
    const cipherSuites = concatBytes(...[4865, 4866, 49199, 49200, 49195, 49196].flatMap(u16ToBytes));
    const extensions = [
        concatBytes(0xff, 1, 0, 1, 0) // renegotiation_info (RFC 5746): ext_type=0xff01, len=1, renegotiated_connection_len=0
    ];
    if (serverName) {
        const hostBytes = textEncoder.encode(serverName);
        extensions.push(
            concatBytes(
                0, 0, // extension_type = 0 (server_name)
                u16ToBytes(hostBytes.length + 5), // extension_data 长度
                u16ToBytes(hostBytes.length + 3), // server_name_list 长度
                0, // name_type = 0 (host_name)
                u16ToBytes(hostBytes.length), // host_name 长度
                hostBytes // host_name 字节
            )
        );
    }
    const keyShareEntries = concatUint8Arrays(
        concatBytes(0, 29, u16ToBytes(keyShares.x25519.length), keyShares.x25519), // group 29 (X25519)
        concatBytes(0, 23, u16ToBytes(keyShares.p256.length), keyShares.p256)      // group 23 (Secp256r1)
    );
    extensions.push(
        concatBytes(u16ToBytes(11), 0, 2, 1, 0), // ec_point_formats (11): len=2, format_list_len=1, format 0 (uncompressed)
        concatBytes(u16ToBytes(10), 0, 6, 0, 4, 0, 29, 0, 23), // supported_groups (10): len=6, list_len=4, groups: [29, 23]
        concatBytes(
            u16ToBytes(13), // signature_algorithms (13)
            0, 34,          // ext_len = 34
            0, 32,          // algorithms_len = 32 (16 种签名组合，每种 2 字节)
            ...[
                2052, 2053, 2054, // rsa_pss_rsae_sha256/384/512
                2055, 2056,       // ed25519, ed448
                2057, 2058, 2059, // rsa_pss_pss_sha256/384/512
                1027, 1283, 1539, // ecdsa_secp256r1/384r1/521r1_sha256/384/512
                1025, 1281, 1537, // rsa_pkcs1_sha256/384/512
                513, 515          // rsa_pkcs1_sha1, ecdsa_sha1 (向后兼容)
            ].flatMap(u16ToBytes)
        ),
        concatBytes(u16ToBytes(43), 0, 5, 4, 3, 4, 3, 3), // supported_versions (43): len=5, list_len=4, versions: [0x0304 (TLS 1.3), 0x0303 (TLS 1.2)]
        concatBytes(u16ToBytes(51), u16ToBytes(keyShareEntries.length + 2), u16ToBytes(keyShareEntries.length), keyShareEntries) // key_share (51)
    );
    const serializedExtensions = concatUint8Arrays(...extensions);
    return wrapHandshakeMessage(
        1, // HandshakeType: ClientHello (1)
        concatBytes(
            u16ToBytes(0x0303), // legacy_version: TLS 1.2
            clientRandom,       // 32 字节客户端随机数
            sessionId.length,   // legacy_session_id 长度 (32)
            sessionId,          // 伪会话 ID
            u16ToBytes(cipherSuites.length), // cipher_suites 长度
            cipherSuites,       // 密码套件列表
            1, 0,               // legacy_compression_methods: len=1, method=0 (null)
            u16ToBytes(serializedExtensions.length), // extensions 总长度
            serializedExtensions // 序列化后的扩展集合
        )
    );
}
// ============================================================================
// 6. TLS 客户端实现主体 (TlsClient)
// ============================================================================
/**
 * TLS 1.2 / TLS 1.3 双协议自适应轻量级客户端
 *
 * 负责本实现覆盖的 TLS 连接流程:
 * 1. 握手阶段: 提供双曲线公钥、解析 ServerHello、判定 TLS 版本并派生记录保护密钥；
 * 2. 传输阶段: 对应用层明文进行分片、分批加密发送与接收解密；
 * 3. 更新与关闭: 处理 TLS 1.3 KeyUpdate、Alert 告警以及发送 `close_notify` 后关闭底层套接字。
 *
 * 此处“握手完成”表示实现所需的消息流程已经走完，不表示已经认证服务端；具体缺失的验证见文件头安全说明。
 */
class TlsClient {
    /**
     * @param {Object} socket - 抽象双向传输套接字对象
     * @param {ReadableStream<Uint8Array>} socket.readable - 支持 BYOB reader 的底层字节输入流
     * @param {WritableStream<Uint8Array>} socket.writable - 底层网络输出流 (WritableStream)
     * @param {() => (void | Promise<void>)} [socket.close] - 可选的底层套接字关闭回调；本类调用时不等待其返回值
     * @param {Object} [options={}] - 客户端可选配置项
     * @param {string} [options.serverName=""] - 目标 SNI 主机域名 (用于扩展 0x0000)
     */
    constructor(socket, options = {}) {
        this.socket = socket;
        this.serverName = options.serverName || "";
        this.clientRandom = crypto.getRandomValues(new Uint8Array(32));
        this.sessionId = crypto.getRandomValues(new Uint8Array(32));
        // 握手消息转录散列累加缓冲区 (初始分配 8KB，动态扩容)
        this.transcriptBuffer = new Uint8Array(8192);
        this.transcriptLen = 0;
        // 单调递增记录序列号计数器 (使用 Number，精确范围不超过 Number.MAX_SAFE_INTEGER)
        this.clientSeqNum = 0;
        this.serverSeqNum = 0;
        // 记录层 (5B 首部) 与握手层 (4B 首部) 滑动窗口流解析器
        this.recordParser = new StreamParser(32768, 5, (buf, offset) => readU16BE(buf, offset + 3));
        this.handshakeParser = new StreamParser(4096, 4, (buf, offset) => (buf[offset + 1] << 16) | readU16BE(buf, offset + 2));
        this.keyPairs = new Map();
        this.packetQueue = [];
        this.writeQueue = Promise.resolve(); // 写入任务排队 Promise 链，使报文发送及序列号分配按调用顺序执行
        this.readBuffer = new Uint8Array(65536); // BYOB 预分配 64KB 读取缓冲区
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
        // TLS 1.3 密码状态
        this.handshakeSecret = null;
        this.clientHandshakeKey = null;
        this.serverHandshakeKey = null;
        this.clientHandshakeIv = null;
        this.serverHandshakeIv = null;
        this.clientAppKey = null;
        this.clientAppIv = null;
        this.serverAppKey = null;
        this.serverAppIv = null;
        this.clientAppSecret = null;
        this.serverAppSecret = null;
        // TLS 1.2 密码状态
        this.masterSecret = null;
        this.clientWriteKey = null;
        this.serverWriteKey = null;
        this.clientWriteIv = null;
        this.serverWriteIv = null;
    }
    /**
     * 追加握手原始报文（不含 5 字节记录层头部）到转录缓冲区 (Transcript Buffer)
     *
     * @param {Uint8Array} data - 握手消息的原始字节数据
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
    /**
     * 获取当前所有已累计握手报文的共享视图（用于计算 Transcript-Hash）
     *
     * @returns {Uint8Array} 当前转录缓冲区有效区间的视图；后续扩容前它与内部缓冲区共享内存
     */
    getTranscript() {
        return this.transcriptBuffer.subarray(0, this.transcriptLen);
    }
    /**
     * 获取并单调递增客户端发送序列号
     *
     * @returns {number} 自增前的序列号数值
     */
    nextClientSeq() {
        return this.clientSeqNum++;
    }
    /**
     * 获取并单调递增服务端接收序列号
     *
     * @returns {number} 自增前的序列号数值
     */
    nextServerSeq() {
        return this.serverSeqNum++;
    }
    /**
     * 标记连接失败，并尝试关闭套接字、取消读取和中止写入
     */
    fail() {
        const client = this;
        client.failed = client.closed = true;
        try { client.socket?.close(); } catch {}
        try { client.reader?.cancel(); } catch {}
        try { client.writer?.abort(); } catch {}
    }
    /**
     * 从底层网络流以 BYOB (Bring-Your-Own-Buffer) 模式拉取数据
     *
     * @returns {Promise<ReadableStreamReadResult<Uint8Array>>} 读取结果对象 `{value, done}`
     * @throws {Error} 若底层读取被拒绝，或读取结果对象为 null/undefined，则抛出错误
     */
    async readChunk() {
        const client = this;
        const result = await client.reader.read(client.readBuffer);
        if (!result) throw new Error("Socket read returned null/undefined");
        if (!result.done && result.value) {
            // 在 BYOB 模式下底层 ArrayBuffer 所有权会被转移，在此重新绑定新的 TypedArray 视图
            client.readBuffer = new Uint8Array(result.value.buffer);
        }
        return result;
    }
    /**
     * TLS 记录层事件驱动循环
     *
     * 持续从解析器中排空完整记录帧并交付 `onRecord` 处理；当解析器缓冲区数据耗尽时，
     * 挂起并异步从网络拉取下一批数据切片，直至 `onRecord` 返回真值退出循环。
     *
     * @param {(record: {type: number, version: number, length: number, fragment: Uint8Array}) => Promise<any> | any} onRecord - 记录帧处理回调
     * @returns {Promise<void>}
     */
    async processRecords(onRecord) {
        const client = this;
        while (true) {
            let record;
            while ((record = client.recordParser.next())) {
                if (await onRecord(record)) return;
            }
            const {value, done} = await client.readChunk();
            if (done) throw new Error("Connection closed during record processing");
            client.recordParser.feed(value);
        }
    }
    /**
     * 更新服务端读取流量密钥并归零接收序列号 (RFC 8446 Section 7.2 KeyUpdate)
     *
     * ```text
     * next_server_app_secret = HKDF-Expand-Label(server_app_secret, "traffic upd", "", HashLen)
     * ```
     */
    async updateServerKeys() {
        const hash = this.cipherConfig.hash;
        const hashLen = getHashLength(hash);
        const {keyLen, ivLen} = this.cipherConfig;
        this.serverAppSecret = await hkdfExpandLabel(hash, this.serverAppSecret, "traffic upd", EMPTY_BUFFER, hashLen);
        [this.serverAppKey, this.serverAppIv] = await deriveTrafficKeys(hash, this.serverAppSecret, keyLen, ivLen, "decrypt");
        this.serverSeqNum = 0;
    }
    /**
     * 更新客户端写入流量密钥并归零发送序列号 (RFC 8446 Section 7.2 KeyUpdate)
     *
     * ```text
     * next_client_app_secret = HKDF-Expand-Label(client_app_secret, "traffic upd", "", HashLen)
     * ```
     */
    async updateClientKeys() {
        const hash = this.cipherConfig.hash;
        const hashLen = getHashLength(hash);
        const {keyLen, ivLen} = this.cipherConfig;
        this.clientAppSecret = await hkdfExpandLabel(hash, this.clientAppSecret, "traffic upd", EMPTY_BUFFER, hashLen);
        [this.clientAppKey, this.clientAppIv] = await deriveTrafficKeys(hash, this.clientAppSecret, keyLen, ivLen, "encrypt");
        this.clientSeqNum = 0;
    }
    /**
     * 在 TLS 1.3 连接上发送 KeyUpdate，以轮换本端写密钥并可选请求对端更新其写密钥 (RFC 8446 Section 4.6.3)
     *
     * @param {number} [requestUpdate=0] - 0: update_not_requested, 1: update_requested (对端收到后亦须发送 KeyUpdate)
     * @returns {Promise<void>}
     */
    sendKeyUpdate(requestUpdate = 0) {
        const client = this;
        if (!client.handshakeComplete || client.failed || client.closing) {
            return Promise.reject(new Error("Socket not ready or closing"));
        }
        const task = client.writeQueue.then(async () => {
            if (client.failed || client.closing) throw new Error("Connection failed or closing");
            const keyUpdateMsg = wrapHandshakeMessage(24, new Uint8Array([requestUpdate]));
            const encrypted = await client.encryptTls13(keyUpdateMsg, client.nextClientSeq(), 22);
            await client.writer.write(wrapTlsRecord(23, encrypted));
            await client.updateClientKeys();
        });
        const chained = task.catch((err) => {
            client.fail();
            throw err;
        });
        client.writeQueue = chained.catch(() => {});
        return chained;
    }
    /**
     * 执行本实现覆盖的 TLS 客户端握手流程 (自适应 TLS 1.2 与 TLS 1.3)
     *
     * 详细执行步骤（不包含服务端身份认证和服务端 Finished 校验）:
     * 1. 预先并发生成 X25519 与 P-256 双曲线临时密钥对；
     * 2. 组装并发送 ClientHello 握手报文；记录层采用版本 0x0301 (TLS 1.0) 以实现中间盒兼容；
     * 3. 接收并解析 ServerHello，判定服务端选定协议版本与密码套件:
     *    - 分支 A (TLS 1.3):
     *      a. 计算 ECDH 共享秘密 Z；
     *      b. 计算 Early Secret 与 Handshake Secret；
     *      c. 派生 Client/Server Handshake 密钥与 IV；
     *      d. 解密并记录服务端后续报文 (EncryptedExtensions, Certificate, CertificateVerify, Finished)，但不验证证书、CertificateVerify 或 Finished；
     *      e. 计算 Master Secret 与 Client/Server Application 密钥；
     *      f. 回复客户端 Finished 报文 (若有证书请求则用空 Certificate 表示没有客户端证书)，并在其前发送兼容性 ChangeCipherSpec 记录；
     *      g. 序列号归零，进入应用数据保护状态。
     *    - 分支 B (TLS 1.2):
     *      a. 接收 ServerKeyExchange (提取但不验证服务端 ECDH 临时公钥的签名) 与 ServerHelloDone；
     *      b. 计算 Pre-Master Secret，发送 ClientKeyExchange；
     *      c. 通过 TLS 1.2 PRF 派生 Master Secret 与对称密钥块 (Key Block)；
     *      d. 发送 ChangeCipherSpec 与加密的 Client Finished 报文；
     *      e. 接收服务端的 ChangeCipherSpec，解密后识别 Server Finished 消息类型，但不比对 verify_data；
     *      f. 握手完成，进入应用数据保护状态。
     *
     * @returns {Promise<void>} 本实现所需握手消息处理完成时解析；不代表服务端身份或 Finished 已验证
     */
    async handshake() {
        const client = this;
        const [p256KeyPair, x25519KeyPair] = await Promise.all([
            generateEcdhKeyPair("P-256"),
            generateEcdhKeyPair("X25519")
        ]);
        client.keyPairs = new Map([
            [23, p256KeyPair],
            [29, x25519KeyPair]
        ]);
        client.reader = client.socket.readable.getReader({mode: "byob"});
        client.writer = client.socket.writable.getWriter();
        try {
            const clientHello = buildClientHello(
                client.clientRandom,
                client.serverName,
                {p256: p256KeyPair.pk, x25519: x25519KeyPair.pk},
                {sessionId: client.sessionId}
            );
            client.recordHandshake(clientHello);
            // RFC 8446 附录 D.4: ClientHello 外层记录层协议版本设为 0x0301 (769 即 TLS 1.0)
            await client.writer.write(wrapTlsRecord(22, clientHello, 769));
            const serverHello = await client.readServerHello();
            // ----------------------------------------------------------------
            // 分支 A: TLS 1.3 握手流程 (RFC 8446)
            // ----------------------------------------------------------------
            if (serverHello.isTls13) {
                const groupCurve = serverHello.ks?.group === 29 ? "X25519" : serverHello.ks?.group === 23 ? "P-256" : null;
                const localKeyPair = client.keyPairs.get(serverHello.ks?.group);
                if (!groupCurve || !serverHello.ks?.key?.length || !localKeyPair) {
                    throw new Error("Missing or invalid key_share from server");
                }
                const hash = client.cipherConfig.hash;
                const hashLen = getHashLength(hash);
                const {keyLen, ivLen} = client.cipherConfig;
                // 1. 计算 Diffie-Hellman 共享秘密 (Shared Secret)
                const sharedSecret = await deriveSharedSecret(localKeyPair.kp.privateKey, serverHello.ks.key, groupCurve);
                // 2. HKDF 密钥调度: Early Secret -> Derived Early Secret -> Handshake Secret
                const earlySecret = await hkdfExtract(hash, null, new Uint8Array(hashLen));
                const emptyHash = await hashDigest(hash, EMPTY_BUFFER);
                const derivedEarlySecret = await hkdfExpandLabel(hash, earlySecret, "derived", emptyHash, hashLen);
                client.handshakeSecret = await hkdfExtract(hash, derivedEarlySecret, sharedSecret);
                // 3. 派生 Handshake 阶段流量密钥与 IV
                const hsTranscriptHash = await hashDigest(hash, client.getTranscript());
                const clientHsSecret = await hkdfExpandLabel(hash, client.handshakeSecret, "c hs traffic", hsTranscriptHash, hashLen);
                const serverHsSecret = await hkdfExpandLabel(hash, client.handshakeSecret, "s hs traffic", hsTranscriptHash, hashLen);
                [client.clientHandshakeKey, client.clientHandshakeIv] = await deriveTrafficKeys(hash, clientHsSecret, keyLen, ivLen, "encrypt");
                [client.serverHandshakeKey, client.serverHandshakeIv] = await deriveTrafficKeys(hash, serverHsSecret, keyLen, ivLen, "decrypt");
                let certRequestReceived = false;
                // 4. 读取并解密服务端 Handshake Flight (EncryptedExtensions, Certificate, CertificateVerify, Finished)
                await client.processRecords(async (record) => {
                    if (record.type === 20 || record.type === 22) return; // 忽略兼容性 CCS 以及此阶段未处理的明文 Handshake 记录
                    if (record.type === 21) {
                        if (isUnrecognizedNameAlert(record.fragment)) return;
                        throw new Error("TLS alert received during handshake");
                    }
                    if (record.type !== 23) return;
                    const decrypted = await aesGcmDecrypt(
                        client.serverHandshakeKey,
                        xorIv(client.serverHandshakeIv, client.nextServerSeq()),
                        record.fragment,
                        createTls13Aad(record.fragment.length)
                    );
                    const {data, type} = unpadTls13Plaintext(decrypted);
                    if (type === 22) {
                        client.handshakeParser.feed(data);
                        let hsMsg;
                        while ((hsMsg = client.handshakeParser.next())) {
                            client.recordHandshake(hsMsg.raw);
                            if (hsMsg.type === 13) {
                                certRequestReceived = true; // 服务端请求客户端证书 (CertificateRequest)
                            } else if (hsMsg.type === 20) {
                                return 1; // 收到 Server Finished (20)，握手入站流程完毕
                            }
                        }
                    }
                });
                // 5. HKDF 密钥调度: Handshake Secret -> Master Secret -> Application Traffic Secrets
                const finishedTranscriptHash = await hashDigest(hash, client.getTranscript());
                const derivedHsSecret = await hkdfExpandLabel(hash, client.handshakeSecret, "derived", emptyHash, hashLen);
                const masterSecret = await hkdfExtract(hash, derivedHsSecret, new Uint8Array(hashLen));
                client.clientAppSecret = await hkdfExpandLabel(hash, masterSecret, "c ap traffic", finishedTranscriptHash, hashLen);
                client.serverAppSecret = await hkdfExpandLabel(hash, masterSecret, "s ap traffic", finishedTranscriptHash, hashLen);
                [client.clientAppKey, client.clientAppIv] = await deriveTrafficKeys(hash, client.clientAppSecret, keyLen, ivLen, "encrypt");
                [client.serverAppKey, client.serverAppIv] = await deriveTrafficKeys(hash, client.serverAppSecret, keyLen, ivLen, "decrypt");
                // 6. 若服务端请求客户端认证，构造空 Certificate 表示没有可提供的客户端证书
                let certMessage = EMPTY_BUFFER;
                if (certRequestReceived) {
                    certMessage = wrapHandshakeMessage(11, new Uint8Array(4));
                    client.recordHandshake(certMessage);
                }
                // 7. 计算并组装客户端 Finished 校验报文: verify_data = HMAC(finished_key, Transcript-Hash)
                const clientFinishedKey = await hkdfExpandLabel(hash, clientHsSecret, "finished", EMPTY_BUFFER, hashLen);
                const clientFinishedVerify = await hmacSign(hash, clientFinishedKey, await hashDigest(hash, client.getTranscript()));
                const clientFinishedMsg = wrapHandshakeMessage(20, clientFinishedVerify);
                client.recordHandshake(clientFinishedMsg);
                // 8. 加密并发射客户端证书 (若有) 与 Finished 报文
                const encryptedPayload = concatUint8Arrays(certMessage, clientFinishedMsg, new Uint8Array([22]));
                const encryptedRecord = await aesGcmEncrypt(
                    client.clientHandshakeKey,
                    xorIv(client.clientHandshakeIv, client.nextClientSeq()),
                    encryptedPayload,
                    createTls13Aad(encryptedPayload.length + 16)
                );
                // RFC 8446 附录 D.4: 在客户端第二个握手 flight 前发送兼容性 ChangeCipherSpec (CCS) 记录
                const dummyCcsRecord = wrapTlsRecord(20, new Uint8Array([1]), 0x0303);
                await client.writer.write(concatUint8Arrays(dummyCcsRecord, wrapTlsRecord(23, encryptedRecord)));
                // 9. 应用数据加密准备: 双向序列号重置为 0
                client.clientSeqNum = client.serverSeqNum = 0;
            }
                // ----------------------------------------------------------------
                // 分支 B: TLS 1.2 握手流程 (RFC 5246)
            // ----------------------------------------------------------------
            else {
                let serverKeyExchange = null;
                let serverHelloDone = false;
                let certRequestReceived = false;
                const processHandshake = async (hsMsg) => {
                    client.recordHandshake(hsMsg.raw);
                    if (hsMsg.type === 12) {
                        // ServerKeyExchange (12): 提取 Curve ID 与服务端 ECDH 临时公钥
                        serverKeyExchange = {
                            namedCurve: readU16BE(hsMsg.body, 1),
                            serverPublicKey: hsMsg.body.subarray(4, 4 + hsMsg.body[3])
                        };
                    } else if (hsMsg.type === 14) {
                        serverHelloDone = true; // ServerHelloDone (14): 服务端握手消息发送完毕
                        return 1;
                    } else if (hsMsg.type === 13) {
                        certRequestReceived = true; // CertificateRequest (13)
                    }
                };
                let done = false;
                let pendingMsg;
                while ((pendingMsg = client.handshakeParser.next())) {
                    if (await processHandshake(pendingMsg)) {
                        done = true;
                        break;
                    }
                }
                if (!done) {
                    let record;
                    while ((record = client.recordParser.next())) {
                        if (record.type === 22) {
                            client.handshakeParser.feed(record.fragment);
                            while ((pendingMsg = client.handshakeParser.next())) {
                                if (await processHandshake(pendingMsg)) {
                                    done = true;
                                    break;
                                }
                            }
                            if (done) break;
                        }
                    }
                }
                if (!done) {
                    await client.processRecords(async (record) => {
                        if (record.type === 21) {
                            if (isUnrecognizedNameAlert(record.fragment)) return;
                            throw new Error("TLS alert received");
                        }
                        if (record.type === 20) {
                            throw new Error("Server attempted unexpected session resumption, which is unsupported");
                        }
                        if (record.type === 22) {
                            client.handshakeParser.feed(record.fragment);
                            let m;
                            while ((m = client.handshakeParser.next())) {
                                if (await processHandshake(m)) return 1;
                            }
                        }
                    });
                }
                if (!serverHelloDone || !serverKeyExchange) {
                    throw new Error("TLS 1.2 handshake failed: missing ServerKeyExchange or ServerHelloDone");
                }
                const namedCurve = serverKeyExchange.namedCurve === 29 ? "X25519" : serverKeyExchange.namedCurve === 23 ? "P-256" : null;
                const localKeyPair = client.keyPairs.get(serverKeyExchange.namedCurve);
                if (!namedCurve || !localKeyPair) {
                    throw new Error("Unsupported curve in ServerKeyExchange");
                }
                // 1. 若服务端请求客户端证书，构造空 Certificate 表示没有可提供的证书
                let clientCertRecord = EMPTY_BUFFER;
                if (certRequestReceived) {
                    const emptyCert = wrapHandshakeMessage(11, new Uint8Array(3));
                    client.recordHandshake(emptyCert);
                    clientCertRecord = wrapTlsRecord(22, emptyCert);
                }
                // 2. 计算 Pre-Master Secret 并构造 ClientKeyExchange 消息
                const preMasterSecret = await deriveSharedSecret(localKeyPair.kp.privateKey, serverKeyExchange.serverPublicKey, namedCurve);
                const clientKeyExchangeMsg = wrapHandshakeMessage(16, concatUint8Arrays(new Uint8Array([localKeyPair.pk.length]), localKeyPair.pk));
                client.recordHandshake(clientKeyExchangeMsg);
                // 3. PRF 派生 Master Secret: PRF(preMasterSecret, "master secret", clientRandom + serverRandom, 48)
                const hash = client.cipherConfig.hash;
                client.masterSecret = await prfTls12(
                    preMasterSecret,
                    "master secret",
                    concatUint8Arrays(client.clientRandom, client.serverRandom),
                    48,
                    hash
                );
                // 4. PRF 派生 Key Block: PRF(masterSecret, "key expansion", serverRandom + clientRandom, 2*keyLen + 2*ivLen)
                // 注意: RFC 5246 明确规定此处随机数顺序为 serverRandom 在前，clientRandom 在后！
                const {keyLen, ivLen} = client.cipherConfig;
                const keyBlock = await prfTls12(
                    client.masterSecret,
                    "key expansion",
                    concatUint8Arrays(client.serverRandom, client.clientRandom),
                    2 * keyLen + 2 * ivLen,
                    hash
                );
                [client.clientWriteKey, client.serverWriteKey] = await Promise.all([
                    importAesGcmKey(keyBlock.subarray(0, keyLen), "encrypt"),
                    importAesGcmKey(keyBlock.subarray(keyLen, 2 * keyLen), "decrypt")
                ]);
                client.clientWriteIv = keyBlock.subarray(2 * keyLen, 2 * keyLen + ivLen); // 4 字节隐式 IV
                client.serverWriteIv = keyBlock.subarray(2 * keyLen + ivLen, 2 * keyLen + 2 * ivLen);
                // 5. 构造 Client Finished 报文并使用刚刚就绪的 TLS 1.2 对称密钥加密
                const clientFinishedVerify = await prfTls12(
                    client.masterSecret,
                    "client finished",
                    await hashDigest(hash, client.getTranscript()),
                    12,
                    hash
                );
                const clientFinishedMsg = wrapHandshakeMessage(20, clientFinishedVerify);
                client.recordHandshake(clientFinishedMsg);
                const encryptedClientFinished = await client.encryptTls12(clientFinishedMsg, 22);
                // 6. 发送客户端飞行队列: [ClientCert] + ClientKeyExchange + ChangeCipherSpec + EncryptedFinished
                await client.writer.write(concatUint8Arrays(
                    clientCertRecord,
                    wrapTlsRecord(22, clientKeyExchangeMsg),
                    wrapTlsRecord(20, new Uint8Array([1])),
                    wrapTlsRecord(22, encryptedClientFinished)
                ));
                // 7. 接收服务端的 ChangeCipherSpec (20)，解密后确认存在 Finished (22)，但不校验其 verify_data
                let ccsReceived = false;
                await client.processRecords(async (record) => {
                    if (record.type === 21) {
                        if (isUnrecognizedNameAlert(record.fragment)) return;
                        throw new Error("TLS alert received");
                    }
                    if (record.type === 20) {
                        ccsReceived = true;
                        return;
                    }
                    if (record.type === 22 && ccsReceived) {
                        const decrypted = await client.decryptTls12(record.fragment, 22);
                        client.handshakeParser.feed(decrypted);
                        let hsMsg;
                        while ((hsMsg = client.handshakeParser.next())) {
                            if (hsMsg.type === 20) return 1;
                        }
                    }
                });
            }
            // 所需握手消息流程已完成；清除对临时密钥对及部分握手期材料的长期引用
            client.handshakeComplete = true;
            client.clientRandom = client.sessionId = client.serverRandom = client.masterSecret = client.handshakeSecret = null;
            client.clientHandshakeKey = client.serverHandshakeKey = client.clientHandshakeIv = client.serverHandshakeIv = null;
            client.keyPairs.clear();
            client.keyPairs = null;
        } finally {
            if (!client.handshakeComplete || client.failed) {
                try { client.reader?.releaseLock(); } catch {}
                try { client.writer?.releaseLock(); } catch {}
            }
        }
    }
    /**
     * 等待并解析服务端的 ServerHello 握手报文帧
     *
     * 提取服务端选定的协议版本 (TLS 1.2 vs TLS 1.3)、密码套件、服务端随机数以及 key_share 密钥共享扩展。
     *
     * @returns {Promise<{version: number, sr: Uint8Array, sid: Uint8Array, cs: number, comp: number, sv: number, ks: {group: number, key: Uint8Array} | null, isTls13: boolean}>}
     * @throws {Error} 若未收到 ServerHello 或服务端协商了不支持的协议/套件时抛出异常
     */
    async readServerHello() {
        const client = this;
        while (true) {
            const {value, done} = await client.readChunk();
            if (done) throw new Error("Connection closed before ServerHello");
            client.recordParser.feed(value);
            let record;
            while ((record = client.recordParser.next())) {
                if (record.type === 21) {
                    if (isUnrecognizedNameAlert(record.fragment)) continue;
                    throw new Error("TLS alert during ServerHello");
                }
                if (record.type === 20) {
                    continue; // 忽略兼容模式或其他来源的明文 CCS
                }
                if (record.type === 22) {
                    client.handshakeParser.feed(record.fragment);
                    let hsMsg;
                    while ((hsMsg = client.handshakeParser.next())) {
                        if (hsMsg.type !== 2) continue; // 仅过滤 ServerHello (HandshakeType = 2)
                        client.recordHandshake(hsMsg.raw);
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
                        // 遍历并解析 ServerHello 的 Extensions 扩展块
                        if (offset < hsMsg.body.length) {
                            const extensionsEnd = offset + 2 + readU16BE(hsMsg.body, offset);
                            offset += 2;
                            while (offset + 4 <= extensionsEnd) {
                                const extType = readU16BE(hsMsg.body, offset);
                                const extLen = readU16BE(hsMsg.body, offset + 2);
                                const extData = hsMsg.body.subarray((offset += 4), (offset += extLen));
                                if (extType === 43 && extLen >= 2) {
                                    // supported_versions (43): TLS 1.3 核心版本协商标记 (0x0304 即 772)
                                    selectedVersion = readU16BE(extData, 0);
                                } else if (extType === 51 && extLen >= 2) {
                                    // key_share (51): 服务端选定的命名曲线与其临时公钥
                                    keyShare = {
                                        group: readU16BE(extData, 0),
                                        key: extLen >= 4 ? extData.subarray(4, 4 + readU16BE(extData, 2)) : EMPTY_BUFFER
                                    };
                                }
                            }
                        }
                        const isTls13 = selectedVersion === 772; // 0x0304
                        const isSha384 = cipherSuite === 4866 || cipherSuite === 49200 || cipherSuite === 49196;
                        // 合法性校验: 必须选用无压缩 (0)、受支持的密码套件以及匹配的 TLS 版本
                        if (
                            (!isSha384 && cipherSuite !== 4865 && cipherSuite !== 49199 && cipherSuite !== 49195) ||
                            compressionMethod !== 0 ||
                            (cipherSuite < 49000) !== isTls13 ||
                            (!isTls13 && selectedVersion !== 771) // 0x0303
                        ) {
                            throw new Error("Invalid or unsupported cipher suite / TLS version in ServerHello");
                        }
                        client.serverRandom = serverRandom;
                        client.cipherSuite = cipherSuite;
                        client.cipherConfig = {
                            keyLen: isSha384 ? 32 : 16,
                            ivLen: isTls13 ? 12 : 4, // TLS 1.3 为 12B Base IV; TLS 1.2 为 4B 隐式 IV
                            hash: isSha384 ? "SHA-384" : "SHA-256",
                            tls13: isTls13
                        };
                        client.isTls13 = isTls13;
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
     * TLS 1.2 AES-GCM 数据帧认证加密 (RFC 5289 / RFC 5246)
     *
     * 采用无分支算法原地组装 AAD 与 Nonce，规避对象创建，并调用 Web Crypto 进行认证加密。
     *
     * @param {Uint8Array} plaintext - 待加密的明文数据
     * @param {number} contentType - 协议类型 (22: Handshake, 23: Application Data, 21: Alert)
     * @param {number} [seqNum=this.nextClientSeq()] - 记录序列号
     * @returns {Promise<Uint8Array>} 组装好的密文数据: `[8 字节显式 Nonce] || [密文主体] || [16 字节 Auth Tag]`
     */
    async encryptTls12(plaintext, contentType, seqNum = this.nextClientSeq()) {
        const aad = new Uint8Array(13);
        const l = seqNum >>> 0, h = (seqNum / 0x100000000) >>> 0;
        aad[0] = h >>> 24;
        aad[1] = h >>> 16;
        aad[2] = h >>> 8;
        aad[3] = h;
        aad[4] = l >>> 24;
        aad[5] = l >>> 16;
        aad[6] = l >>> 8;
        aad[7] = l;
        aad[8] = contentType;
        aad[9] = 3;
        aad[10] = 3;
        aad[11] = plaintext.length >> 8;
        aad[12] = plaintext.length;
        const seqBytes = aad.subarray(0, 8);
        const iv = new Uint8Array(12);
        iv.set(this.clientWriteIv);
        iv.set(seqBytes, 4);
        const encrypted = await aesGcmEncrypt(this.clientWriteKey, iv, plaintext, aad);
        const result = new Uint8Array(8 + encrypted.length);
        result.set(seqBytes);
        result.set(encrypted, 8);
        return result;
    }
    /**
     * TLS 1.2 AES-GCM 数据帧认证解密 (RFC 5289 / RFC 5246)
     *
     * 从密文切片头部提取 8 字节显式 Nonce，结合 4 字节服务端固定隐式 IV 拼装 12 字节 Nonce；
     * 采用无分支算法原地组装 13 字节 AAD，并调用 Web Crypto 校验认证标签并解密。
     *
     * @param {Uint8Array} recordFragment - 记录层密文切片 (包含前置 8B 显式 Nonce 与尾部 16B Tag)
     * @param {number} contentType - 记录层协议类型
     * @param {number} [seqNum=this.nextServerSeq()] - 预期的单调递增接收序列号
     * @returns {Promise<Uint8Array>} 解密出的原始明文载荷
     */
    async decryptTls12(recordFragment, contentType, seqNum = this.nextServerSeq()) {
        const explicitNonce = recordFragment.subarray(0, 8);
        const ciphertext = recordFragment.subarray(8);
        const iv = new Uint8Array(12);
        iv.set(this.serverWriteIv);
        iv.set(explicitNonce, 4);
        const aad = new Uint8Array(13);
        const l = seqNum >>> 0, h = (seqNum / 0x100000000) >>> 0;
        aad[0] = h >>> 24;
        aad[1] = h >>> 16;
        aad[2] = h >>> 8;
        aad[3] = h;
        aad[4] = l >>> 24;
        aad[5] = l >>> 16;
        aad[6] = l >>> 8;
        aad[7] = l;
        const plaintextLen = ciphertext.length - 16;
        aad[8] = contentType;
        aad[9] = 3;
        aad[10] = 3;
        aad[11] = plaintextLen >> 8;
        aad[12] = plaintextLen;
        return aesGcmDecrypt(this.serverWriteKey, iv, ciphertext, aad);
    }
    /**
     * 使用 TLS 1.3 应用流量密钥对记录内容进行认证加密 (RFC 8446 Section 5.2)
     *
     * 1. 组装内层明文: `TLSInnerPlaintext = plaintext || contentType (1B)`；
     * 2. 计算 Nonce: `clientAppIv ^ seqNum`；
     * 3. 组装 5 字节 AAD: `[23, 3, 3, (innerLen + 16) >> 8, (innerLen + 16) & 0xff]`；
     * 4. 调用 AES-GCM 执行认证加密。
     *
     * @param {Uint8Array} plaintext - 明文数据
     * @param {number} [seqNum=this.nextClientSeq()] - 记录发送序列号
     * @param {number} [contentType=23] - 真实内容类型 (默认 23: Application Data)
     * @returns {Promise<Uint8Array>} 密文数据与 16 字节认证标签的拼接结果
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
     * TLS 1.3 加密记录的认证解密 (RFC 8446 Section 5.2)
     *
     * 1. 计算 Nonce: `serverAppIv ^ seqNum`；
     * 2. 组装 5 字节 AAD: `[23, 3, 3, ciphertextLen >> 8, ciphertextLen & 0xff]`；
     * 3. 执行 AES-GCM 解密；
     * 4. 调用 `unpadTls13Plaintext` 去除填充并剥离真实的 `ContentType`。
     *
     * @param {Uint8Array} ciphertext - 密文数据
     * @param {number} [seqNum=this.nextServerSeq()] - 预期的接收序列号
     * @param {CryptoKey} [key=this.serverAppKey] - 解密密钥
     * @param {Uint8Array} [iv=this.serverAppIv] - 基础初始向量
     * @returns {Promise<{data: Uint8Array, type: number}>} 真实的明文载荷与内容类型
     */
    async decryptTls13(ciphertext, seqNum = this.nextServerSeq(), key = this.serverAppKey, iv = this.serverAppIv) {
        const decrypted = await aesGcmDecrypt(key, xorIv(iv, seqNum), ciphertext, createTls13Aad(ciphertext.length));
        return unpadTls13Plaintext(decrypted);
    }
    /**
     * 发送应用层明文数据
     *
     * 【分批加密与有序发送】:
     * 1. 有序发送: 依托 `writeQueue` Promise 链排队执行，使写入任务与序列号分配保持调用顺序；
     * 2. 小包直发: 数据 <= 16KB 时单次加密封装直发；
     * 3. 大包流水线: 数据 > 16KB 时自动切分为 16KB 分片，按 8 个分片一组由 `Promise.all` 并发调用底层
     *    Web Crypto；再经由 `wrapMultipleRecords` 单次分配打包为连续字节流，按批次写入底层输出流。
     *
     * @param {Uint8Array | ArrayBuffer | ArrayLike<number>} data - 待发送的应用层明文数据
     * @returns {Promise<void>} 对应的底层 `WritableStreamDefaultWriter.write()` 完成时解析
     */
    write(data) {
        const client = this;
        if (!client.handshakeComplete || client.failed || client.closing) {
            return Promise.reject(new Error("Socket not ready or closing"));
        }
        const payload = data instanceof Uint8Array ? data.slice() : new Uint8Array(data);
        if (!payload.length) return Promise.resolve();
        const task = client.writeQueue.then(async () => {
            if (client.failed || client.closing) throw new Error("Connection failed or closing");
            const MAX_FRAGMENT_LEN = 16384; // RFC 标准记录层明文最大分片上限 (16KB)
            // 小包路径: 单个记录直接加密封装
            if (payload.length <= MAX_FRAGMENT_LEN) {
                const encrypted = client.isTls13
                    ? await client.encryptTls13(payload)
                    : await client.encryptTls12(payload, 23);
                return client.writer.write(wrapTlsRecord(23, encrypted));
            }
            // 大包流水线路径: 8 分片并发加密组装
            for (let offset = 0; offset < payload.length;) {
                const chunkPromises = [];
                for (let i = 0; i < 8 && offset < payload.length; i++, offset += MAX_FRAGMENT_LEN) {
                    const chunk = payload.subarray(offset, Math.min(offset + MAX_FRAGMENT_LEN, payload.length));
                    const seq = client.nextClientSeq();
                    chunkPromises.push(
                        client.isTls13
                            ? client.encryptTls13(chunk, seq)
                            : client.encryptTls12(chunk, 23, seq)
                    );
                }
                const encryptedChunks = await Promise.all(chunkPromises);
                await client.writer.write(wrapMultipleRecords(encryptedChunks, 23));
            }
        });
        const chained = task.catch((err) => {
            client.fail();
            throw err;
        });
        client.writeQueue = chained.catch(() => {});
        return chained;
    }
    /**
     * 读取解密后的应用层数据
     *
     * 【多包批处理与快速解密】:
     * 1. 优先从内存已解密缓冲队列 (`packetQueue`) 中弹出数据；
     * 2. 若队列为空，从网络流拉取数据并从 `recordParser` 中批处理最多 8 个 TLS 记录帧并发解密；
     * 3. 按内容类型分发记录；TLS 1.3 使用解密后的内层类型，TLS 1.2 使用已认证的记录层类型:
     *    - 23 (Application Data): 压入应用数据队列；
     *    - 21 (Alert): 触发告警处理并响应关闭；
     *    - 22 (Handshake): 处理 TLS 1.3 KeyUpdate 并自动轮换密钥。
     *
     * @returns {Promise<Uint8Array | null>} 解密出的明文数据；若连接已关闭且无残留数据则返回 null
     */
    read() {
        const client = this;
        if (client.failed || !client.handshakeComplete) {
            return Promise.reject(new Error("Connection failed or handshake not complete"));
        }
        return (async () => {
            while (true) {
                if (client.packetQueue.length) {
                    return client.packetQueue.length === 1
                        ? client.packetQueue.pop()
                        : concatUint8Arrays(...client.packetQueue.splice(0));
                }
                if (client.closed) return null;
                const batch = [];
                for (let record; batch.length < 8 && (record = client.recordParser.next());) {
                    if (!(client.isTls13 ? record.type === 20 : ![21, 22, 23].includes(record.type))) {
                        if (client.isTls13 && record.type !== 23) throw new Error("Unexpected record type in TLS 1.3");
                        batch.push(record);
                    }
                }
                if (batch.length) {
                    // TLS 1.3 批量并发解密
                    if (client.isTls13) {
                        const startSeq = client.serverSeqNum;
                        const key = client.serverAppKey;
                        const iv = client.serverAppIv;
                        let decryptedBatch;
                        try {
                            decryptedBatch = await Promise.all(
                                batch.map((r, idx) => client.decryptTls13(r.fragment, startSeq + idx, key, iv))
                            );
                        } catch {}
                        if (decryptedBatch) {
                            client.serverSeqNum = startSeq + decryptedBatch.length;
                            for (const item of decryptedBatch) await client.processTls13Record(item);
                        } else {
                            // 批量中的任一解密失败时，按记录顺序重新解密，使失败前的记录仍能依次处理
                            for (let i = 0; i < batch.length; i++) {
                                const item = await client.decryptTls13(batch[i].fragment, client.serverSeqNum++);
                                await client.processTls13Record(item);
                            }
                        }
                    }
                    // TLS 1.2 批量并发解密
                    else {
                        const startSeq = client.serverSeqNum;
                        const decryptedBatch = await Promise.all(
                            batch.map((c, l) => client.decryptTls12(c.fragment, c.type, startSeq + l))
                        );
                        client.serverSeqNum = startSeq + batch.length;
                        for (let c = 0; c < decryptedBatch.length; c++) {
                            const l = decryptedBatch[c];
                            const h = batch[c].type;
                            if (h === 23) {
                                client.packetQueue.push(l);
                            } else if (h === 21) {
                                client.processAlert(l);
                            } else if (h === 22) {
                                client.handshakeParser.feed(l);
                                while (client.handshakeParser.next()) {}
                            }
                        }
                    }
                    if (client.packetQueue.length) {
                        return client.packetQueue.length === 1
                            ? client.packetQueue.pop()
                            : concatUint8Arrays(...client.packetQueue.splice(0));
                    }
                    if (client.closed) return null;
                    continue;
                }
                if (client.closed) return null;
                const {value, done} = await client.readChunk();
                if (done) return null;
                client.recordParser.feed(value);
            }
        })().catch((err) => {
            client.fail();
            throw err;
        });
    }
    /**
     * 处理接收到的 TLS 告警协议报文 (Alert Protocol)
     *
     * 告警格式见 RFC 5246 第 7.2 节；TLS 1.3 的告警处理规则见 RFC 8446 第 6 节。
     * 下列级别说明是本实现采用的传统字段解释；TLS 1.3 接收方通常应忽略 legacy AlertLevel:
     * - Level 1: Warning (警告)
     * - Level 2: Fatal (致命错误，必须立即中断连接)
     * - Description 0: close_notify (对端优雅关闭通知)
     *
     * @param {Uint8Array} alertBytes - 2 字节告警载荷: [Level, Description]
     * @throws {Error} 当 level 为 2，或 level 为 1 且 description 不是 close_notify 时抛出错误
     */
    processAlert(alertBytes) {
        this.closed = true;
        if (alertBytes && alertBytes.length >= 2) {
            const level = alertBytes[0];
            const description = alertBytes[1];
            if (level === 2 || (level === 1 && description !== 0)) {
                this.fail();
                throw new Error(`TLS alert received: level ${level}, description ${description}`);
            }
        }
        this.close();
    }
    /**
     * 处理 TLS 1.3 解密剥离后的真实内层报文帧
     *
     * @param {{data: Uint8Array, type: number}} record - 解密后的内层明文及真实 ContentType
     */
    async processTls13Record({data, type}) {
        if (type === 23) {
            this.packetQueue.push(data); // 应用数据
        } else if (type === 21) {
            this.processAlert(data); // 告警消息
        } else if (type === 22) {
            // 握手消息 (如 post-handshake KeyUpdate)
            this.handshakeParser.feed(data);
            let msg;
            while ((msg = this.handshakeParser.next())) {
                if (msg.type === 24) { // KeyUpdate (24)
                    const requestUpdate = msg.body[0];
                    await this.updateServerKeys();
                    if (requestUpdate === 1) {
                        await this.sendKeyUpdate(0);
                    }
                }
            }
        }
    }
    /**
     * 发送 TLS `close_notify` 后关闭底层套接字 (Graceful Teardown)
     *
     * 关闭告警见 RFC 5246 第 7.2.1 节与 RFC 8446 第 6.1 节:
     * 尝试构造、加密并发送 `close_notify` 告警 (Level 1, Description 0)，随后关闭底层套接字。
     * 该操作入队至 `writeQueue`，等待先前排队的 `writer.write()` 完成后发送告警；它不会等待对端返回
     * `close_notify`，也不保证底层网络已经完成物理发送。关闭告警的加密或写入错误会被内部忽略。
     *
     * @returns {Promise<void>} 关闭序列结束并调用底层 `socket.close()` 后解析；关闭告警发送失败也会解析
     */
    close() {
        const client = this;
        if (client.closePromise) return client.closePromise;
        if (client.failed || !client.handshakeComplete) {
            client.socket?.close();
            return (client.closePromise = Promise.resolve());
        }
        client.closing = true;
        client.writeQueue = client.closePromise = client.writeQueue
            .then(async () => {
                const closeNotify = new Uint8Array([1, 0]); // Level: 1 (warning), Description: 0 (close_notify)
                const encrypted = client.isTls13
                    ? await client.encryptTls13(closeNotify, client.nextClientSeq(), 21)
                    : await client.encryptTls12(closeNotify, 21);
                await client.writer.write(wrapTlsRecord(client.isTls13 ? 23 : 21, encrypted));
            })
            .catch(() => {})
            .finally(() => {
                client.closed = true;
                client.socket?.close();
            });
        return client.closePromise;
    }
}
export {TlsClient};
