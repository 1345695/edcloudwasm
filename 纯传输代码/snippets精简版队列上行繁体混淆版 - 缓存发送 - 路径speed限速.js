import {connect as 建立雲端連線} from 'cloudflare:sockets';
const 識碼 = 'd342d11e-d424-4583-b36e-524ab1f0afa4';
const 密雜 = '509eece82eb6910bebef9af9496092d3244b6c0d69ef3aaa4b12c565';
const 緩大 = 256 * 1024;
const 啟閾 = 50 * 1024 * 1024;
const 最塊 = 64 * 1024;
const 刷時 = 4;
const 網限 = 20;
const 代序 = ['socks', 'http', 'https', 'turn', 'turns'];
const 代址 = {EU: 'ProxyIP.DE.CMLiussss.net', AS: 'ProxyIP.SG.CMLiussss.net', JP: 'ProxyIP.JP.CMLiussss.net', US: 'ProxyIP.US.CMLiussss.net'};
const 房區 = {
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
const 房映 = new Map();
for (const [區代, 房集] of Object.entries(房區)) {for (const 房代 of 房集) 房映.set(房代, 代址[區代])}
const 識位 = new Uint8Array(16), 雜位 = new Uint8Array(56), 偏陣 = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 4, 4, 4, 4];
for (let 序 = 0, 暫值; 序 < 16; 序++) 識位[序] = (((暫值 = 識碼.charCodeAt(序 * 2 + 偏陣[序])) > 64 ? 暫值 + 9 : 暫值) & 0xF) << 4 | (((暫值 = 識碼.charCodeAt(序 * 2 + 偏陣[序] + 1)) > 64 ? 暫值 + 9 : 暫值) & 0xF);
for (let 序 = 0; 序 < 56; 序++) 雜位[序] = 密雜.charCodeAt(序);
const [編碼, 解碼, 通初] = [new TextEncoder(), new TextDecoder(), new Uint8Array([5, 2, 0, 2])];
const 錯頁 = `<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx/1.25.3</center></body></html>`;
const 址字 = (址類, 址位) => {
    if (址類 === 3) return 解碼.decode(址位);
    if (址類 === 1) return `${址位[0]}.${址位[1]}.${址位[2]}.${址位[3]}`;
    let 六址 = ((址位[0] << 8) | 址位[1]).toString(16);
    for (let 序 = 1; 序 < 8; 序++) 六址 += ':' + ((址位[序 * 2] << 8) | 址位[序 * 2 + 1]).toString(16);
    return `[${六址}]`;
};
const 解主埠 = (址串, 預埠) => {
    let 主 = 址串, 埠 = 預埠, 索位;
    if (址串.charCodeAt(0) === 91) {
        if ((索位 = 址串.indexOf(']:')) !== -1) {
            主 = 址串.substring(0, 索位 + 1);
            埠 = 址串.substring(索位 + 2);
        }
    } else if ((索位 = 址串.indexOf('.tp')) !== -1 && 址串.lastIndexOf(':') === -1) {
        埠 = 址串.substring(索位 + 3, 址串.indexOf('.', 索位 + 3));
    } else if ((索位 = 址串.lastIndexOf(':')) !== -1) {
        主 = 址串.substring(0, 索位);
        埠 = 址串.substring(索位 + 1);
    }
    return [主, (埠 = parseInt(埠), isNaN(埠) ? 預埠 : 埠)];
};
const 解認 = (認參) => {
    let 用名, 密, 主串;
    const 艾位 = 認參.lastIndexOf('@');
    if (艾位 === -1) {主串 = 認參} else {
        const 認片 = 認參.substring(0, 艾位);
        主串 = 認參.substring(艾位 + 1);
        const 冒位 = 認片.indexOf(':');
        if (冒位 === -1) {用名 = 認片} else {
            用名 = 認片.substring(0, 冒位);
            密 = 認片.substring(冒位 + 1);
        }
    }
    const [主名, 埠] = 解主埠(主串, 1080);
    return {用名, 密, 主名, 埠};
};
const 建連 = (主名, 埠, 連選, 連槽 = 建立雲端連線({hostname: 主名, port: 埠}, 連選)) => 連槽.opened.then(() => 連槽);
const 經通 = async (目類, 目埠, 通認, 址位) => {
    const 通槽 = await 建連(通認.主名, 通認.埠);
    const 寫入器 = 通槽.writable.getWriter();
    const 讀取器 = 通槽.readable.getReader();
    await 寫入器.write(通初);
    const {value: 認回} = await 讀取器.read();
    if (!認回 || 認回[0] !== 5 || 認回[1] === 0xFF) return null;
    if (認回[1] === 2) {
        if (!通認.用名) return null;
        const 用位 = 編碼.encode(通認.用名);
        const 密位 = 編碼.encode(通認.密 || '');
        const 用長 = 用位.length, 密長 = 密位.length, 認請 = new Uint8Array(3 + 用長 + 密長)
        認請[0] = 1, 認請[1] = 用長, 認請.set(用位, 2), 認請[2 + 用長] = 密長, 認請.set(密位, 3 + 用長);
        await 寫入器.write(認請);
        const {value: 認果} = await 讀取器.read();
        if (!認果 || 認果[0] !== 1 || 認果[1] !== 0) return null;
    } else if (認回[1] !== 0) {return null}
    const 是域 = 目類 === 3, 通請 = new Uint8Array(6 + 址位.length + (是域 ? 1 : 0));
    通請[0] = 5, 通請[1] = 1, 通請[2] = 0, 通請[3] = 目類;
    是域 ? (通請[4] = 址位.length, 通請.set(址位, 5)) : 通請.set(址位, 4);
    通請[通請.length - 2] = 目埠 >> 8, 通請[通請.length - 1] = 目埠 & 0xff;
    await 寫入器.write(通請);
    const {value: 最終回} = await 讀取器.read();
    if (!最終回 || 最終回[1] !== 0) return null;
    寫入器.releaseLock(), 讀取器.releaseLock();
    return 通槽;
};
const 固超頭 = `User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36\r\nProxy-Connection: Keep-Alive\r\nConnection: Keep-Alive\r\n\r\n`;
const 編固頭 = 編碼.encode(固超頭);
const 經超 = async (目類, 目埠, 超認, 址位, 用安 = false) => {
    const {用名, 密, 主名, 埠} = 超認;
    const 連選 = 用安 ? {secureTransport: 'on', allowHalfOpen: false} : undefined;
    const 代槽 = await 建連(主名, 埠, 連選);
    const 寫入器 = 代槽.writable.getWriter();
    const 超主 = 址字(目類, 址位);
    let 動頭 = `CONNECT ${超主}:${目埠} HTTP/1.1\r\nHost: ${超主}:${目埠}\r\n`;
    if (用名) 動頭 += `Proxy-Authorization: Basic ${btoa(`${用名}:${密 || ''}`)}\r\n`;
    const 全頭 = new Uint8Array(動頭.length * 3 + 編固頭.length);
    const {written: 寫長} = 編碼.encodeInto(動頭, 全頭);
    全頭.set(編固頭, 寫長);
    await 寫入器.write(全頭.subarray(0, 寫長 + 編固頭.length));
    寫入器.releaseLock();
    const 讀取器 = 代槽.readable.getReader();
    const 暫緩 = new Uint8Array(512);
    let 讀位 = 0, 狀查 = false;
    while (讀位 < 暫緩.length) {
        const {value: 讀值, done: 完成} = await 讀取器.read();
        if (完成 || 讀位 + 讀值.length > 暫緩.length) return null;
        const 前讀 = 讀位;
        暫緩.set(讀值, 讀位);
        讀位 += 讀值.length;
        if (!狀查 && 讀位 >= 12) {
            if (暫緩[9] !== 50) return null;
            狀查 = true;
        }
        let 序 = Math.max(15, 前讀 - 3);
        while ((序 = 暫緩.indexOf(13, 序)) !== -1 && 序 <= 讀位 - 4) {
            if (暫緩[序 + 1] === 10 && 暫緩[序 + 2] === 13 && 暫緩[序 + 3] === 10) {
                讀取器.releaseLock();
                return 代槽;
            }
            序++;
        }
    }
    return null;
};
const 魔字 = new Uint8Array([0x21, 0x12, 0xA4, 0x42]);
const 串位 = (...陣列) => {
    let 總長 = 0, 序 = 0, 偏 = 0;
    for (; 序 < 陣列.length; 序++) 總長 += 陣列[序].length;
    const 果 = new Uint8Array(總長);
    for (序 = 0; 序 < 陣列.length; 序++) {
        果.set(陣列[序], 偏);
        偏 += 陣列[序].length;
    }
    return 果;
};
const stun屬 = (型, 值) => {
    const 長 = 值.length, 緩 = new Uint8Array(4 + 長 + (4 - 長 % 4) % 4);
    緩[0] = 型 >> 8, 緩[1] = 型 & 0xff, 緩[2] = 長 >> 8, 緩[3] = 長 & 0xff, 緩.set(值, 4);
    return 緩;
};
const stun訊 = (型, 交易, 屬陣列) => {
    const 內容 = 串位(...屬陣列), 長 = 內容.length, 標頭 = new Uint8Array(20 + 長);
    標頭[0] = 型 >> 8, 標頭[1] = 型 & 0xff, 標頭[2] = 長 >> 8, 標頭[3] = 長 & 0xff, 標頭.set(魔字, 4), 標頭.set(交易, 8), 標頭.set(內容, 20);
    return 標頭;
};
const 異端 = (位址, 埠) => {
    const 緩 = new Uint8Array(8);
    緩[1] = 1;
    const 異或埠 = 埠 ^ 0x2112;
    緩[2] = 異或埠 >> 8, 緩[3] = 異或埠 & 0xff;
    let 段序 = 0, 數值 = 0;
    for (let 序 = 0; 序 < 位址.length; 序++) {
        const 字元 = 位址.charCodeAt(序);
        if (字元 === 46) {
            緩[4 + 段序] = 數值 ^ 魔字[段序++];
            數值 = 0;
        } else {數值 = 數值 * 10 + (字元 - 48)}
    }
    緩[4 + 段序] = 數值 ^ 魔字[段序];
    return 緩;
};
const 解析Stun = 料 => {
    if (料.length < 20 || 魔字.some((值, 序) => 料[4 + 序] !== 值)) return null;
    const 訊長 = (料[2] << 8) | 料[3], 屬 = {};
    for (let 偏 = 20; 偏 + 4 <= 20 + 訊長;) {
        const 型 = (料[偏] << 8) | 料[偏 + 1], 長 = (料[偏 + 2] << 8) | 料[偏 + 3];
        if (偏 + 4 + 長 > 料.length) break;
        屬[型] = 料.subarray(偏 + 4, 偏 + 4 + 長);
        偏 += 4 + 長 + (4 - 長 % 4) % 4;
    }
    return {型: (料[0] << 8) | 料[1], 屬};
};
const 解錯 = 料 => 料?.length >= 4 ? (料[2] & 7) * 100 + 料[3] : 0;
const 加整 = async (訊, 加鑰) => {
    const 長 = 訊.length, 果 = new Uint8Array(長 + 24);
    果.set(訊);
    const 新長 = (訊[2] << 8 | 訊[3]) + 24;
    果[2] = 新長 >> 8, 果[3] = 新長 & 0xff;
    const 簽名 = new Uint8Array(await crypto.subtle.sign('HMAC', 加鑰, 果.subarray(0, 長)));
    果[長] = 0x00, 果[長 + 1] = 0x08, 果[長 + 2] = 0x00, 果[長 + 3] = 0x14, 果.set(簽名, 長 + 4);
    return 果;
};
const 讀Stun = async (讀取器, 剩料) => {
    let 塊列 = 剩料 && 剩料.length ? [剩料] : [];
    let 總長 = 剩料 ? 剩料.length : 0;
    const 拉取 = async () => {
        const {done: 完成, value: 讀值} = await 讀取器.read();
        if (完成) throw 0;
        塊列.push(讀值);
        總長 += 讀值.length;
    };
    const 取緩 = () => {
        if (塊列.length === 1) return 塊列[0];
        const 緩 = new Uint8Array(總長);
        let 偏 = 0;
        for (let 序 = 0; 序 < 塊列.length; 序++) {
            緩.set(塊列[序], 偏);
            偏 += 塊列[序].length;
        }
        塊列 = [緩];
        return 緩;
    };
    try {
        while (總長 < 20) await 拉取();
        let 緩 = 取緩();
        if (緩[4] !== 0x21 || 緩[5] !== 0x12 || 緩[6] !== 0xA4 || 緩[7] !== 0x42) return null;
        const 需長 = 20 + ((緩[2] << 8) | 緩[3]);
        if (需長 > 8192) return null;
        while (總長 < 需長) await 拉取();
        緩 = 取緩();
        return [解析Stun(緩.subarray(0, 需長)), 總長 > 需長 ? 緩.subarray(需長) : null];
    } catch {return null}
};
const md5 = async 字串 => new Uint8Array(await crypto.subtle.digest('MD5', 編碼.encode(字串)));
const 經轉 = async ({主名, 埠, 用名, 密}, 目址, 目埠, 用安 = false) => {
    let 控槽 = null, 資槽 = null, 資諾 = null;
    const 關 = () => [控槽, 資槽].forEach(插槽 => {try {插槽?.close()} catch {}});
    const 建立連線 = () => 建連(主名, 埠, 用安 ? {secureTransport: 'on', allowHalfOpen: false} : undefined);
    try {
        控槽 = await 建立連線();
        const 控寫 = 控槽.writable.getWriter(), 控讀 = 控槽.readable.getReader();
        const 交緩 = new Uint8Array(12), 交易 = () => crypto.getRandomValues(交緩), 傳協 = new Uint8Array([6, 0, 0, 0]);
        await 控寫.write(stun訊(0x003, 交易(), [stun屬(0x019, 傳協)]));
        let [回, 剩餘] = await 讀Stun(控讀);
        if (!回) throw 0;
        let 加鑰 = null, 認屬 = [];
        const 簽 = 訊 => 加鑰 ? 加整(訊, 加鑰) : 訊;
        const 端 = stun屬(0x012, 異端(目址, 目埠));
        if (回.型 === 0x113 && 用名 && 解錯(回.屬[0x009]) === 401) {
            const 域 = 解碼.decode(回.屬[0x014] ?? []), 隨值 = 回.屬[0x015] ?? [];
            const 鑰位 = await md5(`${用名}:${域}:${密}`);
            加鑰 = await crypto.subtle.importKey('raw', 鑰位, {name: 'HMAC', hash: 'SHA-1'}, false, ['sign']);
            認屬 = [stun屬(0x006, 編碼.encode(用名)), stun屬(0x014, 編碼.encode(域)), stun屬(0x015, 隨值)];
            const [分訊, 許訊, 連訊] = await Promise.all([
                簽(stun訊(0x003, 交易(), [stun屬(0x019, 傳協), ...認屬])),
                簽(stun訊(0x008, 交易(), [端, ...認屬])),
                簽(stun訊(0x00A, 交易(), [端, ...認屬]))
            ]);
            await 控寫.write(串位(分訊, 許訊, 連訊));
            資諾 = 建立連線();
            [回, 剩餘] = await 讀Stun(控讀, 剩餘);
            if (回?.型 !== 0x103) throw 0;
        } else if (回.型 === 0x103) {
            const [許訊, 連訊] = await Promise.all([
                簽(stun訊(0x008, 交易(), [端, ...認屬])),
                簽(stun訊(0x00A, 交易(), [端, ...認屬]))
            ]);
            await 控寫.write(串位(許訊, 連訊));
            資諾 = 建立連線();
        } else {throw 0}
        [回, 剩餘] = await 讀Stun(控讀, 剩餘);
        if (回?.型 !== 0x108) throw 0;
        [回] = await 讀Stun(控讀, 剩餘);
        if (回?.型 !== 0x10A || !回.屬[0x02A]) throw 0;
        資槽 = await 資諾;
        const 資寫 = 資槽.writable.getWriter(), 資讀 = 資槽.readable.getReader();
        await 資寫.write(await 簽(stun訊(0x00B, 交易(), [stun屬(0x02A, 回.屬[0x02A]), ...認屬])));
        let 額料;
        [回, 額料] = await 讀Stun(資讀);
        if (回?.型 !== 0x10B) throw 0;
        控讀.releaseLock(), 控寫.releaseLock(), 資讀.releaseLock(), 資寫.releaseLock();
        return {readable: 資槽.readable, writable: 資槽.writable, close: 關, extra: 額料};
    } catch {
        關();
        return null;
    }
};
const 解址料 = (暫緩, 偏, 址類) => {
    const 位址長 = 址類 === 3 ? 暫緩[偏++] : 址類 === 1 ? 4 : 址類 === 4 ? 16 : null;
    if (位址長 === null) return null;
    const 料偏 = 偏 + 位址長;
    if (料偏 > 暫緩.length) return null;
    const 址位 = 暫緩.subarray(偏, 料偏);
    return {址位, 料偏};
};
const 解請包 = (首塊) => {
    for (let 序 = 0; 序 < 16; 序++) if (首塊[序 + 1] !== 識位[序]) return null;
    let 偏 = 19 + 首塊[17];
    const 埠 = (首塊[偏] << 8) | 首塊[偏 + 1];
    let 址類 = 首塊[偏 + 2];
    if (址類 !== 1) 址類 += 1;
    const 址訊 = 解址料(首塊, 偏 + 3, 址類);
    if (!址訊) return null;
    return {址類, 址位: 址訊.址位, 料偏: 址訊.料偏, 埠};
};
const 解透包 = (首塊) => {
    for (let 序 = 0; 序 < 56; 序++) if (首塊[序] !== 雜位[序]) return null;
    const 址類 = 首塊[59];
    const 址訊 = 解址料(首塊, 60, 址類);
    if (!址訊) return null;
    const 埠 = (首塊[址訊.料偏] << 8) | 首塊[址訊.料偏 + 1];
    return {址類, 址位: 址訊.址位, 料偏: 址訊.料偏 + 4, 埠};
};
const 解影包 = (首塊) => {
    const 址類 = 首塊[0];
    const 址訊 = 解址料(首塊, 1, 址類);
    if (!址訊) return null;
    const 埠 = (首塊[址訊.料偏] << 8) | 首塊[址訊.料偏 + 1];
    return {址類, 址位: 址訊.址位, 料偏: 址訊.料偏 + 2, 埠};
};
const 域選 = {headers: {'Accept': 'application/dns-json'}}, 域快 = new Map();
const 域解 = async (域名, 型, 解析) => {
    const 快鍵 = 型 + ':' + 域名, 現時 = Date.now(), 已快 = 域快.get(快鍵);
    if (已快) {
        if (已快.過時 > 現時) return 已快.果值;
        域快.delete(快鍵);
    }
    const 回 = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(域名)}&type=${型}`, 域選);
    if (!回.ok) return null;
    const 查果 = await 回.json(), 答 = 查果.Answer || 查果.answer;
    if (!答 || 答.length === 0) return null;
    const 果 = 解析(答);
    if (果) 域快.set(快鍵, {過時: 現時 + 300000, 果值: 果});
    return 果;
};
const 址解 = 域名 => 域解(域名, 'A', 答 => {
    let 位址 = null;
    for (let 序 = 0, 長 = 答.length; 序 < 長; 序++) if (答[序].type === 1 && 答[序].data) {
        位址 = 答[序].data;
        break;
    }
    return 位址;
});
const 文解 = 文域 => 域解(文域, 'TXT', 答 => {
    let 文料, 序 = 0, 長 = 答.length;
    for (; 序 < 長; 序++) if (答[序].type === 16) {
        文料 = 答[序].data;
        break;
    }
    if (!文料) return null;
    if (文料.charCodeAt(0) === 34 && 文料.charCodeAt(文料.length - 1) === 34) 文料 = 文料.slice(1, -1);
    const 原料 = 文料.split(/,|\\010|\n/), 前列 = [];
    for (序 = 0, 長 = 原料.length; 序 < 長; 序++) {
        const 暫串 = 原料[序].trim();
        if (暫串) 前列.push(暫串);
    }
    return 前列.length ? 前列 : null;
});
const 代正 = /william|fxpip|hhtxt/;
const 連代 = async (參值, 文記) => {
    if (文記 || 代正.test(參值)) {
        const 解址 = await 文解(參值);
        if (!解址 || 解址.length === 0) return null;
        const [主, 埠] = 解主埠(解址[(Math.random() * 解址.length) | 0], 443);
        return 建連(主, 埠);
    }
    const [主, 埠] = 解主埠(參值, 443);
    return 建連(主, 埠);
};
const 策映 = new Map([
    [0, async ({址類, 埠, 址位}) => {
        const 主名 = 址字(址類, 址位);
        return 建連(主名, 埠);
    }],
    [1, async ({址類, 埠, 址位}, 參值) => {
        const 通認 = 解認(參值);
        return 經通(址類, 埠, 通認, 址位);
    }],
    [2, async ({址類, 埠, 址位}, 參值) => {
        const 超認 = 解認(參值);
        return 經超(址類, 埠, 超認, 址位);
    }],
    [6, async ({址類, 埠, 址位}, 參值) => {
        const 超認 = 解認(參值);
        return 經超(址類, 埠, 超認, 址位, true);
    }],
    [3, async (_解請, 參值, 文記) => {
        return 連代(參值, 文記);
    }],
    [5, async ({址類, 埠, 址位}, 參值) => {
        let 目址 = 址字(址類, 址位);
        if (址類 === 3) {
            目址 = await 址解(目址);
            if (!目址) return null;
        } else if (址類 === 4) {return null}
        return 經轉(解認(參值), 目址, 埠);
    }],
    [7, async ({址類, 埠, 址位}, 參值) => {
        let 目址 = 址字(址類, 址位);
        if (址類 === 3) {
            目址 = await 址解(目址);
            if (!目址) return null;
        } else if (址類 === 4) {return null}
        return 經轉(解認(參值), 目址, 埠, true);
    }]
]);
const 網典 = new Map(), 網鍵 = new Array(網限);
let 網序 = 0;
const 參正 = /(speed|gs5|s5all|ghttp|httpall|ghttps|httpsall|gturn|turnall|gturns|turnsall|s5|socks|http|https|turn|turns|txtip|ip)(?:=|:\/\/|%3A%2F%2F)([^&]+)|(proxyall|globalproxy)/gi;
const 建傳連 = async (解請, 請) => {
    let 網串 = 請.url, 淨徑 = 網串.slice(網串.indexOf('/', 10) + 1), 徑長 = 淨徑.length, 策列 = [], 速;
    if (徑長 > 3 && 淨徑.charCodeAt(徑長 - 4) === 47 && 淨徑.charCodeAt(徑長 - 3) === 84 && 淨徑.charCodeAt(徑長 - 2) === 117 && 淨徑.charCodeAt(徑長 - 1) === 110) {
        淨徑 = 淨徑.slice(0, 徑長 - 4);
    } else {
        const 字碼 = 淨徑.charCodeAt(徑長 - 1);
        if (字碼 === 47 || 字碼 === 61) 淨徑 = 淨徑.slice(0, 徑長 - 1);
    }
    const 已果 = 網典.get(淨徑);
    if (已果 !== undefined) {
        策列 = 已果.策列, 速 = 已果.速;
    } else {
        if (淨徑.length < 6) {策列.push({型: 0}, {型: 3, 參: 房映.get(請.cf?.colo) ?? 代址.US})} else {
            參正.lastIndex = 0;
            let 匹項, 暫指 = Object.create(null);
            while ((匹項 = 參正.exec(淨徑))) 暫指[(匹項[1] || 匹項[3]).toLowerCase()] = 匹項[2] ? (匹項[2].charCodeAt(匹項[2].length - 1) === 61 ? 匹項[2].slice(0, -1) : 匹項[2]) : true;
            if (暫指.speed) 速 = 暫指.speed;
            const 通設 = 暫指.gs5 || 暫指.s5all || 暫指.s5 || 暫指.socks, 超設 = 暫指.ghttp || 暫指.httpall || 暫指.http, 安超設 = 暫指.ghttps || 暫指.httpsall || 暫指.https, 中設 = 暫指.gturn || 暫指.turnall || 暫指.turn, 安中設 = 暫指.gturns || 暫指.turnsall || 暫指.turns;
            const 全代 = !!(暫指.gs5 || 暫指.s5all || 暫指.ghttp || 暫指.httpall || 暫指.ghttps || 暫指.httpsall || 暫指.gturn || 暫指.turnall || 暫指.gturns || 暫指.turnsall || 暫指.proxyall || 暫指.globalproxy);
            if (!全代) 策列.push({型: 0});
            const 加策 = (暫值, 型值, 文記) => {
                if (!暫值) return;
                const 分段 = decodeURIComponent(暫值).split(',');
                for (let 序 = 0; 序 < 分段.length; 序++) if (分段[序]) 策列.push(文記 ? {型: 型值, 參: 分段[序], 文記} : {型: 型值, 參: 分段[序]});
            };
            for (let 序 = 0; 序 < 代序.length; 序++) {
                const 鍵序 = 代序[序];
                鍵序 === 'socks' ? 加策(通設, 1) : 鍵序 === 'http' ? 加策(超設, 2) : 鍵序 === 'https' ? 加策(安超設, 6) : 鍵序 === 'turn' ? 加策(中設, 5) : 鍵序 === 'turns' ? 加策(安中設, 7) : 0;
            }
            if (全代) {if (!策列.length) 策列.push({型: 0})} else {
                加策(暫指.ip, 3), 加策(暫指.txtip, 3, true);
                策列.push({型: 3, 參: 房映.get(請.cf?.colo) ?? 代址.US});
            }
        }
        const 舊鍵 = 網鍵[網序];
        if (舊鍵 !== undefined) 網典.delete(舊鍵);
        網鍵[網序] = 淨徑;
        網典.set(淨徑, {策列, 速});
        網序 = (網序 + 1) % 網限;
    }
    for (let 序 = 0; 序 < 策列.length; 序++) {
        try {
            const 連槽 = await 策映.get(策列[序].型)?.(解請, 策列[序].參, 策列[序].文記);
            if (連槽) return {連槽, 速};
        } catch {}
    }
    return null;
};
const 手管 = async (讀流, 寫通, 關連, 速) => {
    const 數值 = parseFloat(速), 限速 = 數值 > 0;
    let 管緩大 = 緩大, 管刷時 = 刷時, 管啟閾 = 啟閾;
    if (限速) {
        管啟閾 = 數值 > 256 ? Number.MAX_SAFE_INTEGER : 數值 * 1048576;
        let 佳大 = 管緩大, 佳時 = Infinity, 佳差 = Infinity;
        for (let 大小 = 262144; 大小 <= 524288; 大小 += 65536) {
            const 毫秒 = Math.max(2, Math.round(大小 * 1000 / 管啟閾)), 絕差 = Math.abs(大小 * 1000 / 毫秒 - 管啟閾);
            if (絕差 < 佳差 || (絕差 === 佳差 && 毫秒 < 佳時)) 佳大 = 大小, 佳時 = 毫秒, 佳差 = 絕差;
        }
        管緩大 = 佳大, 管刷時 = 佳時;
    }
    const 安緩大 = 管緩大 - 最塊, 快刷偏 = 最塊 << 1;
    let 緩圖 = new Uint8Array(管緩大), 備緩 = new ArrayBuffer(最塊);
    let 偏 = 0, 總位 = 0, 時間 = 0, 計時 = null, 恢復 = null, 正讀 = false, 需刷 = false, 護刷 = false;
    let 快刷 = true;
    const 刷出 = () => {
        if (正讀) return 需刷 = true;
        快刷 = 偏 < 快刷偏;
        if (偏 > 0) {
            偏 > 安緩大
                ? (寫通.send(緩圖.subarray(0, 偏)), 緩圖 = new Uint8Array(管緩大))
                : 寫通.send(緩圖.slice(0, 偏));
            偏 = 0;
        }
        需刷 = false, 護刷 = false, 計時 && (clearTimeout(計時), 計時 = null), 恢復?.(), 恢復 = null;
    };
    const 讀取器 = 讀流.getReader({mode: 'byob'});
    try {
        while (true) {
            const 用備 = 偏 > 0 && 護刷;
            let 讀緩 = 緩圖.buffer, 讀偏 = 偏;
            正讀 = 偏 > 0;
            用備 && (讀緩 = 備緩, 讀偏 = 0, 正讀 = false);
            const {done: 完成, value: 讀值} = await 讀取器.read(new Uint8Array(讀緩, 讀偏, 最塊));
            正讀 = false;
            用備 ? (緩圖.set(讀值, 偏), 備緩 = 讀值.buffer) : (緩圖 = new Uint8Array(讀值.buffer));
            if (完成) break;
            const 塊長 = 讀值.byteLength;
            if (!塊長) {
                需刷 && 刷出();
                continue;
            }
            偏 += 塊長, 總位 += 塊長;
            if (需刷 || 塊長 < 2048) {
                刷出();
            } else {
                if (快刷 || 塊長 < 28672) {
                    if (!限速) 總位 = 0;
                    時間 = 2;
                } else if (總位 > 管啟閾) 時間 = 管刷時;
                計時 ||= setTimeout(刷出, 時間), 護刷 = 塊長 < 最塊;
                偏 > 安緩大 && (總位 > 管啟閾 ? await new Promise(果值 => 恢復 = 果值) : 刷出());
            }
        }
    } catch {偏 = 0, 關連?.()} finally {正讀 = false, 刷出()}
};
const 建傳寫 = (寫函, 關連) => {
    const 佇列 = new Array(2048);
    let 佇首 = 0, 佇尾 = 0, 佇數 = 0, 聚緩 = null, 排空中 = false, 已關 = false;
    const 關寫 = () => {
        if (已關) return;
        已關 = true;
        for (let 序 = 0; 序 < 2048; 序++) 佇列[序] = null;
        關連?.();
    };
    const 排隊 = async () => {
        if (已關) return;
        try {
            while (佇數 > 0 && !已關) {
                let 塊 = 佇列[佇首];
                if (塊.byteLength >= 最塊) {
                    佇列[佇首] = null, 佇首 = (佇首 + 1) & 2047, 佇數--;
                    await 寫函.write(塊);
                    continue;
                }
                let 聚長 = 0;
                聚緩 ||= new Uint8Array(最塊);
                while (佇數 > 0) {
                    塊 = 佇列[佇首];
                    if (聚長 + 塊.byteLength > 最塊) break;
                    聚緩.set(塊, 聚長), 聚長 += 塊.byteLength;
                    佇列[佇首] = null, 佇首 = (佇首 + 1) & 2047, 佇數--;
                }
                if (聚長 > 0) await 寫函.write(聚緩.subarray(0, 聚長));
            }
        } catch {關寫()} finally {排空中 = false}
    };
    return 塊值 => {
        if (已關) return;
        const 料 = 塊值.constructor === Uint8Array ? 塊值 : new Uint8Array(塊值);
        if (!料.byteLength) return;
        if (佇數 === 2048) return 關寫();
        佇列[佇尾] = 料, 佇尾 = (佇尾 + 1) & 2047, 佇數++;
        if (!排空中) 排空中 = true, queueMicrotask(排隊);
    };
};
const 建微隊 = (消函, 關連) => {
    const 佇列 = new Array(1024);
    let 佇首 = 0, 佇尾 = 0, 佇數 = 0, 排空中 = false, 已關 = false;
    const 關隊 = () => {
        if (已關) return;
        已關 = true;
        for (let 序 = 0; 序 < 1024; 序++) 佇列[序] = null;
        關連?.();
    };
    const 排隊 = async () => {
        if (已關) return;
        try {
            while (佇數 > 0 && !已關) {
                const 塊 = 佇列[佇首];
                佇列[佇首] = null, 佇首 = (佇首 + 1) & 1023, 佇數--;
                await 消函(塊);
            }
        } catch {關隊()} finally {排空中 = false}
    };
    return 塊 => {
        if (已關) return;
        if (佇數 === 1024) return 關隊();
        佇列[佇尾] = 塊, 佇尾 = (佇尾 + 1) & 1023, 佇數++;
        if (!排空中) 排空中 = true, queueMicrotask(排隊);
    };
};
const 處網連 = async (網連, 請) => {
    const 參頭 = 請.headers.get('Referer');
    const 協頭 = 參頭 || 請.headers.get('sec-websocket-protocol');
    let 早頭 = null;
    if (參頭) {
        早頭 = 協頭.slice(請.headers.get('host').length);
    } else if (協頭) {
        早頭 = 協頭;
    }
    // @ts-ignore
    const 早料 = 早頭 ? Uint8Array.fromBase64(早頭, {alphabet: 'base64url'}) : null;
    let 傳寫, 處隊 = null, 解請, 傳槽;
    const 關連 = () => {
        try {傳槽?.close()} catch {}
        try {網連.close(1011, 'WebSocket is closed')} catch {}
    };
    const 處 = 料塊 => {
        try {
            if (傳寫) return 傳寫(料塊);
            return (async () => {
                料塊 = 早料 ? 料塊 : new Uint8Array(料塊);
                if (料塊.length > 58 && 料塊[56] === 13 && 料塊[57] === 10) {
                    解請 = 解透包(料塊);
                } else if ((解請 = 解請包(料塊))) {
                    網連.send(new Uint8Array([料塊[0], 0]));
                } else {解請 = 解影包(料塊)}
                if (!解請) return 關連();
                const 負料 = 料塊.subarray(解請.料偏);
                const 傳果 = await 建傳連(解請, 請);
                if (!傳果) return 關連();
                傳槽 = 傳果.連槽;
                const 寫函 = 傳槽.writable.getWriter();
                if (負料.byteLength) 寫函.write(負料);
                傳寫 = 建傳寫(寫函, 關連);
                if (傳槽.extra?.length) 網連.send(傳槽.extra);
                手管(傳槽.readable, 網連, 關連, 傳果.速);
            })();
        } catch {關連()}
    };
    處隊 = 建微隊(處, 關連);
    if (早料) 處隊(早料);
    網連.addEventListener("message", 事 => (傳寫 || 處隊)(事.data));
    網連.addEventListener("error", 關連);
    網連.addEventListener("close", 關連);
};
export default {
    async fetch(請) {
        if (請.headers.get('Upgrade') === 'websocket') {
            const {0: 客槽, 1: 網連} = new WebSocketPair();
            // @ts-ignore
            網連.accept({allowHalfOpen: true}), 網連.binaryType = "arraybuffer";
            處網連(網連, 請);
            return new Response(null, {status: 101, webSocket: 客槽});
        }
        return new Response(錯頁, {status: 404, headers: {'Content-Type': 'text/html; charset=UTF-8'}});
    }
};
