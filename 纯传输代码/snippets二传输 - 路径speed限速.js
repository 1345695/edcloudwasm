import {connect as ce} from "cloudflare:sockets";
const ue = "d342d11e-d424-4583-b36e-524ab1f0afa4";
const ke = 256 * 1024;
const We = 50 * 1024 * 1024;
const V = 64 * 1024;
const Re = 4;
const fe = ["socks", "http", "https", "turn", "turns"];
const pe = "https://cloudflare-dns.com/dns-query";
const Z = "proxy.zjcloud.us.ci";
const he = e => e > 64 ? (e & 7) + 9 : e & 15;
const M = e => he(ue.charCodeAt(e)) << 4 | he(ue.charCodeAt(e + 1));
const Ce = M(0), Le = M(2), Ee = M(4), Pe = M(6), Oe = M(9), He = M(11), Ie = M(14), $e = M(16), ve = M(19), ze = M(21), De = M(24), Fe = M(26), Be = M(28), Ne = M(30), je = M(32), Qe = M(34);
const B = new TextEncoder, ee = new TextDecoder;
const Ve = `<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx/1.25.3</center></body></html>`;
const te = (e, n) => {
    if (e === 2) return ee.decode(n);
    if (e === 1) return `${n[0]}.${n[1]}.${n[2]}.${n[3]}`;
    let t = (n[0] << 8 | n[1]).toString(16);
    for (let r = 1; r < 8; r++) t += ":" + (n[r * 2] << 8 | n[r * 2 + 1]).toString(16);
    return `[${t}]`
};
const re = (e, n) => {
    let t = e, r = n, s;
    if (e.charCodeAt(0) === 91) {
        if ((s = e.indexOf("]:")) !== -1) {
            t = e.substring(0, s + 1);
            r = e.substring(s + 2)
        }
    } else if ((s = e.indexOf(".tp")) !== -1 && e.lastIndexOf(":") === -1) {r = e.substring(s + 3, e.indexOf(".", s + 3))} else if ((s = e.lastIndexOf(":")) !== -1) {
        t = e.substring(0, s);
        r = e.substring(s + 1)
    }
    return [t, (r = parseInt(r), isNaN(r) ? n : r)]
};
const _e = e => {
    let n, t, r;
    const s = e.lastIndexOf("@");
    if (s === -1) {r = e} else {
        const i = e.substring(0, s);
        r = e.substring(s + 1);
        const c = i.indexOf(":");
        if (c === -1) {n = i} else {
            n = i.substring(0, c);
            t = i.substring(c + 1)
        }
    }
    const [o, l] = re(r, 1080);
    return {username: n, password: t, hostname: o, port: l}
};
const _ = (e, n, t, r = ce({hostname: e, port: n}, t)) => r.opened.then(() => r);
const Ke = async (e, n, t, r) => {
    const s = await _(t.hostname, t.port);
    const o = s.writable.getWriter(), l = s.readable.getReader();
    await o.write(new Uint8Array([5, 2, 0, 2]));
    const {value: i} = await l.read();
    if (!i || i[0] !== 5 || i[1] === 255) return null;
    if (i[1] === 2) {
        if (!t.username) return null;
        const h = B.encode(t.username), y = B.encode(t.password || "");
        const d = h.length, m = y.length, w = new Uint8Array(3 + d + m);
        w[0] = 1, w[1] = d, w.set(h, 2), w[2 + d] = m, w.set(y, 3 + d);
        await o.write(w);
        const {value: x} = await l.read();
        if (!x || x[0] !== 1 || x[1] !== 0) return null
    } else if (i[1] !== 0) {return null}
    const c = e === 3, u = new Uint8Array(6 + r.length + (c ? 1 : 0));
    u[0] = 5, u[1] = 1, u[2] = 0, u[3] = e;
    c ? (u[4] = r.length, u.set(r, 5)) : u.set(r, 4);
    u[u.length - 2] = n >> 8, u[u.length - 1] = n & 255;
    await o.write(u);
    const {value: a} = await l.read();
    if (!a || a[1] !== 0) return null;
    o.releaseLock(), l.releaseLock();
    return s
};
const Xe = `User-Agent:Mozilla/5.0(X11;Linux x86_64)AppleWebKit/537.36\r\nProxy-Connection:Keep-Alive\r\nConnection:Keep-Alive\r\n\r\n`;
const ne = B.encode(Xe);
const de = async (e, n, t, r, s = false) => {
    const {username: o, password: l, hostname: i, port: c} = t;
    const u = s ? {secureTransport: "on", allowHalfOpen: false} : void 0;
    const a = await _(i, c, u), h = a.writable.getWriter();
    const y = te(e, r);
    let d = `CONNECT ${y}:${n} HTTP/1.1\r\nHost:${y}:${n}\r\n`;
    if (o) {d += `Proxy-Authorization:Basic ${btoa(`${o}:${l || ""}`)}\r\n`}
    const m = new Uint8Array(d.length * 3 + ne.length), {written: w} = B.encodeInto(d, m);
    m.set(ne, w);
    await h.write(m.subarray(0, w + ne.length));
    h.releaseLock();
    const x = a.readable.getReader(), T = new Uint8Array(512);
    let S = 0, A = false;
    while (S < T.length) {
        const {value: g, done: v} = await x.read();
        if (v || S + g.length > T.length) return null;
        const W = S;
        T.set(g, S), S += g.length;
        if (!A && S >= 12) {
            if (T[9] !== 50) return null;
            A = true
        }
        let U = Math.max(15, W - 3);
        while ((U = T.indexOf(13, U)) !== -1 && U <= S - 4) {
            if (T[U + 1] === 10 && T[U + 2] === 13 && T[U + 3] === 10) {
                x.releaseLock();
                return a
            }
            U++
        }
    }
    return null
};
const J = new Uint8Array([33, 18, 164, 66]);
const se = (...e) => {
    let n = 0, t = 0, r = 0;
    for (; t < e.length; t++) n += e[t].length;
    const s = new Uint8Array(n);
    for (t = 0; t < e.length; t++) {
        s.set(e[t], r);
        r += e[t].length
    }
    return s
};
const $ = (e, n) => {
    const t = n.length, r = new Uint8Array(4 + t + (4 - t % 4) % 4);
    r[0] = e >> 8, r[1] = e & 255, r[2] = t >> 8, r[3] = t & 255, r.set(n, 4);
    return r
};
const N = (e, n, t) => {
    const r = se(...t), s = r.length, o = new Uint8Array(20 + s);
    o[0] = e >> 8, o[1] = e & 255, o[2] = s >> 8, o[3] = s & 255, o.set(J, 4), o.set(n, 8), o.set(r, 20);
    return o
};
const qe = (e, n) => {
    const t = new Uint8Array(8);
    t[1] = 1;
    const r = n ^ 8466;
    t[2] = r >> 8, t[3] = r & 255;
    let s = 0, o = 0;
    for (let l = 0; l < e.length; l++) {
        const i = e.charCodeAt(l);
        if (i === 46) {
            t[4 + s] = o ^ J[s++];
            o = 0
        } else {o = o * 10 + (i - 48)}
    }
    t[4 + s] = o ^ J[s];
    return t
};
const Ge = e => {
    if (e.length < 20 || J.some((r, s) => e[4 + s] !== r)) return null;
    const n = e[2] << 8 | e[3], t = {};
    for (let r = 20; r + 4 <= 20 + n;) {
        const s = e[r] << 8 | e[r + 1], o = e[r + 2] << 8 | e[r + 3];
        if (r + 4 + o > e.length) break;
        t[s] = e.subarray(r + 4, r + 4 + o);
        r += 4 + o + (4 - o % 4) % 4
    }
    return {type: e[0] << 8 | e[1], attrs: t, tid: e.slice(8, 20)}
};
const we = e => e?.length >= 4 ? (e[2] & 7) * 100 + e[3] : 0;
const Je = async (e, n) => {
    const t = e.length, r = new Uint8Array(t + 24);
    r.set(e);
    const s = (e[2] << 8 | e[3]) + 24;
    r[2] = s >> 8, r[3] = s & 255;
    const o = new Uint8Array(await crypto.subtle.sign("HMAC", n, r.subarray(0, t)));
    r[t] = 0, r[t + 1] = 8, r[t + 2] = 0, r[t + 3] = 20, r.set(o, t + 4);
    return r
};
const Ye = async (e, n) => {
    let t = n && n.length ? [n] : [];
    let r = n ? n.length : 0;
    const s = async () => {
        const {done: l, value: i} = await e.read();
        if (l) throw new Error;
        t.push(i);
        r += i.length
    };
    const o = () => {
        if (t.length === 1) return t[0];
        const l = new Uint8Array(r);
        let i = 0;
        for (let c = 0; c < t.length; c++) {
            l.set(t[c], i);
            i += t[c].length
        }
        t = [l];
        return l
    };
    try {
        while (r < 20) await s();
        let l = o();
        if (l[4] !== 33 || l[5] !== 18 || l[6] !== 164 || l[7] !== 66) return null;
        const i = 20 + (l[2] << 8 | l[3]);
        if (i > 8192) return null;
        while (r < i) await s();
        l = o();
        return [Ge(l.subarray(0, i)), r > i ? l.subarray(i) : null]
    } catch {return null}
};
const ye = async e => new Uint8Array(await crypto.subtle.digest("MD5", B.encode(e)));
const ge = async ({hostname: e, port: n, username: t, password: r}, {addrType: s, port: o, addrBytes: l}, i = false) => {
    let c = te(s, l);
    if (s === 2) {c = rt(c).catch(() => null)} else if (s === 3) return null;
    let u = null, a = null, h = null;
    let y = null, d = null, m = null, w = false, x = null;
    const T = () => {
        w = true;
        if (x !== null) clearTimeout(x), x = null;
        [u, a].forEach(f => {try {f?.close()} catch {}});
        [d, y].forEach(f => {try {f?.releaseLock()} catch {}})
    };
    const S = () => {
        const f = i ? {secureTransport: "on", allowHalfOpen: false} : void 0;
        const b = ce({hostname: e, port: n}, f);
        return _(e, n, f, b).catch(p => {
            try {b.close()} catch {}
            throw p
        })
    };
    const A = () => crypto.getRandomValues(new Uint8Array(12));
    const g = (f, b) => f?.length === b?.length && f.every((p, k) => p === b[k]);
    const v = f => {
        let b = "";
        for (let p = 0; p < f.length; p++) b += f[p].toString(16).padStart(2, "0");
        return b
    };
    const W = async (f, b, p = null, k = null) => {
        const z = v(b), C = k?.get(z);
        if (C) {
            k.delete(z);
            return [C, p]
        }
        let L = p;
        for (; ;) {
            const j = await Ye(f, L);
            if (!j) throw new Error;
            const [D, Q] = j;
            L = Q;
            if (g(D.tid, b)) return [D, L];
            if (k) k.set(v(D.tid), D)
        }
    };
    const U = new Map;
    const E = async f => {
        const [b, p] = await W(d, f, m, U);
        m = p;
        return b
    };
    const q = f => new Uint8Array([f >>> 24 & 255, f >>> 16 & 255, f >>> 8 & 255, f & 255]);
    const P = f => f?.length >= 4 ? f[0] * 16777216 + f[1] * 65536 + f[2] * 256 + f[3] : 0;
    let O = null, R = [], H = "";
    const I = f => O ? Je(f, O) : f;
    const K = async f => {
        const b = f?.attrs?.[21]?.slice();
        if (!t || !b?.length) return false;
        const p = f.attrs?.[20]?.length ? ee.decode(f.attrs[20]) : H;
        if (!p) return false;
        if (p !== H || !O) {
            const k = await ye(`${t}:${p}:${r}`);
            O = await crypto.subtle.importKey("raw", k, {name: "HMAC", hash: "SHA-1"}, false, ["sign"])
        }
        H = p;
        R = [$(6, B.encode(t)), $(20, B.encode(H)), $(21, b)];
        return true
    };
    const Ae = async (f, b, p) => {
        for (let k = 0; k < 2; k++) {
            if (w) throw new Error;
            const z = A();
            await y.write(await I(N(f, z, [...b, ...R])));
            const C = await E(z);
            if (C?.type === p) return C;
            const L = we(C?.attrs?.[9]);
            if ((L === 401 || L === 438) && await K(C)) continue;
            throw new Error
        }
        throw new Error
    };
    try {
        const f = S();
        h = S().then(F => {
            a = F;
            if (w) {try {F.close()} catch {}}
            return F
        });
        h.catch(() => {});
        u = await f;
        y = u.writable.getWriter(), d = u.readable.getReader();
        let b = A();
        await y.write(N(3, b, [$(25, new Uint8Array([6, 0, 0, 0]))]));
        let p = await E(b);
        if (!p) throw new Error;
        const k = await c;
        if (!k) throw new Error;
        const z = $(18, qe(k, o));
        let C = null, L = null, j = null, D = null;
        if (p.type === 275 && t && we(p.attrs[9]) === 401) {
            const F = ee.decode(p.attrs[20] ?? []), X = p.attrs[21] ?? [];
            const Ue = await ye(`${t}:${F}:${r}`);
            O = await crypto.subtle.importKey("raw", Ue, {name: "HMAC", hash: "SHA-1"}, false, ["sign"]);
            H = F;
            R = [$(6, B.encode(t)), $(20, B.encode(F)), $(21, X)];
            const ie = A();
            C = A(), L = A();
            const [Te, Se, Me] = await Promise.all([I(N(3, ie, [$(25, new Uint8Array([6, 0, 0, 0])), ...R])), I(N(8, C, [z, ...R])), I(N(10, L, [z, ...R]))]);
            j = Se, D = Me;
            await y.write(se(Te, j, D));
            p = await E(ie)
        } else if (p.type === 259) {
            C = A(), L = A();
            [j, D] = await Promise.all([I(N(8, C, [z, ...R])), I(N(10, L, [z, ...R]))]);
            await y.write(se(j, D))
        } else {throw new Error}
        if (p?.type !== 259) throw new Error;
        let Q = P(p.attrs?.[13]) || 600;
        p = await E(C);
        if (p?.type !== 264) throw new Error;
        p = await E(L);
        if (p?.type !== 266 || !p.attrs[42]) throw new Error;
        await h;
        const ae = a.writable.getWriter(), oe = a.readable.getReader();
        b = A();
        await ae.write(await I(N(11, b, [$(42, p.attrs[42]), ...R])));
        let le;
        [p, le] = await W(oe, b);
        if (p?.type !== 267) throw new Error;
        oe.releaseLock(), ae.releaseLock();
        let G = 0;
        const Y = async () => {
            if (w) return;
            try {
                const F = await Ae(4, [$(13, q(Q))], 260), X = P(F.attrs?.[13]);
                if (X === 0) throw new Error;
                if (X > 0) Q = X;
                G = 0;
                if (!w) x = setTimeout(Y, Math.min(3e5, Math.max(5e3, Math.floor(Q * 500))))
            } catch {
                if (w) return;
                G++, G <= 3 ? x = setTimeout(Y, G * 2e3) : T()
            }
        };
        if (!w) x = setTimeout(Y, Math.min(3e5, Math.max(5e3, Math.floor(Q * 500))));
        return {readable: a.readable, writable: a.writable, close: T, extra: le}
    } catch {
        T();
        return null
    }
};
const Ze = e => {
    const n = e.length;
    const t = {success: false, needMore: false, handshake: null, parsedRequest: null};
    if (n < 17) return t.needMore = true, t;
    if (!(e[1] === Ce && e[2] === Le && e[3] === Ee && e[4] === Pe && e[5] === Oe && e[6] === He && e[7] === Ie && e[8] === $e && e[9] === ve && e[10] === ze && e[11] === De && e[12] === Fe && e[13] === Be && e[14] === Ne && e[15] === je && e[16] === Qe)) {return t}
    if (n < 18) return t.needMore = true, t;
    const r = 19 + e[17];
    if (n < r + 4) return t.needMore = true, t;
    const s = e[r + 2];
    const o = s === 2 ? e[r + 3] : s === 1 ? 4 : s === 3 ? 16 : 0;
    if (!o) return t;
    const l = s === 2 ? r + 4 : r + 3, i = l + o;
    if (n < i) return t.needMore = true, t;
    const c = e[r] << 8 | e[r + 1];
    t.handshake = new Uint8Array([e[0], 0]);
    t.success = true;
    t.parsedRequest = {addrType: s, addrBytes: e.subarray(l, i), dataOffset: i, port: c, isDns: c === 53};
    return t
};
const et = {headers: {Accept: "application/dns-json"}}, tt = {"content-type": "application/dns-message"};
const be = async (e, n) => {
    try {
        const t = await fetch(`${pe}?name=${encodeURIComponent(e)}&type=${n}`, et);
        if (!t.ok) return null;
        const r = await t.json();
        const s = r.Answer || r.answer;
        if (!s || s.length === 0) return null;
        return s
    } catch {return null}
};
const rt = async e => {
    const n = await be(e, "A");
    if (!n) return null;
    let t = null;
    for (let r = 0, s = n.length; r < s; r++) if (n[r].type === 1 && n[r].data) {
        t = n[r].data;
        break
    }
    return t
};
const nt = async e => {
    if (e.byteLength < 2) return null;
    const n = e.subarray(2);
    let t;
    try {
        const o = await fetch(pe, {method: "POST", headers: tt, body: n});
        if (!o.ok) return null;
        t = await o.arrayBuffer()
    } catch {return null}
    const r = t.byteLength;
    const s = new Uint8Array(2 + r);
    s[0] = r >> 8 & 255, s[1] = r & 255;
    s.set(new Uint8Array(t), 2);
    return s
};
const st = async e => {
    const n = await be(e, "TXT");
    if (!n) return null;
    let t, r = 0, s = n.length;
    for (; r < s; r++) if (n[r].type === 16) {
        t = n[r].data;
        break
    }
    if (!t) return null;
    if (t.charCodeAt(0) === 34 && t.charCodeAt(t.length - 1) === 34) t = t.slice(1, -1);
    const o = t.split(/,|\\010|\n/), l = [];
    for (r = 0, s = o.length; r < s; r++) {
        const i = o[r].trim();
        if (i) l.push(i)
    }
    return l.length ? l : null
};
const at = /william|fxpip|hhtxt/;
const ot = async (e, n) => {
    if (n || at.test(e)) {
        const s = await st(e);
        if (!s || s.length === 0) return null;
        const [o, l] = re(s[Math.random() * s.length | 0], 443);
        return _(o, l)
    }
    const [t, r] = re(e, 443);
    return _(t, r)
};
const lt = new Map([[0, async ({addrType: e, port: n, addrBytes: t}) => _(te(e, t), n)], [1, async ({addrType: e, port: n, addrBytes: t}, r) => Ke(e, n, r, t)], [2, async ({addrType: e, port: n, addrBytes: t}, r) => de(e, n, r, t)], [6, async ({addrType: e, port: n, addrBytes: t}, r) => de(e, n, r, t, true)], [5, async (e, n) => ge(n, e)], [7, async (e, n) => ge(n, e, true)], [3, async (e, n, t) => ot(n, t)]]);
const me = /(speed|gs5|s5all|ghttp|httpall|ghttps|httpsall|gturn|turnall|gturns|turnsall|s5|socks|http|https|turn|turns|txtip|ip)(?:=|:\/\/|%3A%2F%2F)([^&]+)|(proxyall|globalproxy|global)/gi;
const it = async (e, n) => {
    let t = n.url, r = t.slice(t.indexOf("/", 10) + 1), s = r.length, o = [], l;
    const i = r.charCodeAt(s - 1);
    if (i === 47 || i === 61) r = r.slice(0, s - 1);
    const c = n.cf?.colo;
    const u = c ? `${c.toLowerCase()}.proxy.zjcloud.us.ci` : Z;
    if (r.length < 6) {o.push({type: 0}, {type: 3, param: u}, {type: 3, param: Z})} else {
        const a = Object.create(null);
        me.lastIndex = 0;
        let h;
        while (h = me.exec(r)) {a[(h[1] || h[3]).toLowerCase()] = h[2] ? h[2].charCodeAt(h[2].length - 1) === 61 ? h[2].slice(0, -1) : h[2] : true}
        if (a.speed) l = a.speed;
        const y = a.gs5 || a.s5all || a.s5 || a.socks, d = a.ghttp || a.httpall || a.http, m = a.ghttps || a.httpsall || a.https, w = a.gturn || a.turnall || a.turn, x = a.gturns || a.turnsall || a.turns;
        const T = !!(a.gs5 || a.s5all || a.ghttp || a.httpall || a.ghttps || a.httpsall || a.gturn || a.turnall || a.gturns || a.turnsall || a.proxyall || a.globalproxy || a.global);
        if (!T) o.push({type: 0});
        const S = (A, g, v) => {
            if (!A) return;
            const W = decodeURIComponent(A).split(",").filter(Boolean);
            for (let U = 0; U < W.length; U++) o.push(v ? {type: g, param: W[U], txt: v} : {type: g, param: g === 1 || g === 2 || g === 5 || g === 6 || g === 7 ? _e(W[U]) : W[U]})
        };
        for (let A = 0; A < fe.length; A++) {
            const g = fe[A];
            S(g === "socks" ? y : g === "http" ? d : g === "https" ? m : g === "turn" ? w : x, g === "socks" ? 1 : g === "http" ? 2 : g === "https" ? 6 : g === "turn" ? 5 : 7)
        }
        if (T) {if (!o.length) o.push({type: 0})} else {
            S(a.ip, 3), S(a.txtip, 3, true);
            o.push({type: 3, param: u}, {type: 3, param: Z})
        }
    }
    for (let a = 0; a < o.length; a++) {
        try {
            const h = lt.get(o[a].type);
            const y = await (h?.(e, o[a].param, o[a].txt));
            if (y) return {socket: y, speed: l}
        } catch {}
    }
    return null
};
const ct = async (e, n, t, r) => {
    const s = parseFloat(r), o = s > 0;
    let l = ke, i = Re, c = We;
    if (o) {
        c = s > 256 ? Number.MAX_SAFE_INTEGER : s * 1048576;
        let P = l, O = Infinity, R = Infinity;
        for (let H = 262144; H <= 524288; H += 65536) {
            const I = Math.max(2, Math.round(H * 1e3 / c)), K = Math.abs(H * 1e3 / I - c);
            if (K < R || K === R && I < O) P = H, O = I, R = K
        }
        l = P, i = O
    }
    const u = l - V, a = V << 1;
    let h = new Uint8Array(l), y = new ArrayBuffer(V);
    let d = 0, m = 0, w = 0, x = null, T = null, S = false;
    let A = false, g = false, v = true, W, U;
    const E = () => {
        if (S) return A = true;
        v = d < a;
        if (d > 0) n.send(h.subarray(0, d)), d = 0;
        A = false, g = false, x && (clearTimeout(x), x = null), T?.(), T = null
    };
    const q = e.getReader({mode: "byob"});
    try {
        while (true) {
            if (d > 0 && g) {
                ({done: W, value: U} = await q.read(new Uint8Array(y, 0, V)));
                h.set(U, d), y = U.buffer
            } else {
                S = d > 0;
                ({done: W, value: U} = await q.read(new Uint8Array(h.buffer, d, V)));
                S = false, h = new Uint8Array(U.buffer)
            }
            if (W) break;
            const P = U.byteLength;
            if (!P) {
                A && E();
                continue
            }
            d += P, m += P;
            if (A) {E()} else {
                if (v || P < 28672) {
                    if (!o) m = 0;
                    w = 2
                } else if (m > c) w = i;
                x ||= setTimeout(E, w), g = P < V;
                d > u && (m > c ? await new Promise(O => T = O) : E())
            }
        }
    } catch {d = 0, t?.()} finally {S = false, E()}
};
const ut = (e, n) => {
    const t = new Uint8Array(32768);
    let r = 0, s = null, o = false;
    const l = () => {
        if (o) return;
        o = true;
        s && (clearTimeout(s), s = null);
        n?.()
    };
    const i = u => {try {e.write(u)} catch {l()}};
    const c = () => {
        s && (clearTimeout(s), s = null);
        if (!r || o) return;
        const u = r;
        r = 0, i(t.subarray(0, u))
    };
    return u => {
        if (o) return;
        const a = u.constructor === Uint8Array ? u : new Uint8Array(u), h = a.byteLength;
        if (!h) return;
        r + h > 32768 && c(), t.set(a, r), r += h, r === 32768 ? c() : (s && clearTimeout(s), s = setTimeout(c, 2))
    }
};
const ft = (e, n) => {
    const t = new Array(256).fill(null);
    let r = 0, s = 0, o = 0, l = false, i = false;
    const c = () => {
        if (i) return;
        i = true;
        for (let a = 0; a < 256; a++) t[a] = null;
        n?.()
    };
    const u = async () => {
        if (i) return;
        try {
            while (o > 0 && !i) {
                const a = t[r];
                t[r] = null, r = r + 1 & 255, o--;
                await e(a)
            }
        } catch {c()} finally {l = false}
    };
    return a => {
        if (i) return;
        if (o === 256) return c();
        t[s] = a, s = s + 1 & 255, o++;
        if (!l) l = true, queueMicrotask(u)
    }
};
const xe = async (e, n, t, r, s, o = false) => {
    n.needMore = false;
    const l = Ze(e);
    if (l.handshake) r.send(l.handshake);
    if (!l.success) return l.needMore ? n.needMore = true : s();
    const i = l.parsedRequest;
    const c = e.subarray(i.dataOffset);
    if (i.isDns) {
        const u = await nt(c);
        if (u?.byteLength) r.send(u);
        if (!o) return s()
    } else {
        const u = await it(i, t);
        if (!u) return s();
        n.tcpSocket = u.socket;
        const a = n.tcpSocket.writable.getWriter();
        n.rawTcpWriter = a;
        if (c.byteLength) a.write(c);
        if (n.tcpSocket.extra?.length) await r.send(n.tcpSocket.extra);
        if (n.xwebPipeTo) return n.tcpWriter = h => a.write(h);
        n.tcpWriter = ut(a, s);
        ct(n.tcpSocket.readable, r, s, u.speed)
    }
};
const pt = async (e, n) => {
    const t = n.headers.get("Referer");
    const r = t || n.headers.get("sec-websocket-protocol");
    let s = null;
    if (t) {s = r.slice(n.headers.get("host").length)} else if (r) {s = r}
    const o = s ? Uint8Array.fromBase64(s, {alphabet: "base64url"}) : null;
    const l = {tcpWriter: null, tcpSocket: null};
    let i = null;
    const c = () => {e.close(1011, "WebSocket is closed")};
    const u = a => {
        if (l.tcpWriter) return l.tcpWriter(a);
        return xe(o ? a : new Uint8Array(a), l, n, e, c, o !== null)
    };
    i = ft(u, c);
    if (o) i(o);
    e.addEventListener("message", a => (l.tcpWriter || i)(a.data));
    e.addEventListener("error", c)
};
const ht = {"Content-Type": "application/octet-stream", "grpc-status": "0", "X-Accel-Buffering": "no", "Cache-Control": "no-store"};
const dt = async e => {
    const n = e.body?.getReader({mode: "byob"});
    if (!n) return new Response(null, {status: 400});
    const t = {tcpWriter: null, tcpSocket: null, needMore: false, xwebPipeTo: true};
    const r = new IdentityTransformStream({highWaterMark: 1024 * 1024}), s = new IdentityTransformStream({highWaterMark: 1024 * 1024 * 1024}), o = r.writable.getWriter();
    const l = () => {if (t.xwebPipeTo) {t.xwebPipeTo = false, n.cancel().catch(() => {}), o.close().catch(() => {})}};
    const i = {send(c) {if (c?.byteLength) return o.write(c)}};
    (async () => {
        let c = new Uint8Array(32768), u = new ArrayBuffer(8192), a = 0, h = 0, y = null, d, m;
        const w = () => {
            if (a > 0 && t.tcpWriter && c) t.tcpWriter(c.subarray(0, a)), a = 0;
            y && (clearTimeout(y), y = null)
        };
        try {
            while (true) {
                if (a > 0 && t.tcpWriter) {
                    ({done: d, value: m} = await n.read(new Uint8Array(u, 0, 8192)));
                    c.set(m, a), u = m.buffer
                } else {
                    ({done: d, value: m} = await n.read(new Uint8Array(c.buffer, a, 8192)));
                    c = new Uint8Array(m.buffer)
                }
                if (d) break;
                const x = m.byteLength;
                if (!x) continue;
                a += x;
                if (t.tcpWriter) {
                    if (++h >= 8e3) {
                        w();
                        await t.rawTcpWriter.ready;
                        n.releaseLock(), t.rawTcpWriter.releaseLock(), t.xwebPipeTo = false, c = null, u = null;
                        e.body.pipeThrough(s).pipeTo(t.tcpSocket.writable);
                        break
                    }
                    a > 24576 ? w() : (y && clearTimeout(y), y = setTimeout(w, 2))
                } else {
                    t.needMore = false;
                    await xe(c.subarray(0, a), t, e, i, l);
                    if (t.tcpSocket && t.xwebPipeTo && !t.downstreamPiped) {
                        t.downstreamPiped = true, o.releaseLock();
                        t.tcpSocket.readable.pipeTo(r.writable)
                    }
                    if (!t.needMore) a = 0
                }
            }
        } catch {a = 0, l()} finally {w()}
    })().catch(l);
    return new Response(r.readable, {headers: ht})
};
export default {
    async fetch(e) {
        if (e.method === "POST" && e.headers.get("content-type")?.startsWith("application/grpc")) return dt(e);
        if (e.headers.get("Upgrade") === "websocket") {
            const {0: n, 1: t} = new WebSocketPair;
            t.accept({allowHalfOpen: true}), t.binaryType = "arraybuffer";
            pt(t, e);
            return new Response(null, {status: 101, webSocket: n})
        }
        return new Response(Ve, {status: 200, headers: {"Content-Type": "text/html; charset=UTF-8"}})
    }
};