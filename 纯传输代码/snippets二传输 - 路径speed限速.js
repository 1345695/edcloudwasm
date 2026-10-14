import {connect as ce} from "cloudflare:sockets";
const ue = "d342d11e-d424-4583-b36e-524ab1f0afa4";
const ke = 256 * 1024;
const We = 50 * 1024 * 1024;
const _ = 64 * 1024;
const Ce = 4;
const fe = ["socks", "http", "https", "turn", "turns"];
const pe = "https://cloudflare-dns.com/dns-query";
const he = e => e > 64 ? (e & 7) + 9 : e & 15;
const M = e => he(ue.charCodeAt(e)) << 4 | he(ue.charCodeAt(e + 1));
const Re = M(0), Le = M(2), Ee = M(4), Pe = M(6), He = M(9), Oe = M(11), Ie = M(14), $e = M(16), ve = M(19), De = M(21), Fe = M(24), ze = M(26), Be = M(28), Ne = M(30), Qe = M(32), Ve = M(34);
const _e = () => {
    const e = Math.random() * 65536 | 0;
    return String.fromCharCode(112 ^ (e & 1) << 5, 114 ^ (e >> 1 & 1) << 5, 111 ^ (e >> 2 & 1) << 5, 120 ^ (e >> 3 & 1) << 5, 121 ^ (e >> 4 & 1) << 5, 46, 122 ^ (e >> 5 & 1) << 5, 106 ^ (e >> 6 & 1) << 5, 99 ^ (e >> 7 & 1) << 5, 108 ^ (e >> 8 & 1) << 5, 111 ^ (e >> 9 & 1) << 5, 117 ^ (e >> 10 & 1) << 5, 100 ^ (e >> 11 & 1) << 5, 46, 117 ^ (e >> 12 & 1) << 5, 115 ^ (e >> 13 & 1) << 5, 46, 99 ^ (e >> 14 & 1) << 5, 105 ^ (e >> 15 & 1) << 5)
};
const Z = _e();
const B = new TextEncoder, ee = new TextDecoder;
const Ke = `<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx/1.25.3</center></body></html>`;
const te = (e, n) => {
    if (e === 2) return n.length <= 64 ? String.fromCharCode.apply(null, n) : ee.decode(n);
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
const Xe = e => {
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
const K = (e, n, t, r = ce({hostname: e, port: n}, t)) => r.opened.then(() => r);
const je = async (e, n, t, r) => {
    const s = await K(t.hostname, t.port);
    const o = s.writable.getWriter(), l = s.readable.getReader();
    await o.write(new Uint8Array([5, 2, 0, 2]));
    const {value: i} = await l.read();
    if (!i || i[0] !== 5 || i[1] === 255) return null;
    if (i[1] === 2) {
        if (!t.username) return null;
        const h = B.encode(t.username), g = B.encode(t.password || "");
        const w = h.length, m = g.length, d = new Uint8Array(3 + w + m);
        d[0] = 1, d[1] = w, d.set(h, 2), d[2 + w] = m, d.set(g, 3 + w);
        await o.write(d);
        const {value: x} = await l.read();
        if (!x || x[0] !== 1 || x[1] !== 0) return null
    } else if (i[1] !== 0) {return null}
    if (e !== 1) e++;
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
const qe = `User-Agent:Mozilla/5.0(X11;Linux x86_64)AppleWebKit/537.36\r\nProxy-Connection:Keep-Alive\r\nConnection:Keep-Alive\r\n\r\n`;
const ne = B.encode(qe);
const we = async (e, n, t, r, s = false) => {
    const {username: o, password: l, hostname: i, port: c} = t;
    const u = s ? {secureTransport: "on", allowHalfOpen: false} : void 0;
    const a = await K(i, c, u), h = a.writable.getWriter();
    const g = te(e, r);
    let w = `CONNECT ${g}:${n} HTTP/1.1\r\nHost:${g}:${n}\r\n`;
    if (o) w += `Proxy-Authorization:Basic ${btoa(`${o}:${l || ""}`)}\r\n`;
    const m = new Uint8Array(w.length * 3 + ne.length), {written: d} = B.encodeInto(w, m);
    m.set(ne, d);
    await h.write(m.subarray(0, d + ne.length));
    h.releaseLock();
    const x = a.readable.getReader(), T = new Uint8Array(512);
    let S = 0, A = false;
    while (S < T.length) {
        const {value: y, done: v} = await x.read();
        if (v || S + y.length > T.length) return null;
        const W = S;
        T.set(y, S), S += y.length;
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
const Ge = (e, n) => {
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
const Je = e => {
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
const de = e => e?.length >= 4 ? (e[2] & 7) * 100 + e[3] : 0;
const Ye = async (e, n) => {
    const t = e.length, r = new Uint8Array(t + 24);
    r.set(e);
    const s = (e[2] << 8 | e[3]) + 24;
    r[2] = s >> 8, r[3] = s & 255;
    const o = new Uint8Array(await crypto.subtle.sign("HMAC", n, r.subarray(0, t)));
    r[t] = 0, r[t + 1] = 8, r[t + 2] = 0, r[t + 3] = 20, r.set(o, t + 4);
    return r
};
const Ze = async (e, n) => {
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
        return [Je(l.subarray(0, i)), r > i ? l.subarray(i) : null]
    } catch {return null}
};
const ye = async e => new Uint8Array(await crypto.subtle.digest("MD5", B.encode(e)));
const ge = async ({hostname: e, port: n, username: t, password: r}, {addrType: s, port: o, addrBytes: l}, i = false) => {
    let c = te(s, l);
    if (s === 2) {c = nt(c).catch(() => null)} else if (s === 3) return null;
    let u = null, a = null, h = null;
    let g = null, w = null, m = null, d = false, x = null;
    const T = () => {
        d = true;
        if (x !== null) clearTimeout(x), x = null;
        [u, a].forEach(f => {try {f?.close()} catch {}});
        [w, g].forEach(f => {try {f?.releaseLock()} catch {}})
    };
    const S = () => {
        const f = i ? {secureTransport: "on", allowHalfOpen: false} : void 0;
        const b = ce({hostname: e, port: n}, f);
        return K(e, n, f, b).catch(p => {
            try {b.close()} catch {}
            throw p
        })
    };
    const A = () => crypto.getRandomValues(new Uint8Array(12));
    const y = (f, b) => f?.length === b?.length && f.every((p, k) => p === b[k]);
    const v = f => {
        let b = "";
        for (let p = 0; p < f.length; p++) b += f[p].toString(16).padStart(2, "0");
        return b
    };
    const W = async (f, b, p = null, k = null) => {
        const D = v(b), R = k?.get(D);
        if (R) {
            k.delete(D);
            return [R, p]
        }
        let L = p;
        for (; ;) {
            const Q = await Ze(f, L);
            if (!Q) throw new Error;
            const [F, V] = Q;
            L = V;
            if (y(F.tid, b)) return [F, L];
            if (k) k.set(v(F.tid), F)
        }
    };
    const U = new Map;
    const E = async f => {
        const [b, p] = await W(w, f, m, U);
        m = p;
        return b
    };
    const q = f => new Uint8Array([f >>> 24 & 255, f >>> 16 & 255, f >>> 8 & 255, f & 255]);
    const P = f => f?.length >= 4 ? f[0] * 16777216 + f[1] * 65536 + f[2] * 256 + f[3] : 0;
    let H = null, C = [], O = "";
    const I = f => H ? Ye(f, H) : f;
    const X = async f => {
        const b = f?.attrs?.[21]?.slice();
        if (!t || !b?.length) return false;
        const p = f.attrs?.[20]?.length ? ee.decode(f.attrs[20]) : O;
        if (!p) return false;
        if (p !== O || !H) {
            const k = await ye(`${t}:${p}:${r}`);
            H = await crypto.subtle.importKey("raw", k, {name: "HMAC", hash: "SHA-1"}, false, ["sign"])
        }
        O = p;
        C = [$(6, B.encode(t)), $(20, B.encode(O)), $(21, b)];
        return true
    };
    const Ae = async (f, b, p) => {
        for (let k = 0; k < 2; k++) {
            if (d) throw new Error;
            const D = A();
            await g.write(await I(N(f, D, [...b, ...C])));
            const R = await E(D);
            if (R?.type === p) return R;
            const L = de(R?.attrs?.[9]);
            if ((L === 401 || L === 438) && await X(R)) continue;
            throw new Error
        }
        throw new Error
    };
    try {
        const f = S();
        h = S().then(z => {
            a = z;
            if (d) try {z.close()} catch {}
            return z
        });
        h.catch(() => {});
        u = await f;
        g = u.writable.getWriter(), w = u.readable.getReader();
        let b = A();
        await g.write(N(3, b, [$(25, new Uint8Array([6, 0, 0, 0]))]));
        let p = await E(b);
        if (!p) throw new Error;
        const k = await c;
        if (!k) throw new Error;
        const D = $(18, Ge(k, o));
        let R = null, L = null, Q = null, F = null;
        if (p.type === 275 && t && de(p.attrs[9]) === 401) {
            const z = ee.decode(p.attrs[20] ?? []), j = p.attrs[21] ?? [];
            const Ue = await ye(`${t}:${z}:${r}`);
            H = await crypto.subtle.importKey("raw", Ue, {name: "HMAC", hash: "SHA-1"}, false, ["sign"]);
            O = z;
            C = [$(6, B.encode(t)), $(20, B.encode(z)), $(21, j)];
            const ie = A();
            R = A(), L = A();
            const [Te, Se, Me] = await Promise.all([I(N(3, ie, [$(25, new Uint8Array([6, 0, 0, 0])), ...C])), I(N(8, R, [D, ...C])), I(N(10, L, [D, ...C]))]);
            Q = Se, F = Me;
            await g.write(se(Te, Q, F));
            p = await E(ie)
        } else if (p.type === 259) {
            R = A(), L = A();
            [Q, F] = await Promise.all([I(N(8, R, [D, ...C])), I(N(10, L, [D, ...C]))]);
            await g.write(se(Q, F))
        } else {throw new Error}
        if (p?.type !== 259) throw new Error;
        let V = P(p.attrs?.[13]) || 600;
        p = await E(R);
        if (p?.type !== 264) throw new Error;
        p = await E(L);
        if (p?.type !== 266 || !p.attrs[42]) throw new Error;
        await h;
        const ae = a.writable.getWriter(), oe = a.readable.getReader();
        b = A();
        await ae.write(await I(N(11, b, [$(42, p.attrs[42]), ...C])));
        let le;
        [p, le] = await W(oe, b);
        if (p?.type !== 267) throw new Error;
        oe.releaseLock(), ae.releaseLock();
        let G = 0;
        const Y = async () => {
            if (d) return;
            try {
                const z = await Ae(4, [$(13, q(V))], 260), j = P(z.attrs?.[13]);
                if (j === 0) throw new Error;
                if (j > 0) V = j;
                G = 0;
                if (!d) x = setTimeout(Y, Math.min(3e5, Math.max(5e3, Math.floor(V * 500))))
            } catch {
                if (d) return;
                G++, G <= 3 ? x = setTimeout(Y, G * 2e3) : T()
            }
        };
        if (!d) x = setTimeout(Y, Math.min(3e5, Math.max(5e3, Math.floor(V * 500))));
        return {readable: a.readable, writable: a.writable, close: T, extra: le}
    } catch {
        T();
        return null
    }
};
const et = e => {
    const n = e.length;
    const t = {success: false, needMore: false, handshake: null, parsedRequest: null};
    if (n < 17) return t.needMore = true, t;
    if (!(e[1] === Re && e[2] === Le && e[3] === Ee && e[4] === Pe && e[5] === He && e[6] === Oe && e[7] === Ie && e[8] === $e && e[9] === ve && e[10] === De && e[11] === Fe && e[12] === ze && e[13] === Be && e[14] === Ne && e[15] === Qe && e[16] === Ve)) {return t}
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
const tt = {headers: {Accept: "application/dns-json"}}, rt = {"content-type": "application/dns-message"};
const be = async (e, n) => {
    try {
        const t = await fetch(`${pe}?name=${encodeURIComponent(e)}&type=${n}`, tt);
        if (!t.ok) return null;
        const r = await t.json();
        const s = r.Answer || r.answer;
        if (!s || s.length === 0) return null;
        return s
    } catch {return null}
};
const nt = async e => {
    const n = await be(e, "A");
    if (!n) return null;
    let t = null;
    for (let r = 0, s = n.length; r < s; r++) if (n[r].type === 1 && n[r].data) {
        t = n[r].data;
        break
    }
    return t
};
const st = async e => {
    if (e.byteLength < 2) return null;
    const n = e.subarray(2);
    let t;
    try {
        const o = await fetch(pe, {method: "POST", headers: rt, body: n});
        if (!o.ok) return null;
        t = await o.arrayBuffer()
    } catch {return null}
    const r = t.byteLength;
    const s = new Uint8Array(2 + r);
    s[0] = r >> 8 & 255, s[1] = r & 255;
    s.set(new Uint8Array(t), 2);
    return s
};
const at = async e => {
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
const ot = /william|fxpip|hhtxt/;
const lt = async (e, n) => {
    if (n || ot.test(e)) {
        const s = await at(e);
        if (!s || s.length === 0) return null;
        const [o, l] = re(s[Math.random() * s.length | 0], 443);
        return K(o, l)
    }
    const [t, r] = re(e, 443);
    return K(t, r)
};
const it = new Map([[0, async ({addrType: e, port: n, addrBytes: t}) => K(te(e, t), n)], [1, async ({addrType: e, port: n, addrBytes: t}, r) => je(e, n, r, t)], [2, async ({addrType: e, port: n, addrBytes: t}, r) => we(e, n, r, t)], [6, async ({addrType: e, port: n, addrBytes: t}, r) => we(e, n, r, t, true)], [5, async (e, n) => ge(n, e)], [7, async (e, n) => ge(n, e, true)], [3, async (e, n, t) => lt(n, t)]]);
const me = /(speed|gs5|s5all|ghttp|httpall|ghttps|httpsall|gturn|turnall|gturns|turnsall|s5|socks|http|https|turn|turns|txtip|ip)(?:=|:\/\/|%3A%2F%2F)([^&]+)|(proxyall|globalproxy|global)/gi;
const ct = async (e, n) => {
    let t = n.url, r = t.slice(t.indexOf("/", 10) + 1), s = r.length, o = [], l;
    const i = r.charCodeAt(s - 1);
    if (i === 47 || i === 61) r = r.slice(0, s - 1);
    const c = n.cf?.colo;
    const u = (c ? c + "." : "") + Z;
    if (r.length < 6) {o.push({type: 0}, {type: 3, param: u}, {type: 3, param: Z})} else {
        const a = Object.create(null);
        me.lastIndex = 0;
        let h;
        while (h = me.exec(r)) {a[(h[1] || h[3]).toLowerCase()] = h[2] ? h[2].charCodeAt(h[2].length - 1) === 61 ? h[2].slice(0, -1) : h[2] : true}
        if (a.speed) l = a.speed;
        const g = a.gs5 || a.s5all || a.s5 || a.socks, w = a.ghttp || a.httpall || a.http, m = a.ghttps || a.httpsall || a.https, d = a.gturn || a.turnall || a.turn, x = a.gturns || a.turnsall || a.turns;
        const T = !!(a.gs5 || a.s5all || a.ghttp || a.httpall || a.ghttps || a.httpsall || a.gturn || a.turnall || a.gturns || a.turnsall || a.proxyall || a.globalproxy || a.global);
        if (!T) o.push({type: 0});
        const S = (A, y, v) => {
            if (!A) return;
            const W = decodeURIComponent(A).split(",").filter(Boolean);
            for (let U = 0; U < W.length; U++) o.push(v ? {type: y, param: W[U], txt: v} : {type: y, param: y === 1 || y === 2 || y === 5 || y === 6 || y === 7 ? Xe(W[U]) : W[U]})
        };
        for (let A = 0; A < fe.length; A++) {
            const y = fe[A];
            S(y === "socks" ? g : y === "http" ? w : y === "https" ? m : y === "turn" ? d : x, y === "socks" ? 1 : y === "http" ? 2 : y === "https" ? 6 : y === "turn" ? 5 : 7)
        }
        if (T) {if (!o.length) o.push({type: 0})} else {
            S(a.ip, 3), S(a.txtip, 3, true);
            o.push({type: 3, param: u}, {type: 3, param: Z})
        }
    }
    for (let a = 0; a < o.length; a++) {
        try {
            const h = it.get(o[a].type);
            const g = await (h?.(e, o[a].param, o[a].txt));
            if (g) return {socket: g, speed: l}
        } catch {}
    }
    return null
};
const ut = async (e, n, t, r) => {
    const s = parseFloat(r), o = s > 0;
    let l = ke, i = Ce, c = We;
    if (o) {
        c = s > 256 ? Number.MAX_SAFE_INTEGER : s * 1048576;
        let P = l, H = Infinity, C = Infinity;
        for (let O = 262144; O <= 524288; O += 65536) {
            const I = Math.max(2, Math.round(O * 1e3 / c)), X = Math.abs(O * 1e3 / I - c);
            if (X < C || X === C && I < H) P = O, H = I, C = X
        }
        l = P, i = H
    }
    const u = l - _, a = _ << 1;
    let h = new Uint8Array(l), g = new ArrayBuffer(_);
    let w = 0, m = 0, d = 0, x = null, T = null, S = false;
    let A = false, y = false, v = true, W, U;
    const E = () => {
        if (S) return A = true;
        v = w < a;
        if (w > 0) n.send(h.subarray(0, w)), w = 0;
        A = false, y = false, x && (clearTimeout(x), x = null), T?.(), T = null
    };
    const q = e.getReader({mode: "byob"});
    try {
        while (true) {
            if (w > 0 && y) {
                ({done: W, value: U} = await q.read(new Uint8Array(g, 0, _)));
                h.set(U, w), g = U.buffer
            } else {
                S = w > 0;
                ({done: W, value: U} = await q.read(new Uint8Array(h.buffer, w, _)));
                S = false, h = new Uint8Array(U.buffer)
            }
            if (W) break;
            const P = U.byteLength;
            if (!P) {
                A && E();
                continue
            }
            w += P, m += P;
            if (A) {E()} else {
                if (v || P < 28672) {
                    if (!o) m = 0;
                    d = 2
                } else if (m > c) d = i;
                x ||= setTimeout(E, d), y = P < _;
                w > u && (m > c ? await new Promise(H => T = H) : E())
            }
        }
    } catch {w = 0, t?.()} finally {S = false, E()}
};
const ft = (e, n) => {
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
        r + h > 32768 && c(), t.set(a, r), r += h, r === 32768 ? c() : s ||= setTimeout(c, 2)
    }
};
const pt = (e, n) => {
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
    const l = et(e);
    if (l.handshake) r.send(l.handshake);
    if (!l.success) return l.needMore ? n.needMore = true : s();
    const i = l.parsedRequest;
    const c = e.subarray(i.dataOffset);
    if (i.isDns) {
        const u = await st(c);
        if (u?.byteLength) r.send(u);
        if (!o) return s()
    } else {
        const u = await ct(i, t);
        if (!u) return s();
        n.tcpSocket = u.socket;
        const a = n.tcpSocket.writable.getWriter();
        n.rawTcpWriter = a;
        if (c.byteLength) a.write(c);
        if (n.tcpSocket.extra?.length) await r.send(n.tcpSocket.extra);
        if (n.xwebPipeTo) return n.tcpWriter = h => a.write(h);
        n.tcpWriter = ft(a, s);
        ut(n.tcpSocket.readable, r, s, u.speed)
    }
};
const ht = async (e, n) => {
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
    i = pt(u, c);
    if (o) i(o);
    e.addEventListener("message", a => (l.tcpWriter || i)(a.data));
    e.addEventListener("error", c)
};
const wt = {"Content-Type": "application/octet-stream", "grpc-status": "0", "X-Accel-Buffering": "no", "Cache-Control": "no-store"};
const dt = async e => {
    const n = e.body?.getReader({mode: "byob"});
    if (!n) return new Response(null, {status: 400});
    const t = {tcpWriter: null, tcpSocket: null, needMore: false, xwebPipeTo: true};
    const r = new IdentityTransformStream({highWaterMark: 1024 * 1024}), s = new IdentityTransformStream({highWaterMark: 1024 * 1024 * 1024}), o = r.writable.getWriter();
    const l = () => {if (t.xwebPipeTo) t.xwebPipeTo = false, n.cancel().catch(() => {}), o.close().catch(() => {})};
    const i = {send(c) {if (c?.byteLength) return o.write(c)}};
    (async () => {
        let c = new Uint8Array(32768), u = new ArrayBuffer(8192), a = 0, h = 0, g = null, w, m;
        const d = () => {
            if (a > 0 && t.tcpWriter && c) t.tcpWriter(c.subarray(0, a)), a = 0;
            g && (clearTimeout(g), g = null)
        };
        try {
            while (true) {
                if (a > 0 && t.tcpWriter) {
                    ({done: w, value: m} = await n.read(new Uint8Array(u, 0, 8192)));
                    c.set(m, a), u = m.buffer
                } else {
                    ({done: w, value: m} = await n.read(new Uint8Array(c.buffer, a, 8192)));
                    c = new Uint8Array(m.buffer)
                }
                if (w) break;
                const x = m.byteLength;
                if (!x) continue;
                a += x;
                if (t.tcpWriter) {
                    if (++h >= 8e3) {
                        d();
                        await t.rawTcpWriter.ready;
                        n.releaseLock(), t.rawTcpWriter.releaseLock(), t.xwebPipeTo = false, c = null, u = null;
                        e.body.pipeThrough(s).pipeTo(t.tcpSocket.writable);
                        break
                    }
                    a > 24576 ? d() : g ||= setTimeout(d, 2)
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
        } catch {a = 0, l()} finally {d()}
    })().catch(l);
    return new Response(r.readable, {headers: wt})
};
export default {
    async fetch(e) {
        if (e.method === "POST" && e.headers.get("content-type")?.startsWith("application/grpc")) return dt(e);
        if (e.headers.get("Upgrade") === "websocket") {
            const {0: n, 1: t} = new WebSocketPair;
            t.accept({allowHalfOpen: true}), t.binaryType = "arraybuffer";
            ht(t, e);
            return new Response(null, {status: 101, webSocket: n})
        }
        return new Response(Ke, {status: 200, headers: {"Content-Type": "text/html; charset=UTF-8"}})
    }
};