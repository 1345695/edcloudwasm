import {connect as ce} from "cloudflare:sockets";
const ke = "d342d11e-d424-4583-b36e-524ab1f0afa4";
const Se = 256 * 1024;
const Ue = 50 * 1024 * 1024;
const Q = 64 * 1024;
const Me = 4;
const ie = ["socks", "http", "https", "turn", "turns"];
const ue = "https://cloudflare-dns.com/dns-query";
const Y = "proxy.zjcloud.us.ci";
const We = Uint8Array.from(ke.replace(/-/g, "").match(/../g), r => parseInt(r, 16));
const F = new TextEncoder, Z = new TextDecoder;
const Re = `<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx/1.25.3</center></body></html>`;
const ee = (r, n) => {
    if (r === 2) return Z.decode(n);
    if (r === 1) return `${n[0]}.${n[1]}.${n[2]}.${n[3]}`;
    let e = (n[0] << 8 | n[1]).toString(16);
    for (let t = 1; t < 8; t++) e += ":" + (n[t * 2] << 8 | n[t * 2 + 1]).toString(16);
    return `[${e}]`
};
const te = (r, n) => {
    let e = r, t = n, s;
    if (r.charCodeAt(0) === 91) {
        if ((s = r.indexOf("]:")) !== -1) {
            e = r.substring(0, s + 1);
            t = r.substring(s + 2)
        }
    } else if ((s = r.indexOf(".tp")) !== -1 && r.lastIndexOf(":") === -1) {t = r.substring(s + 3, r.indexOf(".", s + 3))} else if ((s = r.lastIndexOf(":")) !== -1) {
        e = r.substring(0, s);
        t = r.substring(s + 1)
    }
    return [e, (t = parseInt(t), isNaN(t) ? n : t)]
};
const Le = r => {
    let n, e, t;
    const s = r.lastIndexOf("@");
    if (s === -1) {t = r} else {
        const c = r.substring(0, s);
        t = r.substring(s + 1);
        const i = c.indexOf(":");
        if (i === -1) {n = c} else {
            n = c.substring(0, i);
            e = c.substring(i + 1)
        }
    }
    const [o, l] = te(t, 1080);
    return {username: n, password: e, hostname: o, port: l}
};
const V = (r, n, e, t = ce({hostname: r, port: n}, e)) => t.opened.then(() => t);
const Ce = async (r, n, e, t) => {
    const s = await V(e.hostname, e.port);
    const o = s.writable.getWriter(), l = s.readable.getReader();
    await o.write(new Uint8Array([5, 2, 0, 2]));
    const {value: c} = await l.read();
    if (!c || c[0] !== 5 || c[1] === 255) return null;
    if (c[1] === 2) {
        if (!e.username) return null;
        const h = F.encode(e.username), d = F.encode(e.password || "");
        const w = h.length, T = d.length, y = new Uint8Array(3 + w + T);
        y[0] = 1, y[1] = w, y.set(h, 2), y[2 + w] = T, y.set(d, 3 + w);
        await o.write(y);
        const {value: g} = await l.read();
        if (!g || g[0] !== 1 || g[1] !== 0) return null
    } else if (c[1] !== 0) {return null}
    const i = r === 3, u = new Uint8Array(6 + t.length + (i ? 1 : 0));
    u[0] = 5, u[1] = 1, u[2] = 0, u[3] = r;
    i ? (u[4] = t.length, u.set(t, 5)) : u.set(t, 4);
    u[u.length - 2] = n >> 8, u[u.length - 1] = n & 255;
    await o.write(u);
    const {value: a} = await l.read();
    if (!a || a[1] !== 0) return null;
    o.releaseLock(), l.releaseLock();
    return s
};
const Ee = `User-Agent:Mozilla/5.0(X11;Linux x86_64)AppleWebKit/537.36\r\nProxy-Connection:Keep-Alive\r\nConnection:Keep-Alive\r\n\r\n`;
const re = F.encode(Ee);
const fe = async (r, n, e, t, s = false) => {
    const {username: o, password: l, hostname: c, port: i} = e;
    const u = s ? {secureTransport: "on", allowHalfOpen: false} : void 0;
    const a = await V(c, i, u), h = a.writable.getWriter();
    const d = ee(r, t);
    let w = `CONNECT ${d}:${n} HTTP/1.1\r\nHost:${d}:${n}\r\n`;
    if (o) w += `Proxy-Authorization:Basic ${btoa(`${o}:${l || ""}`)}\r\n`;
    const T = new Uint8Array(w.length * 3 + re.length), {written: y} = F.encodeInto(w, T);
    T.set(re, y);
    await h.write(T.subarray(0, y + re.length));
    h.releaseLock();
    const g = a.readable.getReader(), x = new Uint8Array(512);
    let m = 0, k = false;
    while (m < x.length) {
        const {value: b, done: $} = await g.read();
        if ($ || m + b.length > x.length) return null;
        const M = m;
        x.set(b, m), m += b.length;
        if (!k && m >= 12) {
            if (x[9] !== 50) return null;
            k = true
        }
        let S = Math.max(15, M - 3);
        while ((S = x.indexOf(13, S)) !== -1 && S <= m - 4) {
            if (x[S + 1] === 10 && x[S + 2] === 13 && x[S + 3] === 10) {
                g.releaseLock();
                return a
            }
            S++
        }
    }
    return null
};
const G = new Uint8Array([33, 18, 164, 66]);
const ne = (...r) => {
    let n = 0, e = 0, t = 0;
    for (; e < r.length; e++) n += r[e].length;
    const s = new Uint8Array(n);
    for (e = 0; e < r.length; e++) {
        s.set(r[e], t);
        t += r[e].length
    }
    return s
};
const H = (r, n) => {
    const e = n.length, t = new Uint8Array(4 + e + (4 - e % 4) % 4);
    t[0] = r >> 8, t[1] = r & 255, t[2] = e >> 8, t[3] = e & 255, t.set(n, 4);
    return t
};
const B = (r, n, e) => {
    const t = ne(...e), s = t.length, o = new Uint8Array(20 + s);
    o[0] = r >> 8, o[1] = r & 255, o[2] = s >> 8, o[3] = s & 255, o.set(G, 4), o.set(n, 8), o.set(t, 20);
    return o
};
const Pe = (r, n) => {
    const e = new Uint8Array(8);
    e[1] = 1;
    const t = n ^ 8466;
    e[2] = t >> 8, e[3] = t & 255;
    let s = 0, o = 0;
    for (let l = 0; l < r.length; l++) {
        const c = r.charCodeAt(l);
        if (c === 46) {
            e[4 + s] = o ^ G[s++];
            o = 0
        } else {o = o * 10 + (c - 48)}
    }
    e[4 + s] = o ^ G[s];
    return e
};
const Ie = r => {
    if (r.length < 20 || G.some((t, s) => r[4 + s] !== t)) return null;
    const n = r[2] << 8 | r[3], e = {};
    for (let t = 20; t + 4 <= 20 + n;) {
        const s = r[t] << 8 | r[t + 1], o = r[t + 2] << 8 | r[t + 3];
        if (t + 4 + o > r.length) break;
        e[s] = r.subarray(t + 4, t + 4 + o);
        t += 4 + o + (4 - o % 4) % 4
    }
    return {type: r[0] << 8 | r[1], attrs: e, tid: r.slice(8, 20)}
};
const pe = r => r?.length >= 4 ? (r[2] & 7) * 100 + r[3] : 0;
const Oe = async (r, n) => {
    const e = r.length, t = new Uint8Array(e + 24);
    t.set(r);
    const s = (r[2] << 8 | r[3]) + 24;
    t[2] = s >> 8, t[3] = s & 255;
    const o = new Uint8Array(await crypto.subtle.sign("HMAC", n, t.subarray(0, e)));
    t[e] = 0, t[e + 1] = 8, t[e + 2] = 0, t[e + 3] = 20, t.set(o, e + 4);
    return t
};
const He = async (r, n) => {
    let e = n && n.length ? [n] : [];
    let t = n ? n.length : 0;
    const s = async () => {
        const {done: l, value: c} = await r.read();
        if (l) throw new Error;
        e.push(c);
        t += c.length
    };
    const o = () => {
        if (e.length === 1) return e[0];
        const l = new Uint8Array(t);
        let c = 0;
        for (let i = 0; i < e.length; i++) {
            l.set(e[i], c);
            c += e[i].length
        }
        e = [l];
        return l
    };
    try {
        while (t < 20) await s();
        let l = o();
        if (l[4] !== 33 || l[5] !== 18 || l[6] !== 164 || l[7] !== 66) return null;
        const c = 20 + (l[2] << 8 | l[3]);
        if (c > 8192) return null;
        while (t < c) await s();
        l = o();
        return [Ie(l.subarray(0, c)), t > c ? l.subarray(c) : null]
    } catch {return null}
};
const he = async r => new Uint8Array(await crypto.subtle.digest("MD5", F.encode(r)));
const de = async ({hostname: r, port: n, username: e, password: t}, {addrType: s, port: o, addrBytes: l}, c = false) => {
    let i = ee(s, l);
    if (s === 2) {i = De(i).catch(() => null)} else if (s === 3) return null;
    let u = null, a = null, h = null;
    let d = null, w = null, T = null, y = false, g = null;
    const x = () => {
        y = true;
        if (g !== null) clearTimeout(g), g = null;
        [u, a].forEach(f => {try {f?.close()} catch {}});
        [w, d].forEach(f => {try {f?.releaseLock()} catch {}})
    };
    const m = () => {
        const f = c ? {secureTransport: "on", allowHalfOpen: false} : void 0;
        const A = ce({hostname: r, port: n}, f);
        return V(r, n, f, A).catch(p => {
            try {A.close()} catch {}
            throw p
        })
    };
    const k = () => crypto.getRandomValues(new Uint8Array(12));
    const b = (f, A) => f?.length === A?.length && f.every((p, U) => p === A[U]);
    const $ = f => {
        let A = "";
        for (let p = 0; p < f.length; p++) A += f[p].toString(16).padStart(2, "0");
        return A
    };
    const M = async (f, A, p = null, U = null) => {
        const v = $(A), R = U?.get(v);
        if (R) {
            U.delete(v);
            return [R, p]
        }
        let L = p;
        for (; ;) {
            const N = await He(f, L);
            if (!N) throw new Error;
            const [z, j] = N;
            L = j;
            if (b(z.tid, A)) return [z, L];
            if (U) U.set($(z.tid), z)
        }
    };
    const S = new Map;
    const C = async f => {
        const [A, p] = await M(w, f, T, S);
        T = p;
        return A
    };
    const _ = f => new Uint8Array([f >>> 24 & 255, f >>> 16 & 255, f >>> 8 & 255, f & 255]);
    const E = f => f?.length >= 4 ? f[0] * 16777216 + f[1] * 65536 + f[2] * 256 + f[3] : 0;
    let P = null, W = [], I = "";
    const O = f => P ? Oe(f, P) : f;
    const K = async f => {
        const A = f?.attrs?.[21]?.slice();
        if (!e || !A?.length) return false;
        const p = f.attrs?.[20]?.length ? Z.decode(f.attrs[20]) : I;
        if (!p) return false;
        if (p !== I || !P) {
            const U = await he(`${e}:${p}:${t}`);
            P = await crypto.subtle.importKey("raw", U, {name: "HMAC", hash: "SHA-1"}, false, ["sign"])
        }
        I = p;
        W = [H(6, F.encode(e)), H(20, F.encode(I)), H(21, A)];
        return true
    };
    const be = async (f, A, p) => {
        for (let U = 0; U < 2; U++) {
            if (y) throw new Error;
            const v = k();
            await d.write(await O(B(f, v, [...A, ...W])));
            const R = await C(v);
            if (R?.type === p) return R;
            const L = pe(R?.attrs?.[9]);
            if ((L === 401 || L === 438) && await K(R)) continue;
            throw new Error
        }
        throw new Error
    };
    try {
        const f = m();
        h = m().then(D => {
            a = D;
            if (y) try {D.close()} catch {}
            return D
        });
        h.catch(() => {});
        u = await f;
        d = u.writable.getWriter(), w = u.readable.getReader();
        let A = k();
        await d.write(B(3, A, [H(25, new Uint8Array([6, 0, 0, 0]))]));
        let p = await C(A);
        if (!p) throw new Error;
        const U = await i;
        if (!U) throw new Error;
        const v = H(18, Pe(U, o));
        let R = null, L = null, N = null, z = null;
        if (p.type === 275 && e && pe(p.attrs[9]) === 401) {
            const D = Z.decode(p.attrs[20] ?? []), X = p.attrs[21] ?? [];
            const me = await he(`${e}:${D}:${t}`);
            P = await crypto.subtle.importKey("raw", me, {name: "HMAC", hash: "SHA-1"}, false, ["sign"]);
            I = D;
            W = [H(6, F.encode(e)), H(20, F.encode(D)), H(21, X)];
            const le = k();
            R = k(), L = k();
            const [xe, Ae, Te] = await Promise.all([O(B(3, le, [H(25, new Uint8Array([6, 0, 0, 0])), ...W])), O(B(8, R, [v, ...W])), O(B(10, L, [v, ...W]))]);
            N = Ae, z = Te;
            await d.write(ne(xe, N, z));
            p = await C(le)
        } else if (p.type === 259) {
            R = k(), L = k();
            [N, z] = await Promise.all([O(B(8, R, [v, ...W])), O(B(10, L, [v, ...W]))]);
            await d.write(ne(N, z))
        } else {throw new Error}
        if (p?.type !== 259) throw new Error;
        let j = E(p.attrs?.[13]) || 600;
        p = await C(R);
        if (p?.type !== 264) throw new Error;
        p = await C(L);
        if (p?.type !== 266 || !p.attrs[42]) throw new Error;
        await h;
        const se = a.writable.getWriter(), ae = a.readable.getReader();
        A = k();
        await se.write(await O(B(11, A, [H(42, p.attrs[42]), ...W])));
        let oe;
        [p, oe] = await M(ae, A);
        if (p?.type !== 267) throw new Error;
        ae.releaseLock(), se.releaseLock();
        let q = 0;
        const J = async () => {
            if (y) return;
            try {
                const D = await be(4, [H(13, _(j))], 260), X = E(D.attrs?.[13]);
                if (X === 0) throw new Error;
                if (X > 0) j = X;
                q = 0;
                if (!y) g = setTimeout(J, Math.min(3e5, Math.max(5e3, Math.floor(j * 500))))
            } catch {
                if (y) return;
                q++, q <= 3 ? g = setTimeout(J, q * 2e3) : x()
            }
        };
        if (!y) g = setTimeout(J, Math.min(3e5, Math.max(5e3, Math.floor(j * 500))));
        return {readable: a.readable, writable: a.writable, close: x, extra: oe}
    } catch {
        x();
        return null
    }
};
const $e = r => {
    const n = r.length;
    const e = {success: false, needMore: false, handshake: null, parsedRequest: null};
    if (n < 17) return e.needMore = true, e;
    for (let u = 0; u < 16; u++) if (r[u + 1] !== We[u]) return e;
    if (n < 18) return e.needMore = true, e;
    const t = 19 + r[17];
    if (n < t + 4) return e.needMore = true, e;
    const s = r[t + 2];
    const o = s === 2 ? r[t + 3] : s === 1 ? 4 : s === 3 ? 16 : 0;
    if (!o) return e;
    const l = s === 2 ? t + 4 : t + 3, c = l + o;
    if (n < c) return e.needMore = true, e;
    const i = r[t] << 8 | r[t + 1];
    e.handshake = new Uint8Array([r[0], 0]);
    e.success = true;
    e.parsedRequest = {addrType: s, addrBytes: r.subarray(l, c), dataOffset: c, port: i, isDns: i === 53};
    return e
};
const ve = {headers: {Accept: "application/dns-json"}}, ze = {"content-type": "application/dns-message"};
const we = async (r, n) => {
    try {
        const e = await fetch(`${ue}?name=${encodeURIComponent(r)}&type=${n}`, ve);
        if (!e.ok) return null;
        const t = await e.json();
        const s = t.Answer || t.answer;
        if (!s || s.length === 0) return null;
        return s
    } catch {return null}
};
const De = async r => {
    const n = await we(r, "A");
    if (!n) return null;
    let e = null;
    for (let t = 0, s = n.length; t < s; t++) if (n[t].type === 1 && n[t].data) {
        e = n[t].data;
        break
    }
    return e
};
const Fe = async r => {
    if (r.byteLength < 2) return null;
    const n = r.subarray(2);
    let e;
    try {
        const o = await fetch(ue, {method: "POST", headers: ze, body: n});
        if (!o.ok) return null;
        e = await o.arrayBuffer()
    } catch {return null}
    const t = e.byteLength;
    const s = new Uint8Array(2 + t);
    s[0] = t >> 8 & 255, s[1] = t & 255;
    s.set(new Uint8Array(e), 2);
    return s
};
const Be = async r => {
    const n = await we(r, "TXT");
    if (!n) return null;
    let e, t = 0, s = n.length;
    for (; t < s; t++) if (n[t].type === 16) {
        e = n[t].data;
        break
    }
    if (!e) return null;
    if (e.charCodeAt(0) === 34 && e.charCodeAt(e.length - 1) === 34) e = e.slice(1, -1);
    const o = e.split(/,|\\010|\n/), l = [];
    for (t = 0, s = o.length; t < s; t++) {
        const c = o[t].trim();
        if (c) l.push(c)
    }
    return l.length ? l : null
};
const Ne = /william|fxpip|hhtxt/;
const je = async (r, n) => {
    if (n || Ne.test(r)) {
        const s = await Be(r);
        if (!s || s.length === 0) return null;
        const [o, l] = te(s[Math.random() * s.length | 0], 443);
        return V(o, l)
    }
    const [e, t] = te(r, 443);
    return V(e, t)
};
const Qe = new Map([[0, async ({addrType: r, port: n, addrBytes: e}) => V(ee(r, e), n)], [1, async ({addrType: r, port: n, addrBytes: e}, t) => Ce(r, n, t, e)], [2, async ({addrType: r, port: n, addrBytes: e}, t) => fe(r, n, t, e)], [6, async ({addrType: r, port: n, addrBytes: e}, t) => fe(r, n, t, e, true)], [5, async (r, n) => de(n, r)], [7, async (r, n) => de(n, r, true)], [3, async (r, n, e) => je(n, e)]]);
const ye = /(speed|gs5|s5all|ghttp|httpall|ghttps|httpsall|gturn|turnall|gturns|turnsall|s5|socks|http|https|turn|turns|txtip|ip)(?:=|:\/\/|%3A%2F%2F)([^&]+)|(proxyall|globalproxy|global)/gi;
const Ve = async (r, n) => {
    let e = n.url, t = e.slice(e.indexOf("/", 10) + 1), s = t.length, o = [], l;
    const c = t.charCodeAt(s - 1);
    if (c === 47 || c === 61) t = t.slice(0, s - 1);
    const i = n.cf?.colo;
    const u = i ? `${i.toLowerCase()}.proxy.zjcloud.us.ci` : Y;
    if (t.length < 6) {o.push({type: 0}, {type: 3, param: u}, {type: 3, param: Y})} else {
        const a = Object.create(null);
        ye.lastIndex = 0;
        let h;
        while (h = ye.exec(t)) {a[(h[1] || h[3]).toLowerCase()] = h[2] ? h[2].charCodeAt(h[2].length - 1) === 61 ? h[2].slice(0, -1) : h[2] : true}
        if (a.speed) l = a.speed;
        const d = a.gs5 || a.s5all || a.s5 || a.socks, w = a.ghttp || a.httpall || a.http, T = a.ghttps || a.httpsall || a.https, y = a.gturn || a.turnall || a.turn, g = a.gturns || a.turnsall || a.turns;
        const x = !!(a.gs5 || a.s5all || a.ghttp || a.httpall || a.ghttps || a.httpsall || a.gturn || a.turnall || a.gturns || a.turnsall || a.proxyall || a.globalproxy || a.global);
        if (!x) o.push({type: 0});
        const m = (k, b, $) => {
            if (!k) return;
            const M = decodeURIComponent(k).split(",").filter(Boolean);
            for (let S = 0; S < M.length; S++) o.push($ ? {type: b, param: M[S], txt: $} : {type: b, param: b === 1 || b === 2 || b === 5 || b === 6 || b === 7 ? Le(M[S]) : M[S]})
        };
        for (let k = 0; k < ie.length; k++) {
            const b = ie[k];
            m(b === "socks" ? d : b === "http" ? w : b === "https" ? T : b === "turn" ? y : g, b === "socks" ? 1 : b === "http" ? 2 : b === "https" ? 6 : b === "turn" ? 5 : 7)
        }
        if (x) {if (!o.length) o.push({type: 0})} else {
            m(a.ip, 3), m(a.txtip, 3, true);
            o.push({type: 3, param: u}, {type: 3, param: Y})
        }
    }
    for (let a = 0; a < o.length; a++) {
        try {
            const h = Qe.get(o[a].type);
            const d = await (h?.(r, o[a].param, o[a].txt));
            if (d) return {socket: d, speed: l}
        } catch {}
    }
    return null
};
const Ke = async (r, n, e, t) => {
    const s = parseFloat(t), o = s > 0;
    let l = Se, c = Me, i = Ue;
    if (o) {
        i = s > 256 ? Number.MAX_SAFE_INTEGER : s * 1048576;
        let E = l, P = Infinity, W = Infinity;
        for (let I = 262144; I <= 524288; I += 65536) {
            const O = Math.max(2, Math.round(I * 1e3 / i)), K = Math.abs(I * 1e3 / O - i);
            if (K < W || K === W && O < P) E = I, P = O, W = K
        }
        l = E, c = P
    }
    const u = l - Q, a = Q << 1;
    let h = new Uint8Array(l), d = new ArrayBuffer(Q);
    let w = 0, T = 0, y = 0, g = null, x = null, m = false;
    let k = false, b = false, $ = true, M, S;
    const C = () => {
        if (m) return k = true;
        $ = w < a;
        if (w > 0) n.send(h.subarray(0, w)), w = 0;
        k = false, b = false, g && (clearTimeout(g), g = null), x?.(), x = null
    };
    const _ = r.getReader({mode: "byob"});
    try {
        while (true) {
            if (w > 0 && b) {
                ({done: M, value: S} = await _.read(new Uint8Array(d, 0, Q)));
                h.set(S, w), d = S.buffer
            } else {
                m = w > 0;
                ({done: M, value: S} = await _.read(new Uint8Array(h.buffer, w, Q)));
                m = false, h = new Uint8Array(S.buffer)
            }
            if (M) break;
            const E = S.byteLength;
            if (!E) {
                k && C();
                continue
            }
            w += E, T += E;
            if (k) {C()} else {
                if ($ || E < 28672) {
                    if (!o) T = 0;
                    y = 2
                } else if (T > i) y = c;
                g ||= setTimeout(C, y), b = E < Q;
                w > u && (T > i ? await new Promise(P => x = P) : C())
            }
        }
    } catch {w = 0, e?.()} finally {m = false, C()}
};
const Xe = (r, n) => {
    const e = new Uint8Array(32768);
    let t = 0, s = null, o = false;
    const l = () => {
        if (o) return;
        o = true;
        s && (clearTimeout(s), s = null);
        n?.()
    };
    const c = u => {try {r.write(u)} catch {l()}};
    const i = () => {
        s && (clearTimeout(s), s = null);
        if (!t || o) return;
        const u = t;
        t = 0, c(e.subarray(0, u))
    };
    return u => {
        if (o) return;
        const a = u.constructor === Uint8Array ? u : new Uint8Array(u), h = a.byteLength;
        if (!h) return;
        t + h > 32768 && i(), e.set(a, t), t += h, t === 32768 ? i() : (s && clearTimeout(s), s = setTimeout(i, 2))
    }
};
const _e = (r, n) => {
    const e = new Array(256).fill(null);
    let t = 0, s = 0, o = 0, l = false, c = false;
    const i = () => {
        if (c) return;
        c = true;
        for (let a = 0; a < 256; a++) e[a] = null;
        n?.()
    };
    const u = async () => {
        if (c) return;
        try {
            while (o > 0 && !c) {
                const a = e[t];
                e[t] = null, t = t + 1 & 255, o--;
                await r(a)
            }
        } catch {i()} finally {l = false}
    };
    return a => {
        if (c) return;
        if (o === 256) return i();
        e[s] = a, s = s + 1 & 255, o++;
        if (!l) l = true, queueMicrotask(u)
    }
};
const ge = async (r, n, e, t, s, o = false) => {
    n.needMore = false;
    const l = $e(r);
    if (l.handshake) t.send(l.handshake);
    if (!l.success) return l.needMore ? n.needMore = true : s();
    const c = l.parsedRequest;
    const i = r.subarray(c.dataOffset);
    if (c.isDns) {
        const u = await Fe(i);
        if (u?.byteLength) t.send(u);
        if (!o) return s()
    } else {
        const u = await Ve(c, e);
        if (!u) return s();
        n.tcpSocket = u.socket;
        const a = n.tcpSocket.writable.getWriter();
        n.rawTcpWriter = a;
        if (i.byteLength) a.write(i);
        if (n.tcpSocket.extra?.length) await t.send(n.tcpSocket.extra);
        if (n.xwebPipeTo) return n.tcpWriter = h => a.write(h);
        n.tcpWriter = Xe(a, s);
        Ke(n.tcpSocket.readable, t, s, u.speed)
    }
};
const qe = async (r, n) => {
    const e = n.headers.get("Referer");
    const t = e || n.headers.get("sec-websocket-protocol");
    let s = null;
    if (e) {s = t.slice(n.headers.get("host").length)} else if (t) {s = t}
    const o = s ? Uint8Array.fromBase64(s, {alphabet: "base64url"}) : null;
    const l = {tcpWriter: null, tcpSocket: null};
    let c = null;
    const i = () => {
        try {l.tcpSocket?.close()} catch {}
        try {r.close(1011, "WebSocket is closed")} catch {}
    };
    const u = a => {
        if (l.tcpWriter) return l.tcpWriter(a);
        return ge(o ? a : new Uint8Array(a), l, n, r, i, o !== null)
    };
    c = _e(u, i);
    if (o) c(o);
    r.addEventListener("message", a => (l.tcpWriter || c)(a.data));
    r.addEventListener("error", i)
};
const Ge = {"Content-Type": "application/octet-stream", "grpc-status": "0", "X-Accel-Buffering": "no", "Cache-Control": "no-store"};
const Je = async r => {
    const n = r.body?.getReader({mode: "byob"});
    if (!n) return new Response(null, {status: 400});
    const e = {tcpWriter: null, tcpSocket: null, needMore: false, xwebPipeTo: true};
    const t = new IdentityTransformStream({highWaterMark: 1024 * 1024}), s = new IdentityTransformStream({highWaterMark: 1024 * 1024 * 1024}), o = t.writable.getWriter();
    let l = false, c = new AbortController;
    const i = a => {
        if (l) return;
        l = true;
        !c.signal.aborted && c.abort(a);
        if (e.xwebPipeTo) try {o.abort(a).catch(() => {})} catch {}
        try {e.tcpSocket?.close()} catch {}
    };
    const u = {send(a) {if (a?.byteLength) return o.write(a)}};
    (async () => {
        let a = new Uint8Array(32768), h = new ArrayBuffer(8192), d = 0, w = 0, T = null, y, g;
        const x = () => {
            if (d > 0 && e.tcpWriter && a) e.tcpWriter(a.subarray(0, d)), d = 0;
            T && (clearTimeout(T), T = null)
        };
        try {
            while (true) {
                if (d > 0 && e.tcpWriter) {
                    ({done: y, value: g} = await n.read(new Uint8Array(h, 0, 8192)));
                    a.set(g, d), h = g.buffer
                } else {
                    ({done: y, value: g} = await n.read(new Uint8Array(a.buffer, d, 8192)));
                    a = new Uint8Array(g.buffer)
                }
                if (y) break;
                const m = g.byteLength;
                if (!m) continue;
                d += m;
                if (e.tcpWriter) {
                    w++;
                    if (w >= 8e3) {
                        x();
                        await e.rawTcpWriter.ready;
                        n.releaseLock(), e.rawTcpWriter.releaseLock(), e.xwebPipeTo = false, a = null, h = null;
                        r.body.pipeThrough(s, {signal: c.signal}).pipeTo(e.tcpSocket.writable, {signal: c.signal}).catch(i);
                        break
                    }
                    d > 24576 ? x() : (T && clearTimeout(T), T = setTimeout(x, 2))
                } else {
                    e.needMore = false;
                    await ge(a.subarray(0, d), e, r, u, i);
                    if (e.tcpSocket && e.xwebPipeTo && !e.downstreamPiped) {
                        e.downstreamPiped = true, o.releaseLock();
                        e.tcpSocket.readable.pipeTo(t.writable, {signal: c.signal}).then(() => i(), i)
                    }
                    if (!e.needMore) d = 0
                }
            }
        } catch (m) {
            d = 0;
            try {await (n?.cancel(m))} catch {}
            i(m)
        } finally {
            x(), a = null, h = null;
            if (e.xwebPipeTo && !e.tcpSocket) i()
        }
    })().catch(i);
    return new Response(t.readable, {headers: Ge})
};
export default {
    async fetch(r) {
        if (r.method === "POST" && r.headers.get("content-type")?.startsWith("application/grpc")) return Je(r);
        if (r.headers.get("Upgrade") === "websocket") {
            const {0: n, 1: e} = new WebSocketPair;
            e.accept({allowHalfOpen: true}), e.binaryType = "arraybuffer";
            qe(e, r);
            return new Response(null, {status: 101, webSocket: n})
        }
        return new Response(Re, {status: 200, headers: {"Content-Type": "text/html; charset=UTF-8"}})
    }
};