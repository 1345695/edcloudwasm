export const {TlsClient} = (() => {
    const b = crypto.subtle, V = new TextEncoder, g = new Uint8Array(0), y = i => [i >> 8, i & 255], A = (i, t) => i[t] << 8 | i[t + 1], q = (...i) => {
            const t = n => {
                let s = 0;
                for (let c = 0; c < n.length; c++) {
                    const l = n[c];
                    s += l instanceof Uint8Array ? l.length : Array.isArray(l) ? t(l) : 1
                }
                return s
            }, e = new Uint8Array(t(i));
            let r = 0;
            const a = n => {
                for (let s = 0; s < n.length; s++) {
                    const c = n[s];
                    c instanceof Uint8Array ? (e.set(c, r), r += c.length) : Array.isArray(c) ? a(c) : e[r++] = c
                }
            };
            return a(i), e
        }, d = (...i) => {
            const t = new Uint8Array(i.reduce((r, a) => r + (a?.length || 0), 0));
            let e = 0;
            for (const r of i) r?.length && (t.set(r, e), e += r.length);
            return t
        }, X = i => i === "SHA-384" ? 48 : 32, G = i => i?.[0] === 1 && i[1] === 112, D = async (i, t, e) => new Uint8Array(await b.sign("HMAC", t.type ? t : await b.importKey("raw", t, {name: "HMAC", hash: i}, !1, ["sign"]), e)), K = async (i, t) => new Uint8Array(await b.digest(i, t)), W = (i, t) => b.importKey("raw", i, {name: "AES-GCM"}, !1, [t]), N = async (i, t, e, r) => new Uint8Array(await b.encrypt({name: "AES-GCM", iv: t, additionalData: r}, i, e)),
        O = async (i, t, e, r) => new Uint8Array(await b.decrypt({name: "AES-GCM", iv: t, additionalData: r}, i, e)), M = (i, t, e = 771, r = t.length) => {
            const a = new Uint8Array(5 + r);
            return a[0] = i, a[1] = e >> 8, a[2] = e & 255, a[3] = r >> 8, a[4] = r & 255, a.set(t, 5), a
        }, $ = (i, t = 23) => {
            let e = 0;
            for (let n = 0; n < i.length; n++) e += 5 + i[n].length;
            const r = new Uint8Array(e);
            let a = 0;
            for (let n = 0; n < i.length; n++) {
                const s = i[n], c = s.length;
                r[a] = t, r[a + 1] = 3, r[a + 2] = 3, r[a + 3] = c >> 8, r[a + 4] = c & 255, r.set(s, a + 5), a += 5 + c
            }
            return r
        }, L = (i, t, e = t.length) => {
            const r = new Uint8Array(4 + e);
            return r[0] = i, r[1] = e >> 16 & 255, r[2] = e >> 8 & 255, r[3] = e & 255, r.set(t, 4), r
        }, R = i => new Uint8Array([23, 3, 3, i >> 8, i & 255]), tt = i => {
            const t = new Uint8Array(8), e = i >>> 0;
            if (t[7] = e & 255, t[6] = e >>> 8 & 255, t[5] = e >>> 16 & 255, t[4] = e >>> 24, i > 4294967295) {
                const r = Math.floor(i / 4294967296) >>> 0;
                t[3] = r & 255, t[2] = r >>> 8 & 255, t[1] = r >>> 16 & 255, t[0] = r >>> 24
            }
            return t
        }, z = (i, t, e) => D(i, t?.length ? t : new Uint8Array(X(i)), e), F = async (i, t, e, r, a = "SHA-256") => {
            const n = d(V.encode(t), e), s = i.type ? i : await b.importKey("raw", i, {name: "HMAC", hash: a}, !1, ["sign"]);
            let c = g, l = n;
            for (; c.length < r;) l = await D(a, s, l), c = d(c, await D(a, s, d(l, n)));
            return c.slice(0, r)
        }, E = async (i, t, e, r, a) => {
            const n = typeof e == "string" ? V.encode("tls13 " + e) : e, s = X(i), c = n.length, l = r.length, h = new Uint8Array(4 + c + l);
            h[0] = a >> 8, h[1] = a & 255, h[2] = c, h.set(n, 3), h[3 + c] = l, l && h.set(r, 4 + c);
            const w = t.type ? t : await b.importKey("raw", t, {name: "HMAC", hash: i}, !1, ["sign"]);
            let k = g, p = g;
            for (let v = 1; v <= Math.ceil(a / s); v++) {
                const U = new Uint8Array(p.length + h.length + 1);
                p.length && U.set(p), U.set(h, p.length), U[p.length + h.length] = v, p = await D(i, w, U), k = d(k, p)
            }
            return k.slice(0, a)
        }, Q = async (i = "P-256") => {
            const t = i === "X25519", e = await b.generateKey(t ? {name: i} : {name: "ECDH", namedCurve: i}, !0, ["deriveBits"]);
            return {kp: e, pk: new Uint8Array(await b.exportKey("raw", e.publicKey))}
        }, Y = async (i, t, e = "P-256") => {
            const r = e === "X25519", a = await b.importKey("raw", t, r ? {name: e} : {name: "ECDH", namedCurve: e}, !1, []);
            return new Uint8Array(await b.deriveBits({name: r ? e : "ECDH", public: a}, i, 256))
        }, et = (i, t, e, {sessionId: r = g} = {}) => {
            const a = q(...[4865, 4866, 49199, 49200, 49195, 49196].flatMap(y)), n = [q(255, 1, 0, 1, 0)];
            if (t) {
                const l = V.encode(t);
                n.push(q(0, 0, y(l.length + 5), y(l.length + 3), 0, y(l.length), l))
            }
            const s = d(q(0, 29, y(e.x25519.length), e.x25519), q(0, 23, y(e.p256.length), e.p256));
            n.push(q(y(11), 0, 2, 1, 0), q(y(10), 0, 6, 0, 4, 0, 29, 0, 23), q(y(13), 0, 34, 0, 32, ...[2052, 2053, 2054, 2055, 2056, 2057, 2058, 2059, 1027, 1283, 1539, 1025, 1281, 1537, 513, 515].flatMap(y)), q(y(43), 0, 5, 4, 3, 4, 3, 3), q(y(51), y(s.length + 2), y(s.length), s));
            const c = d(...n);
            return L(1, q(y(771), i, r.length, r, y(a.length), a, 1, 0, y(c.length), c))
        }, T = async (i, t, e, r, a) => {
            const n = t.type ? t : await b.importKey("raw", t, {name: "HMAC", hash: i}, !1, ["sign"]), [s, c] = await Promise.all([E(i, n, "key", g, e), E(i, n, "iv", g, r)]);
            return [await W(s, a), c]
        }, Z = i => {
            let t = i.length - 1;
            for (; t >= 0 && !i[t];) t--;
            if (t < 0) throw new Error;
            return {data: i.subarray(0, t), type: i[t]}
        }, B = (i, t) => {
            const e = i.slice(), r = e.length, a = t >>> 0;
            if (e[r - 1] ^= a & 255, e[r - 2] ^= a >>> 8 & 255, e[r - 3] ^= a >>> 16 & 255, e[r - 4] ^= a >>> 24, t > 4294967295) {
                const n = Math.floor(t / 4294967296) >>> 0;
                e[r - 5] ^= n & 255, e[r - 6] ^= n >>> 8 & 255, e[r - 7] ^= n >>> 16 & 255, e[r - 8] ^= n >>> 24
            }
            return e
        };
    class _ {
        constructor(t, e, r) {this.b = new Uint8Array(t), this.h = this.t = 0, this.l = e, this.g = r}
        feed(t) {
            const e = this;
            if (e.t + t.length > e.b.length) {
                const r = e.t - e.h, a = r + t.length > e.b.length, n = a ? new Uint8Array(Math.max(e.b.length * 2, r + t.length)) : e.b;
                a ? n.set(e.b.subarray(e.h, e.t)) : n.copyWithin(0, e.h, e.t), e.b = n, e.t = r, e.h = 0
            }
            e.b.set(t, e.t), e.t += t.length
        }
        next() {
            const t = this;
            if (t.t - t.h < t.l) return null;
            const e = t.g(t.b, t.h);
            if (t.l === 5 && e > 18432) throw new Error;
            if (t.t - t.h < t.l + e) return null;
            const r = t.b.subarray(t.h, t.h += t.l + e), a = r.subarray(t.l);
            return t.h === t.t && (t.h = t.t = 0), {type: r[0], version: t.l === 5 ? A(r, 1) : 0, length: e, body: a, fragment: a, raw: r}
        }
    }
    class rt {
        constructor(t, e = {}) {
            const r = this;
            r.sk = t, r.sn = e.serverName || "", r.cr = crypto.getRandomValues(new Uint8Array(32)), r.id = crypto.getRandomValues(new Uint8Array(32)), r.hb = new Uint8Array(8192), r.hl = 0, r.cn = 0, r.qn = 0, r.rp = new _(32768, 5, (a, n) => A(a, n + 3)), r.hp = new _(4096, 4, (a, n) => a[n + 1] << 16 | A(a, n + 2)), r.kp = new Map, r.pq = [], r.wq = Promise.resolve(), r.rb = new Uint8Array(65536), r.rd = null, r.wr = null, r.fl = !1, r.cl = !1, r.cg = !1, r.hc = !1, r.cp = null, r.i3 = !1, r.cs = null, r.cc = null, r.sr = null, r.hs = null, r.ch = null, r.ci = null, r.sh = null, r.si = null, r.ak = null, r.ai = null, r.bk = null, r.bi = null, r.ms = null, r.ck = null, r.wk = null, r.cv = null, r.wv = null, r.as = null, r.bs = null
        }
        rh(t) {
            const e = this;
            if (e.hl + t.length > e.hb.length) {
                const r = new Uint8Array(Math.max(e.hb.length * 2, e.hl + t.length));
                r.set(e.hb.subarray(0, e.hl)), e.hb = r
            }
            e.hb.set(t, e.hl), e.hl += t.length
        }
        ts() {return this.hb.subarray(0, this.hl)}
        fc() {return this.cn++}
        fs() {return this.qn++}
        fail() {
            const t = this;
            t.fl = t.cl = !0;
            try {t.sk?.close()} catch {}
            try {t.rd?.cancel()} catch {}
            try {t.wr?.abort()} catch {}
        }
        async rc() {
            const t = this, e = await t.rd.read(t.rb);
            if (!e) throw new Error;
            return !e.done && e.value && (t.rb = new Uint8Array(e.value.buffer)), e
        }
        async pr(t) {
            const e = this;
            for (; ;) {
                for (let n; n = e.rp.next();) if (await t(n)) return;
                const {value: r, done: a} = await e.rc();
                if (a) throw new Error;
                e.rp.feed(r)
            }
        }
        async handshake() {
            const t = this, [e, r] = await Promise.all([Q("P-256"), Q("X25519")]);
            t.kp = new Map([[23, e], [29, r]]), t.rd = t.sk.readable.getReader({mode: "byob"}), t.wr = t.sk.writable.getWriter();
            try {
                const a = et(t.cr, t.sn, {p256: e.pk, x25519: r.pk}, {sessionId: t.id});
                t.rh(a), await t.wr.write(M(22, a, 769));
                const n = await t.rsh();
                if (n.isTls13) {
                    const s = n.ks?.group === 29 ? "X25519" : n.ks?.group === 23 ? "P-256" : null, c = t.kp.get(n.ks?.group);
                    if (!s || !n.ks?.key?.length || !c) throw new Error;
                    const l = t.cc.hash, h = X(l), {keyLen: w, ivLen: k} = t.cc, p = await Y(c.kp.privateKey, n.ks.key, s), v = await E(l, await z(l, null, new Uint8Array(h)), "derived", await K(l, g), h);
                    t.hs = await z(l, v, p);
                    const U = await K(l, t.ts()), f = await E(l, t.hs, "c hs traffic", U, h), P = await E(l, t.hs, "s hs traffic", U, h);
                    [t.ch, t.ci] = await T(l, f, w, k, "encrypt"), [t.sh, t.si] = await T(l, P, w, k, "decrypt");
                    let m = !1;
                    await t.pr(async u => {
                        if (u.type === 20 || u.type === 22) return;
                        if (u.type === 21) {
                            if (G(u.fragment)) return;
                            throw new Error
                        }
                        if (u.type !== 23) return;
                        const {data: nt, type: at} = Z(await O(t.sh, B(t.si, t.fs()), u.fragment, R(u.fragment.length)));
                        if (at === 22) {
                            t.hp.feed(nt);
                            for (let I; I = t.hp.next();) if (t.rh(I.raw), I.type === 13) m = !0; else if (I.type === 20) return 1
                        }
                    });
                    const C = await K(l, t.ts()), x = await E(l, t.hs, "derived", await K(l, g), h), H = await z(l, x, new Uint8Array(h));
                    t.as = await E(l, H, "c ap traffic", C, h), t.bs = await E(l, H, "s ap traffic", C, h), [t.ak, t.ai] = await T(l, t.as, w, k, "encrypt"), [t.bk, t.bi] = await T(l, t.bs, w, k, "decrypt");
                    let S = g;
                    m && (S = L(11, [0, 0, 0, 0]), t.rh(S));
                    const J = await E(l, f, "finished", g, h), j = L(20, await D(l, J, await K(l, t.ts())));
                    t.rh(j);
                    const o = d(S, j, [22]);
                    await t.wr.write(d(M(20, [1]), M(23, await N(t.ch, B(t.ci, t.fc()), o, R(o.length + 16))))), t.cn = t.qn = 0
                } else {
                    let s = null, c = !1, l = !1;
                    const h = async o => {
                        if (t.rh(o.raw), o.type === 12) {
                            s = {nc: A(o.body, 1), spk: o.body.subarray(4, 4 + o.body[3])};
                        } else {
                            if (o.type === 14) return c = !0, 1;
                            o.type === 13 && (l = !0)
                        }
                    };
                    let w = !1;
                    for (let o; o = t.hp.next();) if (await h(o)) {
                        w = !0;
                        break
                    }
                    if (!w) {
                        for (let o; o = t.rp.next();) if (o.type === 22) {
                            t.hp.feed(o.fragment);
                            for (let u; u = t.hp.next();) if (await h(u)) {
                                w = !0;
                                break
                            }
                            if (w) break
                        }
                    }
                    if (w || await t.pr(async o => {
                        if (o.type === 21) {
                            if (G(o.fragment)) return;
                            throw new Error
                        }
                        if (o.type === 20) throw new Error;
                        if (o.type === 22) {
                            t.hp.feed(o.fragment);
                            for (let u; u = t.hp.next();) if (await h(u)) return 1
                        }
                    }), !c || !s) {
                        throw new Error;
                    }
                    const k = s.nc === 29 ? "X25519" : s.nc === 23 ? "P-256" : null, p = t.kp.get(s.nc);
                    if (!k || !p) throw new Error;
                    let v = g;
                    if (l) {
                        const o = L(11, [0, 0, 0]);
                        t.rh(o), v = M(22, o)
                    }
                    const U = await Y(p.kp.privateKey, s.spk, k), f = L(16, d([p.pk.length], p.pk));
                    t.rh(f);
                    const P = t.cc.hash;
                    t.ms = await F(U, "master secret", d(t.cr, t.sr), 48, P);
                    const {keyLen: m, ivLen: C} = t.cc, x = await F(t.ms, "key expansion", d(t.sr, t.cr), 2 * m + 2 * C, P);
                    [t.ck, t.wk] = await Promise.all([W(x.subarray(0, m), "encrypt"), W(x.subarray(m, 2 * m), "decrypt")]), t.cv = x.subarray(2 * m, 2 * m + C), t.wv = x.subarray(2 * m + C, 2 * m + 2 * C);
                    const H = await F(t.ms, "client finished", await K(P, t.ts()), 12, P), S = L(20, H);
                    t.rh(S);
                    const J = await t.e12(S, 22);
                    await t.wr.write(d(v, M(22, f), M(20, [1]), M(22, J)));
                    let j = !1;
                    await t.pr(async o => {
                        if (o.type === 21) {
                            if (G(o.fragment)) return;
                            throw new Error
                        }
                        if (o.type === 20) return void (j = !0);
                        if (o.type === 22 && j) {
                            t.hp.feed(await t.d12(o.fragment, 22));
                            for (let u; u = t.hp.next();) if (u.type === 20) return 1
                        }
                    })
                }
                t.hc = !0, t.cr = t.id = t.sr = t.ms = t.hs = t.ch = t.sh = t.ci = t.si = null, t.kp.clear(), t.kp = null
            } finally {
                if (!t.hc || t.fl) {
                    try {t.rd?.releaseLock()} catch {}
                    try {t.wr?.releaseLock()} catch {}
                }
            }
        }
        async rsh() {
            const t = this;
            for (; ;) {
                const {value: e, done: r} = await t.rc();
                if (r) throw new Error;
                t.rp.feed(e);
                for (let a; a = t.rp.next();) {
                    if (a.type === 21) {
                        if (G(a.fragment)) continue;
                        throw new Error
                    }
                    if (a.type !== 20 && a.type === 22) {
                        t.hp.feed(a.fragment);
                        for (let n; n = t.hp.next();) {
                            if (n.type !== 2) continue;
                            t.rh(n.raw);
                            let s = 2;
                            const c = A(n.body, 0), l = n.body.slice(s, s += 32), h = n.body[s++], w = n.body.subarray(s, s += h), k = A(n.body, s);
                            s += 2;
                            const p = n.body[s++];
                            let v = c, U = null;
                            if (s < n.body.length) {
                                const m = s + 2 + A(n.body, s);
                                for (s += 2; s + 4 <= m;) {
                                    const C = A(n.body, s), x = A(n.body, s + 2), H = n.body.subarray(s += 4, s += x);
                                    C === 43 && x >= 2 ? v = A(H, 0) : C === 51 && x >= 2 && (U = {group: A(H, 0), key: x >= 4 ? H.subarray(4, 4 + A(H, 2)) : g})
                                }
                            }
                            const f = {version: c, sr: l, sid: w, cs: k, comp: p, sv: v, ks: U, isTls13: v === 772}, P = f.cs === 4866 || f.cs === 49200 || f.cs === 49196;
                            if (!P && f.cs !== 4865 && f.cs !== 49199 && f.cs !== 49195 || p !== 0 || f.cs < 49e3 !== f.isTls13 || !f.isTls13 && f.sv !== 771) throw new Error;
                            return t.sr = f.sr, t.cs = f.cs, t.cc = {keyLen: P ? 32 : 16, ivLen: f.isTls13 ? 12 : 4, hash: P ? "SHA-384" : "SHA-256", tls13: f.isTls13}, t.i3 = f.isTls13, f
                        }
                    }
                }
            }
        }
        async e12(t, e, r = this.fc()) {
            const a = tt(r), n = new Uint8Array(12);
            n.set(this.cv), n.set(a, 4);
            const s = new Uint8Array(13);
            s.set(a), s[8] = e, s[9] = 3, s[10] = 3, s[11] = t.length >> 8, s[12] = t.length & 255;
            const c = await N(this.ck, n, t, s), l = new Uint8Array(8 + c.length);
            return l.set(a), l.set(c, 8), l
        }
        async d12(t, e, r = this.fs()) {
            const a = t.subarray(0, 8), n = t.subarray(8), s = new Uint8Array(12);
            s.set(this.wv), s.set(a, 4);
            const c = new Uint8Array(13), l = r >>> 0, h = n.length - 16;
            if (c[7] = l & 255, c[6] = l >>> 8 & 255, c[5] = l >>> 16 & 255, c[4] = l >>> 24, r > 4294967295) {
                const w = Math.floor(r / 4294967296) >>> 0;
                c[3] = w & 255, c[2] = w >>> 8 & 255, c[1] = w >>> 16 & 255, c[0] = w >>> 24
            }
            return c[8] = e, c[9] = 3, c[10] = 3, c[11] = h >> 8, c[12] = h & 255, O(this.wk, s, n, c)
        }
        async e13(t, e = this.fc(), r = 23) {
            const a = new Uint8Array(t.length + 1);
            return a.set(t), a[t.length] = r, N(this.ak, B(this.ai, e), a, R(a.length + 16))
        }
        async d13(t, e = this.fs(), r = this.bk, a = this.bi) {return Z(await O(r, B(a, e), t, R(t.length)))}
        write(t) {
            const e = this;
            if (!e.hc || e.fl || e.cg) return Promise.reject(new Error);
            const r = t instanceof Uint8Array ? t.slice() : new Uint8Array(t);
            if (!r.length) return Promise.resolve();
            const a = e.wq.then(async () => {
                if (e.fl || e.cg) throw new Error;
                if (r.length <= 16384) return e.wr.write(M(23, e.i3 ? await e.e13(r) : await e.e12(r, 23)));
                for (let s = 0; s < r.length;) {
                    const c = [];
                    for (let l = 0; l < 8 && s < r.length; l++, s += 16384) {
                        const h = r.subarray(s, Math.min(s + 16384, r.length)), w = e.fc();
                        c.push(e.i3 ? e.e13(h, w) : e.e12(h, 23, w))
                    }
                    await e.wr.write($(await Promise.all(c)))
                }
            }), n = a.catch(s => {throw e.fail(), s});
            return e.wq = n.catch(() => {}), n
        }
        read() {
            const t = this;
            return t.fl || !t.hc ? Promise.reject(new Error) : (async () => {
                for (; ;) {
                    if (t.pq.length) return t.pq.length === 1 ? t.pq.pop() : d(...t.pq.splice(0));
                    if (t.cl) return null;
                    const e = [];
                    for (let n; e.length < 8 && (n = t.rp.next());) if (!(t.i3 ? n.type === 20 : ![21, 22, 23].includes(n.type))) {
                        if (t.i3 && n.type !== 23) throw new Error;
                        e.push(n)
                    }
                    if (e.length) {
                        if (t.i3) {
                            const n = t.qn, s = t.bk, c = t.bi;
                            let l;
                            try {l = await Promise.all(e.map((h, w) => t.d13(h.fragment, n + w, s, c)))} catch {}
                            if (l) {
                                t.qn = n + l.length;
                                for (const h of l) await t.p13(h)
                            } else {
                                for (let h = 0; h < e.length; h++) await t.p13(await t.d13(e[h].fragment, t.qn++))
                            }
                        } else {
                            const n = t.qn, s = await Promise.all(e.map((c, l) => t.d12(c.fragment, c.type, n + l)));
                            t.qn = n + e.length;
                            for (let c = 0; c < s.length; c++) {
                                const l = s[c], h = e[c].type;
                                if (h === 23) t.pq.push(l); else if (h === 21) t.pa(l); else if (h === 22) for (t.hp.feed(l); t.hp.next();) ;
                            }
                        }
                        if (t.pq.length) return t.pq.length === 1 ? t.pq.pop() : d(...t.pq.splice(0));
                        if (t.cl) return null;
                        continue
                    }
                    if (t.cl) return null;
                    const {value: r, done: a} = await t.rc();
                    if (a) return null;
                    t.rp.feed(r)
                }
            })().catch(e => {throw t.fail(), e})
        }
        pa(t) {
            const e = this;
            if (e.cl = !0, t && t.length >= 2) {
                const r = t[0], a = t[1];
                if (r === 2 || r === 1 && a !== 0) throw e.fail(), new Error
            }
            e.close()
        }
        async p13({data: t, type: e}) {
            if (e === 23) {
                this.pq.push(t);
            } else if (e === 21) {
                this.pa(t);
            } else if (e === 22) {
                this.hp.feed(t);
                for (let r; r = this.hp.next();) r.type === 24 && (await this.uv(), r.body[0] === 1 && await this.su(0))
            }
        }
        async uk() {
            const t = this, e = t.cc.hash, r = X(e), {keyLen: a, ivLen: n} = t.cc;
            t.as = await E(e, t.as, "traffic upd", g, r), [t.ak, t.ai] = await T(e, t.as, a, n, "encrypt"), t.cn = 0
        }
        async uv() {
            const t = this, e = t.cc.hash, r = X(e), {keyLen: a, ivLen: n} = t.cc;
            t.bs = await E(e, t.bs, "traffic upd", g, r), [t.bk, t.bi] = await T(e, t.bs, a, n, "decrypt"), t.qn = 0
        }
        su(t = 0) {
            const e = this;
            if (!e.hc || e.fl || e.cg) return Promise.reject(new Error);
            const r = e.wq.then(async () => {
                if (e.fl || e.cg) throw new Error;
                const n = L(24, [t]);
                await e.wr.write(M(23, await e.e13(n, e.fc(), 22))), await e.uk()
            }), a = r.catch(n => {throw e.fail(), n});
            return e.wq = a.catch(() => {}), a
        }
        close() {
            const t = this;
            return t.cp ? t.cp : t.fl || !t.hc ? (t.sk?.close(), t.cp = Promise.resolve()) : (t.cg = !0, t.wq = t.cp = t.wq.then(async () => {
                const e = new Uint8Array([1, 0]), r = t.i3 ? await t.e13(e, t.fc(), 21) : await t.e12(e, 21);
                await t.wr.write(M(t.i3 ? 23 : 21, r))
            }).catch(() => {}).finally(() => {t.cl = !0, t.sk?.close()}))
        }
    }
    return {TlsClient: rt}
})();
