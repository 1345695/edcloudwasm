export const {TlsClient} = (() => {
    const b = crypto.subtle, V = new TextEncoder, g = new Uint8Array(0), f = s => [s >> 8, s & 255], A = (s, t) => s[t] << 8 | s[t + 1], E = (...s) => {
            const t = a => {
                let i = 0;
                for (let c = 0; c < a.length; c++) {
                    const l = a[c];
                    i += l instanceof Uint8Array ? l.length : Array.isArray(l) ? t(l) : 1
                }
                return i
            }, e = new Uint8Array(t(s));
            let r = 0;
            const n = a => {
                for (let i = 0; i < a.length; i++) {
                    const c = a[i];
                    c instanceof Uint8Array ? (e.set(c, r), r += c.length) : Array.isArray(c) ? n(c) : e[r++] = c
                }
            };
            return n(s), e
        }, d = (...s) => {
            const t = new Uint8Array(s.reduce((r, n) => r + (n?.length || 0), 0));
            let e = 0;
            for (const r of s) r?.length && (t.set(r, e), e += r.length);
            return t
        }, D = s => s === "SHA-384" ? 48 : 32, G = s => s?.[0] === 1 && s[1] === 112, X = async (s, t, e) => new Uint8Array(await b.sign("HMAC", t.type ? t : await b.importKey("raw", t, {name: "HMAC", hash: s}, !1, ["sign"]), e)), K = async (s, t) => new Uint8Array(await b.digest(s, t)), W = (s, t) => b.importKey("raw", s, {name: "AES-GCM"}, !1, [t]), J = async (s, t, e, r) => new Uint8Array(await b.encrypt({name: "AES-GCM", iv: t, additionalData: r}, s, e)),
        N = async (s, t, e, r) => new Uint8Array(await b.decrypt({name: "AES-GCM", iv: t, additionalData: r}, s, e)), P = (s, t, e = 771, r = t.length) => {
            const n = new Uint8Array(5 + r);
            return n[0] = s, n[1] = e >> 8, n[2] = e & 255, n[3] = r >> 8, n[4] = r & 255, n.set(t, 5), n
        }, $ = (s, t = 23) => {
            let e = 0;
            for (let a = 0; a < s.length; a++) e += 5 + s[a].length;
            const r = new Uint8Array(e);
            let n = 0;
            for (let a = 0; a < s.length; a++) {
                const i = s[a], c = i.length;
                r[n] = t, r[n + 1] = 3, r[n + 2] = 3, r[n + 3] = c >> 8, r[n + 4] = c & 255, r.set(i, n + 5), n += 5 + c
            }
            return r
        }, L = (s, t, e = t.length) => {
            const r = new Uint8Array(4 + e);
            return r[0] = s, r[1] = e >> 16 & 255, r[2] = e >> 8 & 255, r[3] = e & 255, r.set(t, 4), r
        }, R = s => new Uint8Array([23, 3, 3, s >> 8, s & 255]), z = (s, t, e) => X(s, t?.length ? t : new Uint8Array(D(s)), e), F = async (s, t, e, r, n = "SHA-256") => {
            const a = d(V.encode(t), e), i = s.type ? s : await b.importKey("raw", s, {name: "HMAC", hash: n}, !1, ["sign"]);
            let c = g, l = a;
            for (; c.length < r;) l = await X(n, i, l), c = d(c, await X(n, i, d(l, a)));
            return c.slice(0, r)
        }, q = async (s, t, e, r, n) => {
            const a = typeof e == "string" ? V.encode("tls13 " + e) : e, i = D(s), c = a.length, l = r.length, h = new Uint8Array(4 + c + l);
            h[0] = n >> 8, h[1] = n & 255, h[2] = c, h.set(a, 3), h[3 + c] = l, l && h.set(r, 4 + c);
            const w = t.type ? t : await b.importKey("raw", t, {name: "HMAC", hash: s}, !1, ["sign"]);
            let k = g, p = g;
            for (let U = 1; U <= Math.ceil(n / i); U++) {
                const v = new Uint8Array(p.length + h.length + 1);
                p.length && v.set(p), v.set(h, p.length), v[p.length + h.length] = U, p = await X(s, w, v), k = d(k, p)
            }
            return k.slice(0, n)
        }, Q = async (s = "P-256") => {
            const t = s === "X25519", e = await b.generateKey(t ? {name: s} : {name: "ECDH", namedCurve: s}, !0, ["deriveBits"]);
            return {kp: e, pk: new Uint8Array(await b.exportKey("raw", e.publicKey))}
        }, Y = async (s, t, e = "P-256") => {
            const r = e === "X25519", n = await b.importKey("raw", t, r ? {name: e} : {name: "ECDH", namedCurve: e}, !1, []);
            return new Uint8Array(await b.deriveBits({name: r ? e : "ECDH", public: n}, s, 256))
        }, tt = (s, t, e, {sessionId: r = g} = {}) => {
            const n = E(...[4865, 4866, 49199, 49200, 49195, 49196].flatMap(f)), a = [E(255, 1, 0, 1, 0)];
            if (t) {
                const l = V.encode(t);
                a.push(E(0, 0, f(l.length + 5), f(l.length + 3), 0, f(l.length), l))
            }
            const i = d(E(0, 29, f(e.x25519.length), e.x25519), E(0, 23, f(e.p256.length), e.p256));
            a.push(E(f(11), 0, 2, 1, 0), E(f(10), 0, 6, 0, 4, 0, 29, 0, 23), E(f(13), 0, 34, 0, 32, ...[2052, 2053, 2054, 2055, 2056, 2057, 2058, 2059, 1027, 1283, 1539, 1025, 1281, 1537, 513, 515].flatMap(f)), E(f(43), 0, 5, 4, 3, 4, 3, 3), E(f(51), f(i.length + 2), f(i.length), i));
            const c = d(...a);
            return L(1, E(f(771), s, r.length, r, f(n.length), n, 1, 0, f(c.length), c))
        }, T = async (s, t, e, r, n) => {
            const a = t.type ? t : await b.importKey("raw", t, {name: "HMAC", hash: s}, !1, ["sign"]), [i, c] = await Promise.all([q(s, a, "key", g, e), q(s, a, "iv", g, r)]);
            return [await W(i, n), c]
        }, Z = s => {
            let t = s.length - 1;
            for (; t >= 0 && !s[t];) t--;
            if (t < 0) throw new Error;
            return {data: s.subarray(0, t), type: s[t]}
        }, B = (s, t) => {
            const e = s.slice(), r = t >>> 0, n = t / 4294967296 >>> 0, a = e.length - 8;
            return e[a] ^= n >>> 24, e[a + 1] ^= n >>> 16, e[a + 2] ^= n >>> 8, e[a + 3] ^= n, e[a + 4] ^= r >>> 24, e[a + 5] ^= r >>> 16, e[a + 6] ^= r >>> 8, e[a + 7] ^= r, e
        };
    class _ {
        constructor(t, e, r) {this.b = new Uint8Array(t), this.h = this.t = 0, this.l = e, this.g = r}
        feed(t) {
            const e = this;
            if (e.t + t.length > e.b.length) {
                const r = e.t - e.h, n = r + t.length > e.b.length, a = n ? new Uint8Array(Math.max(e.b.length * 2, r + t.length)) : e.b;
                n ? a.set(e.b.subarray(e.h, e.t)) : a.copyWithin(0, e.h, e.t), e.b = a, e.t = r, e.h = 0
            }
            e.b.set(t, e.t), e.t += t.length
        }
        next() {
            const t = this;
            if (t.t - t.h < t.l) return null;
            const e = t.g(t.b, t.h);
            if (t.l === 5 && e > 18432) throw new Error;
            if (t.t - t.h < t.l + e) return null;
            const r = t.b.subarray(t.h, t.h += t.l + e), n = r.subarray(t.l);
            return t.h === t.t && (t.h = t.t = 0), {type: r[0], version: t.l === 5 ? A(r, 1) : 0, length: e, body: n, fragment: n, raw: r}
        }
    }
    class et {
        constructor(t, e = {}) {
            const r = this;
            r.sk = t, r.sn = e.serverName || "", r.cr = crypto.getRandomValues(new Uint8Array(32)), r.id = crypto.getRandomValues(new Uint8Array(32)), r.hb = new Uint8Array(8192), r.hl = 0, r.cn = 0, r.qn = 0, r.rp = new _(32768, 5, (n, a) => A(n, a + 3)), r.hp = new _(4096, 4, (n, a) => n[a + 1] << 16 | A(n, a + 2)), r.kp = new Map, r.pq = [], r.wq = Promise.resolve(), r.rb = new Uint8Array(65536), r.rd = null, r.wr = null, r.fl = !1, r.cl = !1, r.cg = !1, r.hc = !1, r.cp = null, r.i3 = !1, r.cs = null, r.cc = null, r.sr = null, r.hs = null, r.ch = null, r.ci = null, r.sh = null, r.si = null, r.ak = null, r.ai = null, r.bk = null, r.bi = null, r.ms = null, r.ck = null, r.wk = null, r.cv = null, r.wv = null, r.as = null, r.bs = null
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
                for (let a; a = e.rp.next();) if (await t(a)) return;
                const {value: r, done: n} = await e.rc();
                if (n) throw new Error;
                e.rp.feed(r)
            }
        }
        async handshake() {
            const t = this, [e, r] = await Promise.all([Q("P-256"), Q("X25519")]);
            t.kp = new Map([[23, e], [29, r]]), t.rd = t.sk.readable.getReader({mode: "byob"}), t.wr = t.sk.writable.getWriter();
            try {
                const n = tt(t.cr, t.sn, {p256: e.pk, x25519: r.pk}, {sessionId: t.id});
                t.rh(n), await t.wr.write(P(22, n, 769));
                const a = await t.rsh();
                if (a.isTls13) {
                    const i = a.ks?.group === 29 ? "X25519" : a.ks?.group === 23 ? "P-256" : null, c = t.kp.get(a.ks?.group);
                    if (!i || !a.ks?.key?.length || !c) throw new Error;
                    const l = t.cc.hash, h = D(l), {keyLen: w, ivLen: k} = t.cc, p = await Y(c.kp.privateKey, a.ks.key, i), U = await q(l, await z(l, null, new Uint8Array(h)), "derived", await K(l, g), h);
                    t.hs = await z(l, U, p);
                    const v = await K(l, t.ts()), y = await q(l, t.hs, "c hs traffic", v, h), C = await q(l, t.hs, "s hs traffic", v, h);
                    [t.ch, t.ci] = await T(l, y, w, k, "encrypt"), [t.sh, t.si] = await T(l, C, w, k, "decrypt");
                    let m = !1;
                    await t.pr(async u => {
                        if (u.type === 20 || u.type === 22) return;
                        if (u.type === 21) {
                            if (G(u.fragment)) return;
                            throw new Error
                        }
                        if (u.type !== 23) return;
                        const {data: rt, type: nt} = Z(await N(t.sh, B(t.si, t.fs()), u.fragment, R(u.fragment.length)));
                        if (nt === 22) {
                            t.hp.feed(rt);
                            for (let I; I = t.hp.next();) if (t.rh(I.raw), I.type === 13) m = !0; else if (I.type === 20) return 1
                        }
                    });
                    const M = await K(l, t.ts()), x = await q(l, t.hs, "derived", await K(l, g), h), H = await z(l, x, new Uint8Array(h));
                    t.as = await q(l, H, "c ap traffic", M, h), t.bs = await q(l, H, "s ap traffic", M, h), [t.ak, t.ai] = await T(l, t.as, w, k, "encrypt"), [t.bk, t.bi] = await T(l, t.bs, w, k, "decrypt");
                    let S = g;
                    m && (S = L(11, new Uint8Array(4)), t.rh(S));
                    const O = await q(l, y, "finished", g, h), j = L(20, await X(l, O, await K(l, t.ts())));
                    t.rh(j);
                    const o = d(S, j, new Uint8Array([22]));
                    await t.wr.write(d(P(20, new Uint8Array([1])), P(23, await J(t.ch, B(t.ci, t.fc()), o, R(o.length + 16))))), t.cn = t.qn = 0
                } else {
                    let i = null, c = !1, l = !1;
                    const h = async o => {
                        if (t.rh(o.raw), o.type === 12) {
                            i = {nc: A(o.body, 1), spk: o.body.subarray(4, 4 + o.body[3])};
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
                    }), !c || !i) {
                        throw new Error;
                    }
                    const k = i.nc === 29 ? "X25519" : i.nc === 23 ? "P-256" : null, p = t.kp.get(i.nc);
                    if (!k || !p) throw new Error;
                    let U = g;
                    if (l) {
                        const o = L(11, new Uint8Array(3));
                        t.rh(o), U = P(22, o)
                    }
                    const v = await Y(p.kp.privateKey, i.spk, k), y = L(16, d(new Uint8Array([p.pk.length]), p.pk));
                    t.rh(y);
                    const C = t.cc.hash;
                    t.ms = await F(v, "master secret", d(t.cr, t.sr), 48, C);
                    const {keyLen: m, ivLen: M} = t.cc, x = await F(t.ms, "key expansion", d(t.sr, t.cr), 2 * m + 2 * M, C);
                    [t.ck, t.wk] = await Promise.all([W(x.subarray(0, m), "encrypt"), W(x.subarray(m, 2 * m), "decrypt")]), t.cv = x.subarray(2 * m, 2 * m + M), t.wv = x.subarray(2 * m + M, 2 * m + 2 * M);
                    const H = await F(t.ms, "client finished", await K(C, t.ts()), 12, C), S = L(20, H);
                    t.rh(S);
                    const O = await t.e12(S, 22);
                    await t.wr.write(d(U, P(22, y), P(20, new Uint8Array([1])), P(22, O)));
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
                for (let n; n = t.rp.next();) {
                    if (n.type === 21) {
                        if (G(n.fragment)) continue;
                        throw new Error
                    }
                    if (n.type !== 20 && n.type === 22) {
                        t.hp.feed(n.fragment);
                        for (let a; a = t.hp.next();) {
                            if (a.type !== 2) continue;
                            t.rh(a.raw);
                            let i = 2;
                            const c = A(a.body, 0), l = a.body.slice(i, i += 32), h = a.body[i++], w = a.body.subarray(i, i += h), k = A(a.body, i);
                            i += 2;
                            const p = a.body[i++];
                            let U = c, v = null;
                            if (i < a.body.length) {
                                const m = i + 2 + A(a.body, i);
                                for (i += 2; i + 4 <= m;) {
                                    const M = A(a.body, i), x = A(a.body, i + 2), H = a.body.subarray(i += 4, i += x);
                                    M === 43 && x >= 2 ? U = A(H, 0) : M === 51 && x >= 2 && (v = {group: A(H, 0), key: x >= 4 ? H.subarray(4, 4 + A(H, 2)) : g})
                                }
                            }
                            const y = {version: c, sr: l, sid: w, cs: k, comp: p, sv: U, ks: v, isTls13: U === 772}, C = y.cs === 4866 || y.cs === 49200 || y.cs === 49196;
                            if (!C && y.cs !== 4865 && y.cs !== 49199 && y.cs !== 49195 || p !== 0 || y.cs < 49e3 !== y.isTls13 || !y.isTls13 && y.sv !== 771) throw new Error;
                            return t.sr = y.sr, t.cs = y.cs, t.cc = {keyLen: C ? 32 : 16, ivLen: y.isTls13 ? 12 : 4, hash: C ? "SHA-384" : "SHA-256", tls13: y.isTls13}, t.i3 = y.isTls13, y
                        }
                    }
                }
            }
        }
        async e12(t, e, r = this.fc()) {
            const n = new Uint8Array(13), a = r >>> 0, i = r / 4294967296 >>> 0;
            n[0] = i >>> 24, n[1] = i >>> 16, n[2] = i >>> 8, n[3] = i, n[4] = a >>> 24, n[5] = a >>> 16, n[6] = a >>> 8, n[7] = a, n[8] = e, n[9] = 3, n[10] = 3, n[11] = t.length >> 8, n[12] = t.length & 255;
            const c = n.subarray(0, 8), l = new Uint8Array(12);
            l.set(this.cv), l.set(c, 4);
            const h = await J(this.ck, l, t, n), w = new Uint8Array(8 + h.length);
            return w.set(c), w.set(h, 8), w
        }
        async d12(t, e, r = this.fs()) {
            const n = t.subarray(0, 8), a = t.subarray(8), i = new Uint8Array(12);
            i.set(this.wv), i.set(n, 4);
            const c = new Uint8Array(13), l = a.length - 16, h = r >>> 0, w = r / 4294967296 >>> 0;
            return c[0] = w >>> 24, c[1] = w >>> 16, c[2] = w >>> 8, c[3] = w, c[4] = h >>> 24, c[5] = h >>> 16, c[6] = h >>> 8, c[7] = h, c[8] = e, c[9] = 3, c[10] = 3, c[11] = l >> 8, c[12] = l & 255, N(this.wk, i, a, c)
        }
        async e13(t, e = this.fc(), r = 23) {
            const n = new Uint8Array(t.length + 1);
            return n.set(t), n[t.length] = r, J(this.ak, B(this.ai, e), n, R(n.length + 16))
        }
        async d13(t, e = this.fs(), r = this.bk, n = this.bi) {return Z(await N(r, B(n, e), t, R(t.length)))}
        write(t) {
            const e = this;
            if (!e.hc || e.fl || e.cg) return Promise.reject(new Error);
            const r = t instanceof Uint8Array ? t.slice() : new Uint8Array(t);
            if (!r.length) return Promise.resolve();
            const n = e.wq.then(async () => {
                if (e.fl || e.cg) throw new Error;
                if (r.length <= 16384) return e.wr.write(P(23, e.i3 ? await e.e13(r) : await e.e12(r, 23)));
                for (let i = 0; i < r.length;) {
                    const c = [];
                    for (let l = 0; l < 8 && i < r.length; l++, i += 16384) {
                        const h = r.subarray(i, Math.min(i + 16384, r.length)), w = e.fc();
                        c.push(e.i3 ? e.e13(h, w) : e.e12(h, 23, w))
                    }
                    await e.wr.write($(await Promise.all(c)))
                }
            }), a = n.catch(i => {throw e.fail(), i});
            return e.wq = a.catch(() => {}), a
        }
        read() {
            const t = this;
            return t.fl || !t.hc ? Promise.reject(new Error) : (async () => {
                for (; ;) {
                    if (t.pq.length) return t.pq.length === 1 ? t.pq.pop() : d(...t.pq.splice(0));
                    if (t.cl) return null;
                    const e = [];
                    for (let a; e.length < 8 && (a = t.rp.next());) if (!(t.i3 ? a.type === 20 : ![21, 22, 23].includes(a.type))) {
                        if (t.i3 && a.type !== 23) throw new Error;
                        e.push(a)
                    }
                    if (e.length) {
                        if (t.i3) {
                            const a = t.qn, i = t.bk, c = t.bi;
                            let l;
                            try {l = await Promise.all(e.map((h, w) => t.d13(h.fragment, a + w, i, c)))} catch {}
                            if (l) {
                                t.qn = a + l.length;
                                for (const h of l) await t.p13(h)
                            } else {
                                for (let h = 0; h < e.length; h++) await t.p13(await t.d13(e[h].fragment, t.qn++))
                            }
                        } else {
                            const a = t.qn, i = await Promise.all(e.map((c, l) => t.d12(c.fragment, c.type, a + l)));
                            t.qn = a + e.length;
                            for (let c = 0; c < i.length; c++) {
                                const l = i[c], h = e[c].type;
                                if (h === 23) t.pq.push(l); else if (h === 21) t.pa(l); else if (h === 22) for (t.hp.feed(l); t.hp.next();) ;
                            }
                        }
                        if (t.pq.length) return t.pq.length === 1 ? t.pq.pop() : d(...t.pq.splice(0));
                        if (t.cl) return null;
                        continue
                    }
                    if (t.cl) return null;
                    const {value: r, done: n} = await t.rc();
                    if (n) return null;
                    t.rp.feed(r)
                }
            })().catch(e => {throw t.fail(), e})
        }
        pa(t) {
            const e = this;
            if (e.cl = !0, t && t.length >= 2) {
                const r = t[0], n = t[1];
                if (r === 2 || r === 1 && n !== 0) throw e.fail(), new Error
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
            const t = this, e = t.cc.hash, r = D(e), {keyLen: n, ivLen: a} = t.cc;
            t.as = await q(e, t.as, "traffic upd", g, r), [t.ak, t.ai] = await T(e, t.as, n, a, "encrypt"), t.cn = 0
        }
        async uv() {
            const t = this, e = t.cc.hash, r = D(e), {keyLen: n, ivLen: a} = t.cc;
            t.bs = await q(e, t.bs, "traffic upd", g, r), [t.bk, t.bi] = await T(e, t.bs, n, a, "decrypt"), t.qn = 0
        }
        su(t = 0) {
            const e = this;
            if (!e.hc || e.fl || e.cg) return Promise.reject(new Error);
            const r = e.wq.then(async () => {
                if (e.fl || e.cg) throw new Error;
                const a = L(24, new Uint8Array([t]));
                await e.wr.write(P(23, await e.e13(a, e.fc(), 22))), await e.uk()
            }), n = r.catch(a => {throw e.fail(), a});
            return e.wq = n.catch(() => {}), n
        }
        close() {
            const t = this;
            return t.cp ? t.cp : t.fl || !t.hc ? (t.sk?.close(), t.cp = Promise.resolve()) : (t.cg = !0, t.wq = t.cp = t.wq.then(async () => {
                const e = new Uint8Array([1, 0]), r = t.i3 ? await t.e13(e, t.fc(), 21) : await t.e12(e, 21);
                await t.wr.write(P(t.i3 ? 23 : 21, r))
            }).catch(() => {}).finally(() => {t.cl = !0, t.sk?.close()}))
        }
    }
    return {TlsClient: et}
})();
