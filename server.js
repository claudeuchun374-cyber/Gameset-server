// GAMESET server — o'yin + xonalar + akkaunt + CL/Premium/baraban/buyurtma/admin
const http = require("http");
const fs = require("fs");
const path = require("path");
const nodeCrypto = require("crypto");
const { WebSocketServer } = require("ws");

const SB_URL = (process.env.SUPABASE_URL || "").replace(/\/$/, "");
const SB_KEY = process.env.SUPABASE_KEY || "";
const HAS_DB = !!(SB_URL && SB_KEY);

const PORT = process.env.PORT || 3000;
const MAX_PER_ROOM = 20;
const INDEX = path.join(__dirname, "index.html");

const rooms = new Map(); // xona kodi -> Set(ws)
let nextId = 1;


// ---------- Baza (Supabase) ----------
async function sb(pathq, opts = {}) {
  const r = await fetch(SB_URL + "/rest/v1/" + pathq, {
    ...opts,
    headers: { apikey: SB_KEY, ...(SB_KEY.startsWith("eyJ") ? { Authorization: "Bearer " + SB_KEY } : {}), "Content-Type": "application/json", ...(opts.headers || {}) },
  });
  const txt = await r.text();
  if (!r.ok) throw new Error("db " + r.status + " " + txt.slice(0, 200));
  return txt ? JSON.parse(txt) : null;
}
const enc = encodeURIComponent;
const sha = (x) => nodeCrypto.createHash("sha256").update(String(x)).digest("hex");
const TOP_FIELDS = new Set(["best", "count", "rb"]);

function readJson(req) {
  return new Promise((resolve, reject) => {
    let n = 0, chunks = [];
    req.on("data", (c) => { n += c.length; if (n > 400000) { reject(new Error("katta")); req.destroy(); } else chunks.push(c); });
    req.on("end", () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString() || "{}")); } catch (e) { reject(new Error("json")); } });
    req.on("error", reject);
  });
}

// o'yinchi ma'lumotini tozalash: raqamli maydonlar haqiqiy raqam bo'lishi shart
function cleanDoc(d) {
  if (!d || typeof d !== "object" || Array.isArray(d)) throw new Error("data");
  const ALLOW = ["name","g","best","last","count","lv","xp","rb","tr","trTot","pets","ep","eq","eggs","auto","e3f","spk","spa","tails","tail","maxCp","rs","upd"];
  const o = {};
  for (const k of ALLOW) if (k in d) o[k] = d[k];
  for (const k of ["best", "count", "rb"]) {
    if (k in o && !(typeof o[k] === "number" && Number.isFinite(o[k]) && o[k] >= 0 && o[k] < 1e12)) delete o[k];
  }
  if (typeof o.name === "string") o.name = o.name.slice(0, 16);
  if (JSON.stringify(o).length > 20000) throw new Error("katta");
  return o;
}

const same = (x, y) => { const p = Buffer.from(String(x || "")), q = Buffer.from(String(y || "")); return p.length === q.length && nodeCrypto.timingSafeEqual(p, q); };

async function checkAuth(uid, secret) {
  if (!/^u[a-f0-9]{16}$/.test(uid) || !/^[a-f0-9]{32}$/.test(secret)) return false;
  const h = sha(secret);
  const rows = await sb("docs?collection=eq.auth&id=eq." + enc(uid) + "&select=data");
  if (rows.length === 0) {
    await sb("docs?on_conflict=collection,id", {
      method: "POST",
      headers: { Prefer: "resolution=ignore-duplicates" },
      body: JSON.stringify({ collection: "auth", id: uid, data: { h } }),
    });
    const again = await sb("docs?collection=eq.auth&id=eq." + enc(uid) + "&select=data");
    return again.length === 1 && same(again[0].data.h, h);
  }
  const d = rows[0].data || {};
  return same(d.h, h) || (Array.isArray(d.hs) && d.hs.some((x) => same(x, h)));
}

// ---------- login: nom + parol (parol scrypt bilan xeshlanadi, ochiq saqlanmaydi) ----------
const scrypt = (pw, salt) => new Promise((res, rej) => nodeCrypto.scrypt(pw, salt, 32, (e, k) => (e ? rej(e) : res(k))));
const tries = new Map(); // kalit -> [vaqtlar]
function blocked(key, max) {
  const now = Date.now();
  const a = (tries.get(key) || []).filter((t) => now - t < 600000);
  tries.set(key, a);
  return a.length >= max;
}
const addTry = (key) => tries.set(key, [...(tries.get(key) || []), Date.now()]);
const putDoc = (collection, id, data, prefer) =>
  sb("docs?on_conflict=collection,id", {
    method: "POST",
    headers: { Prefer: prefer || "resolution=merge-duplicates" },
    body: JSON.stringify({ collection, id, data, updated_at: new Date().toISOString() }),
  });
const getDoc = async (collection, id) => {
  const r = await sb("docs?collection=eq." + collection + "&id=eq." + enc(id) + "&select=data");
  return r[0] ? r[0].data : null;
};

async function register(body) {
  const uid = String(body.uid || "");
  if (!(await checkAuth(uid, String(body.secret || "")))) return [403, { error: "akkaunt tasdiqlanmadi" }];
  const un = String(body.username || ""), pw = String(body.password || "");
  if (!/^[A-Za-z0-9_]{3,16}$/.test(un)) return [400, { error: "Nom 3-16 ta lotin harf, raqam yoki _ bo'lsin" }];
  if (pw.length < 6 || pw.length > 64) return [400, { error: "Parol 6-64 belgi bo'lsin" }];
  if (await getDoc("uname", uid)) return [409, { error: "Bu akkaunt allaqachon ro'yxatdan o'tgan" }];
  const salt = nodeCrypto.randomBytes(16).toString("hex");
  const ph = (await scrypt(pw, salt)).toString("hex");
  await putDoc("login", un.toLowerCase(), { uid, salt, ph }, "resolution=ignore-duplicates");
  const mine = await getDoc("login", un.toLowerCase());
  if (!mine || mine.uid !== uid || mine.ph !== ph) return [409, { error: "Bu nom band, boshqasini tanlang" }];
  await putDoc("uname", uid, { un });
  return [200, { ok: true }];
}

async function login(body, ip) {
  const un = String(body.username || "").toLowerCase(), pw = String(body.password || "");
  if (!/^[a-z0-9_]{3,16}$/.test(un) || pw.length < 1 || pw.length > 64) return [403, { error: "Nom yoki parol noto'g'ri" }];
  const k1 = "u|" + un + "|" + ip, k2 = "i|" + ip;
  if (blocked(k1, 6) || blocked(k2, 30)) return [429, { error: "Juda ko'p urinish. 10 daqiqadan keyin qayta urinib ko'ring" }];
  const rec = await getDoc("login", un);
  const salt = rec ? rec.salt : "00".repeat(16);
  const ph = (await scrypt(pw, salt)).toString("hex");
  if (!rec || !same(rec.ph, ph)) { addTry(k1); addTry(k2); return [403, { error: "Nom yoki parol noto'g'ri" }]; }
  tries.delete(k1);
  const secret = nodeCrypto.randomBytes(16).toString("hex"); // shu qurilma uchun yangi kalit
  const cur = (await getDoc("auth", rec.uid)) || {};
  const hs = [...(Array.isArray(cur.hs) ? cur.hs : []), sha(secret)].slice(-5);
  await putDoc("auth", rec.uid, { h: cur.h || "", hs });
  return [200, { uid: rec.uid, secret }];
}


// ---------- 3-qadam: CL, Premium, baraban, buyurtmalar, admin (hamma qoida SERVERDA tekshiriladi) ----------
const ADMIN_USER = (process.env.ADMIN_USER || "jahongir").toLowerCase(); // shu nom bilan ro'yxatdan o'tgan akkaunt = admin
const ADMIN_NICK = process.env.ADMIN_NICK || "JAHONGIR";
const PACKS = [[40, 5000], [80, 10000], [200, 25000], [400, 50000]]; // [CL, so'm]
const PLANS = { m1: [1, 40000], m3: [3, 100000], y1: [12, 350000] }; // [oy, so'm]
const DAY = 864e5;
const DB_COLS = new Set(["config", "users", "ledger", "orders", "omsgs", "wheel", "wlog", "alog"]);
const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const ORDER_ST = new Set(["new", "awaiting", "receipt", "confirmed", "rejected"]);

let chain = Promise.resolve(); // yozuvlar ketma-ket bajariladi (balans bo'yicha poyga bo'lmasin)
const serial = (fn) => { const p = chain.then(fn, fn); chain = p.catch(() => {}); return p; };

let adminCache = { t: 0, uid: "" };
async function adminUid() {
  if (Date.now() - adminCache.t < 20000) return adminCache.uid;
  const rec = await getDoc("login", ADMIN_USER);
  adminCache = { t: Date.now(), uid: rec ? String(rec.uid) : "" };
  return adminCache.uid;
}
async function rowsBy(col, field, val, limit) {
  const r = await sb("docs?collection=eq." + col + "&data->>" + field + "=eq." + enc(val) + "&select=id,data&limit=" + limit);
  return r.map((x) => ({ id: x.id, data: x.data }));
}
const calcBal = (rows) => { let cl = 0; for (const r of rows) if (r.cur === "cl") cl += (r.type === "grant" ? 1 : -1) * (+r.amt || 0); return Math.max(0, Math.round(cl)); };
const int = (v, a, b) => Number.isInteger(v) && v >= a && v <= b;
const str = (v, n) => String(v == null ? "" : v).slice(0, n);
const bad = (m) => [400, { error: m || "noto'g'ri so'rov" }];

async function configData() {
  const c = (await getDoc("config", "app")) || {};
  return { ...c, adminUid: await adminUid(), adminNick: c.adminNick || ADMIN_NICK, firstPlayerId: "100001" };
}

async function playerApi(b) {
  const uid = String(b.uid || "");
  if (!(await checkAuth(uid, String(b.secret || "")))) return [403, { error: "akkaunt tasdiqlanmadi" }];
  return serial(async () => {
    const admin = (await adminUid()) === uid;
    const cfg = (await getDoc("config", "app")) || {};
    const u = (await getDoc("users", uid)) || {};
    const nick = str(b.nick || "Player", 16), g = str(b.g, 8);
    let playerId = String(u.playerId || "");
    let next = Math.max(100002, Number(cfg.nextId) || 100002); // faqat raqamli ID: admin 100001, qolganlar 100002 dan
    if (admin) playerId = "100001";
    else if (u.idVersion !== 3 || !/^\d{6,9}$/.test(playerId) || playerId === "100001") { playerId = String(next); next++; }
    const old = Array.isArray(u.old) ? u.old.slice(0, 8) : [];
    if (u.nick && u.nick !== nick && !old.includes(u.nick)) old.unshift(u.nick);
    await putDoc("config", "app", { ...cfg, nextId: next, firstPlayerId: "100001", updatedAt: Date.now() });
    await putDoc("users", uid, { nick, g, playerId, idVersion: 3, role: admin ? "admin" : "player", old: old.slice(0, 8), upd: Date.now() });
    return [200, { adminUid: await adminUid(), adminNick: cfg.adminNick || ADMIN_NICK, playerId, firstPlayerId: "100001" }];
  });
}

async function dbApi(b) {
  const col = String(b.collection || ""), op = String(b.op || "");
  if (!DB_COLS.has(col)) return [403, { error: "ruxsat yo'q" }];
  const id = b.id == null ? "" : String(b.id);
  if (op === "get" && col === "config" && id === "app") return [200, { data: await configData() }];
  const uid = String(b.uid || "");
  if (!(await checkAuth(uid, String(b.secret || "")))) return [403, { error: "akkaunt tasdiqlanmadi" }];
  const admin = uid !== "" && (await adminUid()) === uid;
  if (op !== "get" && op !== "query" && blocked("db|" + uid, 400)) return [429, { error: "juda ko'p so'rov" }];

  if (op === "get") {
    if (!ID_RE.test(id)) return bad("id");
    const d = await getDoc(col, id);
    if (!d) return [200, { data: null }];
    const own = col === "config" ? false : col === "users" || col === "wheel" ? id === uid : d.uid === uid;
    if (col === "omsgs" || col === "wlog" || col === "alog") { if (!admin) return [403, { error: "ruxsat yo'q" }]; }
    else if (!admin && !own) return [403, { error: "ruxsat yo'q" }];
    return [200, { data: d }];
  }

  if (op === "query") {
    const lim = Math.max(1, Math.min(1000, parseInt(b.limit) || 100));
    const w = Array.isArray(b.where) ? b.where.filter((x) => Array.isArray(x) && x[1] === "==") : [];
    if (w.length) {
      const [f, , v] = w[0];
      if (f === "uid" && ["ledger", "orders", "wheel"].includes(col)) {
        if (!admin && String(v) !== uid) return [403, { error: "ruxsat yo'q" }];
        return [200, { rows: await rowsBy(col, "uid", String(v), lim) }];
      }
      if (f === "playerId" && col === "users") {
        if (!admin) return [403, { error: "ruxsat yo'q" }];
        if (!/^\d{6,9}$/.test(String(v))) return bad("ID");
        return [200, { rows: await rowsBy("users", "playerId", String(v), 5) }];
      }
      if (f === "oid" && col === "omsgs") {
        const o = await getDoc("orders", String(v));
        if (!o || (!admin && o.uid !== uid)) return [403, { error: "ruxsat yo'q" }];
        return [200, { rows: await rowsBy("omsgs", "oid", String(v), lim) }];
      }
      return bad("filtr");
    }
    if (!admin) return [403, { error: "ruxsat yo'q" }];
    const r = await sb("docs?collection=eq." + col + "&select=id,data&order=updated_at.desc&limit=" + Math.min(lim, 500));
    return [200, { rows: r.map((x) => ({ id: x.id, data: x.data })) }];
  }

  if (op !== "set" && op !== "update") return bad("op");
  if (!ID_RE.test(id)) return bad("id");
  const d = b.data;
  if (!d || typeof d !== "object" || Array.isArray(d) || JSON.stringify(d).length > 320000) return bad("data");

  return serial(async () => {
    const cur = await getDoc(col, id);
    const now = Date.now();

    if (col === "config") {
      if (!admin || op !== "update" || typeof d.adminNick !== "string" || !d.adminNick.trim()) return [403, { error: "ruxsat yo'q" }];
      await putDoc("config", "app", { ...(cur || {}), adminNick: str(d.adminNick.trim(), 16), updatedAt: now });
      return [200, { ok: true }];
    }
    if (col === "users") return [403, { error: "ruxsat yo'q" }];

    if (col === "ledger") {
      if (op !== "set") return [403, { error: "ruxsat yo'q" }];
      if (cur) return [200, { ok: true, dup: true }]; // bir xil id ikki marta yozilmaydi
      if (d.type === "spend") {
        if (d.uid !== uid || d.cur !== "cl" || !int(d.amt, 0, 1e6)) return bad("ledger");
        const bal = calcBal((await rowsBy("ledger", "uid", uid, 1000)).map((r) => r.data));
        if (bal < d.amt) return [409, { error: "CL yetarli emas" }];
        await putDoc("ledger", id, { uid, type: "spend", cur: "cl", amt: d.amt, ref: str(d.ref, 60), by: uid, t: now });
        return [200, { ok: true }];
      }
      if (d.type === "grant") {
        if (!admin) return [403, { error: "ruxsat yo'q" }];
        if (!ID_RE.test(String(d.uid || ""))) return bad("uid");
        const row = { uid: String(d.uid), type: "grant", by: uid, ref: str(d.ref, 60), t: now };
        if (d.cur === "cl" && int(d.amt, 1, 1e6)) { row.cur = "cl"; row.amt = d.amt; }
        else if (d.cur === "prem" && int(d.months, 1, 24)) { row.cur = "prem"; row.months = d.months; }
        else return bad("grant");
        await putDoc("ledger", id, row);
        return [200, { ok: true }];
      }
      return bad("ledger");
    }

    if (col === "orders") {
      if (op === "set") {
        if (cur || d.uid !== uid) return [403, { error: "ruxsat yo'q" }];
        let ok = false;
        if (d.kind === "cl") ok = PACKS.some((p) => p[0] === d.amt && p[1] === d.price);
        else if (d.kind === "prem") ok = Object.values(PLANS).some((p) => p[0] === d.amt && p[1] === d.price);
        if (!ok) return bad("buyurtma narxi noto'g'ri");
        await putDoc("orders", id, { uid, nick: str(d.nick, 16), pid: /^\d{6,9}$/.test(String(d.pid)) ? String(d.pid) : "", kind: d.kind, item: str(d.item, 60), amt: d.amt, price: d.price, no: str(d.no, 32), status: "new", t: now, upd: now });
        return [200, { ok: true }];
      }
      if (!cur) return [404, { error: "topilmadi" }];
      const keys = Object.keys(d);
      if (admin) {
        if (!keys.every((k) => ["status", "upd", "cBy", "cAt"].includes(k)) || (d.status !== undefined && !ORDER_ST.has(d.status))) return bad("order");
        const nx = { ...cur }; if (d.status) nx.status = d.status; nx.upd = now;
        if (d.status === "confirmed") { nx.cBy = uid; nx.cAt = now; }
        await putDoc("orders", id, nx);
        return [200, { ok: true }];
      }
      if (cur.uid !== uid || !keys.every((k) => ["status", "upd"].includes(k)) || !((d.status === "receipt" && ["new", "awaiting", "receipt"].includes(cur.status)) || (d.status === "awaiting" && cur.status === "new"))) return [403, { error: "ruxsat yo'q" }];
      await putDoc("orders", id, { ...cur, status: d.status, upd: now });
      return [200, { ok: true }];
    }

    if (col === "omsgs") {
      if (op !== "set" || cur) return [403, { error: "ruxsat yo'q" }];
      const o = await getDoc("orders", String(d.oid || ""));
      if (!o || (!admin && o.uid !== uid)) return [403, { error: "ruxsat yo'q" }];
      const from = admin ? (d.from === "s" ? "s" : "a") : d.from === "s" ? "s" : "u";
      const img = typeof d.img === "string" && /^data:image\/jpeg;base64,[A-Za-z0-9+/=]+$/.test(d.img) && d.img.length <= 300000 ? d.img : "";
      await putDoc("omsgs", id, { oid: String(d.oid), from, fromUid: uid, text: str(d.text, 2000), img, t: now });
      return [200, { ok: true }];
    }

    if (col === "wheel") {
      if (id !== uid) return [403, { error: "ruxsat yo'q" }];
      if (op === "set") {
        if (cur && cur.last && now - cur.last < DAY) return [409, { error: "baraban hali tayyor emas" }];
        await putDoc("wheel", uid, { last: now, prize: str(d.prize, 20), pend: 1, n: ((cur && +cur.n) || 0) + 1, nick: str(d.nick, 16), carpetUntil: (cur && cur.carpetUntil) || 0, carpetReady: !!(cur && cur.carpetReady) });
        return [200, { ok: true }];
      }
      if (!cur) return [404, { error: "topilmadi" }];
      const nx = { ...cur };
      for (const k of Object.keys(d)) {
        if (k === "pend") { if (d.pend !== 0 || !cur.pend) return [409, { error: "sovrin allaqachon olingan" }]; nx.pend = 0; }
        else if (k === "claimedAt") nx.claimedAt = now;
        else if (k === "carpetReady") nx.carpetReady = !!d.carpetReady;
        else if (k === "carpetUntil") { if (!(typeof d.carpetUntil === "number" && d.carpetUntil >= 0 && d.carpetUntil <= now + 120000)) return bad("carpet"); nx.carpetUntil = d.carpetUntil; }
        else return bad("maydon");
      }
      await putDoc("wheel", uid, nx);
      return [200, { ok: true }];
    }

    if (col === "wlog") {
      if (op !== "set" || cur || d.uid !== uid) return [403, { error: "ruxsat yo'q" }];
      await putDoc("wlog", id, { uid, nick: str(d.nick, 16), prize: str(d.prize, 20), t: now });
      return [200, { ok: true }];
    }
    if (col === "alog") {
      if (!admin || op !== "set" || cur) return [403, { error: "ruxsat yo'q" }];
      await putDoc("alog", id, { t: now, by: uid, byNick: str(d.byNick, 16), act: str(d.act, 30), to: str(d.to, 40), toNick: str(d.toNick, 16), detail: str(d.detail, 200) });
      return [200, { ok: true }];
    }
    return [403, { error: "ruxsat yo'q" }];
  });
}

async function api(name, body, ip) {
  if (!HAS_DB) return [503, { error: "baza ulanmagan" }];
  if (name === "register") return register(body);
  if (name === "login") return login(body, ip);
  if (name === "player") return playerApi(body);
  if (name === "db") return dbApi(body);
  if (body.collection !== "parkour") return [403, { error: "ruxsat yo'q" }];
  if (name === "get") {
    const id = String(body.id || "");
    if (!/^[A-Za-z0-9_-]{1,40}$/.test(id)) return [400, { error: "id" }];
    const rows = await sb("docs?collection=eq.parkour&id=eq." + enc(id) + "&select=data");
    return [200, { data: rows[0] ? rows[0].data : null }];
  }
  if (name === "set") {
    const uid = String(body.uid || "");
    if (!(await checkAuth(uid, String(body.secret || "")))) return [403, { error: "akkaunt tasdiqlanmadi" }];
    const data = cleanDoc(body.data);
    await sb("docs?on_conflict=collection,id", {
      method: "POST",
      headers: { Prefer: "resolution=merge-duplicates" },
      body: JSON.stringify({ collection: "parkour", id: uid, data, updated_at: new Date().toISOString() }),
    });
    return [200, { ok: true }];
  }
  if (name === "top") {
    const f = String(body.field);
    if (!TOP_FIELDS.has(f)) return [400, { error: "field" }];
    const dir = body.dir === "desc" ? -1 : 1;
    const n = Math.max(1, Math.min(100, parseInt(body.n) || 20));
    let rows = await sb("docs?collection=eq.parkour&select=id,data&limit=3000");
    rows = rows.filter((r) => r.data && typeof r.data[f] === "number" && r.data[f] > 0);
    rows.sort((x, y) => (x.data[f] - y.data[f]) * dir);
    return [200, { rows: rows.slice(0, n) }];
  }
  return [404, { error: "topilmadi" }];
}

const CORS = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "Content-Type", "Access-Control-Allow-Methods": "POST, GET, OPTIONS" };

const server = http.createServer(async (req, res) => {
  const url = req.url.split("?")[0];
  if (req.method === "OPTIONS") { res.writeHead(204, CORS); return res.end(); }
  if (req.method === "POST" && url.startsWith("/api/")) {
    try {
      const [code, out] = await api(url.slice(5), await readJson(req), String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim());
      res.writeHead(code, { "Content-Type": "application/json", ...CORS });
      return res.end(JSON.stringify(out));
    } catch (e) {
      console.log("api xato:", e.message);
      res.writeHead(500, { "Content-Type": "application/json", ...CORS });
      return res.end(JSON.stringify({ error: "server xatosi" }));
    }
  }
  if (url === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ ok: true, db: HAS_DB, rooms: rooms.size, players: wss.clients.size }));
  }
  if (url === "/" || url === "/index.html") {
    return fs.readFile(INDEX, (err, data) => {
      if (err) {
        res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8" });
        return res.end("GAMESET server ishlayapti (index.html hali yuklanmagan)");
      }
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(data);
    });
  }
  res.writeHead(404);
  res.end("Topilmadi");
});

const wss = new WebSocketServer({ server });

const num = (v) => (Number.isFinite(+v) ? Math.max(-5000, Math.min(5000, +v)) : 0);
const send = (ws, obj) => ws.readyState === 1 && ws.send(JSON.stringify(obj));

// faqat ruxsat etilgan maydonlar qabul qilinadi
function clean(p) {
  const o = {};
  if (!p || typeof p !== "object") return o;
  if ("n" in p) o.n = String(p.n).slice(0, 16);
  if ("g" in p) o.g = String(p.g).slice(0, 12);
  if ("pk" in p) o.pk = 1;
  for (const k of ["x", "y", "z", "r"]) if (k in p) o[k] = num(p[k]);
  for (const k of ["m", "j"]) if (k in p) o[k] = p[k] ? 1 : 0;
  return o;
}

function broadcast(from, obj) {
  const r = rooms.get(from.room);
  if (!r) return;
  for (const c of r) if (c !== from) send(c, obj);
}

function leave(ws) {
  if (!ws.room) return;
  const r = rooms.get(ws.room);
  if (r) {
    r.delete(ws);
    broadcast(ws, { t: "left", id: ws.id });
    if (r.size === 0) rooms.delete(ws.room);
  }
  ws.room = null;
}

wss.on("connection", (ws) => {
  ws.id = nextId++;
  ws.room = null;
  ws.p = {};
  ws.msgCount = 0;
  const timer = setInterval(() => (ws.msgCount = 0), 1000); // soniyasiga 40 tadan ko'p xabar e'tiborsiz

  ws.on("message", (raw) => {
    if (++ws.msgCount > 40) return;
    let m;
    try { m = JSON.parse(raw); } catch { return; }

    if (m.t === "join") {
      leave(ws);
      const code = String(m.room || "LOBBY").slice(0, 24);
      const r = rooms.get(code) || new Set();
      if (r.size >= MAX_PER_ROOM) return send(ws, { t: "full" });
      ws.p = clean(m.p);
      ws.room = code;
      rooms.set(code, r);
      send(ws, { t: "joined", id: ws.id, peers: [...r].map((c) => ({ id: c.id, p: c.p })) });
      r.add(ws);
      broadcast(ws, { t: "pres", id: ws.id, p: ws.p });
    } else if (m.t === "pres" && ws.room) {
      ws.p = Object.assign(ws.p, clean(m.p));
      broadcast(ws, { t: "pres", id: ws.id, p: ws.p });
    }
  });

  ws.on("close", () => { clearInterval(timer); leave(ws); });
  ws.on("error", () => {});
});

server.listen(PORT, () => console.log("GAMESET server port " + PORT));
