// GAMESET server — 2-qadam: o'yinni tarqatish + xonalarda o'yinchilarni real vaqtda ko'rsatish
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

function readJson(req, max = 60000) {
  return new Promise((resolve, reject) => {
    let n = 0, chunks = [];
    req.on("data", (c) => { n += c.length; if (n > max) { reject(new Error("katta")); req.destroy(); } else chunks.push(c); });
    req.on("end", () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString() || "{}")); } catch (e) { reject(new Error("json")); } });
    req.on("error", reject);
  });
}

// o'yinchi ma'lumotini tozalash: raqamli maydonlar haqiqiy raqam bo'lishi shart
function cleanDoc(d) {
  if (!d || typeof d !== "object" || Array.isArray(d)) throw new Error("data");
  const o = { ...d };
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


// ---------- foydalanuvchi o'yinlari (e'lon qilish / ro'yxat / o'chirish) ----------
// Hozircha faqat shu nomdagi akkauntlar e'lon qila oladi (Premium serverga ko'chirilgach almashtiriladi)
const CREATORS = (process.env.CREATORS || "jahongir,johongir").toLowerCase().split(",").map((x) => x.trim()).filter(Boolean);
const gameKinds = new Set(["Parkour", "Yig'ish", "Poyga", "Boshqa"]);
const pubTimes = new Map();

async function publishGame(body) {
  const uid = String(body.uid || "");
  if (!(await checkAuth(uid, String(body.secret || "")))) return [403, { error: "akkaunt tasdiqlanmadi" }];
  const un = await getDoc("uname", uid);
  if (!un || !CREATORS.includes(String(un.un).toLowerCase())) return [403, { error: "O'yin e'lon qilish hozircha faqat Premium/yaratuvchi akkauntlar uchun" }];
  const g = body.game || {};
  const name = String(g.n || "").trim().slice(0, 30);
  const html = String(g.html || "");
  const img = String(g.img || "");
  if (name.length < 2) return [400, { error: "O'yin nomi kamida 2 belgi bo'lsin" }];
  if (!/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(img) || img.length > 60000) return [400, { error: "Rasm noto'g'ri yoki juda katta" }];
  if (html.length < 50 || html.length > 450000) return [400, { error: "O'yin fayli 450 KB dan kichik bo'lishi kerak" }];
  const kind = gameKinds.has(g.c) ? g.c : "Boshqa";
  const now = Date.now();
  const arr = (pubTimes.get(uid) || []).filter((t) => now - t < 600000);
  if (arr.length >= 5) return [429, { error: "Juda tez-tez e'lon qilyapsiz, biroz kuting" }];
  const mine = (await sb("docs?collection=eq.games&select=id,data&limit=3000")).filter((r) => r.data && r.data.uid === uid);
  if (mine.length >= 20) return [400, { error: "Eng ko'pi bilan 20 ta o'yin e'lon qilish mumkin" }];
  pubTimes.set(uid, [...arr, now]);
  const id = nodeCrypto.randomBytes(5).toString("hex");
  await putDoc("gamehtml", id, { html });
  await putDoc("games", id, { n: name, c: kind, by: un.un, uid, img, at: now });
  return [200, { ok: true, id }];
}
async function gamesList() {
  const rows = (await sb("docs?collection=eq.games&select=id,data&limit=3000")).filter((r) => r.data && r.data.n);
  rows.sort((a, b) => (b.data.at || 0) - (a.data.at || 0));
  return [200, { games: rows.slice(0, 40).map((r) => ({ id: r.id, n: r.data.n, c: r.data.c, by: r.data.by, img: r.data.img, uid: r.data.uid, at: r.data.at })) }];
}
async function gameGet(body) {
  const id = String(body.id || "");
  if (!/^[a-f0-9]{10}$/.test(id)) return [400, { error: "id" }];
  const d = await getDoc("gamehtml", id);
  return d ? [200, { html: d.html }] : [404, { error: "O'yin topilmadi" }];
}
async function unpublishGame(body) {
  const uid = String(body.uid || ""), id = String(body.id || "");
  if (!(await checkAuth(uid, String(body.secret || "")))) return [403, { error: "akkaunt tasdiqlanmadi" }];
  if (!/^[a-f0-9]{10}$/.test(id)) return [400, { error: "id" }];
  const g = await getDoc("games", id);
  if (!g || g.uid !== uid) return [403, { error: "Bu sizning o'yiningiz emas" }];
  await sb("docs?collection=eq.games&id=eq." + enc(id), { method: "DELETE", headers: { Prefer: "return=minimal" } });
  await sb("docs?collection=eq.gamehtml&id=eq." + enc(id), { method: "DELETE", headers: { Prefer: "return=minimal" } });
  return [200, { ok: true }];
}

async function api(name, body, ip) {
  if (!HAS_DB) return [503, { error: "baza ulanmagan" }];
  if (name === "register") return register(body);
  if (name === "login") return login(body, ip);
  if (name === "publish") return publishGame(body);
  if (name === "games_list") return gamesList();
  if (name === "game") return gameGet(body);
  if (name === "unpublish") return unpublishGame(body);
  if (body.collection !== "parkour" && body.collection !== "parkour2") return [403, { error: "ruxsat yo'q" }];
  if (name === "get") {
    const id = String(body.id || "");
    if (!/^[A-Za-z0-9_-]{1,40}$/.test(id)) return [400, { error: "id" }];
    const rows = await sb("docs?collection=eq." + body.collection + "&id=eq." + enc(id) + "&select=data");
    return [200, { data: rows[0] ? rows[0].data : null }];
  }
  if (name === "set") {
    const uid = String(body.uid || "");
    if (!(await checkAuth(uid, String(body.secret || "")))) return [403, { error: "akkaunt tasdiqlanmadi" }];
    const data = cleanDoc(body.data);
    await sb("docs?on_conflict=collection,id", {
      method: "POST",
      headers: { Prefer: "resolution=merge-duplicates" },
      body: JSON.stringify({ collection: body.collection, id: uid, data, updated_at: new Date().toISOString() }),
    });
    return [200, { ok: true }];
  }
  if (name === "top") {
    const f = String(body.field);
    if (!TOP_FIELDS.has(f)) return [400, { error: "field" }];
    const dir = body.dir === "desc" ? -1 : 1;
    const n = Math.max(1, Math.min(100, parseInt(body.n) || 20));
    let rows = await sb("docs?collection=eq." + body.collection + "&select=id,data&limit=3000");
    rows = rows.filter((r) => r.data && typeof r.data[f] === "number" && r.data[f] > 0);
    rows.sort((x, y) => (x.data[f] - y.data[f]) * dir);
    return [200, { rows: rows.slice(0, n) }];
  }
  return [404, { error: "topilmadi" }];
}

const CORS = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "Content-Type", "Access-Control-Allow-Methods": "POST, GET, OPTIONS" };

const server = http.createServer(async (req, res) => {
  const url = req.url.split("?")[0];
  if (url === "/.well-known/assetlinks.json") { // Android ilovasi (APK) manzil satrisiz ochilishi uchun
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify([{
      relation: ["delegate_permission/common.handle_all_urls"],
      target: {
        namespace: "android_app",
        package_name: "com.gameset.app",
        sha256_cert_fingerprints: ["98:4B:D2:C7:2F:F9:5F:13:92:5B:FF:63:78:8C:C3:48:46:69:16:89:66:B4:04:6E:A3:11:D8:96:35:D4:15:67"],
      },
    }]));
  }
  if (req.method === "OPTIONS") { res.writeHead(204, CORS); return res.end(); }
  if (req.method === "POST" && url.startsWith("/api/")) {
    try {
      const [code, out] = await api(url.slice(5), await readJson(req, url === "/api/publish" ? 700000 : 60000), String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim());
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
