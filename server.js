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

function readJson(req) {
  return new Promise((resolve, reject) => {
    let n = 0, chunks = [];
    req.on("data", (c) => { n += c.length; if (n > 60000) { reject(new Error("katta")); req.destroy(); } else chunks.push(c); });
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
    return again.length === 1 && again[0].data.h === h;
  }
  const a = Buffer.from(rows[0].data.h || ""), b = Buffer.from(h);
  return a.length === b.length && nodeCrypto.timingSafeEqual(a, b);
}

async function api(name, body) {
  if (!HAS_DB) return [503, { error: "baza ulanmagan" }];
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
      const [code, out] = await api(url.slice(5), await readJson(req));
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
