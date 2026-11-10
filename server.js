// GAMESET server — 2-qadam: o'yinni tarqatish + xonalarda o'yinchilarni real vaqtda ko'rsatish
const http = require("http");
const fs = require("fs");
const path = require("path");
const { WebSocketServer } = require("ws");

const PORT = process.env.PORT || 3000;
const MAX_PER_ROOM = 20;
const INDEX = path.join(__dirname, "index.html");

const rooms = new Map(); // xona kodi -> Set(ws)
let nextId = 1;

const server = http.createServer((req, res) => {
  const url = req.url.split("?")[0];
  if (url === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ ok: true, rooms: rooms.size, players: wss.clients.size }));
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
