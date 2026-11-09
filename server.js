// GAMESET server — 1-qadam: xonalar va o'yinchi harakatini real vaqtda tarqatish
const http = require("http");
const express = require("express");
const { WebSocketServer } = require("ws");

const PORT = process.env.PORT || 3000;
const MAX_PER_ROOM = 10;

const app = express();
app.get("/", (req, res) => res.send("GAMESET server ishlayapti"));
app.get("/health", (req, res) =>
  res.json({ ok: true, rooms: rooms.size, players: wss.clients.size })
);

const server = http.createServer(app);
const wss = new WebSocketServer({ server });
const rooms = new Map(); // xona kodi -> Set(ws)
let nextId = 1;

const num = (v) => (Number.isFinite(+v) ? Math.max(-5000, Math.min(5000, +v)) : 0);
const pub = (c) => ({ id: c.id, name: c.name, x: c.x, y: c.y, z: c.z, ry: c.ry });
const send = (ws, obj) => ws.readyState === 1 && ws.send(JSON.stringify(obj));

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
    broadcast(ws, { t: "player_leave", id: ws.id });
    if (r.size === 0) rooms.delete(ws.room);
  }
  ws.room = null;
}

wss.on("connection", (ws) => {
  ws.id = nextId++;
  ws.room = null;
  ws.name = "Player";
  ws.x = ws.y = ws.z = ws.ry = 0;
  ws.msgCount = 0;

  // oddiy himoya: soniyasiga 40 tadan ko'p xabarni e'tiborsiz qoldiramiz
  const timer = setInterval(() => (ws.msgCount = 0), 1000);

  ws.on("message", (raw) => {
    if (++ws.msgCount > 40) return;
    let m;
    try { m = JSON.parse(raw); } catch { return; }

    if (m.t === "join") {
      leave(ws);
      const code = String(m.room || "LOBBY").toUpperCase().slice(0, 8);
      const r = rooms.get(code) || new Set();
      if (r.size >= MAX_PER_ROOM) return send(ws, { t: "error", msg: "Xona to'la" });
      ws.name = String(m.name || "Player").slice(0, 16);
      ws.room = code;
      rooms.set(code, r);
      r.add(ws);
      send(ws, { t: "joined", id: ws.id, room: code, players: [...r].filter((c) => c !== ws).map(pub) });
      broadcast(ws, { t: "player_join", p: pub(ws) });
    } else if (m.t === "move" && ws.room) {
      ws.x = num(m.x); ws.y = num(m.y); ws.z = num(m.z); ws.ry = num(m.ry);
      broadcast(ws, { t: "move", id: ws.id, x: ws.x, y: ws.y, z: ws.z, ry: ws.ry });
    }
  });

  ws.on("close", () => { clearInterval(timer); leave(ws); });
  ws.on("error", () => {});
});

server.listen(PORT, () => console.log("GAMESET server port " + PORT));
