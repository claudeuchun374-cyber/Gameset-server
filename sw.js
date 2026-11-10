// GAMESET service worker: tarmoq birinchi, oflayn bo'lsa keshdan
const C = "gameset-v1";
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));
self.addEventListener("fetch", (e) => {
  const r = e.request;
  if (r.method !== "GET" || new URL(r.url).pathname.startsWith("/api/")) return;
  e.respondWith(fetch(r).then((res) => { const c = res.clone(); caches.open(C).then((k) => k.put(r, c)).catch(() => {}); return res; }).catch(() => caches.match(r)));
});
