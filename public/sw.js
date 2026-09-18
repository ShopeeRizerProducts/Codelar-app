const CACHE = "codelar-os-v2";
const CORE_ASSETS = ["/manifest.json", "/icon-192.png", "/icon-512.png"];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(CORE_ASSETS)));
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// API calls: network-first, cache only as an offline fallback.
// The page itself (navigation) and its script/style: network-first too, so updates always show —
// this is a dashboard with your business data, it should never show a stale screen just to save a request.
// Only truly static assets (icons, manifest) are cache-first, since those rarely change.
self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  const isStaticAsset = CORE_ASSETS.includes(url.pathname);

  if (isStaticAsset) {
    event.respondWith(
      caches.match(event.request).then((cached) => cached || fetch(event.request))
    );
    return;
  }

  event.respondWith(
    fetch(event.request)
      .then((res) => {
        if (event.request.method === "GET" && res.ok) {
          const clone = res.clone();
          caches.open(CACHE).then((cache) => cache.put(event.request, clone));
        }
        return res;
      })
      .catch(() => caches.match(event.request))
  );
});
