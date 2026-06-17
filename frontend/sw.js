// Service worker: caches the app shell so Sandboxed installs and launches
// offline. The detonation API is a different origin and is never cached —
// requests to it always go to the network.
const CACHE = "sandboxed-v1";
const SHELL = [
  "./",
  "./index.html",
  "./manifest.webmanifest",
  "./icon.svg",
  "./icons/icon-192.png",
  "./icons/icon-512.png",
  "./icons/apple-touch-icon-180.png",
  "./icons/favicon-32.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return; // never intercept POST /detonate
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return; // CDN + API → straight to network

  // Cache-first for the app shell; fall back to network, then to the app shell
  // for navigations so the installed app opens even when offline.
  event.respondWith(
    caches.match(req).then((cached) => {
      if (cached) return cached;
      return fetch(req)
        .then((res) => {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(req, copy));
          return res;
        })
        .catch(() => (req.mode === "navigate" ? caches.match("./index.html") : undefined));
    })
  );
});
