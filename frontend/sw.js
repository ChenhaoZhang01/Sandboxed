// Service worker: caches the app shell so Sandboxed installs and launches
// offline. The detonation API is a different origin and is never cached —
// requests to it always go to the network.
const CACHE = "sandboxed-v4";
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

  // Stale-while-revalidate: serve the cached copy immediately (fast + offline),
  // but always re-fetch in the background and update the cache so code changes
  // (styles.css, app.js, the game) propagate on the next load instead of being
  // pinned to a stale version forever. Falls back to the app shell for offline
  // navigations.
  event.respondWith(
    caches.match(req).then((cached) => {
      const network = fetch(req)
        .then((res) => {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(req, copy));
          return res;
        })
        .catch(() => (req.mode === "navigate" ? caches.match("./index.html") : undefined));
      return cached || network;
    })
  );
});
