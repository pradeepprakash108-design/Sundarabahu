/* Sundarabahu service worker (installability only).
   Deliberately caches NOTHING: pages depend on the signed-in role (full or student) and /api/* carries sign-in,
   so every request goes straight to the network exactly as before. Only a failed page navigation (no network)
   shows a small offline notice. Bump VERSION to force update. */
const VERSION = 'sb-pwa-1';
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
const OFFLINE = '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sundarabahu</title><body style="font-family:system-ui,sans-serif;background:#F4EBDD;color:#13232B;display:grid;place-items:center;min-height:100vh;margin:0;text-align:center;padding:24px"><div><h2 style="color:#7A1F2B">You are offline</h2><p>Sundarabahu needs an internet connection to sign in and load your lessons. Please reconnect and try again.</p><button onclick="location.reload()" style="font:inherit;padding:10px 18px;border:0;border-radius:10px;background:#7A1F2B;color:#fff">Retry</button></div></body>';
self.addEventListener('fetch', e => {
  const r = e.request;
  if (r.method !== 'GET' || r.mode !== 'navigate') return;   // everything else: untouched, browser default
  e.respondWith(fetch(r).catch(() => new Response(OFFLINE, { status: 503, headers: { 'content-type': 'text/html; charset=utf-8' } })));
});
