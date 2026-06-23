const CACHE_NAME = 'safetrack-v2-cache';
const ASSETS_TO_CACHE = [
  '/',
  '/index.html',
  '/manifest.json',
  '/css/main.css',
  '/css/calendar.css',
  '/js/app.js',
  '/js/api.js',
  '/js/auth-router.js',
  '/js/realtime.js',
  '/js/glass-tour.js',
  '/js/sos.js',
  '/js/icons.js',
  '/js/dock.js',
  '/js/map.js',
  '/js/bip39.js',
  '/js/calendar.js',
  '/js/contacts.js',
  '/js/trackers.js',
  '/js/settings.js',
  '/js/nostr-p2p.js',
  '/js/avatar-engine.js'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      console.log('[SW] Pre-caching critical assets');
      return cache.addAll(ASSETS_TO_CACHE);
    }).catch(err => console.error('[SW] Cache addAll failed:', err))
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys => {
      return Promise.all(keys.map(key => {
        if (key !== CACHE_NAME) return caches.delete(key);
      }));
    }).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', event => {
  // Graceful fallback for network failures
  event.respondWith(
    caches.match(event.request).then(cached => {
      return cached || fetch(event.request).catch(err => {
        console.warn('[SW] Fetch failed for:', event.request.url);
        // Return a generic offline response if it's a page navigation
        if (event.request.mode === 'navigate') {
          return caches.match('/index.html');
        }
        return new Response('Offline', { status: 503, statusText: 'Offline' });
      });
    })
  );
});

self.addEventListener('sync', event => {
  if (event.tag === 'sync-sos') {
    event.waitUntil(flushSOSQueue());
  }
});

async function flushSOSQueue() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('SafeTrackDB', 1);
    request.onsuccess = async (e) => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains('offline_sos')) {
        resolve();
        return;
      }
      const tx = db.transaction('offline_sos', 'readonly');
      const store = tx.objectStore('offline_sos');
      const getAll = store.getAll();
      getAll.onsuccess = async () => {
        for (const item of getAll.result) {
          try {
            const resp = await fetch('/sos/trigger', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(item.data)
            });
            if (resp.ok) {
              const delTx = db.transaction('offline_sos', 'readwrite');
              delTx.objectStore('offline_sos').delete(item.id);
            }
          } catch (err) {
            console.error('[SW] Sync flush failed:', err);
          }
        }
        resolve();
      };
      getAll.onerror = reject;
    };
    request.onerror = reject;
  });
}
