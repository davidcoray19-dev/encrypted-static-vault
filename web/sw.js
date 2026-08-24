// Deliberately no caching.
//
// Every other app in this family precaches its shell for offline use. This one
// must not: the Cache Storage API writes to disk, unencrypted, and survives the
// tab. Anything cached here would be a decrypted copy of what the whole design
// exists to protect. The vault must also always come fresh from the server, or
// a reload would show a version the sync tool has already replaced.
//
// The worker exists only so the page is installable as a PWA.
self.addEventListener('install',  () => self.skipWaiting());
self.addEventListener('activate', e => {
  // Clear anything an earlier version of this worker may have cached.
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});
self.addEventListener('fetch', e => { e.respondWith(fetch(e.request)); });
