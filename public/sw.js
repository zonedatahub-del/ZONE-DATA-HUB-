// Zone Data Hub — Service Worker
// Caches the shell for offline support and fast loading

const CACHE = 'zdh-v1';
const SHELL = [
  '/',
  '/index.html',
  'https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Syne:wght@400;700;800;900&family=DM+Sans:wght@300;400;500;600&display=swap',
  'https://www.gstatic.com/firebasejs/10.12.0/firebase-app-compat.js',
  'https://www.gstatic.com/firebasejs/10.12.0/firebase-auth-compat.js',
  'https://www.gstatic.com/firebasejs/10.12.0/firebase-firestore-compat.js',
  'https://js.paystack.co/v1/inline.js'
];

// Install: cache the app shell
self.addEventListener('install', function(e){
  e.waitUntil(
    caches.open(CACHE).then(function(cache){
      // Cache what we can — external CDN resources may fail, that's ok
      return Promise.allSettled(
        SHELL.map(url => cache.add(url).catch(function(){}))
      );
    })
  );
  self.skipWaiting();
});

// Activate: clean old caches
self.addEventListener('activate', function(e){
  e.waitUntil(
    caches.keys().then(function(keys){
      return Promise.all(
        keys.filter(k => k !== CACHE).map(k => caches.delete(k))
      );
    })
  );
  self.clients.claim();
});

// Fetch: network first, fall back to cache
self.addEventListener('fetch', function(e){
  // Skip non-GET and Firebase/Paystack API calls — always go to network
  if(e.request.method !== 'GET') return;
  var url = e.request.url;
  if(url.includes('firestore.googleapis.com') ||
     url.includes('identitytoolkit.googleapis.com') ||
     url.includes('api.paystack.co') ||
     url.includes('paystack') ||
     url.includes('firebase')) {
    return; // Let Firebase handle its own requests
  }

  e.respondWith(
    fetch(e.request)
      .then(function(resp){
        // Cache successful responses for the shell
        if(resp && resp.status === 200){
          var clone = resp.clone();
          caches.open(CACHE).then(function(cache){ cache.put(e.request, clone); });
        }
        return resp;
      })
      .catch(function(){
        // Offline: serve from cache
        return caches.match(e.request).then(function(cached){
          return cached || caches.match('/');
        });
      })
  );
});
