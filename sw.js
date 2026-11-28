// OZ CÔNG SỞ · Service Worker giải mã cục bộ AES-256-GCM (V13 Dual-Engine)
const DB_NAME = 'oz_studio_vault_v130';
const STORE_NAME = 'session';
const MAX_CACHE_BYTES = 64 * 1024 * 1024;
const MAX_CACHE_ENTRIES = 6;

let memKey = null;
let memFiles = null;
let memSaltHex = '';
const plainCache = new Map();
let cacheBytesTotal = 0;

function openDb() {
  return new Promise((resolve, reject) => {
    try {
      const req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          db.createObjectStore(STORE_NAME);
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    } catch (e) {
      reject(e);
    }
  });
}

async function restoreFromIdb() {
  if (memKey && memFiles) return true;
  try {
    const db = await openDb();
    const rec = await new Promise((resolve) => {
      const tx = db.transaction(STORE_NAME, 'readonly');
      const getReq = tx.objectStore(STORE_NAME).get('current');
      getReq.onsuccess = () => resolve(getReq.result || null);
      getReq.onerror = () => resolve(null);
    });
    if (!rec || !rec.keyBits || !rec.files) return false;
    memKey = await crypto.subtle.importKey('raw', new Uint8Array(rec.keyBits), { name: 'AES-GCM' }, false, ['decrypt']);
    memFiles = rec.files;
    memSaltHex = rec.saltHex || '';
    return true;
  } catch {
    return false;
  }
}

function clearMemVault() {
  memKey = null;
  memFiles = null;
  memSaltHex = '';
  plainCache.clear();
  cacheBytesTotal = 0;
}

self.addEventListener('install', (event) => {
  event.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    await restoreFromIdb();
    await self.clients.claim();
  })());
});

self.addEventListener('message', (event) => {
  const msg = event.data;
  const replyPort = event.ports?.[0];
  event.waitUntil((async () => {
    if (msg?.type === 'OZ_UNLOCK' && msg.keyBits && msg.files) {
      clearMemVault();
      memKey = await crypto.subtle.importKey('raw', new Uint8Array(msg.keyBits), { name: 'AES-GCM' }, false, ['decrypt']);
      memFiles = msg.files;
      memSaltHex = msg.saltHex || '';
      await self.clients.claim();
      replyPort?.postMessage({ ok: true });
      return;
    }
    if (msg?.type === 'OZ_LOCK') {
      clearMemVault();
      replyPort?.postMessage({ ok: true });
      return;
    }
    replyPort?.postMessage({ ok: false });
  })());
});

async function getDecryptedBuffer(blobUrl, entryKey) {
  if (plainCache.has(entryKey)) {
    const hit = plainCache.get(entryKey);
    plainCache.delete(entryKey);
    plainCache.set(entryKey, hit);
    return hit;
  }
  const res = await fetch(blobUrl, { cache: 'default' });
  if (!res.ok) throw new Error('Không tải được khối dữ liệu mã hóa');
  const raw = await res.arrayBuffer();
  const iv = new Uint8Array(raw, 0, 12);
  const ciphertext = new Uint8Array(raw, 12);
  const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, memKey, ciphertext);

  if (plainBuf.byteLength <= 32 * 1024 * 1024) {
    while ((cacheBytesTotal + plainBuf.byteLength > MAX_CACHE_BYTES || plainCache.size >= MAX_CACHE_ENTRIES) && plainCache.size > 0) {
      const oldestKey = plainCache.keys().next().value;
      const oldestBuf = plainCache.get(oldestKey);
      plainCache.delete(oldestKey);
      cacheBytesTotal -= oldestBuf.byteLength;
    }
    plainCache.set(entryKey, plainBuf);
    cacheBytesTotal += plainBuf.byteLength;
  }
  return plainBuf;
}

self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  const scopeUrl = new URL(self.registration.scope);
  const appPrefix = scopeUrl.pathname.endsWith('/') ? scopeUrl.pathname + 'app/' : scopeUrl.pathname + '/app/';
  if (!url.pathname.startsWith(appPrefix)) return;

  event.respondWith((async () => {
    let relPath = '/' + decodeURIComponent(url.pathname.slice(appPrefix.length));
    if (relPath === '/__health') {
      const ready = await restoreFromIdb();
      return new Response(
        JSON.stringify({ ok: true, unlocked: Boolean(ready && memKey && memFiles), saltHex: memSaltHex }),
        { status: 200, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' } }
      );
    }

    const ready = await restoreFromIdb();
    if (!ready || !memKey || !memFiles) {
      return new Response('Chưa đăng nhập Studio bảo mật', { status: 401, headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' } });
    }

    if (relPath === '/' || relPath === '/studio' || relPath === '/studio/') {
      relPath = '/studio/index.html';
    }
    const entry = memFiles[relPath];
    if (!entry) {
      return new Response('Not Found: ' + relPath, { status: 404, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
    }

    if (req.method === 'HEAD') {
      return new Response(null, {
        status: 200,
        headers: {
          'Content-Type': entry.t,
          'Content-Length': String(entry.s),
          'Accept-Ranges': 'bytes',
        },
      });
    }

    const blobUrl = new URL(entry.b, self.registration.scope).href;
    const plainBuf = await getDecryptedBuffer(blobUrl, relPath);
    const total = plainBuf.byteLength;
    const rangeHeader = req.headers.get('range');

    if (rangeHeader && rangeHeader.startsWith('bytes=')) {
      const parts = rangeHeader.replace('bytes=', '').split('-');
      const start = Math.max(0, parseInt(parts[0], 10) || 0);
      const end = parts[1] ? Math.min(total - 1, parseInt(parts[1], 10)) : total - 1;
      if (start >= total || end < start) {
        return new Response(null, {
          status: 416,
          headers: { 'Content-Range': 'bytes */' + total },
        });
      }
      const chunk = plainBuf.slice(start, end + 1);
      return new Response(chunk, {
        status: 206,
        statusText: 'Partial Content',
        headers: {
          'Content-Type': entry.t,
          'Content-Range': 'bytes ' + start + '-' + end + '/' + total,
          'Content-Length': String(chunk.byteLength),
          'Accept-Ranges': 'bytes',
        },
      });
    }

    return new Response(plainBuf, {
      status: 200,
      headers: {
        'Content-Type': entry.t,
        'Content-Length': String(total),
        'Accept-Ranges': 'bytes',
      },
    });
  })());
});
