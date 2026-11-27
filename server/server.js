'use strict';

const crypto = require('crypto');
const http = require('http');
const store = require('./store');

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';
const RATE_LIMIT_PER_MIN = Number(process.env.RATE_LIMIT_PER_MIN || 20);
const TRUST_PROXY = process.env.TRUST_PROXY === '1';

const fs = require('fs');

// Reloaded when private.pem changes, so `node keys.js init --force` needs no server restart.
let signer = { mtimeMs: fs.statSync(store.PRIVATE_KEY_FILE).mtimeMs, key: store.loadPrivateKey() };
function currentPrivateKey() {
  const { mtimeMs } = fs.statSync(store.PRIVATE_KEY_FILE);
  if (mtimeMs !== signer.mtimeMs) signer = { mtimeMs, key: store.loadPrivateKey() };
  return signer.key;
}
const hits = new Map();

function rateLimited(ip) {
  const now = Date.now();
  const recent = (hits.get(ip) || []).filter((t) => now - t < 60_000);
  hits.set(ip, recent);
  if (recent.length >= RATE_LIMIT_PER_MIN) return true;
  recent.push(now);
  return false;
}

setInterval(() => {
  const now = Date.now();
  for (const [ip, list] of hits) {
    if (!list.some((t) => now - t < 60_000)) hits.delete(ip);
  }
}, 60_000).unref();

// The client verifies this signature with the embedded public key, so a fake
// server cannot answer "ok". The client's random nonce prevents replaying old answers.
function signedReply(res, httpCode, { status, expiresAt, nonce, hwid }) {
  const expires = expiresAt ? Math.floor(expiresAt / 1000) : 0;
  const message = `${nonce}|${status}|${expires}|${hwid}`;
  const sig = crypto
    .sign('sha256', Buffer.from(message), { key: currentPrivateKey(), dsaEncoding: 'ieee-p1363' })
    .toString('hex');
  res.writeHead(httpCode, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end(`status=${status}\nexpires=${expires}\nsig=${sig}\n`);
}

function plainReply(res, httpCode, status) {
  res.writeHead(httpCode, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end(`status=${status}\n`);
}

const server = http.createServer((req, res) => {
  // Behind a trusted reverse proxy the client IP is the last X-Forwarded-For entry (added by the proxy).
  const forwarded = TRUST_PROXY ? String(req.headers['x-forwarded-for'] || '').split(',').pop().trim() : '';
  const ip = forwarded || req.socket.remoteAddress || '';

  if (req.method === 'GET' && req.url === '/health') return plainReply(res, 200, 'ok');
  if (req.method !== 'POST' || req.url !== '/api/verify') return plainReply(res, 404, 'not_found');
  if (rateLimited(ip)) return plainReply(res, 429, 'rate_limited');

  let body = '';
  req.on('data', (chunk) => {
    body += chunk;
    if (body.length > 2048) req.destroy();
  });
  req.on('end', () => {
    const params = new URLSearchParams(body);
    const key = store.normalizeKey(params.get('key'));
    const hwid = String(params.get('hwid') || '').toUpperCase();
    const nonce = String(params.get('nonce') || '').toLowerCase();

    if (!/^[A-Z0-9-]{4,64}$/.test(key) || !/^[A-F0-9]{64}$/.test(hwid) || !/^[a-f0-9]{32}$/.test(nonce)) {
      return plainReply(res, 400, 'bad_request');
    }

    let result;
    try {
      result = store.withLock(() => {
        const db = store.load();
        const r = store.verify(db, key, hwid);
        if (r.changed) store.save(db);
        return r;
      });
    } catch (err) {
      console.error(err.message);
      return plainReply(res, 503, 'busy');
    }

    console.log(`${new Date().toISOString()} ${ip} ${key.slice(0, 10)}… ${hwid.slice(0, 12)}… -> ${result.status}`);
    signedReply(res, 200, { status: result.status, expiresAt: result.expiresAt, nonce, hwid });
  });
});

server.listen(PORT, HOST, () => {
  console.log(`Licenc szerver fut: http://${HOST}:${PORT}  (adatok: ${store.DATA_DIR})`);
});
