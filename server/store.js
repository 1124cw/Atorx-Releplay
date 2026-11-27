'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const DATA_DIR = process.env.LICENSE_DATA_DIR || path.join(__dirname, 'data');
const KEYS_FILE = path.join(DATA_DIR, 'keys.json');
const PRIVATE_KEY_FILE = path.join(DATA_DIR, 'private.pem');
const PUBLIC_KEY_FILE = path.join(DATA_DIR, 'public.pem');
const LOCK_FILE = path.join(DATA_DIR, 'keys.lock');
const LOCK_TIMEOUT_MS = 5000;
const STALE_LOCK_MS = 10000;

const KEY_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const DAY_MS = 24 * 60 * 60 * 1000;

function ensureDataDir() {
  fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
}

function load() {
  ensureDataDir();
  if (!fs.existsSync(KEYS_FILE)) return { keys: {} };
  const db = JSON.parse(fs.readFileSync(KEYS_FILE, 'utf8'));
  if (!db.keys) db.keys = {};
  return db;
}

function save(db) {
  ensureDataDir();
  const tmp = KEYS_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, KEYS_FILE);
}

function sleepSync(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

// Cross-process lock so the server and keys.js never overwrite each other's changes.
function withLock(fn) {
  ensureDataDir();
  const deadline = Date.now() + LOCK_TIMEOUT_MS;
  let fd;
  for (;;) {
    try {
      fd = fs.openSync(LOCK_FILE, 'wx');
      break;
    } catch (err) {
      if (err.code !== 'EEXIST') throw err;
      try {
        if (Date.now() - fs.statSync(LOCK_FILE).mtimeMs > STALE_LOCK_MS) {
          fs.unlinkSync(LOCK_FILE);
          continue;
        }
      } catch {
        continue;
      }
      if (Date.now() > deadline) throw new Error(`A kulcs adatbázis zárolva van (${LOCK_FILE}).`);
      sleepSync(20);
    }
  }
  const release = () => {
    try {
      fs.closeSync(fd);
    } catch {}
    try {
      fs.unlinkSync(LOCK_FILE);
    } catch {}
  };
  process.once('exit', release);
  try {
    return fn();
  } finally {
    process.removeListener('exit', release);
    release();
  }
}

function normalizeKey(key) {
  return String(key || '').trim().toUpperCase();
}

function generateKey(prefix = 'ATRX') {
  const group = () =>
    Array.from({ length: 5 }, () => KEY_ALPHABET[crypto.randomInt(KEY_ALPHABET.length)]).join('');
  return [prefix, group(), group(), group()].join('-');
}

function loadPrivateKey() {
  if (!fs.existsSync(PRIVATE_KEY_FILE)) {
    throw new Error('Nincs aláíró kulcs. Futtasd először: node keys.js init');
  }
  return crypto.createPrivateKey(fs.readFileSync(PRIVATE_KEY_FILE));
}

// Checks a key against the DB, binds it to the HWID on first use and
// returns { status, expiresAt } (expiresAt: unix ms, null = lifetime).
function verify(db, rawKey, hwid, now = Date.now()) {
  const key = normalizeKey(rawKey);
  const entry = db.keys[key];
  if (!entry) return { status: 'invalid', expiresAt: null, changed: false };
  if (entry.revoked) return { status: 'banned', expiresAt: entry.expiresAt, changed: false };
  if (entry.expiresAt && now >= entry.expiresAt) {
    return { status: 'expired', expiresAt: entry.expiresAt, changed: false };
  }

  if (!entry.hwid) {
    entry.hwid = hwid;
    entry.activatedAt = now;
    if (entry.durationDays && !entry.expiresAt) {
      entry.expiresAt = now + entry.durationDays * DAY_MS;
    }
  } else if (entry.hwid !== hwid) {
    return { status: 'hwid_mismatch', expiresAt: entry.expiresAt, changed: false };
  }

  entry.lastSeenAt = now;
  return { status: 'ok', expiresAt: entry.expiresAt || null, changed: true };
}

module.exports = {
  DATA_DIR,
  KEYS_FILE,
  PRIVATE_KEY_FILE,
  PUBLIC_KEY_FILE,
  DAY_MS,
  load,
  save,
  withLock,
  normalizeKey,
  generateKey,
  loadPrivateKey,
  verify,
};
