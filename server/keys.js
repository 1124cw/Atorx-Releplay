#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const store = require('./store');

const CLIENT_HEADER = path.join(__dirname, '..', 'client', 'LicensePublicKey.h');

const HELP = `Atrox licenc kulcs kezelő

Használat: node keys.js <parancs> [opciók]

  init                         Aláíró kulcspár létrehozása (egyszer kell) + client/LicensePublicKey.h
  create [opciók]              Új kulcs(ok) létrehozása
      --days <N>               N napig érvényes az ELSŐ belépéstől számítva
      --until <YYYY-MM-DD>     Fix lejárati dátum
      --lifetime               Soha nem jár le (alapértelmezett, ha semmi nincs megadva)
      --count <N>              Ennyi kulcsot hoz létre (alap: 1)
      --note "<szöveg>"        Megjegyzés (pl. kinek adtad)
  list                         Összes kulcs listázása
  info <KEY>                   Egy kulcs részletei
  extend <KEY> --days <N>      Lejárat meghosszabbítása N nappal
  reset-hwid <KEY>             HWID kötés törlése (új gépen újra aktiválható)
  revoke <KEY>                 Kulcs tiltása
  unrevoke <KEY>               Tiltás feloldása
  delete <KEY>                 Kulcs törlése
`;

function parseArgs(argv) {
  const positional = [];
  const opts = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const name = a.slice(2);
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('--')) opts[name] = true;
      else opts[name] = argv[++i];
    } else positional.push(a);
  }
  return { positional, opts };
}

function fail(msg) {
  console.error(`Hiba: ${msg}`);
  process.exit(1);
}

function fmtDate(ms) {
  return ms ? new Date(ms).toISOString().replace('T', ' ').slice(0, 16) + ' UTC' : '-';
}

function describeExpiry(e) {
  if (e.expiresAt) return fmtDate(e.expiresAt);
  if (e.durationDays) return `${e.durationDays} nap az első belépéstől`;
  return 'örök';
}

function statusOf(e) {
  if (e.revoked) return 'TILTVA';
  if (e.expiresAt && Date.now() >= e.expiresAt) return 'LEJÁRT';
  if (!e.hwid) return 'nem aktivált';
  return 'aktív';
}

function getEntry(db, rawKey) {
  const key = store.normalizeKey(rawKey);
  if (!key) fail('Add meg a kulcsot.');
  const entry = db.keys[key];
  if (!entry) fail(`Nincs ilyen kulcs: ${key}`);
  return [key, entry];
}

function positiveInt(value, name) {
  const n = Number(value);
  if (!Number.isInteger(n) || n <= 0) fail(`--${name} pozitív egész szám legyen.`);
  return n;
}

function cmdInit(opts) {
  store.load();
  if (fs.existsSync(store.PRIVATE_KEY_FILE) && !opts.force) {
    console.log('Már van aláíró kulcs (data/private.pem). Felülíráshoz: node keys.js init --force');
    console.log('FIGYELEM: új kulcspár után a C++ klienst újra kell fordítani!');
  } else {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    fs.writeFileSync(store.PRIVATE_KEY_FILE, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    fs.writeFileSync(store.PUBLIC_KEY_FILE, publicKey.export({ type: 'spki', format: 'pem' }));
    console.log(`Kulcspár létrehozva: ${store.PRIVATE_KEY_FILE}`);
  }

  const jwk = crypto.createPublicKey(fs.readFileSync(store.PUBLIC_KEY_FILE)).export({ format: 'jwk' });
  const raw = Buffer.concat([Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
  const bytes = [...raw].map((b) => `0x${b.toString(16).padStart(2, '0')}`);
  const lines = [];
  for (let i = 0; i < bytes.length; i += 16) lines.push('    ' + bytes.slice(i, i + 16).join(', ') + ',');
  const header = `// Automatikusan generálva: node keys.js init
// A licenc szerver nyilvános kulcsa (ECDSA P-256, X||Y). Ez nem titkos.
#pragma once

static const unsigned char LICENSE_PUBLIC_KEY[64] = {
${lines.join('\n')}
};
`;
  if (fs.existsSync(path.dirname(CLIENT_HEADER))) {
    fs.writeFileSync(CLIENT_HEADER, header);
    console.log(`Nyilvános kulcs beírva: ${CLIENT_HEADER}`);
  } else {
    console.log('\nMásold be ezt a client/LicensePublicKey.h fájlba:\n');
    console.log(header);
  }
}

function cmdCreate(opts) {
  const db = store.load();
  const count = opts.count ? positiveInt(opts.count, 'count') : 1;
  let durationDays = null;
  let expiresAt = null;
  if (opts.days) durationDays = positiveInt(opts.days, 'days');
  if (opts.until) {
    expiresAt = Date.parse(`${opts.until}T23:59:59Z`);
    if (Number.isNaN(expiresAt)) fail('--until formátuma: YYYY-MM-DD');
  }
  if (durationDays && expiresAt) fail('A --days és --until közül csak az egyiket add meg.');

  const created = [];
  for (let i = 0; i < count; i++) {
    let key;
    do key = store.generateKey(opts.prefix || 'ATRX');
    while (db.keys[key]);
    db.keys[key] = {
      createdAt: Date.now(),
      durationDays,
      expiresAt,
      hwid: null,
      activatedAt: null,
      lastSeenAt: null,
      revoked: false,
      note: typeof opts.note === 'string' ? opts.note : '',
    };
    created.push(key);
  }
  store.save(db);
  console.log(`${created.length} kulcs létrehozva (lejárat: ${describeExpiry(db.keys[created[0]])}):`);
  created.forEach((k) => console.log(k));
}

function cmdList() {
  const db = store.load();
  const rows = Object.entries(db.keys).map(([key, e]) => ({
    kulcs: key,
    állapot: statusOf(e),
    lejárat: describeExpiry(e),
    hwid: e.hwid ? e.hwid.slice(0, 12) + '…' : '-',
    megjegyzés: e.note || '',
  }));
  if (!rows.length) return console.log('Nincs még kulcs. Létrehozás: node keys.js create --days 30');
  console.table(rows);
}

function cmdInfo(key) {
  const db = store.load();
  const [k, e] = getEntry(db, key);
  console.log(`Kulcs:        ${k}`);
  console.log(`Állapot:      ${statusOf(e)}`);
  console.log(`Lejárat:      ${describeExpiry(e)}`);
  console.log(`HWID:         ${e.hwid || '-'}`);
  console.log(`Létrehozva:   ${fmtDate(e.createdAt)}`);
  console.log(`Aktiválva:    ${fmtDate(e.activatedAt)}`);
  console.log(`Utoljára:     ${fmtDate(e.lastSeenAt)}`);
  console.log(`Megjegyzés:   ${e.note || '-'}`);
}

function mutate(key, fn, message) {
  const db = store.load();
  const [k, e] = getEntry(db, key);
  fn(e, db, k);
  store.save(db);
  console.log(`${k}: ${message(e)}`);
}

function main() {
  const { positional, opts } = parseArgs(process.argv.slice(2));
  const [cmd, key] = positional;
  switch (cmd) {
    case 'init':
      return cmdInit(opts);
    case 'create':
      return cmdCreate(opts);
    case 'list':
      return cmdList();
    case 'info':
      return cmdInfo(key);
    case 'extend': {
      const days = positiveInt(opts.days, 'days');
      return mutate(
        key,
        (e) => {
          if (e.expiresAt) e.expiresAt = Math.max(e.expiresAt, Date.now()) + days * store.DAY_MS;
          else if (e.durationDays) e.durationDays += days;
          else fail('Ez a kulcs örök, nem kell hosszabbítani.');
        },
        (e) => `új lejárat: ${describeExpiry(e)}`
      );
    }
    case 'reset-hwid':
      return mutate(key, (e) => { e.hwid = null; }, () => 'HWID törölve, új gépen újra aktiválható.');
    case 'revoke':
      return mutate(key, (e) => { e.revoked = true; }, () => 'tiltva.');
    case 'unrevoke':
      return mutate(key, (e) => { e.revoked = false; }, () => 'tiltás feloldva.');
    case 'delete':
      return mutate(key, (e, db, k) => { delete db.keys[k]; }, () => 'törölve.');
    default:
      console.log(HELP);
  }
}

main();
