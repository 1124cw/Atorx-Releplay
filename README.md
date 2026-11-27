# Atrox Roleplay – licenc (key) rendszer

Az .exe indításakor először egy login panel jön fel, ahol licenc kulcsot kell megadni.
A kulcsoknak lehet lejárata, és az első belépéskor a kulcs a géphez (HWID) kötődik.

```
client/   C++ (Win32) login panel – ezt építed be a programodba
server/   Node.js licenc szerver + keys.js kulcskezelő
```

## Működés

1. A program indul → `LicenseGate::Run()` megjeleníti a login panelt.
2. A kliens elküldi a szervernek: kulcs + HWID + egy véletlen nonce.
3. A szerver ellenőrzi (létezik? tiltva? lejárt? másik HWID?). Első belépéskor a kulcsot a HWID-hez köti,
   és ha `--days` kulcs, ekkor indul a lejárat.
4. A szerver a választ ECDSA kulccsal **aláírja**, a kliens a beépített nyilvános kulccsal ellenőrzi.
   Így egy hamis szerverrel (pl. hosts fájl átírás) nem lehet „ok” választ adni.

A HWID = SHA-256( Windows MachineGuid + rendszermeghajtó sorozatszám + CPU azonosító ).

## 1. Szerver beállítása

Kell hozzá Node.js 16+ (külső csomag nem kell).

```bash
cd server
node keys.js init          # aláíró kulcspár + client/LicensePublicKey.h legenerálása (EGYSZER)
node server.js             # szerver indítása (alap port: 3000, PORT=8080 node server.js)
```

A `server/data/` mappában lesz a `keys.json` (kulcsok) és a `private.pem` (titkos aláíró kulcs).
**A `private.pem`-et soha ne add ki és ne töltsd fel** (a `.gitignore` már kizárja).

## 2. Kulcsok kezelése (`keys.js`)

```bash
node keys.js create --days 30 --note "Pisti"     # 30 nap az első belépéstől
node keys.js create --until 2026-12-31           # fix lejárati dátum
node keys.js create --lifetime                   # örök kulcs
node keys.js create --days 7 --count 10          # 10 db 7 napos kulcs
node keys.js list                                # összes kulcs + állapot
node keys.js info ATRX-XXXXX-XXXXX-XXXXX
node keys.js extend ATRX-XXXXX-XXXXX-XXXXX --days 30
node keys.js reset-hwid ATRX-XXXXX-XXXXX-XXXXX   # ha valaki gépet cserélt
node keys.js revoke ATRX-XXXXX-XXXXX-XXXXX       # tiltás (unrevoke = feloldás)
node keys.js delete ATRX-XXXXX-XXXXX-XXXXX
```

A szerver futása közben is használható, nem kell újraindítani.

## 3. Beépítés a C++ programodba

1. Másold a projektedbe: `LicenseGate.h`, `LicenseGate.cpp`, `LicenseConfig.h`, `LicensePublicKey.h`.
2. `LicenseConfig.h`-ban állítsd be a szerver címét (`LICENSE_SERVER_HOST`, `LICENSE_SERVER_PORT`, `LICENSE_SERVER_HTTPS`).
3. A `main` / `WinMain` legelején:

```cpp
#include "LicenseGate.h"

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int) {
    LicenseGate::Result license;
    if (!LicenseGate::Run(hInstance, &license))
        return 0;               // nincs érvényes kulcs -> kilép

    // ... a programod innen indul (license.expiresAt = lejárat unix időben, 0 = örök)
}
```

Visual Studio-ban a szükséges libeket (`winhttp`, `bcrypt`, `uxtheme`) a kód `#pragma comment`-tel magától linkeli.
Konzolos (`int main()`) programban is működik: `LicenseGate::Run(GetModuleHandle(nullptr))`.

Fordítás a mellékelt példával:

```bash
cd client
cmake -B build && cmake --build build --config Release     # -> AtroxLauncher.exe
```

A „Kulcs megjegyzése” bepipálásakor a kulcs a `%APPDATA%\AtroxRoleplay\license.key` fájlba mentődik,
és következő indításkor ki lesz töltve.

## Élesítés

- A szervert egy VPS-en futtasd (pl. `pm2 start server.js`), és tedd HTTPS mögé (nginx / Caddy reverse proxy),
  majd a kliensben `LICENSE_SERVER_HTTPS 1` és port 443. Proxy mögött: `TRUST_PROXY=1 node server.js`.
- Ha új kulcspárt generálsz (`node keys.js init --force`), a C++ klienst újra kell fordítani.
- Kliens oldali védelem 100%-osan nem létezik: egy elszánt cracker patch-elheti az .exe-t.
  Érdemes obfuszkálni / packelni (pl. VMProtect, Themida), ha fontos.
