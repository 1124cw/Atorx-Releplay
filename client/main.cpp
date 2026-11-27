// Példa: így kell beépíteni a saját programodba.
#include <windows.h>
#include "LicenseGate.h"

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int) {
    LicenseGate::Result license;
    if (!LicenseGate::Run(hInstance, &license)) {
        return 0;  // nincs érvényes kulcs -> kilépés
    }

    // ---- innen indul a te programod ----
    MessageBoxW(nullptr, L"Sikeres belépés! Itt indul a program.", L"Atrox Roleplay", MB_OK | MB_ICONINFORMATION);
    return 0;
}
