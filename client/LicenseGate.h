#pragma once

#include <windows.h>
#include <string>

namespace LicenseGate {

struct Result {
    std::wstring key;
    std::wstring hwid;
    long long expiresAt = 0;   // unix másodperc, 0 = örök
};

// Megjeleníti a login panelt és addig nem tér vissza, amíg a felhasználó
// érvényes kulccsal be nem lép (true) vagy be nem zárja az ablakot (false).
bool Run(HINSTANCE instance, Result* result = nullptr);

// Ennek a gépnek a HWID-je (64 hex karakter).
std::wstring GetHwid();

}  // namespace LicenseGate
