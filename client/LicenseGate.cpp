// Fájl UTF-8 BOM-mal mentve, hogy MSVC és MinGW is jól kezelje az ékezeteket.
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "LicenseGate.h"
#include "LicenseConfig.h"
#include "LicensePublicKey.h"

#include <windows.h>
#include <bcrypt.h>
#include <uxtheme.h>
#include <winhttp.h>

#include <cstdint>
#include <ctime>
#include <map>
#include <string>
#include <vector>

#ifdef _MSC_VER
#include <intrin.h>
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#else
#include <cpuid.h>
#endif

namespace LicenseGate {
namespace {

// ---------------------------------------------------------------- helpers

using Bytes = std::vector<uint8_t>;

bool BcryptOk(NTSTATUS status) { return status >= 0; }

std::string ToHex(const uint8_t* data, size_t size, bool upper) {
    const char* digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    std::string out;
    out.reserve(size * 2);
    for (size_t i = 0; i < size; ++i) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 0x0F]);
    }
    return out;
}

bool FromHex(const std::string& hex, Bytes& out) {
    if (hex.size() % 2) return false;
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    out.clear();
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = nibble(hex[i]), lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

std::wstring Widen(const std::string& s) { return std::wstring(s.begin(), s.end()); }

std::string Narrow(const std::wstring& s) {
    std::string out;
    for (wchar_t c : s) out.push_back(c < 128 ? static_cast<char>(c) : '?');
    return out;
}

bool Sha256(const void* data, size_t size, uint8_t out[32]) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    bool ok = BcryptOk(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0)) &&
              BcryptOk(BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0)) &&
              BcryptOk(BCryptHashData(hash, (PUCHAR)data, (ULONG)size, 0)) &&
              BcryptOk(BCryptFinishHash(hash, out, 32, 0));
    if (hash) BCryptDestroyHash(hash);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

std::string RandomHex(size_t bytes) {
    Bytes buf(bytes);
    BCryptGenRandom(nullptr, buf.data(), (ULONG)buf.size(), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return ToHex(buf.data(), buf.size(), false);
}

// ECDSA P-256 / SHA-256 aláírás ellenőrzése a beépített nyilvános kulccsal.
bool VerifySignature(const std::string& message, const Bytes& signature) {
    if (signature.size() != 64) return false;

    uint8_t digest[32];
    if (!Sha256(message.data(), message.size(), digest)) return false;

    Bytes blob(sizeof(BCRYPT_ECCKEY_BLOB) + 64);
    auto* header = reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(blob.data());
    header->dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
    header->cbKey = 32;
    memcpy(blob.data() + sizeof(BCRYPT_ECCKEY_BLOB), LICENSE_PUBLIC_KEY, 64);

    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE key = nullptr;
    bool ok = BcryptOk(BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0)) &&
              BcryptOk(BCryptImportKeyPair(alg, nullptr, BCRYPT_ECCPUBLIC_BLOB, &key, blob.data(),
                                           (ULONG)blob.size(), 0)) &&
              BcryptOk(BCryptVerifySignature(key, nullptr, digest, 32, (PUCHAR)signature.data(),
                                             (ULONG)signature.size(), 0));
    if (key) BCryptDestroyKey(key);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

// ---------------------------------------------------------------- HWID

std::wstring ReadMachineGuid() {
    HKEY key;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", 0,
                      KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS)
        return L"";
    wchar_t value[128] = {};
    DWORD size = sizeof(value) - sizeof(wchar_t);
    DWORD type = 0;
    LONG rc = RegQueryValueExW(key, L"MachineGuid", nullptr, &type, (LPBYTE)value, &size);
    RegCloseKey(key);
    return (rc == ERROR_SUCCESS && type == REG_SZ) ? std::wstring(value) : L"";
}

DWORD ReadSystemVolumeSerial() {
    wchar_t windowsDir[MAX_PATH] = {};
    GetWindowsDirectoryW(windowsDir, MAX_PATH);
    wchar_t root[4] = {windowsDir[0] ? windowsDir[0] : L'C', L':', L'\\', 0};
    DWORD serial = 0;
    GetVolumeInformationW(root, nullptr, 0, &serial, nullptr, nullptr, nullptr, 0);
    return serial;
}

std::string ReadCpuId() {
    unsigned int regs[4] = {};
    char vendor[13] = {};
#ifdef _MSC_VER
    int r[4];
    __cpuid(r, 0);
    memcpy(vendor, &r[1], 4);
    memcpy(vendor + 4, &r[3], 4);
    memcpy(vendor + 8, &r[2], 4);
    __cpuid(r, 1);
    regs[0] = (unsigned)r[0];
    regs[3] = (unsigned)r[3];
#else
    unsigned int a, b, c, d;
    if (__get_cpuid(0, &a, &b, &c, &d)) {
        memcpy(vendor, &b, 4);
        memcpy(vendor + 4, &d, 4);
        memcpy(vendor + 8, &c, 4);
    }
    if (__get_cpuid(1, &a, &b, &c, &d)) {
        regs[0] = a;
        regs[3] = d;
    }
#endif
    char buf[64];
    snprintf(buf, sizeof(buf), "%s-%08X-%08X", vendor, regs[0], regs[3]);
    return buf;
}

// ---------------------------------------------------------------- server

struct Outcome {
    bool ok = false;
    std::wstring message;
    long long expiresAt = 0;
};

bool HttpPost(const std::string& body, std::string& response) {
    bool ok = false;
    HINTERNET session = WinHttpOpen(L"AtroxLicense/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    HINTERNET connect = nullptr, request = nullptr;
    if (session) {
        WinHttpSetTimeouts(session, 5000, 5000, 8000, 8000);
        connect = WinHttpConnect(session, LICENSE_SERVER_HOST, LICENSE_SERVER_PORT, 0);
    }
    if (connect) {
        request = WinHttpOpenRequest(connect, L"POST", LICENSE_SERVER_PATH, nullptr, WINHTTP_NO_REFERER,
                                     WINHTTP_DEFAULT_ACCEPT_TYPES,
                                     LICENSE_SERVER_HTTPS ? WINHTTP_FLAG_SECURE : 0);
    }
    if (request) {
        const wchar_t* headers = L"Content-Type: application/x-www-form-urlencoded\r\n";
        if (WinHttpSendRequest(request, headers, (DWORD)-1L, (LPVOID)body.data(), (DWORD)body.size(),
                               (DWORD)body.size(), 0) &&
            WinHttpReceiveResponse(request, nullptr)) {
            ok = true;
            DWORD available = 0;
            while (WinHttpQueryDataAvailable(request, &available) && available > 0) {
                if (response.size() + available > 8192) break;
                std::string chunk(available, '\0');
                DWORD read = 0;
                if (!WinHttpReadData(request, &chunk[0], available, &read)) break;
                response.append(chunk.data(), read);
            }
        }
    }
    if (request) WinHttpCloseHandle(request);
    if (connect) WinHttpCloseHandle(connect);
    if (session) WinHttpCloseHandle(session);
    return ok;
}

std::map<std::string, std::string> ParseResponse(const std::string& text) {
    std::map<std::string, std::string> out;
    size_t start = 0;
    while (start < text.size()) {
        size_t end = text.find('\n', start);
        if (end == std::string::npos) end = text.size();
        std::string line = text.substr(start, end - start);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        size_t eq = line.find('=');
        if (eq != std::string::npos) out[line.substr(0, eq)] = line.substr(eq + 1);
        start = end + 1;
    }
    return out;
}

std::wstring StatusMessage(const std::string& status) {
    if (status == "invalid") return L"Érvénytelen kulcs.";
    if (status == "expired") return L"Ez a kulcs lejárt.";
    if (status == "banned") return L"Ez a kulcs le van tiltva.";
    if (status == "hwid_mismatch") return L"Ez a kulcs egy másik géphez van kötve.";
    if (status == "rate_limited") return L"Túl sok próbálkozás, várj egy percet.";
    if (status == "bad_request") return L"Hibás kulcs formátum.";
    return L"Ismeretlen szerver válasz.";
}

Outcome VerifyWithServer(const std::wstring& key, const std::wstring& hwid) {
    Outcome result;
    const std::string nonce = RandomHex(16);
    const std::string hwidA = Narrow(hwid);
    const std::string body = "key=" + Narrow(key) + "&hwid=" + hwidA + "&nonce=" + nonce;

    std::string raw;
    if (!HttpPost(body, raw)) {
        result.message = L"Nem sikerült kapcsolódni a licenc szerverhez.";
        return result;
    }

    auto fields = ParseResponse(raw);
    const std::string status = fields["status"];
    if (status != "ok") {
        result.message = StatusMessage(status);
        return result;
    }

    Bytes sig;
    const std::string expires = fields["expires"];
    const std::string signedMessage = nonce + "|" + status + "|" + expires + "|" + hwidA;
    if (!FromHex(fields["sig"], sig) || !VerifySignature(signedMessage, sig)) {
        result.message = L"Érvénytelen szerver válasz (aláírás hiba).";
        return result;
    }

    result.expiresAt = _strtoi64(expires.c_str(), nullptr, 10);
    if (result.expiresAt != 0 && result.expiresAt <= (long long)time(nullptr)) {
        result.message = L"Ez a kulcs lejárt.";
        return result;
    }
    result.ok = true;
    return result;
}

// ---------------------------------------------------------------- saved key

std::wstring SavedKeyPath(bool createDir) {
    wchar_t appData[MAX_PATH] = {};
    if (!GetEnvironmentVariableW(L"APPDATA", appData, MAX_PATH)) return L"";
    std::wstring dir = std::wstring(appData) + L"\\" + LICENSE_APP_FOLDER;
    if (createDir) CreateDirectoryW(dir.c_str(), nullptr);
    return dir + L"\\license.key";
}

std::wstring LoadSavedKey() {
    std::wstring path = SavedKeyPath(false);
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (file == INVALID_HANDLE_VALUE) return L"";
    char buf[128] = {};
    DWORD read = 0;
    ReadFile(file, buf, sizeof(buf) - 1, &read, nullptr);
    CloseHandle(file);
    return Widen(std::string(buf, read));
}

void StoreSavedKey(const std::wstring& key, bool remember) {
    std::wstring path = SavedKeyPath(remember);
    if (path.empty()) return;
    if (!remember) {
        DeleteFileW(path.c_str());
        return;
    }
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
    if (file == INVALID_HANDLE_VALUE) return;
    std::string data = Narrow(key);
    DWORD written = 0;
    WriteFile(file, data.data(), (DWORD)data.size(), &written, nullptr);
    CloseHandle(file);
}

std::wstring SanitizeKey(const std::wstring& input) {
    std::wstring out;
    for (wchar_t c : input) {
        if (c >= L'a' && c <= L'z') c = c - L'a' + L'A';
        if ((c >= L'A' && c <= L'Z') || (c >= L'0' && c <= L'9') || c == L'-') out.push_back(c);
    }
    return out;
}

std::wstring FormatExpiry(long long expiresAt) {
    if (expiresAt == 0) return L"örök";
    time_t t = (time_t)expiresAt;
    tm local{};
    localtime_s(&local, &t);
    wchar_t buf[64];
    wcsftime(buf, 64, L"%Y.%m.%d %H:%M", &local);
    return buf;
}

// ---------------------------------------------------------------- UI

constexpr UINT WM_APP_RESULT = WM_APP + 1;
constexpr UINT_PTR TIMER_CLOSE = 1;
constexpr int ID_KEY = 101;
constexpr int ID_REMEMBER = 102;
constexpr int ID_STATUS = 103;
constexpr int ID_HWID = 104;
constexpr int ID_COPY = 105;
constexpr int ID_TITLE = 106;
constexpr int ID_LOGIN = IDOK;
constexpr int ID_EXIT = IDCANCEL;

const COLORREF kBg = RGB(22, 22, 28);
const COLORREF kEditBg = RGB(38, 38, 46);
const COLORREF kText = RGB(235, 235, 240);
const COLORREF kMuted = RGB(140, 140, 155);
const COLORREF kAccent = RGB(229, 57, 53);
const COLORREF kError = RGB(255, 99, 99);
const COLORREF kSuccess = RGB(102, 214, 128);

struct State {
    HWND window = nullptr;
    HFONT titleFont = nullptr;
    HFONT font = nullptr;
    HFONT smallFont = nullptr;
    HBRUSH bgBrush = nullptr;
    HBRUSH editBrush = nullptr;
    COLORREF statusColor = kMuted;
    bool busy = false;
    bool success = false;
    std::wstring hwid;
    std::wstring key;
    long long expiresAt = 0;
};

State* g_state = nullptr;

struct WorkItem {
    HWND window;
    std::wstring key;
    std::wstring hwid;
};

DWORD WINAPI VerifyThread(LPVOID param) {
    WorkItem* work = static_cast<WorkItem*>(param);
    Outcome* outcome = new Outcome(VerifyWithServer(work->key, work->hwid));
    if (!PostMessageW(work->window, WM_APP_RESULT, 0, (LPARAM)outcome)) delete outcome;
    delete work;
    return 0;
}

void SetStatus(HWND window, const std::wstring& text, COLORREF color) {
    g_state->statusColor = color;
    SetDlgItemTextW(window, ID_STATUS, text.c_str());
    InvalidateRect(GetDlgItem(window, ID_STATUS), nullptr, TRUE);
}

void SetBusy(HWND window, bool busy) {
    g_state->busy = busy;
    EnableWindow(GetDlgItem(window, ID_KEY), !busy);
    EnableWindow(GetDlgItem(window, ID_LOGIN), !busy);
    EnableWindow(GetDlgItem(window, ID_REMEMBER), !busy);
}

void StartLogin(HWND window) {
    if (g_state->busy || g_state->success) return;
    wchar_t buf[128] = {};
    GetDlgItemTextW(window, ID_KEY, buf, 128);
    std::wstring key = SanitizeKey(buf);
    if (key.size() < 4) {
        SetStatus(window, L"Add meg a kulcsodat.", kError);
        SetFocus(GetDlgItem(window, ID_KEY));
        return;
    }
    g_state->key = key;
    if (IsDlgButtonChecked(window, ID_REMEMBER) != BST_CHECKED) StoreSavedKey(L"", false);
    SetBusy(window, true);
    SetStatus(window, L"Ellenőrzés...", kMuted);

    auto* work = new WorkItem{window, key, g_state->hwid};
    HANDLE thread = CreateThread(nullptr, 0, VerifyThread, work, 0, nullptr);
    if (thread) {
        CloseHandle(thread);
    } else {
        delete work;
        SetBusy(window, false);
        SetStatus(window, L"Belső hiba (szál indítása).", kError);
    }
}

HWND AddControl(HWND parent, const wchar_t* cls, const wchar_t* text, DWORD style, int x, int y, int w, int h,
                int id, HFONT font, DWORD exStyle = 0) {
    HWND control = CreateWindowExW(exStyle, cls, text, WS_CHILD | WS_VISIBLE | style, x, y, w, h, parent,
                                   (HMENU)(INT_PTR)id, GetModuleHandleW(nullptr), nullptr);
    SendMessageW(control, WM_SETFONT, (WPARAM)font, TRUE);
    return control;
}

void CreateControls(HWND window) {
    State& s = *g_state;
    AddControl(window, L"STATIC", LICENSE_APP_TITLE, SS_CENTER, 20, 22, 380, 34, ID_TITLE, s.titleFont);
    AddControl(window, L"STATIC", L"Add meg a licenc kulcsodat a belépéshez", SS_CENTER, 20, 60, 380, 20, 0,
               s.smallFont);

    HWND edit = AddControl(window, L"EDIT", L"", WS_TABSTOP | WS_BORDER | ES_AUTOHSCROLL | ES_UPPERCASE | ES_CENTER,
                           30, 92, 360, 30, ID_KEY, s.font);
    SendMessageW(edit, EM_SETLIMITTEXT, 64, 0);
    SendMessageW(edit, EM_SETCUEBANNER, TRUE, (LPARAM)L"ATRX-XXXXX-XXXXX-XXXXX");

    HWND remember = AddControl(window, L"BUTTON", L"Kulcs megjegyzése", WS_TABSTOP | BS_AUTOCHECKBOX, 30, 130, 200,
                               22, ID_REMEMBER, s.smallFont);
    SetWindowTheme(remember, L"", L"");

    AddControl(window, L"BUTTON", L"Belépés", WS_TABSTOP | BS_DEFPUSHBUTTON, 30, 162, 175, 36, ID_LOGIN, s.font);
    AddControl(window, L"BUTTON", L"Kilépés", WS_TABSTOP | BS_PUSHBUTTON, 215, 162, 175, 36, ID_EXIT, s.font);

    AddControl(window, L"STATIC", L"", SS_CENTER, 20, 210, 380, 40, ID_STATUS, s.font);

    std::wstring hwidLabel = L"HWID: " + s.hwid.substr(0, 16) + L"...";
    AddControl(window, L"STATIC", hwidLabel.c_str(), SS_LEFT | SS_CENTERIMAGE, 30, 262, 270, 22, ID_HWID,
               s.smallFont);
    AddControl(window, L"BUTTON", L"HWID másolása", WS_TABSTOP | BS_PUSHBUTTON, 290, 262, 100, 22, ID_COPY,
               s.smallFont);

    std::wstring saved = SanitizeKey(LoadSavedKey());
    if (!saved.empty()) {
        SetWindowTextW(edit, saved.c_str());
        CheckDlgButton(window, ID_REMEMBER, BST_CHECKED);
    }
    SetFocus(edit);
}

void CopyToClipboard(HWND window, const std::wstring& text) {
    if (!OpenClipboard(window)) return;
    EmptyClipboard();
    size_t bytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL mem = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (mem) {
        memcpy(GlobalLock(mem), text.c_str(), bytes);
        GlobalUnlock(mem);
        if (!SetClipboardData(CF_UNICODETEXT, mem)) GlobalFree(mem);
    }
    CloseClipboard();
}

LRESULT CALLBACK WndProc(HWND window, UINT msg, WPARAM wParam, LPARAM lParam) {
    State& s = *g_state;
    switch (msg) {
        case WM_CREATE:
            CreateControls(window);
            return 0;

        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case ID_LOGIN:
                    StartLogin(window);
                    return 0;
                case ID_EXIT:
                    DestroyWindow(window);
                    return 0;
                case ID_COPY:
                    CopyToClipboard(window, s.hwid);
                    SetStatus(window, L"HWID a vágólapra másolva.", kMuted);
                    return 0;
            }
            break;

        case WM_APP_RESULT: {
            Outcome* outcome = reinterpret_cast<Outcome*>(lParam);
            if (outcome->ok) {
                s.success = true;
                s.expiresAt = outcome->expiresAt;
                StoreSavedKey(s.key, IsDlgButtonChecked(window, ID_REMEMBER) == BST_CHECKED);
                SetStatus(window, L"Sikeres belépés!\nLejárat: " + FormatExpiry(outcome->expiresAt), kSuccess);
                SetTimer(window, TIMER_CLOSE, 1200, nullptr);
            } else {
                SetBusy(window, false);
                SetStatus(window, outcome->message, kError);
                SetFocus(GetDlgItem(window, ID_KEY));
            }
            delete outcome;
            return 0;
        }

        case WM_TIMER:
            if (wParam == TIMER_CLOSE) {
                KillTimer(window, TIMER_CLOSE);
                DestroyWindow(window);
            }
            return 0;

        case WM_CTLCOLORSTATIC:
        case WM_CTLCOLORBTN: {
            HDC dc = (HDC)wParam;
            int id = GetDlgCtrlID((HWND)lParam);
            COLORREF color = kText;
            if (id == ID_STATUS) color = s.statusColor;
            else if (id == ID_TITLE) color = kAccent;
            else if (id == ID_HWID) color = kMuted;
            SetTextColor(dc, color);
            SetBkColor(dc, kBg);
            return (LRESULT)s.bgBrush;
        }

        case WM_CTLCOLOREDIT: {
            HDC dc = (HDC)wParam;
            SetTextColor(dc, kText);
            SetBkColor(dc, kEditBg);
            return (LRESULT)s.editBrush;
        }

        case WM_CLOSE:
            DestroyWindow(window);
            return 0;

        case WM_DESTROY:
            KillTimer(window, TIMER_CLOSE);
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(window, msg, wParam, lParam);
}

HFONT MakeFont(int height, int weight) {
    return CreateFontW(-height, 0, 0, 0, weight, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                       CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
}

}  // namespace

std::wstring GetHwid() {
    std::string raw = "MG:" + Narrow(ReadMachineGuid());
    char serial[16];
    snprintf(serial, sizeof(serial), "%08lX", (unsigned long)ReadSystemVolumeSerial());
    raw += "|VS:";
    raw += serial;
    raw += "|CPU:" + ReadCpuId();

    uint8_t digest[32] = {};
    Sha256(raw.data(), raw.size(), digest);
    return Widen(ToHex(digest, sizeof(digest), true));
}

bool Run(HINSTANCE instance, Result* result) {
    State state;
    state.hwid = GetHwid();
    state.titleFont = MakeFont(26, FW_BOLD);
    state.font = MakeFont(16, FW_NORMAL);
    state.smallFont = MakeFont(13, FW_NORMAL);
    state.bgBrush = CreateSolidBrush(kBg);
    state.editBrush = CreateSolidBrush(kEditBg);
    g_state = &state;

    const wchar_t* className = L"AtroxLicenseGateWindow";
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = instance;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon = LoadIconW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(1));
    if (!wc.hIcon) wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wc.hbrBackground = state.bgBrush;
    wc.lpszClassName = className;
    RegisterClassExW(&wc);

    const DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
    RECT rect = {0, 0, 420, 300};
    AdjustWindowRectEx(&rect, style, FALSE, WS_EX_CONTROLPARENT);
    int width = rect.right - rect.left, height = rect.bottom - rect.top;
    int x = (GetSystemMetrics(SM_CXSCREEN) - width) / 2;
    int y = (GetSystemMetrics(SM_CYSCREEN) - height) / 2;

    std::wstring title = std::wstring(LICENSE_APP_TITLE) + L" - Bejelentkezés";
    HWND window = CreateWindowExW(WS_EX_CONTROLPARENT, className, title.c_str(), style, x, y, width, height,
                                  nullptr, nullptr, instance, nullptr);
    if (window) {
        state.window = window;
        ShowWindow(window, SW_SHOW);
        SetForegroundWindow(window);

        MSG msg;
        while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
            if (!IsDialogMessageW(window, &msg)) {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }

    UnregisterClassW(className, instance);
    DeleteObject(state.titleFont);
    DeleteObject(state.font);
    DeleteObject(state.smallFont);
    DeleteObject(state.bgBrush);
    DeleteObject(state.editBrush);
    g_state = nullptr;

    if (state.success && result) {
        result->key = state.key;
        result->hwid = state.hwid;
        result->expiresAt = state.expiresAt;
    }
    return state.success;
}

}  // namespace LicenseGate
