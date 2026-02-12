/*
 * OBJECTIF  : Comprendre la capture d'ecran sur Linux
 * PREREQUIS : Bases C, X11, framebuffer, formats image
 * COMPILE   : gcc -o example example.c
 *
 * Ce programme demontre les techniques de capture d'ecran
 * sur Linux : X11 (XGetImage), Wayland, framebuffer (/dev/fb0),
 * et format BMP. Demonstration pedagogique.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

/*
 * Etape 1 : Architecture graphique Linux
 */
static void explain_graphics_stack(void) {
    printf("[*] Etape 1 : Pile graphique Linux\n\n");

    printf("    ┌──────────────────────────────────────────┐\n");
    printf("    │          Applications GUI                 │\n");
    printf("    ├──────────────────────────────────────────┤\n");
    printf("    │  X11 (Xorg)       │  Wayland Compositor  │\n");
    printf("    │  ┌──────────┐     │  ┌───────────────┐   │\n");
    printf("    │  │ XShmGet  │     │  │ wlr-screencopy│   │\n");
    printf("    │  │ Image    │     │  │ pipewire      │   │\n");
    printf("    │  └──────────┘     │  └───────────────┘   │\n");
    printf("    ├──────────────────────────────────────────┤\n");
    printf("    │  DRM/KMS (Direct Rendering Manager)      │\n");
    printf("    │  /dev/dri/card0                          │\n");
    printf("    ├──────────────────────────────────────────┤\n");
    printf("    │  Framebuffer  /dev/fb0                   │\n");
    printf("    │  (legacy, acces direct aux pixels)       │\n");
    printf("    ├──────────────────────────────────────────┤\n");
    printf("    │  GPU Hardware                            │\n");
    printf("    └──────────────────────────────────────────┘\n\n");

    printf("    Methodes de capture :\n");
    printf("    Methode          | Serveur | Avantages\n");
    printf("    ─────────────────|─────────|──────────────────────\n");
    printf("    XGetImage/XShm   | X11     | Universel, simple\n");
    printf("    xdg-screenshot   | Both    | API portale\n");
    printf("    wlr-screencopy   | Wayland | Natif Wayland\n");
    printf("    PipeWire         | Wayland | Moderne, permissions\n");
    printf("    /dev/fb0         | Aucun   | Pas besoin de serveur\n");
    printf("    DRM              | Aucun   | Moderne, GPU direct\n\n");
}

/*
 * Etape 2 : Capture X11
 */
static void explain_x11_capture(void) {
    printf("[*] Etape 2 : Capture d'ecran via X11\n\n");

    printf("    Code X11 (necessite -lX11) :\n");
    printf("    ───────────────────────────────────\n");
    printf("    #include <X11/Xlib.h>\n");
    printf("    #include <X11/Xutil.h>\n\n");

    printf("    Display *display = XOpenDisplay(NULL);\n");
    printf("    Window root = DefaultRootWindow(display);\n");
    printf("    XWindowAttributes attrs;\n");
    printf("    XGetWindowAttributes(display, root, &attrs);\n\n");

    printf("    // Capturer l'ecran entier\n");
    printf("    XImage *img = XGetImage(display, root,\n");
    printf("        0, 0, attrs.width, attrs.height,\n");
    printf("        AllPlanes, ZPixmap);\n\n");

    printf("    // Acceder aux pixels\n");
    printf("    for (int y = 0; y < img->height; y++) {\n");
    printf("        for (int x = 0; x < img->width; x++) {\n");
    printf("            unsigned long pixel = XGetPixel(img, x, y);\n");
    printf("            uint8_t r = (pixel >> 16) & 0xFF;\n");
    printf("            uint8_t g = (pixel >>  8) & 0xFF;\n");
    printf("            uint8_t b = (pixel      ) & 0xFF;\n");
    printf("        }\n");
    printf("    }\n\n");

    printf("    XDestroyImage(img);\n");
    printf("    XCloseDisplay(display);\n\n");

    printf("    Optimisation avec XShm (shared memory) :\n");
    printf("    ───────────────────────────────────\n");
    printf("    // XShmCreateImage + XShmGetImage\n");
    printf("    // Beaucoup plus rapide (pas de copie reseau)\n");
    printf("    // Ideal pour la capture repetee\n\n");

    /* Verifier si DISPLAY est defini */
    char *display = getenv("DISPLAY");
    printf("    Variable DISPLAY : %s\n",
           display ? display : "(non defini - pas de X11)");

    char *wayland = getenv("WAYLAND_DISPLAY");
    printf("    WAYLAND_DISPLAY  : %s\n\n",
           wayland ? wayland : "(non defini - pas de Wayland)");
}

/*
 * Etape 3 : Format BMP simplifie
 */
static void explain_bmp_format(void) {
    printf("[*] Etape 3 : Format BMP pour la sauvegarde\n\n");

    printf("    Structure d'un fichier BMP :\n");
    printf("    ───────────────────────────────────\n");
    printf("    ┌────────────────────────────────┐\n");
    printf("    │  BMP File Header  (14 octets)  │\n");
    printf("    │  'BM' | fileSize | offset      │\n");
    printf("    ├────────────────────────────────┤\n");
    printf("    │  DIB Header       (40 octets)  │\n");
    printf("    │  width | height | bpp | ...    │\n");
    printf("    ├────────────────────────────────┤\n");
    printf("    │  Pixel Data (BGR, bottom-up)   │\n");
    printf("    │  row padding to 4-byte align   │\n");
    printf("    └────────────────────────────────┘\n\n");

    printf("    Code d'ecriture BMP :\n");
    printf("    ───────────────────────────────────\n");
    printf("    typedef struct __attribute__((packed)) {\n");
    printf("        uint16_t type;       // 'BM' = 0x4D42\n");
    printf("        uint32_t size;       // taille du fichier\n");
    printf("        uint16_t reserved1;\n");
    printf("        uint16_t reserved2;\n");
    printf("        uint32_t offset;     // offset vers les pixels\n");
    printf("    } bmp_file_header_t;\n\n");

    printf("    typedef struct __attribute__((packed)) {\n");
    printf("        uint32_t size;       // 40\n");
    printf("        int32_t  width;\n");
    printf("        int32_t  height;\n");
    printf("        uint16_t planes;     // 1\n");
    printf("        uint16_t bpp;        // 24\n");
    printf("        uint32_t compression;// 0 (aucune)\n");
    printf("        uint32_t img_size;\n");
    printf("        // ... (reste a 0)\n");
    printf("    } bmp_info_header_t;\n\n");

    /* Demo : creer un petit BMP en memoire */
    int w = 4, h = 3;
    int row_size = (w * 3 + 3) & ~3;
    int img_size = row_size * h;
    int file_size = 54 + img_size;

    printf("    Exemple : image %dx%d\n", w, h);
    printf("    Row size (avec padding) : %d octets\n", row_size);
    printf("    Image size : %d octets\n", img_size);
    printf("    File size  : %d octets\n\n", file_size);
}

/*
 * Etape 4 : Capture via framebuffer
 */
static void explain_framebuffer(void) {
    printf("[*] Etape 4 : Capture via framebuffer (/dev/fb0)\n\n");

    printf("    Le framebuffer est un acces direct aux pixels.\n");
    printf("    Pas besoin de X11 ou Wayland.\n\n");

    printf("    Code de capture framebuffer :\n");
    printf("    ───────────────────────────────────\n");
    printf("    #include <linux/fb.h>\n");
    printf("    #include <sys/ioctl.h>\n");
    printf("    #include <sys/mman.h>\n\n");

    printf("    int fb = open(\"/dev/fb0\", O_RDONLY);\n\n");

    printf("    // Obtenir les informations d'ecran\n");
    printf("    struct fb_var_screeninfo vinfo;\n");
    printf("    ioctl(fb, FBIOGET_VSCREENINFO, &vinfo);\n");
    printf("    // vinfo.xres, vinfo.yres, vinfo.bits_per_pixel\n\n");

    printf("    struct fb_fix_screeninfo finfo;\n");
    printf("    ioctl(fb, FBIOGET_FSCREENINFO, &finfo);\n");
    printf("    // finfo.line_length = octets par ligne\n\n");

    printf("    // Mapper le framebuffer en memoire\n");
    printf("    long size = vinfo.yres * finfo.line_length;\n");
    printf("    char *fb_data = mmap(NULL, size,\n");
    printf("        PROT_READ, MAP_SHARED, fb, 0);\n\n");

    printf("    // Copier les pixels\n");
    printf("    // Format : generalement BGRA (32 bits)\n");
    printf("    // Ecrire en BMP ou PNG\n\n");

    printf("    munmap(fb_data, size);\n");
    printf("    close(fb);\n\n");

    /* Verifier si /dev/fb0 existe */
    struct stat st;
    if (stat("/dev/fb0", &st) == 0)
        printf("    /dev/fb0 : present\n\n");
    else
        printf("    /dev/fb0 : non disponible (%s)\n\n", strerror(errno));
}

/*
 * Etape 5 : Capture via outils externes
 */
static void explain_external_tools(void) {
    printf("[*] Etape 5 : Capture via outils externes (fork/exec)\n\n");

    printf("    Methode simple : utiliser des outils existants\n\n");

    printf("    X11 :\n");
    printf("    ───────────────────────────────────\n");
    printf("    xwd -root -silent | convert - /tmp/.s.png\n");
    printf("    import -window root /tmp/.s.png  (ImageMagick)\n");
    printf("    scrot /tmp/.s.png\n");
    printf("    xdotool + xwd\n\n");

    printf("    Wayland :\n");
    printf("    ───────────────────────────────────\n");
    printf("    grim /tmp/.s.png (wlroots)\n");
    printf("    gnome-screenshot -f /tmp/.s.png\n\n");

    printf("    Universel :\n");
    printf("    ───────────────────────────────────\n");
    printf("    xdg-desktop-portal screenshot\n\n");

    printf("    Code d'appel depuis un implant :\n");
    printf("    ───────────────────────────────────\n");
    printf("    FILE *fp = popen(\"scrot -z -o /tmp/.s.png 2>&1\", \"r\");\n");
    printf("    if (fp) {\n");
    printf("        pclose(fp);\n");
    printf("        // Lire /tmp/.s.png et l'envoyer au C2\n");
    printf("        // Puis supprimer le fichier\n");
    printf("        unlink(\"/tmp/.s.png\");\n");
    printf("    }\n\n");

    /* Verifier les outils disponibles */
    printf("    Outils de capture disponibles :\n");
    const char *tools[] = {"scrot", "import", "xwd", "grim",
                           "gnome-screenshot", NULL};
    for (int i = 0; tools[i]; i++) {
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "which %s", tools[i]);
        FILE *fp = popen(cmd, "r");
        if (fp) {
            char path[128] = {0};
            if (fgets(path, sizeof(path), fp)) {
                path[strcspn(path, "\n")] = '\0';
                printf("      %s : %s\n", tools[i], path);
            } else {
                printf("      %s : non trouve\n", tools[i]);
            }
            pclose(fp);
        }
    }
    printf("\n");
}

/*
 * Etape 6 : Exfiltration et compression
 */
static void explain_exfiltration(void) {
    printf("[*] Etape 6 : Exfiltration de captures\n\n");

    printf("    Probleme : les screenshots sont volumineux\n");
    printf("    1920x1080 BMP 24bit = ~6 MB\n\n");

    printf("    Solutions :\n");
    printf("    ───────────────────────────────────\n");
    printf("    1. Compression JPEG (lossy, petit)\n");
    printf("       -> libjpeg ou outils CLI\n\n");
    printf("    2. PNG (lossless, moyen)\n");
    printf("       -> libpng ou popen(\"convert\")\n\n");
    printf("    3. Reduire la resolution\n");
    printf("       -> Capturer 1 pixel sur N\n\n");
    printf("    4. Capturer uniquement les changements\n");
    printf("       -> Diff avec la capture precedente\n\n");
    printf("    5. Encodage base64 pour transit HTTP\n");
    printf("       -> Augmente la taille de 33%%\n\n");

    printf("    Pipeline complet :\n");
    printf("    ───────────────────────────────────\n");
    printf("    1. Capturer (XGetImage ou outil)\n");
    printf("    2. Convertir en JPEG (qualite 50%%)\n");
    printf("    3. Encoder en base64\n");
    printf("    4. POST vers le C2\n");
    printf("    5. Supprimer les fichiers temporaires\n\n");
}

/*
 * Etape 7 : Detection
 */
static void explain_detection(void) {
    printf("[*] Etape 7 : Detection des captures d'ecran\n\n");

    printf("    Indicateurs :\n");
    printf("    ───────────────────────────────────\n");
    printf("    1. Appels XGetImage/XShmGetImage frequents\n");
    printf("       -> Monitorer avec xtrace ou ltrace\n\n");
    printf("    2. Fichiers image dans /tmp, /dev/shm\n");
    printf("       -> Surveiller les creations de .png, .jpg, .bmp\n\n");
    printf("    3. Acces a /dev/fb0 par un processus non-graphique\n");
    printf("       -> auditd sur les ouvertures de /dev/fb0\n\n");
    printf("    4. Processus utilisant scrot/import/grim\n");
    printf("       -> Surveiller les executions de ces outils\n\n");
    printf("    5. POST HTTP volumineux (exfiltration)\n");
    printf("       -> Analyse du trafic reseau\n\n");

    printf("    Protections :\n");
    printf("    - Wayland : isolation des applications\n");
    printf("    - SELinux : restreindre l'acces aux APIs graphiques\n");
    printf("    - Permissions sur /dev/fb0\n");
    printf("    - Monitorer les processus avec connexion X11\n\n");
}

int main(void) {
    printf("[*] Demo : Screenshot Linux\n\n");

    explain_graphics_stack();
    explain_x11_capture();
    explain_bmp_format();
    explain_framebuffer();
    explain_external_tools();
    explain_exfiltration();
    explain_detection();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
