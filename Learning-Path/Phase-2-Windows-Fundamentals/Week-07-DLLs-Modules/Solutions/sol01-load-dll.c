/*
 * SOLUTION - EXERCISE 01: Load DLL
 * Chargement dynamique de user32.dll et appel de MessageBoxA
 */

#include <windows.h>
#include <stdio.h>

// Typedef pour MessageBoxA
typedef int (WINAPI *pfnMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);

BOOL LoadAndCallMessageBox(const char* text, const char* caption)
{
    HMODULE hUser32 = LoadLibraryA("user32.dll");
    if (!hUser32) {
        return FALSE;
    }

    FARPROC pMessageBoxA = GetProcAddress(hUser32, "MessageBoxA");
    if (!pMessageBoxA) {
        FreeLibrary(hUser32);
        return FALSE;
    }

    pfnMessageBoxA fnMsgBox = (pfnMessageBoxA)pMessageBoxA;
    fnMsgBox(NULL, text, caption, MB_OK | MB_ICONINFORMATION);

    FreeLibrary(hUser32);
    return TRUE;
}

BOOL LoadAndCallMessageBoxVerbose(const char* text, const char* caption)
{
    printf("[*] Chargement de user32.dll...\n");
    HMODULE hUser32 = LoadLibraryA("user32.dll");

    if (!hUser32) {
        printf("[-] Échec LoadLibrary\n");
        printf("[-] Code d'erreur: %lu\n", GetLastError());
        return FALSE;
    }

    printf("[+] user32.dll chargé à: 0x%p\n", hUser32);

    printf("[*] Résolution de MessageBoxA...\n");
    FARPROC pMessageBoxA = GetProcAddress(hUser32, "MessageBoxA");

    if (!pMessageBoxA) {
        printf("[-] Échec GetProcAddress\n");
        printf("[-] Code d'erreur: %lu\n", GetLastError());
        FreeLibrary(hUser32);
        return FALSE;
    }

    printf("[+] MessageBoxA trouvé à: 0x%p\n", pMessageBoxA);

    printf("[*] Appel de MessageBoxA...\n");
    pfnMessageBoxA fnMsgBox = (pfnMessageBoxA)pMessageBoxA;
    int result = fnMsgBox(NULL, text, caption, MB_OK | MB_ICONINFORMATION);

    printf("[+] MessageBox retourné: %d\n", result);

    printf("[*] Déchargement de user32.dll...\n");
    FreeLibrary(hUser32);
    printf("[+] user32.dll déchargé\n");

    return TRUE;
}

// Version Unicode (bonus)
typedef int (WINAPI *pfnMessageBoxW)(HWND, LPCWSTR, LPCWSTR, UINT);

BOOL LoadAndCallMessageBoxW(const wchar_t* text, const wchar_t* caption)
{
    HMODULE hUser32 = LoadLibraryW(L"user32.dll");
    if (!hUser32) {
        return FALSE;
    }

    FARPROC pMessageBoxW = GetProcAddress(hUser32, "MessageBoxW");
    if (!pMessageBoxW) {
        FreeLibrary(hUser32);
        return FALSE;
    }

    pfnMessageBoxW fnMsgBox = (pfnMessageBoxW)pMessageBoxW;
    fnMsgBox(NULL, text, caption, MB_OK | MB_ICONINFORMATION);

    FreeLibrary(hUser32);
    return TRUE;
}

int main(void)
{
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║         SOLUTION 01: Load DLL                            ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n\n");

    printf("=== TEST 1: Appel basique ===\n");
    if (LoadAndCallMessageBox("Hello from dynamic loading!", "Exercise 01")) {
        printf("[+] Test 1 réussi\n\n");
    }

    printf("=== TEST 2: Mode verbose ===\n");
    if (LoadAndCallMessageBoxVerbose("Message avec logs détaillés", "Verbose Mode")) {
        printf("[+] Test 2 réussi\n\n");
    }

    printf("=== TEST 3: Unicode (BONUS) ===\n");
    if (LoadAndCallMessageBoxW(L"Unicode message!", L"Unicode Title")) {
        printf("[+] Test 3 réussi\n\n");
    }

    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║ POINTS CLÉS                                               ║\n");
    printf("╠═══════════════════════════════════════════════════════════╣\n");
    printf("║ • LoadLibraryA charge la DLL en mémoire                  ║\n");
    printf("║ • GetProcAddress résout l'adresse de la fonction         ║\n");
    printf("║ • Typedef permet le cast correct du pointeur             ║\n");
    printf("║ • FreeLibrary décharge la DLL (compteur de référence)    ║\n");
    printf("║ • user32.dll n'apparaît PAS dans l'import table!         ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n");

    return 0;
}
