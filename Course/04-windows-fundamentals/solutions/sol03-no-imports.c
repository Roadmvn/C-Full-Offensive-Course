/*
 * SOLUTION - EXERCISE 03: No Imports
 * MessageBox sans aucune trace dans l'import table
 */

#include <windows.h>
#include <stdio.h>

#define XOR_KEY 0x42

void xor_decrypt_string(const unsigned char* encrypted, size_t length, unsigned char key, char* output)
{
    for (size_t i = 0; i < length; i++) {
        output[i] = encrypted[i] ^ key;
    }
    output[length] = '\0';
}

// "user32.dll\0" XOR 0x42
// Script Python: ''.join(f'0x{ord(c) ^ 0x42:02x}, ' for c in "user32.dll\0")
const unsigned char ENC_USER32_DLL[] = {
    0x37, 0x33, 0x25, 0x30, 0x75, 0x74, 0x2e, 0x24, 0x2e, 0x2e, 0x42
};

// "MessageBoxA\0" XOR 0x42
// Script Python: ''.join(f'0x{ord(c) ^ 0x42:02x}, ' for c in "MessageBoxA\0")
const unsigned char ENC_MESSAGEBOXA[] = {
    0x2f, 0x27, 0x33, 0x33, 0x27, 0x2f, 0x27, 0x08, 0x2d, 0x38, 0x03, 0x42
};

typedef int (WINAPI *pfnMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);

#define MB_OK_CUSTOM 0x00000000
#define MB_ICONINFORMATION_CUSTOM 0x00000040

void* ResolveMessageBoxA(void)
{
    char dllName[32] = {0};
    char funcName[32] = {0};

    // Déchiffrer user32.dll
    xor_decrypt_string(ENC_USER32_DLL, sizeof(ENC_USER32_DLL) - 1, XOR_KEY, dllName);

    HMODULE hUser32 = LoadLibraryA(dllName);
    if (!hUser32) {
        SecureZeroMemory(dllName, sizeof(dllName));
        return NULL;
    }

    // Déchiffrer MessageBoxA
    xor_decrypt_string(ENC_MESSAGEBOXA, sizeof(ENC_MESSAGEBOXA) - 1, XOR_KEY, funcName);

    FARPROC pFunc = GetProcAddress(hUser32, funcName);

    // Nettoyer les buffers (OPSEC)
    SecureZeroMemory(dllName, sizeof(dllName));
    SecureZeroMemory(funcName, sizeof(funcName));

    return pFunc;
}

BOOL ShowMessageBox(const char* text, const char* caption)
{
    printf("[*] Résolution dynamique de MessageBoxA...\n");

    void* pFunc = ResolveMessageBoxA();
    if (!pFunc) {
        printf("[-] Échec résolution\n");
        return FALSE;
    }

    printf("[+] MessageBoxA résolu: 0x%p\n", pFunc);

    pfnMessageBoxA fnMsgBox = (pfnMessageBoxA)pFunc;
    fnMsgBox(NULL, text, caption, MB_OK_CUSTOM | MB_ICONINFORMATION_CUSTOM);

    return TRUE;
}

BOOL IsLegitEnvironment(void)
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);

    if (si.dwNumberOfProcessors < 2) {
        printf("[!] Suspect: moins de 2 CPUs\n");
        return FALSE;
    }

    DWORD uptime = GetTickCount();
    if (uptime < 600000) {  // 10 minutes
        printf("[!] Suspect: uptime < 10 minutes\n");
        return FALSE;
    }

    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    DWORD ramGB = (DWORD)(ms.ullTotalPhys / (1024 * 1024 * 1024));

    if (ramGB < 4) {
        printf("[!] Suspect: RAM < 4GB\n");
        return FALSE;
    }

    return TRUE;
}

void PrintBanner(void)
{
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║         SOLUTION 03: No Imports                          ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n\n");
}

void ValidateNoImports(void)
{
    printf("\n╔═══════════════════════════════════════════════════════════╗\n");
    printf("║ VALIDATION                                                ║\n");
    printf("╠═══════════════════════════════════════════════════════════╣\n");
    printf("║ Commandes de vérification:                               ║\n");
    printf("║                                                           ║\n");
    printf("║ Windows:                                                  ║\n");
    printf("║   dumpbin /imports sol03-no-imports.exe                  ║\n");
    printf("║   → Seulement KERNEL32.dll                               ║\n");
    printf("║                                                           ║\n");
    printf("║   strings sol03-no-imports.exe | findstr /i user32       ║\n");
    printf("║   → Rien trouvé                                          ║\n");
    printf("║                                                           ║\n");
    printf("║ Linux (wine):                                             ║\n");
    printf("║   strings sol03-no-imports.exe | grep -i messagebox      ║\n");
    printf("║   → Rien trouvé                                          ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n");
}

int main(void)
{
    PrintBanner();

    printf("=== CHECK: Environnement ===\n");
    if (!IsLegitEnvironment()) {
        printf("[-] Environnement suspect\n");
        printf("[*] Skip exécution (sandbox evasion)\n");
        return 0;
    }
    printf("[+] Environnement légitime\n\n");

    printf("=== TEST: MessageBox dynamique ===\n");
    if (ShowMessageBox("Import table invisible!", "Dynamic Resolution Success")) {
        printf("[+] Succès\n");
    } else {
        printf("[-] Échec\n");
    }

    ValidateNoImports();

    printf("\n╔═══════════════════════════════════════════════════════════╗\n");
    printf("║ TECHNIQUES UTILISÉES                                      ║\n");
    printf("╠═══════════════════════════════════════════════════════════╣\n");
    printf("║ • String obfuscation (XOR)                               ║\n");
    printf("║ • Dynamic API resolution                                 ║\n");
    printf("║ • Import table minimale (kernel32 seulement)             ║\n");
    printf("║ • Memory cleaning (SecureZeroMemory)                     ║\n");
    printf("║ • Anti-sandbox checks                                    ║\n");
    printf("║                                                           ║\n");
    printf("║ Résultat: Invisible à l'analyse statique!                ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n");

    return 0;
}

/*
 * NOTES DE SÉCURITÉ:
 *
 * Ce programme démontre des techniques offensives réelles:
 * - Strings obfusquées empêchent 'strings.exe' de voir les APIs
 * - Import table vide empêche analyse PE statique
 * - SecureZeroMemory empêche dump mémoire de révéler les APIs
 * - Anti-sandbox évite exécution dans environnements d'analyse
 *
 * Un analyste devra:
 * 1. Exécuter le binaire (risqué)
 * 2. Décompiler et analyser manuellement le code
 * 3. Identifier le pattern XOR
 * 4. Déchiffrer les strings manuellement
 *
 * Protection supplémentaires possibles:
 * - API hashing (pas de strings du tout)
 * - PEB walking (pas de GetModuleHandle)
 * - Manual mapping (pas de LoadLibrary)
 * - Polymorphisme du code XOR
 */
