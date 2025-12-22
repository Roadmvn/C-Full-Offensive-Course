/*
 * SOLUTION - EXERCISE 02: API Resolver
 * Système générique et professionnel de résolution d'APIs
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

#define MAX_DLL_CACHE 16

typedef struct _DLL_CACHE_ENTRY {
    char name[64];
    HMODULE handle;
    BOOL loaded;
} DLL_CACHE_ENTRY;

DLL_CACHE_ENTRY g_DllCache[MAX_DLL_CACHE] = {0};

HMODULE GetOrLoadDll(const char* dllName)
{
    // Chercher dans le cache
    for (int i = 0; i < MAX_DLL_CACHE; i++) {
        if (g_DllCache[i].loaded && _stricmp(g_DllCache[i].name, dllName) == 0) {
            return g_DllCache[i].handle;
        }
    }

    // Pas trouvé, charger
    HMODULE hDll = LoadLibraryA(dllName);
    if (!hDll) {
        return NULL;
    }

    // Ajouter au cache
    for (int i = 0; i < MAX_DLL_CACHE; i++) {
        if (!g_DllCache[i].loaded) {
            strncpy_s(g_DllCache[i].name, sizeof(g_DllCache[i].name), dllName, _TRUNCATE);
            g_DllCache[i].handle = hDll;
            g_DllCache[i].loaded = TRUE;
            break;
        }
    }

    return hDll;
}

FARPROC ResolveAPI(const char* dllName, const char* apiName)
{
    HMODULE hDll = GetOrLoadDll(dllName);
    if (!hDll) {
        printf("[-] Échec chargement DLL: %s\n", dllName);
        return NULL;
    }

    FARPROC pFunc = GetProcAddress(hDll, apiName);
    if (!pFunc) {
        printf("[-] Échec résolution API: %s!%s\n", dllName, apiName);
        return NULL;
    }

    return pFunc;
}

// Typedefs
typedef LPVOID (WINAPI *pfnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI *pfnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL (WINAPI *pfnVirtualFree)(LPVOID, SIZE_T, DWORD);
typedef HANDLE (WINAPI *pfnCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD (WINAPI *pfnWaitForSingleObject)(HANDLE, DWORD);
typedef BOOL (WINAPI *pfnCloseHandle)(HANDLE);
typedef DWORD (WINAPI *pfnGetCurrentProcessId)(void);
typedef void (WINAPI *pfnSleep)(DWORD);

typedef struct _API_TABLE {
    pfnVirtualAlloc         VirtualAlloc;
    pfnVirtualProtect       VirtualProtect;
    pfnVirtualFree          VirtualFree;
    pfnCreateThread         CreateThread;
    pfnWaitForSingleObject  WaitForSingleObject;
    pfnCloseHandle          CloseHandle;
    pfnGetCurrentProcessId  GetCurrentProcessId;
    pfnSleep                Sleep;
} API_TABLE;

API_TABLE g_Api = {0};

BOOL InitializeApiTable(void)
{
    printf("[*] Initialisation de la table d'APIs...\n");

    g_Api.VirtualAlloc = (pfnVirtualAlloc)ResolveAPI("kernel32.dll", "VirtualAlloc");
    g_Api.VirtualProtect = (pfnVirtualProtect)ResolveAPI("kernel32.dll", "VirtualProtect");
    g_Api.VirtualFree = (pfnVirtualFree)ResolveAPI("kernel32.dll", "VirtualFree");
    g_Api.CreateThread = (pfnCreateThread)ResolveAPI("kernel32.dll", "CreateThread");
    g_Api.WaitForSingleObject = (pfnWaitForSingleObject)ResolveAPI("kernel32.dll", "WaitForSingleObject");
    g_Api.CloseHandle = (pfnCloseHandle)ResolveAPI("kernel32.dll", "CloseHandle");
    g_Api.GetCurrentProcessId = (pfnGetCurrentProcessId)ResolveAPI("kernel32.dll", "GetCurrentProcessId");
    g_Api.Sleep = (pfnSleep)ResolveAPI("kernel32.dll", "Sleep");

    if (!g_Api.VirtualAlloc || !g_Api.VirtualProtect || !g_Api.CreateThread) {
        printf("[-] Échec résolution d'APIs critiques\n");
        return FALSE;
    }

    printf("[+] APIs résolues:\n");
    printf("    VirtualAlloc:        0x%p\n", g_Api.VirtualAlloc);
    printf("    VirtualProtect:      0x%p\n", g_Api.VirtualProtect);
    printf("    VirtualFree:         0x%p\n", g_Api.VirtualFree);
    printf("    CreateThread:        0x%p\n", g_Api.CreateThread);
    printf("    WaitForSingleObject: 0x%p\n", g_Api.WaitForSingleObject);
    printf("    CloseHandle:         0x%p\n", g_Api.CloseHandle);
    printf("    Sleep:               0x%p\n", g_Api.Sleep);

    return TRUE;
}

BOOL TestMemoryAPIs(void)
{
    printf("\n=== TEST: Memory APIs ===\n");

    LPVOID pMem = g_Api.VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pMem) {
        printf("[-] VirtualAlloc échoué\n");
        return FALSE;
    }
    printf("[+] Mémoire allouée: 0x%p\n", pMem);

    memcpy(pMem, "Dynamic API Test", 16);
    printf("[+] Données écrites: %s\n", (char*)pMem);

    DWORD oldProtect;
    if (!g_Api.VirtualProtect(pMem, 4096, PAGE_EXECUTE_READ, &oldProtect)) {
        printf("[-] VirtualProtect échoué\n");
        g_Api.VirtualFree(pMem, 0, MEM_RELEASE);
        return FALSE;
    }
    printf("[+] Protection changée: PAGE_EXECUTE_READ\n");

    if (!g_Api.VirtualFree(pMem, 0, MEM_RELEASE)) {
        printf("[-] VirtualFree échoué\n");
        return FALSE;
    }
    printf("[+] Mémoire libérée\n");

    return TRUE;
}

DWORD WINAPI SimpleThreadFunc(LPVOID lpParam)
{
    printf("[Thread] Démarré (PID: %lu)\n", g_Api.GetCurrentProcessId());
    g_Api.Sleep(1000);
    printf("[Thread] Terminé\n");
    return 0;
}

BOOL TestThreadAPIs(void)
{
    printf("\n=== TEST: Thread APIs ===\n");

    HANDLE hThread = g_Api.CreateThread(NULL, 0, SimpleThreadFunc, NULL, 0, NULL);
    if (!hThread) {
        printf("[-] CreateThread échoué\n");
        return FALSE;
    }
    printf("[+] Thread créé: handle 0x%p\n", hThread);

    DWORD result = g_Api.WaitForSingleObject(hThread, INFINITE);
    if (result != WAIT_OBJECT_0) {
        printf("[-] WaitForSingleObject échoué\n");
        g_Api.CloseHandle(hThread);
        return FALSE;
    }
    printf("[+] Thread terminé\n");

    g_Api.CloseHandle(hThread);
    printf("[+] Handle fermé\n");

    return TRUE;
}

void CleanupApiTable(void)
{
    printf("\n[*] Nettoyage...\n");

    for (int i = 0; i < MAX_DLL_CACHE; i++) {
        if (g_DllCache[i].loaded) {
            printf("[*] FreeLibrary: %s\n", g_DllCache[i].name);
            FreeLibrary(g_DllCache[i].handle);
            g_DllCache[i].loaded = FALSE;
        }
    }

    memset(&g_Api, 0, sizeof(g_Api));
    printf("[+] Nettoyage terminé\n");
}

int main(void)
{
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║         SOLUTION 02: API Resolver                        ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n\n");

    if (!InitializeApiTable()) {
        printf("[-] Échec initialisation\n");
        return 1;
    }

    if (TestMemoryAPIs()) {
        printf("[+] Memory APIs OK\n");
    }

    if (TestThreadAPIs()) {
        printf("[+] Thread APIs OK\n");
    }

    CleanupApiTable();

    printf("\n╔═══════════════════════════════════════════════════════════╗\n");
    printf("║ ARCHITECTURE PROFESSIONNELLE                              ║\n");
    printf("╠═══════════════════════════════════════════════════════════╣\n");
    printf("║ • Cache de DLLs évite LoadLibrary répétés                ║\n");
    printf("║ • ResolveAPI générique réutilisable partout              ║\n");
    printf("║ • API Table centralisée facile à maintenir               ║\n");
    printf("║ • Pattern utilisé dans tous les implants professionnels  ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n");

    return 0;
}
