/*
 * ═══════════════════════════════════════════════════════════════════════════
 *                    MODULE 26 : API HOOKING
 * ═══════════════════════════════════════════════════════════════════════════
 * AVERTISSEMENT : Usage éducatif uniquement - Environnements de test isolés
 * ═══════════════════════════════════════════════════════════════════════════
 */

#ifdef _WIN32

#include <windows.h>
#include <stdio.h>

/*
 * ═══════════════════════════════════════════════════════════════════════════
 *              TECHNIQUE 1 : IAT HOOKING (Import Address Table)
 * ═══════════════════════════════════════════════════════════════════════════
 */

// Fonction hook pour MessageBoxA
int WINAPI hooked_MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    printf("[HOOK] MessageBoxA intercepté!\n");
    printf("       Texte: %s\n", lpText);
    printf("       Titre: %s\n", lpCaption);

    // Modifier le message
    return MessageBoxA(hWnd, "Message détourné par le hook!", "HOOKED!", uType);
}

// Pointeur vers la fonction originale
typedef int (WINAPI *pMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
pMessageBoxA original_MessageBoxA = NULL;

BOOL iat_hook_function(const char* module, const char* function, LPVOID hook_func, LPVOID* original) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("    IAT HOOKING\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    // Récupérer le module de base
    HMODULE hModule = GetModuleHandleA(NULL);
    if (!hModule) return FALSE;

    // Parser les headers PE
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);

    // Localiser l'Import Directory
    DWORD importRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule + importRVA);

    printf("[*] Recherche de %s!%s dans l'IAT...\n", module, function);

    // Parcourir les DLL importées
    while (importDesc->Name) {
        char* dllName = (char*)((BYTE*)hModule + importDesc->Name);

        if (_stricmp(dllName, module) == 0) {
            printf("[+] Module trouvé: %s\n", dllName);

            // Parcourir les fonctions importées
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->FirstThunk);
            PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->OriginalFirstThunk);

            while (thunk->u1.Function) {
                if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    // Import par ordinal
                } else {
                    PIMAGE_IMPORT_BY_NAME import = (PIMAGE_IMPORT_BY_NAME)((BYTE*)hModule + origThunk->u1.AddressOfData);

                    if (strcmp((char*)import->Name, function) == 0) {
                        printf("[+] Fonction trouvée: %s\n", function);
                        printf("[*] Adresse originale: 0x%p\n", (LPVOID)thunk->u1.Function);

                        // Sauvegarder l'adresse originale
                        if (original) {
                            *original = (LPVOID)thunk->u1.Function;
                        }

                        // Modifier la protection mémoire
                        DWORD oldProtect;
                        VirtualProtect(&thunk->u1.Function, sizeof(LPVOID), PAGE_READWRITE, &oldProtect);

                        // Remplacer par le hook
                        thunk->u1.Function = (DWORD_PTR)hook_func;

                        // Restaurer la protection
                        VirtualProtect(&thunk->u1.Function, sizeof(LPVOID), oldProtect, &oldProtect);

                        printf("[+] Hook installé! Nouvelle adresse: 0x%p\n", hook_func);
                        return TRUE;
                    }
                }

                thunk++;
                origThunk++;
            }
        }

        importDesc++;
    }

    printf("[-] Fonction non trouvée dans l'IAT\n");
    return FALSE;
}

/*
 * ═══════════════════════════════════════════════════════════════════════════
 *              TECHNIQUE 2 : INLINE HOOKING (Hot Patching)
 * ═══════════════════════════════════════════════════════════════════════════
 */

typedef struct {
    BYTE original_bytes[5];  // Bytes originaux (JMP = 5 bytes)
    LPVOID target_function;
    LPVOID hook_function;
    BOOL is_hooked;
} INLINE_HOOK;

BOOL inline_hook_function(LPVOID target, LPVOID hook, INLINE_HOOK* hook_info) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("    INLINE HOOKING (Hot Patching)\n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    printf("[*] Fonction cible: 0x%p\n", target);
    printf("[*] Fonction hook: 0x%p\n", hook);

    // Sauvegarder les bytes originaux
    memcpy(hook_info->original_bytes, target, 5);
    hook_info->target_function = target;
    hook_info->hook_function = hook;

    printf("[*] Bytes originaux: ");
    for (int i = 0; i < 5; i++) {
        printf("%02X ", hook_info->original_bytes[i]);
    }
    printf("\n");

    // Calculer le offset relatif pour le JMP
    DWORD offset = (DWORD)((BYTE*)hook - (BYTE*)target - 5);

    // Construire l'instruction JMP
    BYTE jmp[5] = {
        0xE9,  // JMP opcode
        (BYTE)(offset & 0xFF),
        (BYTE)((offset >> 8) & 0xFF),
        (BYTE)((offset >> 16) & 0xFF),
        (BYTE)((offset >> 24) & 0xFF)
    };

    printf("[*] Instruction JMP: ");
    for (int i = 0; i < 5; i++) {
        printf("%02X ", jmp[i]);
    }
    printf("\n");

    // Modifier la protection mémoire
    DWORD oldProtect;
    if (!VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("[-] VirtualProtect échoué: %lu\n", GetLastError());
        return FALSE;
    }

    // Écrire le JMP
    memcpy(target, jmp, 5);

    // Restaurer la protection
    VirtualProtect(target, 5, oldProtect, &oldProtect);

    hook_info->is_hooked = TRUE;
    printf("[+] Inline hook installé!\n");

    return TRUE;
}

BOOL unhook_function(INLINE_HOOK* hook_info) {
    if (!hook_info->is_hooked) return FALSE;

    printf("\n[*] Restauration des bytes originaux...\n");

    DWORD oldProtect;
    VirtualProtect(hook_info->target_function, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(hook_info->target_function, hook_info->original_bytes, 5);
    VirtualProtect(hook_info->target_function, 5, oldProtect, &oldProtect);

    hook_info->is_hooked = FALSE;
    printf("[+] Hook supprimé\n");

    return TRUE;
}

/*
 * ═══════════════════════════════════════════════════════════════════════════
 *                         DÉMONSTRATIONS
 * ═══════════════════════════════════════════════════════════════════════════
 */

void demo_api_hooking(void) {
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║          MODULE 26 : DÉMONSTRATION API HOOKING               ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n");

    printf("\n⚠️  Usage éducatif uniquement!\n\n");

    // Démo IAT Hooking
    printf("[*] Test 1: MessageBox AVANT hook\n");
    MessageBoxA(NULL, "Message original", "Test", MB_OK);

    // Installer le hook IAT
    iat_hook_function("user32.dll", "MessageBoxA", hooked_MessageBoxA, (LPVOID*)&original_MessageBoxA);

    printf("\n[*] Test 2: MessageBox APRÈS hook IAT\n");
    MessageBoxA(NULL, "Ce message sera intercepté", "Test", MB_OK);

    printf("\n[+] Démo terminée!\n");
}

int main(void) {
    demo_api_hooking();
    return 0;
}

#else

#include <stdio.h>
int main(void) {
    printf("Ce module est spécifique à Windows.\n");
    return 1;
}

#endif
