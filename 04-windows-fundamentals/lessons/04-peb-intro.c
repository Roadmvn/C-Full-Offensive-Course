/*
 * Lesson 04: Introduction to PEB (Process Environment Block)
 *
 * OBJECTIF:
 * Découvrir le PEB, structure fondamentale du processus Windows, et apprendre
 * à l'utiliser pour trouver l'adresse de base de kernel32.dll sans appeler
 * GetModuleHandle (évasion d'EDR).
 *
 * CONCEPTS CLÉS:
 * - PEB (Process Environment Block): métadonnées du processus
 * - TEB (Thread Environment Block): métadonnées du thread
 * - InMemoryOrderModuleList: liste chaînée des DLLs chargées
 * - LDR_DATA_TABLE_ENTRY: entrée pour chaque DLL
 *
 * INTÉRÊT OFFENSIF:
 * - Accès bas niveau au processus sans APIs documentées
 * - Trouver kernel32 sans GetModuleHandle (bypass hooks EDR)
 * - Énumérer les DLLs chargées sans appeler EnumProcessModules
 * - Base pour des techniques avancées (manual mapping, PEB walking)
 */

#include <windows.h>
#include <stdio.h>
#include <winternl.h>  // Pour structures PEB/TEB (ou on les définit nous-mêmes)

/*
 * ════════════════════════════════════════════════════════════════════════
 * STRUCTURES PEB/TEB (Undocumented / Semi-documented)
 * ════════════════════════════════════════════════════════════════════════
 *
 * Ces structures ne sont pas complètement documentées par Microsoft,
 * mais sont stables depuis Windows XP.
 *
 * Source: ntdll.dll, recherche reverse engineering, ReactOS
 */

#ifndef _NTDEF_
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
#endif

/*
 * PEB_LDR_DATA: contient les listes de modules chargés
 */
typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;           // Ordre de chargement
    LIST_ENTRY InMemoryOrderModuleList;         // Ordre en mémoire (on utilise celle-ci)
    LIST_ENTRY InInitializationOrderModuleList; // Ordre d'initialisation
} PEB_LDR_DATA, *PPEB_LDR_DATA;

/*
 * LDR_DATA_TABLE_ENTRY: entrée pour chaque module (DLL) chargé
 */
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;                  // Adresse de base de la DLL
    PVOID EntryPoint;               // Point d'entrée (DllMain)
    ULONG SizeOfImage;              // Taille de l'image en mémoire
    UNICODE_STRING FullDllName;     // Chemin complet
    UNICODE_STRING BaseDllName;     // Nom de base (ex: "kernel32.dll")
    // ... d'autres champs existent mais pas nécessaires ici
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

/*
 * PEB (Process Environment Block)
 * Version simplifiée avec seulement les champs qui nous intéressent
 */
typedef struct _PEB_CUSTOM {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;                      // ← Anti-debug flag!
    BYTE padding1;
    PVOID Mutant;
    PVOID ImageBaseAddress;                     // Adresse de base de l'exe
    PPEB_LDR_DATA Ldr;                          // ← Pointeur vers LDR_DATA
    // ... beaucoup d'autres champs
} PEB_CUSTOM, *PPEB_CUSTOM;

/*
 * TEB (Thread Environment Block)
 * Version ultra-simplifiée
 */
#ifdef _WIN64
typedef struct _TEB_CUSTOM {
    PVOID padding[12];  // NT_TIB structure
    PPEB_CUSTOM ProcessEnvironmentBlock;  // Offset 0x60 en x64
} TEB_CUSTOM, *PTEB_CUSTOM;
#else
typedef struct _TEB_CUSTOM {
    PVOID padding[12];  // NT_TIB structure
    PPEB_CUSTOM ProcessEnvironmentBlock;  // Offset 0x30 en x86
} TEB_CUSTOM, *PTEB_CUSTOM;
#endif

/*
 * ════════════════════════════════════════════════════════════════════════
 * ACCESSING THE PEB
 * ════════════════════════════════════════════════════════════════════════
 *
 * Plusieurs méthodes pour accéder au PEB:
 *
 * 1. NtQueryInformationProcess (documenté mais nécessite ntdll)
 * 2. ReadProcessMemory + NtCurrentPeb (pour remote process)
 * 3. Inline assembly (x86) ou intrinsics (x64)
 * 4. __readgsqword (x64) / __readfsdword (x86)
 */

PPEB_CUSTOM GetPEB(void)
{
#ifdef _WIN64
    /*
     * x64: le PEB est à GS:[0x60]
     * GS pointe vers le TEB (Thread Environment Block)
     */
    PTEB_CUSTOM pTeb = (PTEB_CUSTOM)__readgsqword(0x30);  // TEB en x64: GS:[0x30]
    return pTeb->ProcessEnvironmentBlock;
#else
    /*
     * x86: le PEB est à FS:[0x30]
     * FS pointe vers le TEB
     */
    PTEB_CUSTOM pTeb = (PTEB_CUSTOM)__readfsdword(0x18);  // TEB en x86: FS:[0x18]
    return pTeb->ProcessEnvironmentBlock;
#endif
}

/*
 * Alternative: utiliser NtCurrentPeb() de winternl.h (Windows 8+)
 * Mais on veut montrer la méthode bas niveau.
 */

void demo_peb_access(void)
{
    printf("\n=== DEMO 1: Accès au PEB ===\n");

    PPEB_CUSTOM pPeb = GetPEB();

    if (!pPeb) {
        printf("[-] Échec d'accès au PEB\n");
        return;
    }

    printf("[+] PEB accessible à: 0x%p\n", pPeb);
    printf("[+] ImageBaseAddress (notre .exe): 0x%p\n", pPeb->ImageBaseAddress);
    printf("[+] BeingDebugged flag: %d\n", pPeb->BeingDebugged);

    /*
     * BeingDebugged est un flag anti-debug basique.
     * Si un debugger est attaché, il vaut 1.
     *
     * Contournement: le debugger peut modifier ce flag.
     */

    if (pPeb->BeingDebugged) {
        printf("[!] DEBUGGER DÉTECTÉ via PEB\n");
    } else {
        printf("[+] Pas de debugger détecté\n");
    }
}

/*
 * ════════════════════════════════════════════════════════════════════════
 * WALKING THE MODULE LIST
 * ════════════════════════════════════════════════════════════════════════
 *
 * Le PEB contient un pointeur vers PEB_LDR_DATA, qui contient 3 listes
 * chaînées de modules. On utilise InMemoryOrderModuleList.
 *
 * ORDRE TYPIQUE:
 * 1. ntdll.dll (toujours en premier)
 * 2. kernel32.dll (ou kernelbase.dll sur versions récentes)
 * 3. Notre exe
 * 4. Autres DLLs...
 */

void demo_enumerate_modules(void)
{
    printf("\n=== DEMO 2: Énumération des modules via PEB ===\n");

    PPEB_CUSTOM pPeb = GetPEB();
    if (!pPeb) return;

    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    if (!pLdr) {
        printf("[-] PEB->Ldr est NULL\n");
        return;
    }

    printf("[+] PEB_LDR_DATA à: 0x%p\n", pLdr);

    /*
     * InMemoryOrderModuleList est une liste doublement chaînée.
     * Le premier nœud est un header, les vrais modules commencent après.
     */

    PLIST_ENTRY pListHead = &pLdr->InMemoryOrderModuleList;
    PLIST_ENTRY pListEntry = pListHead->Flink;  // Premier vrai module

    int count = 0;

    while (pListEntry != pListHead && count < 20) {  // Limite à 20 pour éviter boucle infinie
        /*
         * CONTAINING_RECORD macro pour obtenir la structure complète
         * à partir du membre LIST_ENTRY.
         *
         * En gros: pListEntry pointe vers InMemoryOrderLinks dans LDR_DATA_TABLE_ENTRY,
         * on calcule l'offset pour obtenir le début de la structure.
         */

        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(
            pListEntry,
            LDR_DATA_TABLE_ENTRY,
            InMemoryOrderLinks
        );

        printf("\n[%d] DLL: %wZ\n", count, &pEntry->BaseDllName);
        printf("    DllBase:     0x%p\n", pEntry->DllBase);
        printf("    EntryPoint:  0x%p\n", pEntry->EntryPoint);
        printf("    SizeOfImage: %lu bytes\n", pEntry->SizeOfImage);
        printf("    FullPath:    %wZ\n", &pEntry->FullDllName);

        pListEntry = pListEntry->Flink;
        count++;
    }

    printf("\n[+] Total: %d modules énumérés\n", count);
}

/*
 * ════════════════════════════════════════════════════════════════════════
 * FINDING KERNEL32.DLL
 * ════════════════════════════════════════════════════════════════════════
 *
 * Technique offensive: trouver kernel32 en parcourant le PEB plutôt que
 * d'appeler GetModuleHandleA (qui peut être hookée par un EDR).
 */

HMODULE GetKernel32FromPEB(void)
{
    PPEB_CUSTOM pPeb = GetPEB();
    if (!pPeb) return NULL;

    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    if (!pLdr) return NULL;

    PLIST_ENTRY pListHead = &pLdr->InMemoryOrderModuleList;
    PLIST_ENTRY pListEntry = pListHead->Flink;

    while (pListEntry != pListHead) {
        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(
            pListEntry,
            LDR_DATA_TABLE_ENTRY,
            InMemoryOrderLinks
        );

        /*
         * Comparer le nom de la DLL.
         * Note: BaseDllName est en UNICODE_STRING (wchar_t).
         *
         * On cherche "kernel32.dll" ou "KERNEL32.DLL" (case-insensitive).
         */

        if (pEntry->BaseDllName.Buffer) {
            // Conversion simplifiée pour comparaison
            // En vrai code, utiliser wcsicmp ou équivalent

            // Check si c'est kernel32 (simple check sur les premiers chars)
            if (pEntry->BaseDllName.Length >= 24) {  // "kernel32.dll" = 24 bytes en UTF-16
                WCHAR* name = pEntry->BaseDllName.Buffer;

                // Comparaison manuelle (simplifié)
                if ((name[0] == L'k' || name[0] == L'K') &&
                    (name[1] == L'e' || name[1] == L'E') &&
                    (name[2] == L'r' || name[2] == L'R') &&
                    (name[3] == L'n' || name[3] == L'N') &&
                    (name[4] == L'e' || name[4] == L'E') &&
                    (name[5] == L'l' || name[5] == L'L') &&
                    (name[6] == L'3' || name[6] == L'3') &&
                    (name[7] == L'2' || name[7] == L'2')) {

                    return (HMODULE)pEntry->DllBase;
                }
            }
        }

        pListEntry = pListEntry->Flink;
    }

    return NULL;
}

void demo_find_kernel32(void)
{
    printf("\n=== DEMO 3: Trouver kernel32 via PEB Walking ===\n");

    HMODULE hKernel32PEB = GetKernel32FromPEB();

    if (hKernel32PEB) {
        printf("[+] kernel32.dll trouvé via PEB: 0x%p\n", hKernel32PEB);

        // Comparaison avec GetModuleHandleA
        HMODULE hKernel32API = GetModuleHandleA("kernel32.dll");
        printf("[+] kernel32.dll via API:        0x%p\n", hKernel32API);

        if (hKernel32PEB == hKernel32API) {
            printf("[+] Les deux méthodes retournent la même adresse ✓\n");
        }

        /*
         * Maintenant qu'on a kernel32, on peut utiliser GetProcAddress
         * pour résoudre n'importe quelle fonction, SANS avoir appelé
         * GetModuleHandle (qui pourrait être hookée).
         */

        typedef DWORD (WINAPI *pfnGetCurrentProcessId)(void);

        pfnGetCurrentProcessId fnGetPid = (pfnGetCurrentProcessId)GetProcAddress(
            hKernel32PEB,
            "GetCurrentProcessId"
        );

        if (fnGetPid) {
            DWORD pid = fnGetPid();
            printf("[+] PID (via fonction résolue depuis PEB): %lu\n", pid);
        }

    } else {
        printf("[-] kernel32.dll non trouvé via PEB\n");
    }
}

/*
 * ════════════════════════════════════════════════════════════════════════
 * PRACTICAL MALDEV APPLICATION
 * ════════════════════════════════════════════════════════════════════════
 *
 * Combiner PEB walking + GetProcAddress pour résoudre des APIs
 * sans AUCUN appel à GetModuleHandle.
 */

void demo_complete_evasion(void)
{
    printf("\n=== DEMO 4: Résolution complète sans GetModuleHandle ===\n");

    // 1. Obtenir kernel32 via PEB
    HMODULE hKernel32 = GetKernel32FromPEB();
    if (!hKernel32) {
        printf("[-] Échec PEB walking\n");
        return;
    }

    printf("[+] kernel32 via PEB: 0x%p\n", hKernel32);

    // 2. Résoudre GetProcAddress lui-même (pour résoudre d'autres fonctions)
    typedef FARPROC (WINAPI *pfnGetProcAddress)(HMODULE, LPCSTR);
    pfnGetProcAddress fnGetProcAddress = (pfnGetProcAddress)GetProcAddress(
        hKernel32,
        "GetProcAddress"
    );

    if (!fnGetProcAddress) {
        printf("[-] Échec résolution GetProcAddress\n");
        return;
    }

    // 3. Utiliser notre GetProcAddress pour résoudre d'autres APIs
    typedef LPVOID (WINAPI *pfnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
    pfnVirtualAlloc fnVirtualAlloc = (pfnVirtualAlloc)fnGetProcAddress(
        hKernel32,
        "VirtualAlloc"
    );

    if (fnVirtualAlloc) {
        printf("[+] VirtualAlloc résolu: 0x%p\n", fnVirtualAlloc);

        // Test
        LPVOID pMem = fnVirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (pMem) {
            printf("[+] Mémoire allouée: 0x%p\n", pMem);
            printf("[+] TOUT SANS APPEL À GetModuleHandle!\n");
        }
    }
}

/*
 * ════════════════════════════════════════════════════════════════════════
 * ANTI-DEBUG BONUS
 * ════════════════════════════════════════════════════════════════════════
 */

void demo_peb_antidebug(void)
{
    printf("\n=== DEMO 5: Anti-Debug via PEB ===\n");

    PPEB_CUSTOM pPeb = GetPEB();

    /*
     * PEB.BeingDebugged: flag simple mais efficace
     */
    if (pPeb->BeingDebugged) {
        printf("[!] Debugger détecté (PEB.BeingDebugged = 1)\n");
        printf("[!] Un vrai malware quitterait ici ou crasherait volontairement\n");
    } else {
        printf("[+] Pas de debugger détecté\n");
    }

    /*
     * Autres checks possibles dans le PEB:
     * - NtGlobalFlag (offset 0xBC en x86, 0x1BC en x64)
     * - HeapFlags dans les heaps (détecte debug heap)
     *
     * Ces checks nécessitent de parser plus en profondeur le PEB.
     */
}

int main(void)
{
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║         WEEK 7 - LESSON 04: PEB Introduction             ║\n");
    printf("║         Process Environment Block Basics                 ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n");

    demo_peb_access();
    demo_enumerate_modules();
    demo_find_kernel32();
    demo_complete_evasion();
    demo_peb_antidebug();

    printf("\n╔═══════════════════════════════════════════════════════════╗\n");
    printf("║ RÉSUMÉ                                                    ║\n");
    printf("╠═══════════════════════════════════════════════════════════╣\n");
    printf("║ • PEB: structure contenant métadonnées du processus      ║\n");
    printf("║ • Accès via GS:[0x60] (x64) ou FS:[0x30] (x86)           ║\n");
    printf("║ • InMemoryOrderModuleList: liste des DLLs chargées       ║\n");
    printf("║ • PEB Walking: trouver kernel32 sans GetModuleHandle     ║\n");
    printf("║ • BeingDebugged: flag anti-debug dans le PEB             ║\n");
    printf("║ • Usage maldev: évasion complète des hooks EDR           ║\n");
    printf("╚═══════════════════════════════════════════════════════════╝\n");

    printf("\n[*] Cette semaine: fondations pour API hashing, manual mapping\n");

    return 0;
}

/*
 * TECHNIQUES AVANCÉES BASÉES SUR LE PEB:
 *
 * 1. API HASHING:
 *    - Parser l'export table de kernel32 trouvé via PEB
 *    - Hasher chaque nom de fonction
 *    - Comparer au hash cible
 *    - Aucune string d'API dans le binaire!
 *
 * 2. MANUAL MAPPING:
 *    - Charger une DLL depuis un buffer mémoire
 *    - Parser PE header, sections, imports, relocs
 *    - Mapper en mémoire manuellement
 *    - La DLL n'apparaît pas dans les listes du PEB
 *
 * 3. MODULE UNLINKING:
 *    - Retirer notre DLL de InMemoryOrderModuleList
 *    - Invisible pour EnumProcessModules
 *    - Technique de rootkit user-mode
 *
 * 4. ANTI-DEBUG AVANCÉ:
 *    - Vérifier NtGlobalFlag (debug heap)
 *    - Vérifier HeapFlags dans les structures heap
 *    - Détecter remote debugger via CheckRemoteDebuggerPresent
 *
 * 5. PROCESS HOLLOWING:
 *    - Créer processus suspendu
 *    - Accéder à son PEB (ReadProcessMemory)
 *    - Remplacer ImageBaseAddress
 *    - Charger notre payload à la place
 */
