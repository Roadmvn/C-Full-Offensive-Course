/*
 * OBJECTIF  : Comprendre Staged vs Stageless payloads
 * PREREQUIS : Shellcode, HTTP Client, Memory allocation
 * COMPILE   : cl example.c /Fe:example.exe
 *
 * Staged   : petit stager qui telecharge le payload complet
 * Stageless : payload complet embarque dans l'executable
 * Chaque approche a ses avantages et inconvenients.
 */

#include <windows.h>
#include <stdio.h>

void demo_staged_concept(void) {
    printf("[1] Staged Payload (stager + stage)\n\n");
    printf("    Etape 1 : Stager (petit, ~500 bytes)\n");
    printf("    +-----------------------------------------+\n");
    printf("    | connect(C2)                             |\n");
    printf("    | recv(shellcode, size)                   |\n");
    printf("    | VirtualAlloc(RWX)                       |\n");
    printf("    | memcpy(shellcode)                       |\n");
    printf("    | jump(shellcode)                         |\n");
    printf("    +-----------------------------------------+\n\n");
    printf("    Etape 2 : Stage (beacon complet, ~200KB)\n");
    printf("    +-----------------------------------------+\n");
    printf("    | Reflective DLL loader                   |\n");
    printf("    | Beacon C2 complet                       |\n");
    printf("    | Toutes les fonctionnalites              |\n");
    printf("    +-----------------------------------------+\n\n");

    /* Simuler un stager */
    printf("    Simulation du stager :\n");
    unsigned char fake_stage[] = { 0x90, 0x90, 0xC3 }; /* NOP NOP RET */
    DWORD stage_size = sizeof(fake_stage);

    printf("    [+] Connexion au C2...\n");
    printf("    [+] Telechargement du stage (%lu bytes)\n", stage_size);

    void* mem = VirtualAlloc(NULL, stage_size,
                             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (mem) {
        memcpy(mem, fake_stage, stage_size);
        DWORD old;
        VirtualProtect(mem, stage_size, PAGE_EXECUTE_READ, &old);
        printf("    [+] Stage charge en memoire a %p\n", mem);
        printf("    [+] Execution du stage (NOP+RET)\n");
        ((void(*)())mem)();
        printf("    [+] Stage execute avec succes\n");
        VirtualFree(mem, 0, MEM_RELEASE);
    }
    printf("\n");
}

void demo_stageless_concept(void) {
    printf("[2] Stageless Payload (tout embarque)\n\n");
    printf("    +---------------------------------------------+\n");
    printf("    | Executable complet                          |\n");
    printf("    |   - Beacon C2                               |\n");
    printf("    |   - Config (C2 URL, sleep, jitter, keys)    |\n");
    printf("    |   - Toutes les commandes                    |\n");
    printf("    |   - Evasion integree                        |\n");
    printf("    |   Taille: ~200KB - 2MB                      |\n");
    printf("    +---------------------------------------------+\n\n");

    /* Simuler un payload stageless avec config embarquee */
    printf("    Simulation stageless :\n");
    struct {
        char c2_url[128];
        DWORD sleep_ms;
        int jitter_pct;
        char session_key[32];
    } config = {
        "https://cdn.legit-domain.com/api",
        60000,
        25,
        "AES256_KEY_PLACEHOLDER_HERE_XX"
    };
    printf("    [+] Config embarquee :\n");
    printf("        C2 URL  : %s\n", config.c2_url);
    printf("        Sleep   : %lu ms\n", config.sleep_ms);
    printf("        Jitter  : %d%%\n", config.jitter_pct);
    printf("    [+] Pas de telechargement necessaire\n\n");
}

void demo_comparison(void) {
    printf("[3] Comparaison Staged vs Stageless\n\n");
    printf("    +--------------------+-------------------+-------------------+\n");
    printf("    | Critere            | Staged            | Stageless         |\n");
    printf("    +--------------------+-------------------+-------------------+\n");
    printf("    | Taille initiale    | ~500 bytes        | ~200KB - 2MB      |\n");
    printf("    | Reseau necessaire  | OUI (telecharge)  | NON               |\n");
    printf("    | Detection AV       | Stager = discret  | Plus de signatures|\n");
    printf("    | Detection reseau   | Gros transfert    | Pas de stage DL   |\n");
    printf("    | Fiabilite          | Depend du reseau  | Autonome          |\n");
    printf("    | Flexibilite        | Stage modifiable  | Fixe a la compile |\n");
    printf("    | Utilisation        | Exploit initial   | Persistance       |\n");
    printf("    +--------------------+-------------------+-------------------+\n\n");
}

void demo_hybrid(void) {
    printf("[4] Approche hybride\n\n");
    printf("    Stager minimal avec fallback :\n");
    printf("    1. Essayer HTTPS (port 443)\n");
    printf("    2. Si echec -> DNS tunneling\n");
    printf("    3. Si echec -> SMB pipe\n");
    printf("    4. Si echec -> sleep long et retry\n\n");
    printf("    Stageless avec mise a jour :\n");
    printf("    1. Payload complet embarque\n");
    printf("    2. Le C2 peut envoyer des modules supplementaires\n");
    printf("    3. Modules charges en memoire (Reflective DLL)\n");
    printf("    4. Jamais ecrits sur disque\n\n");
    printf("    Detection :\n");
    printf("    - Staged  : surveiller les gros transferts apres connexion\n");
    printf("    - Stageless : signatures sur le binaire, taille suspecte\n\n");
}

int main(void) {
    printf("[*] Demo : Staged vs Stageless Payloads\n");
    printf("[*] ==========================================\n\n");
    demo_staged_concept();
    demo_stageless_concept();
    demo_comparison();
    demo_hybrid();
    printf("[+] Exemple termine avec succes\n");
    return 0;
}
