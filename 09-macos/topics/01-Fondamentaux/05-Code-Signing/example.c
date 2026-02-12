/*
 * OBJECTIF  : Comprendre la signature de code sur macOS
 * PREREQUIS : Bases C, securite macOS, certificats
 * COMPILE   : clang -o example example.c
 *
 * Ce programme demontre le fonctionnement de la signature de
 * code macOS : verification avec codesign, entitlements,
 * structure des signatures, et contournements connus.
 * Demonstration pedagogique.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

/*
 * Etape 1 : Architecture de la signature de code
 */
static void explain_code_signing(void) {
    printf("[*] Etape 1 : Architecture de la signature de code macOS\n\n");

    printf("    ┌──────────────────────────────────────────┐\n");
    printf("    │         CODE SIGNING PIPELINE             │\n");
    printf("    │                                          │\n");
    printf("    │  Developpeur                             │\n");
    printf("    │  ┌──────────────────────────┐            │\n");
    printf("    │  │ 1. Compile le code        │            │\n");
    printf("    │  │ 2. codesign -s \"Dev ID\"   │            │\n");
    printf("    │  │ 3. Ajoute entitlements    │            │\n");
    printf("    │  │ 4. Soumet pour notarization│           │\n");
    printf("    │  └──────────────────────────┘            │\n");
    printf("    │       │                                   │\n");
    printf("    │       v                                   │\n");
    printf("    │  Apple Notary Service                    │\n");
    printf("    │  ┌──────────────────────────┐            │\n");
    printf("    │  │ Analyse statique          │            │\n");
    printf("    │  │ Verifie les malwares      │            │\n");
    printf("    │  │ Delivre un ticket          │            │\n");
    printf("    │  └──────────────────────────┘            │\n");
    printf("    │       │                                   │\n");
    printf("    │       v                                   │\n");
    printf("    │  Execution (Gatekeeper verifie)          │\n");
    printf("    └──────────────────────────────────────────┘\n\n");
}

/*
 * Etape 2 : Verifier la signature d'un binaire
 */
static void demo_check_signature(void) {
    printf("[*] Etape 2 : Verification de la signature\n\n");

    /* Verifier notre propre binaire */
    char self_path[1024] = {0};
    uint32_t size = sizeof(self_path);

    /* Utiliser _NSGetExecutablePath via popen */
    char cmd[256];
    pid_t pid = getpid();
    snprintf(cmd, sizeof(cmd), "codesign -dvvv /proc/%d/exe 2>&1 || "
             "codesign -dvvv $(ps -p %d -o comm=) 2>&1", pid, pid);

    printf("    Commandes de verification :\n");
    printf("    ───────────────────────────────────\n");
    printf("    codesign -v /path/to/binary         # Verifier\n");
    printf("    codesign -dv /path/to/binary         # Details\n");
    printf("    codesign -dvvv /path/to/binary       # Verbose\n\n");

    /* Verifier quelques binaires systeme */
    const char *binaries[] = {"/bin/ls", "/usr/bin/ssh", "/usr/bin/git", NULL};

    for (int i = 0; binaries[i]; i++) {
        struct stat st;
        if (stat(binaries[i], &st) != 0) continue;

        char check_cmd[256];
        snprintf(check_cmd, sizeof(check_cmd),
                 "codesign -d --verbose=1 '%s' 2>&1 | head -3", binaries[i]);

        printf("    %s :\n", binaries[i]);
        FILE *fp = popen(check_cmd, "r");
        if (fp) {
            char line[512];
            while (fgets(line, sizeof(line), fp)) {
                line[strcspn(line, "\n")] = '\0';
                printf("      %s\n", line);
            }
            pclose(fp);
        }
        printf("\n");
    }
}

/*
 * Etape 3 : Entitlements
 */
static void demo_entitlements(void) {
    printf("[*] Etape 3 : Entitlements (droits speciaux)\n\n");

    printf("    Entitlements importants pour la securite :\n");
    printf("    ───────────────────────────────────\n");
    printf("    Entitlement                              | Effet\n");
    printf("    ─────────────────────────────────────────|──────────────\n");
    printf("    com.apple.security.get-task-allow        | Debugging\n");
    printf("    com.apple.system-task-ports              | task_for_pid\n");
    printf("    com.apple.security.cs.disable-library-v  | Charger dylibs\n");
    printf("    com.apple.security.cs.allow-unsigned-exec| Code non signe\n");
    printf("    com.apple.private.tcc.allow              | Bypass TCC\n");
    printf("    com.apple.rootless.install               | Ecrire en SIP\n\n");

    /* Afficher les entitlements d'un binaire */
    printf("    Entitlements de /usr/bin/ssh :\n");
    FILE *fp = popen("codesign -d --entitlements - /usr/bin/ssh 2>&1 | head -20", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            line[strcspn(line, "\n")] = '\0';
            printf("      %s\n", line);
        }
        pclose(fp);
    }
    printf("\n");

    printf("    Commandes pour les entitlements :\n");
    printf("    codesign -d --entitlements - /path/binary\n");
    printf("    ldid -e /path/binary  (outil alternatif)\n\n");
}

/*
 * Etape 4 : Structure interne de la signature
 */
static void explain_signature_structure(void) {
    printf("[*] Etape 4 : Structure interne de la signature\n\n");

    printf("    La signature est stockee dans le Mach-O :\n");
    printf("    ───────────────────────────────────\n");
    printf("    LC_CODE_SIGNATURE -> offset dans le fichier\n\n");

    printf("    ┌────────────────────────────────┐\n");
    printf("    │  SuperBlob (conteneur)          │\n");
    printf("    │  ├── CodeDirectory              │\n");
    printf("    │  │   hash de chaque page (4KB)  │\n");
    printf("    │  │   hash des entitlements      │\n");
    printf("    │  │   hash de l'InfoPlist         │\n");
    printf("    │  ├── Entitlements blob           │\n");
    printf("    │  │   XML plist des droits        │\n");
    printf("    │  ├── CMS Signature               │\n");
    printf("    │  │   PKCS#7 (certificat + sign) │\n");
    printf("    │  └── Requirements                │\n");
    printf("    │      Conditions de confiance     │\n");
    printf("    └────────────────────────────────┘\n\n");

    printf("    Flags de signature :\n");
    printf("    Flag           | Valeur  | Description\n");
    printf("    ───────────────|─────────|──────────────────────\n");
    printf("    CS_VALID       | 0x0001  | Signature valide\n");
    printf("    CS_ADHOC       | 0x0002  | Ad-hoc (pas de cert)\n");
    printf("    CS_RUNTIME     | 0x10000 | Hardened runtime\n");
    printf("    CS_LINKER_SIGNED| 0x20000| Signe par le linker\n\n");
}

/*
 * Etape 5 : Signer un binaire
 */
static void explain_signing_process(void) {
    printf("[*] Etape 5 : Signer un binaire\n\n");

    printf("    Signature ad-hoc (sans certificat) :\n");
    printf("    ───────────────────────────────────\n");
    printf("    codesign -s - binary\n");
    printf("    # Utile pour le dev, pas accepte par Gatekeeper\n\n");

    printf("    Signature avec Developer ID :\n");
    printf("    ───────────────────────────────────\n");
    printf("    codesign -s \"Developer ID Application: Name\" binary\n");
    printf("    codesign --entitlements entitlements.plist \\\n");
    printf("             -s \"Developer ID\" binary\n\n");

    printf("    Hardened Runtime (requis pour notarization) :\n");
    printf("    ───────────────────────────────────\n");
    printf("    codesign -s \"Developer ID\" \\\n");
    printf("             --options runtime \\\n");
    printf("             --entitlements entitlements.plist \\\n");
    printf("             binary\n\n");

    printf("    Identites de signature disponibles :\n");
    FILE *fp = popen("security find-identity -v -p codesigning 2>&1 | head -5", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            line[strcspn(line, "\n")] = '\0';
            printf("      %s\n", line);
        }
        pclose(fp);
    }
    printf("\n");
}

/*
 * Etape 6 : Contournements et attaques
 */
static void explain_bypasses(void) {
    printf("[*] Etape 6 : Contournements et attaques\n\n");

    printf("    Techniques historiques :\n");
    printf("    ───────────────────────────────────\n");
    printf("    1. Dylib hijacking\n");
    printf("       -> Charger une dylib avant la legitime\n");
    printf("       -> Contourne si DYLD_* pas filtre\n\n");
    printf("    2. Fat binary abuse\n");
    printf("       -> Un Mach-O valide + un code malveillant\n");
    printf("       -> Historiquement non verifie completement\n\n");
    printf("    3. Ad-hoc re-signing\n");
    printf("       -> codesign -s - --force binary\n");
    printf("       -> Modifie le binaire et resigne\n\n");
    printf("    4. Entitlements injection\n");
    printf("       -> Ajouter des entitlements a un binaire\n\n");

    printf("    Protections actuelles :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - AMFI (Apple Mobile File Integrity)\n");
    printf("    - Hardened Runtime obligatoire\n");
    printf("    - Notarization requise pour la distribution\n");
    printf("    - SIP protege les binaires systeme\n");
    printf("    - Library Validation empeche les dylibs non signees\n\n");
}

int main(void) {
    printf("[*] Demo : Code Signing macOS\n\n");

    explain_code_signing();
    demo_check_signature();
    demo_entitlements();
    explain_signature_structure();
    explain_signing_process();
    explain_bypasses();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
