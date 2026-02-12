/*
 * OBJECTIF  : Comprendre AMFI (Apple Mobile File Integrity) sur macOS
 * PREREQUIS : Bases C, code signing, entitlements, SIP
 * COMPILE   : clang -o example example.c
 *
 * Ce programme demontre le fonctionnement d'AMFI :
 * architecture, verification des signatures, entitlements,
 * interaction avec le kernel, et contournements historiques.
 * Demonstration pedagogique.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

/*
 * Etape 1 : Architecture AMFI
 */
static void explain_amfi_architecture(void) {
    printf("[*] Etape 1 : Architecture AMFI\n\n");

    printf("    ┌──────────────────────────────────────────┐\n");
    printf("    │  User Space                               │\n");
    printf("    │  ┌──────────┐   ┌──────────────────┐     │\n");
    printf("    │  │ Process  │   │ amfid daemon      │     │\n");
    printf("    │  │ (exec)   │   │ (verificateur)    │     │\n");
    printf("    │  └────┬─────┘   └────────┬─────────┘     │\n");
    printf("    │       │                   ^               │\n");
    printf("    │       │ exec()            │ Mach msg      │\n");
    printf("    │       v                   │               │\n");
    printf("    ├──────────────────────────────────────────┤\n");
    printf("    │  Kernel                                   │\n");
    printf("    │  ┌──────────────────────────────────┐    │\n");
    printf("    │  │  AppleMobileFileIntegrity.kext    │    │\n");
    printf("    │  │  - Intercepte execve()            │    │\n");
    printf("    │  │  - Verifie CodeDirectory hash     │    │\n");
    printf("    │  │  - Valide entitlements            │    │\n");
    printf("    │  │  - Consulte amfid si necessaire    │    │\n");
    printf("    │  └──────────────────────────────────┘    │\n");
    printf("    │  ┌──────────────────────────────────┐    │\n");
    printf("    │  │  MAC Framework (TrustedBSD)       │    │\n");
    printf("    │  │  - Policy hooks                    │    │\n");
    printf("    │  │  - mac_vnode_check_signature       │    │\n");
    printf("    │  └──────────────────────────────────┘    │\n");
    printf("    └──────────────────────────────────────────┘\n\n");

    printf("    AMFI = gardien de l'integrite des fichiers :\n");
    printf("    - KEXT dans le kernel (AppleMobileFileIntegrity.kext)\n");
    printf("    - Daemon userspace (amfid) pour les verifications\n");
    printf("    - Communication via Mach messages\n\n");
}

/*
 * Etape 2 : Role d'AMFI dans l'execution
 */
static void explain_amfi_role(void) {
    printf("[*] Etape 2 : Role d'AMFI dans l'execution\n\n");

    printf("    Flux d'execution d'un binaire :\n");
    printf("    ───────────────────────────────────\n");
    printf("    1. Processus appelle execve()\n");
    printf("    2. Kernel charge le Mach-O\n");
    printf("    3. AMFI.kext intercepte (MAC hook)\n");
    printf("    4. Verifie le CodeDirectory hash\n");
    printf("    5. Si cache miss -> demande a amfid\n");
    printf("    6. amfid verifie la signature CMS\n");
    printf("    7. amfid verifie les entitlements\n");
    printf("    8. Retourne le resultat au kernel\n");
    printf("    9. Kernel autorise ou refuse l'exec\n\n");

    printf("    Verifications effectuees :\n");
    printf("    ───────────────────────────────────\n");
    printf("    Verification         | Description\n");
    printf("    ─────────────────────|──────────────────────────\n");
    printf("    Code signature       | CMS/PKCS#7 valide\n");
    printf("    CodeDirectory        | Hash de chaque page (4KB)\n");
    printf("    Entitlements         | Droits demandes valides\n");
    printf("    Team ID              | Developeur autorise\n");
    printf("    Provisioning profile | Profils iOS/macOS\n");
    printf("    Library validation   | Dylibs signees correctement\n\n");

    /* Verifier si amfid est en cours */
    printf("    Processus amfid :\n");
    FILE *fp = popen("ps aux 2>/dev/null | grep '[a]mfid'", "r");
    if (fp) {
        char line[512];
        if (fgets(line, sizeof(line), fp)) {
            line[strcspn(line, "\n")] = '\0';
            printf("      %s\n", line);
        } else {
            printf("      (amfid non visible - droits insuffisants)\n");
        }
        pclose(fp);
    }
    printf("\n");
}

/*
 * Etape 3 : Flags de signature CS
 */
static void explain_cs_flags(void) {
    printf("[*] Etape 3 : Flags de signature (csops)\n\n");

    printf("    AMFI utilise les CS flags pour les decisions :\n");
    printf("    ───────────────────────────────────\n");
    printf("    Flag                  | Valeur   | Description\n");
    printf("    ──────────────────────|──────────|────────────────────\n");
    printf("    CS_VALID              | 0x00001  | Signature valide\n");
    printf("    CS_ADHOC              | 0x00002  | Pas de certificat\n");
    printf("    CS_GET_TASK_ALLOW     | 0x00004  | Autorise debugging\n");
    printf("    CS_HARD               | 0x00100  | Kill si invalide\n");
    printf("    CS_KILL               | 0x00200  | Kill si page invalide\n");
    printf("    CS_RESTRICT           | 0x00800  | Restrictions DYLD\n");
    printf("    CS_ENFORCEMENT        | 0x01000  | Enforcement actif\n");
    printf("    CS_REQUIRE_LV         | 0x02000  | Library Validation\n");
    printf("    CS_RUNTIME            | 0x10000  | Hardened Runtime\n");
    printf("    CS_LINKER_SIGNED      | 0x20000  | Signe par le linker\n\n");

    printf("    Verifier les flags d'un processus :\n");
    printf("    ───────────────────────────────────\n");
    printf("    #include <sys/codesign.h>\n\n");
    printf("    uint32_t flags;\n");
    printf("    csops(getpid(), CS_OPS_STATUS, &flags, sizeof(flags));\n");
    printf("    printf(\"CS flags: 0x%%x\\n\", flags);\n\n");

    /* Verifier les flags de binaires systeme */
    printf("    Exemple avec codesign :\n");
    FILE *fp = popen("codesign -dvvv /usr/bin/ssh 2>&1 | grep -E '(CDHash|Flags|TeamID)' | head -5", "r");
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
 * Etape 4 : Entitlements et AMFI
 */
static void explain_entitlements_amfi(void) {
    printf("[*] Etape 4 : Entitlements et AMFI\n\n");

    printf("    AMFI valide les entitlements :\n");
    printf("    ───────────────────────────────────\n");
    printf("    1. Lit les entitlements du CodeDirectory\n");
    printf("    2. Verifie qu'ils sont signes correctement\n");
    printf("    3. Verifie que le profil les autorise\n");
    printf("    4. Les rend disponibles au kernel\n\n");

    printf("    Entitlements proteges par AMFI :\n");
    printf("    ───────────────────────────────────\n");
    printf("    Entitlement                        | Protection\n");
    printf("    ───────────────────────────────────|──────────────\n");
    printf("    com.apple.private.*                | Apple only\n");
    printf("    com.apple.rootless.*               | SIP required\n");
    printf("    com.apple.system-task-ports        | task_for_pid\n");
    printf("    platform-application               | Apple apps\n");
    printf("    get-task-allow                     | Debug builds\n");
    printf("    com.apple.security.cs.allow-jit    | JIT autorise\n\n");

    printf("    Verifier les entitlements :\n");
    printf("    ───────────────────────────────────\n");
    printf("    codesign -d --entitlements - /path/binary\n");
    printf("    # Ou via l'API :\n");
    printf("    SecCodeCopySigningInformation(code,\n");
    printf("        kSecCSSigningInformation, &info);\n\n");

    /* Montrer les entitlements d'un processus systeme */
    printf("    Entitlements de /usr/libexec/amfid :\n");
    FILE *fp = popen("codesign -d --entitlements - /usr/libexec/amfid 2>&1 | head -15", "r");
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
 * Etape 5 : Contournements historiques
 */
static void explain_amfi_bypasses(void) {
    printf("[*] Etape 5 : Contournements historiques\n\n");

    printf("    Attaques historiques contre AMFI :\n");
    printf("    ───────────────────────────────────\n");
    printf("    1. amfid patch (jailbreak)\n");
    printf("       -> Patcher amfid pour toujours retourner OK\n");
    printf("       -> Necessite un exploit kernel\n");
    printf("       -> Utilise dans les jailbreaks iOS\n\n");

    printf("    2. AMFI trust cache injection\n");
    printf("       -> Injecter des CDHash dans le trust cache\n");
    printf("       -> Le kernel fait confiance sans verifier\n");
    printf("       -> Utilise par Unc0ver, Checkra1n\n\n");

    printf("    3. get-task-allow abuse\n");
    printf("       -> Binaire signe avec get-task-allow\n");
    printf("       -> Permet task_for_pid() dessus\n");
    printf("       -> Injection de code via le port\n\n");

    printf("    4. DYLD_INSERT_LIBRARIES\n");
    printf("       -> Charger du code non signe via dylib\n");
    printf("       -> Bloque si CS_RESTRICT ou Library Validation\n");
    printf("       -> Fonctionne sur les binaires permissifs\n\n");

    printf("    5. Disable via boot-args\n");
    printf("       -> nvram boot-args=\"amfi_get_out_of_my_way=1\"\n");
    printf("       -> Necessite SIP desactive\n");
    printf("       -> Desactive TOUTES les verifications AMFI\n\n");

    printf("    Protections actuelles :\n");
    printf("    - SIP protege amfid et le KEXT\n");
    printf("    - Secure Boot sur Apple Silicon\n");
    printf("    - Trust cache en read-only\n");
    printf("    - amfid redemmarre si kill (launchd)\n\n");
}

/*
 * Etape 6 : Detection et analyse
 */
static void explain_detection(void) {
    printf("[*] Etape 6 : Detection et analyse\n\n");

    printf("    Commandes utiles :\n");
    printf("    ───────────────────────────────────\n");
    printf("    # Verifier le statut AMFI\n");
    printf("    nvram -p | grep amfi\n\n");
    printf("    # Lister le trust cache\n");
    printf("    kmutil showloaded | grep amfi\n\n");
    printf("    # Verifier si AMFI est charge\n");
    printf("    kextstat | grep AMFI\n\n");

    /* Verifier l'etat d'AMFI */
    printf("    Etat du KEXT AMFI :\n");
    FILE *fp = popen("kextstat 2>/dev/null | grep -i amfi || "
                     "kmutil showloaded 2>/dev/null | grep -i amfi", "r");
    if (fp) {
        char line[512];
        if (fgets(line, sizeof(line), fp)) {
            line[strcspn(line, "\n")] = '\0';
            printf("      %s\n", line);
        } else {
            printf("      (utiliser kmutil showloaded pour verifier)\n");
        }
        pclose(fp);
    }
    printf("\n");

    /* Verifier le boot-arg amfi */
    printf("    Boot-args AMFI :\n");
    fp = popen("nvram boot-args 2>&1", "r");
    if (fp) {
        char line[256];
        if (fgets(line, sizeof(line), fp)) {
            line[strcspn(line, "\n")] = '\0';
            if (strstr(line, "amfi_get_out_of_my_way"))
                printf("      [!] AMFI desactive via boot-args !\n");
            else
                printf("      AMFI actif (pas de boot-arg de bypass)\n");
        }
        pclose(fp);
    }
    printf("\n");

    printf("    Bonnes pratiques :\n");
    printf("    - Garder SIP active\n");
    printf("    - Ne jamais desactiver AMFI en production\n");
    printf("    - Monitorer les modifications de boot-args\n");
    printf("    - Verifier regulierement les signatures\n");
    printf("    - Utiliser Endpoint Security pour les events\n\n");
}

int main(void) {
    printf("[*] Demo : AMFI (Apple Mobile File Integrity)\n\n");

    explain_amfi_architecture();
    explain_amfi_role();
    explain_cs_flags();
    explain_entitlements_amfi();
    explain_amfi_bypasses();
    explain_detection();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
