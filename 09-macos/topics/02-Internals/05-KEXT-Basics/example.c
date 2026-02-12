/*
 * OBJECTIF  : Comprendre les Kernel Extensions (KEXT) macOS
 * PREREQUIS : Bases C, architecture XNU, securite macOS
 * COMPILE   : clang -o example example.c
 *
 * Ce programme demontre le fonctionnement des KEXT macOS :
 * structure, chargement, communication userspace-kernel,
 * transition vers les System Extensions, et impact securite.
 * Demonstration pedagogique.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/utsname.h>

/*
 * Etape 1 : Architecture des KEXT
 */
static void explain_kext_architecture(void) {
    printf("[*] Etape 1 : Architecture des Kernel Extensions\n\n");

    printf("    ┌──────────────────────────────────────────┐\n");
    printf("    │  User Space                               │\n");
    printf("    │  ┌──────────┐   ┌──────────────────┐     │\n");
    printf("    │  │ App      │   │ kextload/kextutil│     │\n");
    printf("    │  └────┬─────┘   └────────┬─────────┘     │\n");
    printf("    │       │ IOKit             │ Load KEXT     │\n");
    printf("    ├───────┼──────────────────┼───────────────┤\n");
    printf("    │  Kernel Space                             │\n");
    printf("    │  ┌──────────────────────────────────┐    │\n");
    printf("    │  │  XNU Kernel                       │    │\n");
    printf("    │  │  ┌──── Mach ──────┐               │    │\n");
    printf("    │  │  │ IPC, VM, Tasks │               │    │\n");
    printf("    │  │  └────────────────┘               │    │\n");
    printf("    │  │  ┌──── BSD ───────┐               │    │\n");
    printf("    │  │  │ Fichiers, Net  │               │    │\n");
    printf("    │  │  └────────────────┘               │    │\n");
    printf("    │  │  ┌──── IOKit ─────┐               │    │\n");
    printf("    │  │  │ Drivers, KEXT  │ <── KEXT ici  │    │\n");
    printf("    │  │  └────────────────┘               │    │\n");
    printf("    │  └──────────────────────────────────┘    │\n");
    printf("    └──────────────────────────────────────────┘\n\n");
}

/*
 * Etape 2 : Structure d'un KEXT
 */
static void explain_kext_structure(void) {
    printf("[*] Etape 2 : Structure d'un KEXT\n\n");

    printf("    Un KEXT est un bundle macOS :\n");
    printf("    ───────────────────────────────────\n");
    printf("    MyDriver.kext/\n");
    printf("    ├── Contents/\n");
    printf("    │   ├── Info.plist     (metadonnees)\n");
    printf("    │   │   ├── CFBundleIdentifier\n");
    printf("    │   │   ├── CFBundleVersion\n");
    printf("    │   │   ├── OSBundleLibraries\n");
    printf("    │   │   └── IOKitPersonalities\n");
    printf("    │   └── MacOS/\n");
    printf("    │       └── MyDriver   (binaire kernel)\n");
    printf("    └── (signature)\n\n");

    printf("    Code minimal d'un KEXT :\n");
    printf("    ───────────────────────────────────\n");
    printf("    #include <mach/mach_types.h>\n\n");
    printf("    kern_return_t MyDriver_start(kmod_info_t *ki, void *d) {\n");
    printf("        printf(\"KEXT loaded\\n\");\n");
    printf("        return KERN_SUCCESS;\n");
    printf("    }\n\n");
    printf("    kern_return_t MyDriver_stop(kmod_info_t *ki, void *d) {\n");
    printf("        printf(\"KEXT unloaded\\n\");\n");
    printf("        return KERN_SUCCESS;\n");
    printf("    }\n\n");
}

/*
 * Etape 3 : Chargement et gestion
 */
static void demo_kext_management(void) {
    printf("[*] Etape 3 : Chargement et gestion des KEXT\n\n");

    printf("    Commandes de gestion :\n");
    printf("    ───────────────────────────────────\n");
    printf("    kextload MyDriver.kext       # Charger\n");
    printf("    kextunload MyDriver.kext     # Decharger\n");
    printf("    kextstat                     # Lister\n");
    printf("    kextutil -t MyDriver.kext    # Valider\n");
    printf("    kmutil showloaded            # macOS 11+\n\n");

    /* Lister les kexts charges */
    printf("    KEXT charges sur ce systeme :\n");
    FILE *fp = popen("kextstat 2>/dev/null | head -15 || "
                     "kmutil showloaded 2>/dev/null | head -15", "r");
    if (fp) {
        char line[512];
        int count = 0;
        while (fgets(line, sizeof(line), fp) && count < 15) {
            line[strcspn(line, "\n")] = '\0';
            printf("      %s\n", line);
            count++;
        }
        pclose(fp);
    }
    printf("\n");

    /* Verifier les KEXT tiers */
    printf("    KEXT tiers installes :\n");
    fp = popen("ls /Library/Extensions/ 2>/dev/null", "r");
    if (fp) {
        char line[256];
        int count = 0;
        while (fgets(line, sizeof(line), fp)) {
            line[strcspn(line, "\n")] = '\0';
            if (strstr(line, ".kext"))
                printf("      /Library/Extensions/%s\n", line);
            count++;
        }
        pclose(fp);
        if (count == 0) printf("      (aucun)\n");
    }
    printf("\n");
}

/*
 * Etape 4 : Securite des KEXT
 */
static void explain_kext_security(void) {
    printf("[*] Etape 4 : Securite des KEXT\n\n");

    printf("    Protections mises en place par Apple :\n");
    printf("    ───────────────────────────────────\n");
    printf("    Version | Protection\n");
    printf("    ────────|────────────────────────────────────\n");
    printf("    10.13   | KEXT doivent etre signees (SKEL)\n");
    printf("    10.13   | User approval requis (UAKEL)\n");
    printf("    10.15   | Depreciation des KEXT\n");
    printf("    10.15   | Introduction System Extensions\n");
    printf("    11.0    | KEXT en Secure Boot = reboot requis\n");
    printf("    12.0    | KEXT de plus en plus restreints\n");
    printf("    13.0+   | Encouragement fort vers DriverKit\n\n");

    printf("    SIP (System Integrity Protection) :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - Empeche le chargement de KEXT non signes\n");
    printf("    - Protege /System/Library/Extensions/\n");
    printf("    - Empeche la modification du kernel\n\n");

    /* Verifier le statut SIP */
    printf("    Statut SIP :\n");
    FILE *fp = popen("csrutil status 2>&1", "r");
    if (fp) {
        char line[256];
        if (fgets(line, sizeof(line), fp)) {
            line[strcspn(line, "\n")] = '\0';
            printf("      %s\n", line);
        }
        pclose(fp);
    }
    printf("\n");
}

/*
 * Etape 5 : Transition vers System Extensions
 */
static void explain_system_extensions(void) {
    printf("[*] Etape 5 : System Extensions (remplacement des KEXT)\n\n");

    printf("    ┌──────────────────────────────────────────┐\n");
    printf("    │  KEXT (ancien)    │  System Ext (nouveau) │\n");
    printf("    │───────────────────│───────────────────────│\n");
    printf("    │  Kernel space     │  User space           │\n");
    printf("    │  Crash = kernel   │  Crash = processus    │\n");
    printf("    │  Acces total      │  API limitees          │\n");
    printf("    │  Difficile a      │  Facile a securiser    │\n");
    printf("    │  securiser        │                       │\n");
    printf("    └──────────────────────────────────────────┘\n\n");

    printf("    Types de System Extensions :\n");
    printf("    ───────────────────────────────────\n");
    printf("    DriverKit         : remplace les IOKit KEXT\n");
    printf("    NetworkExtension  : VPN, proxy, filtre reseau\n");
    printf("    EndpointSecurity  : EDR, antivirus\n\n");

    /* Lister les system extensions */
    printf("    System Extensions installees :\n");
    FILE *fp = popen("systemextensionsctl list 2>&1 | head -10", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            line[strcspn(line, "\n")] = '\0';
            printf("      %s\n", line);
        }
        pclose(fp);
    }
    printf("\n");
}

/*
 * Etape 6 : Implications offensives
 */
static void explain_offensive_implications(void) {
    printf("[*] Etape 6 : Implications offensives\n\n");

    printf("    Rootkits macOS historiques :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - OSX.Crisis (2012) : KEXT rootkit\n");
    printf("    - Hacking Team KEXT : surveillance\n");
    printf("    - Flashback : modificait le kernel\n\n");

    printf("    Pourquoi les KEXT sont dangereux :\n");
    printf("    - Acces total a la memoire kernel\n");
    printf("    - Peuvent hooker les syscalls\n");
    printf("    - Peuvent masquer des processus/fichiers\n");
    printf("    - Persistent au reboot\n\n");

    printf("    Pourquoi c'est difficile aujourd'hui :\n");
    printf("    ───────────────────────────────────\n");
    printf("    - SIP empeche le chargement non autorise\n");
    printf("    - Signature Apple ou Developer ID requise\n");
    printf("    - User approval pour les KEXT tiers\n");
    printf("    - Apple pousse vers les System Extensions\n");
    printf("    - Secure Boot sur Apple Silicon\n\n");

    printf("    Detection :\n");
    printf("    - kextstat / kmutil showloaded\n");
    printf("    - Monitorer /Library/Extensions/\n");
    printf("    - Verifier les signatures des KEXT\n");
    printf("    - Endpoint Security events (KEXTLOAD)\n\n");
}

int main(void) {
    printf("[*] Demo : KEXT Basics macOS\n\n");

    explain_kext_architecture();
    explain_kext_structure();
    demo_kext_management();
    explain_kext_security();
    explain_system_extensions();
    explain_offensive_implications();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
