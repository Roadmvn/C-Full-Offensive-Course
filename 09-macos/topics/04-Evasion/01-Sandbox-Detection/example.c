/*
 * OBJECTIF  : Comprendre la sandbox macOS et sa detection
 * PREREQUIS : Bases C, securite macOS, App Sandbox, TCC
 * COMPILE   : clang -o example example.c
 *
 * Ce programme demontre le fonctionnement de la sandbox macOS :
 * architecture, detection d'environnement sandboxe,
 * profils, limitations, et techniques d'evasion.
 * Demonstration pedagogique.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

/*
 * Etape 1 : Architecture de la sandbox macOS
 */
static void explain_sandbox_architecture(void) {
    printf("[*] Etape 1 : Architecture sandbox macOS\n\n");

    printf("    ┌──────────────────────────────────────────┐\n");
    printf("    │  Application sandboxee                    │\n");
    printf("    │  ┌──────────────────────────────────┐    │\n");
    printf("    │  │ Restrictions :                     │    │\n");
    printf("    │  │ - Acces fichier limite              │    │\n");
    printf("    │  │ - Reseau restreint                 │    │\n");
    printf("    │  │ - IPC limite                       │    │\n");
    printf("    │  │ - Hardware restreint               │    │\n");
    printf("    │  └──────────────┬───────────────────┘    │\n");
    printf("    │                 │ syscall                 │\n");
    printf("    │  ┌──────────────v───────────────────┐    │\n");
    printf("    │  │ Sandbox.kext (kernel)              │    │\n");
    printf("    │  │ - TrustedBSD MAC Framework         │    │\n");
    printf("    │  │ - Verifie le profil sandbox         │    │\n");
    printf("    │  │ - Autorise ou refuse                │    │\n");
    printf("    │  └──────────────────────────────────┘    │\n");
    printf("    └──────────────────────────────────────────┘\n\n");

    printf("    Types de sandbox :\n");
    printf("    ───────────────────────────────────\n");
    printf("    App Sandbox      : obligatoire sur Mac App Store\n");
    printf("    sandbox-exec     : outil CLI pour sandboxer\n");
    printf("    Profils .sb      : regles Scheme/SBPL\n\n");
}

/*
 * Etape 2 : Detection de la sandbox
 */
static void demo_sandbox_detection(void) {
    printf("[*] Etape 2 : Detection de la sandbox\n\n");

    printf("    Methodes de detection :\n");
    printf("    ───────────────────────────────────\n\n");

    /* Methode 1 : Variable d'environnement */
    printf("    1. Variable APP_SANDBOX_CONTAINER_ID :\n");
    const char *sandbox_id = getenv("APP_SANDBOX_CONTAINER_ID");
    printf("      APP_SANDBOX_CONTAINER_ID = %s\n\n",
           sandbox_id ? sandbox_id : "(non defini = pas sandboxe)");

    /* Methode 2 : Acces a /tmp */
    printf("    2. Verifier l'acces a /tmp :\n");
    struct stat st;
    if (stat("/tmp", &st) == 0) {
        printf("      /tmp accessible (probablement pas sandboxe)\n");
    } else {
        printf("      /tmp non accessible (sandbox detectee)\n");
    }
    printf("\n");

    /* Methode 3 : Ecriture dans des repertoires */
    printf("    3. Test d'ecriture dans des repertoires :\n");
    const char *test_dirs[] = {
        "/tmp/.sandbox_test",
        "/var/tmp/.sandbox_test",
        "/Users/Shared/.sandbox_test",
        NULL
    };

    for (int i = 0; test_dirs[i]; i++) {
        FILE *fp = fopen(test_dirs[i], "w");
        if (fp) {
            printf("      %s : ecriture OK (pas sandboxe)\n", test_dirs[i]);
            fclose(fp);
            unlink(test_dirs[i]);
        } else {
            printf("      %s : refuse (%s)\n", test_dirs[i], strerror(errno));
        }
    }
    printf("\n");

    /* Methode 4 : Container path */
    printf("    4. Container path :\n");
    const char *home = getenv("HOME");
    if (home) {
        if (strstr(home, "Containers")) {
            printf("      HOME contient 'Containers' -> sandboxe !\n");
            printf("      HOME = %s\n", home);
        } else {
            printf("      HOME normal : %s\n", home);
        }
    }
    printf("\n");
}

/*
 * Etape 3 : Profils sandbox
 */
static void explain_sandbox_profiles(void) {
    printf("[*] Etape 3 : Profils sandbox (.sb)\n\n");

    printf("    Syntaxe SBPL (Sandbox Profile Language) :\n");
    printf("    ───────────────────────────────────\n");
    printf("    (version 1)\n");
    printf("    (deny default)  ; tout interdire par defaut\n\n");
    printf("    (allow file-read*\n");
    printf("        (subpath \"/usr/lib\"))\n\n");
    printf("    (allow file-read-data\n");
    printf("        (literal \"/etc/resolv.conf\"))\n\n");
    printf("    (allow network-outbound\n");
    printf("        (remote tcp \"*:443\"))\n\n");

    printf("    Utilisation de sandbox-exec :\n");
    printf("    ───────────────────────────────────\n");
    printf("    sandbox-exec -f profile.sb /path/to/binary\n");
    printf("    sandbox-exec -p '(deny default)' /bin/ls\n\n");

    /* Lister les profils systeme */
    printf("    Profils systeme :\n");
    FILE *fp = popen("ls /System/Library/Sandbox/Profiles/ 2>/dev/null | head -10", "r");
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
 * Etape 4 : sandbox_check API
 */
static void explain_sandbox_api(void) {
    printf("[*] Etape 4 : API sandbox_check\n\n");

    printf("    #include <sandbox.h>\n\n");

    printf("    Verifier si on est sandboxe :\n");
    printf("    ───────────────────────────────────\n");
    printf("    // sandbox_check renvoie 0 si l'operation est autorisee\n");
    printf("    int sandboxed = sandbox_check(\n");
    printf("        getpid(),\n");
    printf("        \"file-write*\",\n");
    printf("        SANDBOX_FILTER_PATH,\n");
    printf("        \"/tmp/test\"\n");
    printf("    );\n");
    printf("    // sandboxed != 0 -> dans une sandbox\n\n");

    printf("    Initialiser une sandbox :\n");
    printf("    ───────────────────────────────────\n");
    printf("    char *error = NULL;\n");
    printf("    int ret = sandbox_init(\n");
    printf("        \"(version 1)(deny default)\",\n");
    printf("        SANDBOX_NAMED,\n");
    printf("        &error);\n");
    printf("    if (ret != 0) {\n");
    printf("        fprintf(stderr, \"Sandbox error: %%s\\n\", error);\n");
    printf("        sandbox_free_error(error);\n");
    printf("    }\n\n");
}

/*
 * Etape 5 : Techniques d'evasion
 */
static void explain_evasion(void) {
    printf("[*] Etape 5 : Techniques d'evasion\n\n");

    printf("    1. XPC service abuse :\n");
    printf("    ───────────────────────────────────\n");
    printf("    -> Communiquer avec un service non sandboxe\n");
    printf("    -> Le service execute les actions pour nous\n\n");

    printf("    2. Open/save dialog abuse :\n");
    printf("    ───────────────────────────────────\n");
    printf("    -> PowerBox : l'utilisateur ouvre un fichier\n");
    printf("    -> Le processus obtient un acces temporary\n\n");

    printf("    3. Exploitation de failles :\n");
    printf("    ───────────────────────────────────\n");
    printf("    -> CVE dans Sandbox.kext\n");
    printf("    -> Race conditions dans les checks\n");
    printf("    -> Symlink attacks\n\n");

    printf("    4. Abus de bookmarks :\n");
    printf("    ───────────────────────────────────\n");
    printf("    -> Security-scoped bookmarks\n");
    printf("    -> Persister l'acces a des fichiers\n\n");

    printf("    5. Contourner via interpretes :\n");
    printf("    ───────────────────────────────────\n");
    printf("    -> osascript, python, ruby\n");
    printf("    -> Si disponibles depuis la sandbox\n\n");
}

/*
 * Etape 6 : Detection et protection
 */
static void explain_detection(void) {
    printf("[*] Etape 6 : Detection et protection\n\n");

    printf("    Commandes utiles :\n");
    printf("    ───────────────────────────────────\n");
    printf("    # Verifier si un processus est sandboxe\n");
    printf("    codesign -d --entitlements - /path/app\n");
    printf("    # Chercher com.apple.security.app-sandbox\n\n");
    printf("    # Voir le profil sandbox d'un processus\n");
    printf("    sandbox-exec -D /dev/null cat /dev/stdin\n\n");
    printf("    # Logs sandbox\n");
    printf("    log show --predicate 'category == \"sandbox\"'\n\n");

    /* Verifier les entitlements sandbox de Safari */
    printf("    Entitlements sandbox de Safari :\n");
    FILE *fp = popen("codesign -d --entitlements - /Applications/Safari.app 2>&1 | "
                     "grep -i sandbox | head -5", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            line[strcspn(line, "\n")] = '\0';
            printf("      %s\n", line);
        }
        pclose(fp);
    }
    printf("\n");

    printf("    Protections :\n");
    printf("    - App Sandbox obligatoire pour le Mac App Store\n");
    printf("    - SIP protege Sandbox.kext\n");
    printf("    - Auditer les entitlements sandbox\n");
    printf("    - Monitorer les acces fichiers anormaux\n");
    printf("    - Endpoint Security pour les violations\n\n");
}

int main(void) {
    printf("[*] Demo : Sandbox Detection macOS\n\n");

    explain_sandbox_architecture();
    demo_sandbox_detection();
    explain_sandbox_profiles();
    explain_sandbox_api();
    explain_evasion();
    explain_detection();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
