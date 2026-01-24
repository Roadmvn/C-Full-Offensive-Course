# Solutions - Code Signing

Ce document contient les solutions complètes des exercices du module M05 - Code Signing.

## Exercice 1 : Découverte - Vérifier la signature d'un binaire (Très facile)

**Objectif** : Créer un programme qui vérifie si un fichier est signé et affiche les informations de signature.

### Solution

```c
/*
 * exercice1_verify_signature.c
 *
 * Description : Vérification de signature de code d'un binaire
 *
 * Compilation :
 *   clang -framework Security -o exercice1 exercice1_verify_signature.c
 *
 * Usage :
 *   ./exercice1 /Applications/Safari.app
 */

#include <Security/Security.h>
#include <stdio.h>
#include <string.h>

/*
 * Fonction pour vérifier la signature d'un binaire
 *
 * @param path : Chemin vers le binaire à vérifier
 * @return : 0 si signé et valide, -1 sinon
 */
int check_signature(const char *path) {
    SecStaticCodeRef staticCode = NULL;
    OSStatus status;

    printf("[*] Vérification de : %s\n\n", path);

    // Étape 1 : Créer une référence au code depuis le chemin
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(
        NULL,                       // Allocateur par défaut
        (UInt8*)path,              // Chemin du fichier
        strlen(path),              // Longueur du chemin
        false                      // false = fichier, true = répertoire
    );

    if (url == NULL) {
        printf("[-] Erreur : Chemin invalide\n");
        return -1;
    }

    // Étape 2 : Créer une référence au code statique
    status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &staticCode);
    CFRelease(url);  // Libérer l'URL, on n'en a plus besoin

    if (status != errSecSuccess) {
        printf("[-] Impossible de créer la référence au code\n");
        printf("    Le fichier existe-t-il ?\n");
        return -1;
    }

    // Étape 3 : Vérifier la validité de la signature
    status = SecStaticCodeCheckValidity(
        staticCode,
        kSecCSDefaultFlags,        // Flags par défaut
        NULL                       // Requirements (NULL = vérification standard)
    );

    if (status == errSecSuccess) {
        printf("[+] SIGNATURE VALIDE\n\n");

        // Obtenir des informations supplémentaires
        CFDictionaryRef info = NULL;
        status = SecCodeCopySigningInformation(
            staticCode,
            kSecCSSigningInformation,
            &info
        );

        if (status == errSecSuccess && info != NULL) {
            printf("[*] Informations de signature :\n");

            // Identifier du code
            CFStringRef identifier = CFDictionaryGetValue(info, kSecCodeInfoIdentifier);
            if (identifier) {
                char id_buf[256];
                CFStringGetCString(identifier, id_buf, sizeof(id_buf), kCFStringEncodingUTF8);
                printf("    Identifier : %s\n", id_buf);
            }

            // Format
            CFNumberRef format = CFDictionaryGetValue(info, kSecCodeInfoFormat);
            if (format) {
                int fmt;
                CFNumberGetValue(format, kCFNumberIntType, &fmt);
                printf("    Format : 0x%x\n", fmt);
            }

            CFRelease(info);
        }

        CFRelease(staticCode);
        return 0;

    } else {
        printf("[-] SIGNATURE INVALIDE ou ABSENTE\n");
        printf("    Code d'erreur : %d\n", status);

        // Codes d'erreur courants
        if (status == errSecCSUnsigned) {
            printf("    Raison : Fichier non signé\n");
        } else if (status == errSecCSSignatureFailed) {
            printf("    Raison : Signature corrompue\n");
        } else if (status == errSecCSSignatureInvalid) {
            printf("    Raison : Signature invalide\n");
        }

        CFRelease(staticCode);
        return -1;
    }
}

int main(int argc, char *argv[]) {
    printf("[*] Exercice 1 : Vérification de signature\n");
    printf("==========================================\n\n");

    if (argc < 2) {
        printf("Usage : %s <chemin_vers_binaire>\n", argv[0]);
        printf("\nExemples :\n");
        printf("  %s /Applications/Safari.app\n", argv[0]);
        printf("  %s /bin/ls\n", argv[0]);
        return 1;
    }

    int result = check_signature(argv[1]);

    printf("\n[+] Vérification terminée\n");

    return result;
}
```

### Explications détaillées

1. **SecStaticCodeRef** : Référence à un code statique (binaire sur disque, pas en mémoire).

2. **SecStaticCodeCreateWithPath()** : Crée une référence au code depuis un chemin fichier.

3. **SecStaticCodeCheckValidity()** : Vérifie que la signature est valide et n'a pas été modifiée.

4. **Codes d'erreur** :
   - `errSecSuccess` (0) : Signature valide
   - `errSecCSUnsigned` : Pas de signature
   - `errSecCSSignatureFailed` : Signature corrompue

---

## Exercice 2 : Modification - Extraire les entitlements (Facile)

**Objectif** : Créer un programme qui extrait et affiche les entitlements d'un binaire signé.

### Solution

```c
/*
 * exercice2_extract_entitlements.c
 *
 * Description : Extraction des entitlements d'un binaire signé
 *
 * Compilation :
 *   clang -framework Security -framework CoreFoundation \
 *         -o exercice2 exercice2_extract_entitlements.c
 *
 * Usage :
 *   ./exercice2 /Applications/Safari.app
 */

#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <string.h>

/*
 * Fonction pour extraire et afficher les entitlements
 *
 * @param path : Chemin vers le binaire
 */
void extract_entitlements(const char *path) {
    SecStaticCodeRef staticCode = NULL;
    CFDictionaryRef info = NULL;
    OSStatus status;

    printf("[*] Extraction des entitlements de : %s\n\n", path);

    // Créer référence au code
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(
        NULL, (UInt8*)path, strlen(path), false
    );

    if (url == NULL) {
        printf("[-] Chemin invalide\n");
        return;
    }

    status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &staticCode);
    CFRelease(url);

    if (status != errSecSuccess) {
        printf("[-] Impossible de créer la référence au code\n");
        return;
    }

    // Obtenir les informations de signature (incluant entitlements)
    status = SecCodeCopySigningInformation(
        staticCode,
        kSecCSSigningInformation,  // Flag pour obtenir infos complètes
        &info
    );

    if (status != errSecSuccess) {
        printf("[-] Pas de signature trouvée\n");
        CFRelease(staticCode);
        return;
    }

    // Extraire le dictionnaire des entitlements
    CFDictionaryRef entitlements = CFDictionaryGetValue(
        info,
        kSecCodeInfoEntitlementsDict  // Clé pour les entitlements
    );

    if (entitlements == NULL) {
        printf("[*] Aucun entitlement trouvé\n");
        printf("    (Le binaire est signé mais sans entitlements)\n");
    } else {
        printf("[+] Entitlements trouvés :\n\n");

        // Compter les entitlements
        CFIndex count = CFDictionaryGetCount(entitlements);
        printf("    Nombre d'entitlements : %ld\n\n", count);

        // Allouer des tableaux pour les clés et valeurs
        const void **keys = malloc(count * sizeof(void*));
        const void **values = malloc(count * sizeof(void*));

        CFDictionaryGetKeysAndValues(entitlements, keys, values);

        // Afficher chaque entitlement
        for (CFIndex i = 0; i < count; i++) {
            CFStringRef key = (CFStringRef)keys[i];
            CFTypeRef value = (CFTypeRef)values[i];

            // Convertir la clé en C string
            char key_buf[512];
            CFStringGetCString(key, key_buf, sizeof(key_buf), kCFStringEncodingUTF8);

            printf("  [%ld] %s\n", i + 1, key_buf);

            // Déterminer le type de la valeur
            CFTypeID type = CFGetTypeID(value);

            if (type == CFBooleanGetTypeID()) {
                CFBooleanRef boolValue = (CFBooleanRef)value;
                printf("      Valeur : %s\n",
                       CFBooleanGetValue(boolValue) ? "true" : "false");
            } else if (type == CFStringGetTypeID()) {
                char val_buf[256];
                CFStringGetCString((CFStringRef)value, val_buf,
                                  sizeof(val_buf), kCFStringEncodingUTF8);
                printf("      Valeur : \"%s\"\n", val_buf);
            } else if (type == CFArrayGetTypeID()) {
                CFArrayRef array = (CFArrayRef)value;
                CFIndex array_count = CFArrayGetCount(array);
                printf("      Valeur : [Array de %ld éléments]\n", array_count);
            } else {
                printf("      Valeur : [Type non affiché]\n");
            }

            printf("\n");
        }

        free(keys);
        free(values);

        // Détecter les entitlements dangereux
        printf("\n[*] Analyse de sécurité :\n");

        if (CFDictionaryContainsKey(entitlements,
            CFSTR("com.apple.security.cs.disable-library-validation"))) {
            printf("  [!] RISQUE : disable-library-validation\n");
            printf("      → Injection DYLIB possible\n");
        }

        if (CFDictionaryContainsKey(entitlements,
            CFSTR("com.apple.security.cs.debugger"))) {
            printf("  [!] RISQUE : debugger entitlement\n");
            printf("      → Peut debugger d'autres processus\n");
        }

        if (CFDictionaryContainsKey(entitlements,
            CFSTR("com.apple.security.get-task-allow"))) {
            printf("  [!] INFO : get-task-allow\n");
            printf("      → task_for_pid() autorisé (debug build)\n");
        }
    }

    CFRelease(info);
    CFRelease(staticCode);
}

int main(int argc, char *argv[]) {
    printf("[*] Exercice 2 : Extraction des entitlements\n");
    printf("============================================\n\n");

    if (argc < 2) {
        printf("Usage : %s <chemin_vers_binaire>\n", argv[0]);
        printf("\nExemples :\n");
        printf("  %s /Applications/Safari.app\n", argv[0]);
        printf("  %s /System/Applications/Mail.app\n", argv[0]);
        return 1;
    }

    extract_entitlements(argv[1]);

    printf("\n[+] Extraction terminée\n");

    return 0;
}
```

### Explications détaillées

1. **kSecCodeInfoEntitlementsDict** : Clé pour obtenir le dictionnaire des entitlements depuis les informations de signature.

2. **CFDictionary** : Les entitlements sont stockés dans un dictionnaire CoreFoundation (clé-valeur).

3. **Entitlements dangereux** :
   - `disable-library-validation` : Permet l'injection de DYLIB non signées
   - `debugger` : Permet de debugger d'autres processus
   - `get-task-allow` : Autorise task_for_pid()

---

## Exercice 3 : Création - Scanner des apps pour entitlements dangereux (Moyen)

**Objectif** : Créer un scanner qui parcourt /Applications et identifie les apps avec entitlements à risque.

### Solution

```c
/*
 * exercice3_entitlement_scanner.c
 *
 * Description : Scanner d'applications pour entitlements dangereux
 *
 * Compilation :
 *   clang -framework Security -framework CoreFoundation \
 *         -o exercice3 exercice3_entitlement_scanner.c
 *
 * Usage :
 *   ./exercice3
 */

#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

#define GREEN   "\x1b[32m"
#define RED     "\x1b[31m"
#define YELLOW  "\x1b[33m"
#define RESET   "\x1b[0m"

// Entitlements dangereux à rechercher
const char *dangerous_entitlements[] = {
    "com.apple.security.cs.disable-library-validation",
    "com.apple.security.cs.allow-jit",
    "com.apple.security.cs.allow-unsigned-executable-memory",
    "com.apple.security.cs.debugger",
    "com.apple.security.get-task-allow",
    "com.apple.private.tcc.allow",
    NULL
};

/*
 * Fonction pour vérifier si une app a des entitlements dangereux
 *
 * @param path : Chemin vers l'app
 * @return : Nombre d'entitlements dangereux trouvés
 */
int scan_app_entitlements(const char *path) {
    SecStaticCodeRef staticCode = NULL;
    CFDictionaryRef info = NULL;
    OSStatus status;
    int dangerous_count = 0;

    // Créer référence au code
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(
        NULL, (UInt8*)path, strlen(path), false
    );

    if (url == NULL) return 0;

    status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &staticCode);
    CFRelease(url);

    if (status != errSecSuccess) return 0;

    // Obtenir informations de signature
    status = SecCodeCopySigningInformation(
        staticCode,
        kSecCSSigningInformation,
        &info
    );

    if (status != errSecSuccess) {
        CFRelease(staticCode);
        return 0;
    }

    // Extraire entitlements
    CFDictionaryRef entitlements = CFDictionaryGetValue(
        info,
        kSecCodeInfoEntitlementsDict
    );

    if (entitlements != NULL) {
        // Vérifier chaque entitlement dangereux
        for (int i = 0; dangerous_entitlements[i] != NULL; i++) {
            CFStringRef key = CFStringCreateWithCString(
                NULL,
                dangerous_entitlements[i],
                kCFStringEncodingUTF8
            );

            if (CFDictionaryContainsKey(entitlements, key)) {
                if (dangerous_count == 0) {
                    printf("\n" RED "[!]" RESET " %s\n", path);
                }

                printf("    " YELLOW "→" RESET " %s\n", dangerous_entitlements[i]);
                dangerous_count++;
            }

            CFRelease(key);
        }
    }

    CFRelease(info);
    CFRelease(staticCode);

    return dangerous_count;
}

/*
 * Fonction pour scanner un répertoire d'applications
 *
 * @param dir_path : Chemin vers le répertoire
 */
void scan_directory(const char *dir_path) {
    DIR *dir = opendir(dir_path);
    struct dirent *entry;
    int total_scanned = 0;
    int total_vulnerable = 0;

    if (dir == NULL) {
        printf("[-] Impossible d'ouvrir : %s\n", dir_path);
        return;
    }

    printf("[*] Scan de : %s\n", dir_path);
    printf("========================================\n");

    // Parcourir tous les fichiers
    while ((entry = readdir(dir)) != NULL) {
        // Ignorer . et ..
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        // Vérifier si c'est un .app
        if (strstr(entry->d_name, ".app") != NULL) {
            char full_path[1024];
            snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);

            // Scanner l'application
            int dangerous = scan_app_entitlements(full_path);

            if (dangerous > 0) {
                total_vulnerable++;
            }

            total_scanned++;
        }
    }

    closedir(dir);

    printf("\n========================================\n");
    printf("[*] Résumé :\n");
    printf("    Applications scannées : %d\n", total_scanned);
    printf("    Vulnérables : " RED "%d" RESET "\n", total_vulnerable);
}

int main() {
    printf("\n");
    printf("╔═══════════════════════════════════════╗\n");
    printf("║  Exercice 3 : Entitlement Scanner    ║\n");
    printf("╚═══════════════════════════════════════╝\n\n");

    printf("[*] Entitlements dangereux recherchés :\n");
    for (int i = 0; dangerous_entitlements[i] != NULL; i++) {
        printf("  %d. %s\n", i + 1, dangerous_entitlements[i]);
    }
    printf("\n");

    // Scanner /Applications
    scan_directory("/Applications");

    // Scanner /System/Applications (apps système)
    printf("\n\n");
    scan_directory("/System/Applications");

    printf("\n[+] Scan terminé\n\n");

    return 0;
}
```

### Explications détaillées

1. **Scan récursif** : Le programme parcourt tous les fichiers .app dans un répertoire.

2. **Liste d'entitlements** : On définit une liste d'entitlements considérés comme dangereux en Red Team.

3. **Application offensive** : Ce scanner permet d'identifier rapidement les cibles potentielles pour :
   - DYLIB injection (disable-library-validation)
   - JIT spraying (allow-jit)
   - Process injection (allow-unsigned-executable-memory)

---

## Exercice 4 : Challenge - Bypass Gatekeeper via signature (Difficile)

**Objectif** : Créer un programme qui détecte et supprime l'attribut quarantine pour bypasser Gatekeeper.

### Solution

```c
/*
 * exercice4_gatekeeper_bypass.c
 *
 * Description : Détection et suppression de quarantine pour bypass Gatekeeper
 *
 * Compilation :
 *   clang -framework Security -o exercice4 exercice4_gatekeeper_bypass.c
 *
 * Usage :
 *   ./exercice4 <chemin_app> [--remove]
 */

#include <Security/Security.h>
#include <sys/xattr.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define QUARANTINE_ATTR "com.apple.quarantine"

/*
 * Fonction pour vérifier si un fichier a l'attribut quarantine
 *
 * @param path : Chemin vers le fichier
 * @return : 1 si quarantine présent, 0 sinon, -1 en cas d'erreur
 */
int check_quarantine(const char *path) {
    char buf[1024];
    ssize_t size = getxattr(path, QUARANTINE_ATTR, buf, sizeof(buf), 0, 0);

    if (size > 0) {
        printf("[!] Attribut quarantine détecté\n");
        printf("    Contenu : %.*s\n", (int)size, buf);

        // Parser le contenu
        char *flags_str = strtok(buf, ";");
        char *timestamp = strtok(NULL, ";");
        char *app = strtok(NULL, ";");
        char *uuid = strtok(NULL, ";");

        if (flags_str) printf("    Flags : %s\n", flags_str);
        if (timestamp) printf("    Timestamp : %s\n", timestamp);
        if (app) printf("    App : %s\n", app);
        if (uuid) printf("    UUID : %s\n", uuid);

        return 1;
    } else if (size == -1 && errno == ENOATTR) {
        printf("[+] Pas d'attribut quarantine\n");
        return 0;
    } else {
        printf("[-] Erreur lors de la vérification : %s\n", strerror(errno));
        return -1;
    }
}

/*
 * Fonction pour supprimer l'attribut quarantine
 *
 * @param path : Chemin vers le fichier
 * @return : 0 en cas de succès, -1 en cas d'erreur
 */
int remove_quarantine(const char *path) {
    printf("\n[*] Suppression de l'attribut quarantine...\n");

    if (removexattr(path, QUARANTINE_ATTR, 0) == 0) {
        printf("[+] Quarantine supprimé avec succès\n");
        printf("[+] Le fichier peut maintenant être exécuté sans prompt Gatekeeper\n");
        return 0;
    } else {
        printf("[-] Échec de la suppression : %s\n", strerror(errno));
        return -1;
    }
}

/*
 * Fonction pour vérifier la signature du fichier
 */
void check_code_signature(const char *path) {
    SecStaticCodeRef staticCode = NULL;
    OSStatus status;

    printf("\n[*] Vérification de la signature...\n");

    CFURLRef url = CFURLCreateFromFileSystemRepresentation(
        NULL, (UInt8*)path, strlen(path), false
    );

    if (url == NULL) {
        printf("[-] Chemin invalide\n");
        return;
    }

    status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &staticCode);
    CFRelease(url);

    if (status != errSecSuccess) {
        printf("[-] Pas de signature\n");
        return;
    }

    status = SecStaticCodeCheckValidity(staticCode, kSecCSDefaultFlags, NULL);

    if (status == errSecSuccess) {
        printf("[+] Signature valide\n");

        // Obtenir l'identité du signataire
        CFDictionaryRef info = NULL;
        SecCodeCopySigningInformation(staticCode, kSecCSSigningInformation, &info);

        if (info) {
            CFStringRef identifier = CFDictionaryGetValue(info, kSecCodeInfoIdentifier);
            if (identifier) {
                char id_buf[256];
                CFStringGetCString(identifier, id_buf, sizeof(id_buf),
                                  kCFStringEncodingUTF8);
                printf("    Identifier : %s\n", id_buf);
            }
            CFRelease(info);
        }
    } else if (status == errSecCSUnsigned) {
        printf("[-] Fichier non signé\n");
        printf("    [!] Gatekeeper bloquera ce fichier même sans quarantine\n");
    } else {
        printf("[-] Signature invalide\n");
    }

    CFRelease(staticCode);
}

/*
 * Fonction pour afficher les techniques de bypass
 */
void print_bypass_techniques() {
    printf("\n╔═══════════════════════════════════════════════════════╗\n");
    printf("║      Techniques de Bypass Gatekeeper                 ║\n");
    printf("╚═══════════════════════════════════════════════════════╝\n\n");

    printf("1. Suppression quarantine (cette méthode)\n");
    printf("   → xattr -d com.apple.quarantine <fichier>\n\n");

    printf("2. Archive ZIP sans quarantine\n");
    printf("   → Créer ZIP localement sans téléchargement\n\n");

    printf("3. DMG mount trick\n");
    printf("   → Fichiers dans DMG n'héritent pas quarantine\n\n");

    printf("4. Right-click > Open\n");
    printf("   → Social engineering : demander à l'utilisateur\n\n");

    printf("5. Copie vers /Applications\n");
    printf("   → Désactive App Translocation\n\n");
}

int main(int argc, char *argv[]) {
    printf("\n╔═══════════════════════════════════════╗\n");
    printf("║  Exercice 4 : Gatekeeper Bypass      ║\n");
    printf("╚═══════════════════════════════════════╝\n\n");

    if (argc < 2) {
        printf("Usage : %s <chemin_fichier> [--remove]\n\n", argv[0]);
        printf("Options :\n");
        printf("  --remove : Supprimer l'attribut quarantine\n\n");
        printf("Exemples :\n");
        printf("  %s ~/Downloads/app.app\n", argv[0]);
        printf("  %s ~/Downloads/app.app --remove\n", argv[0]);
        return 1;
    }

    const char *path = argv[1];
    int should_remove = (argc > 2 && strcmp(argv[2], "--remove") == 0);

    printf("[*] Analyse de : %s\n\n", path);

    // Vérifier la signature
    check_code_signature(path);

    printf("\n");

    // Vérifier le quarantine
    int has_quarantine = check_quarantine(path);

    // Supprimer si demandé
    if (has_quarantine == 1 && should_remove) {
        remove_quarantine(path);
    } else if (has_quarantine == 1) {
        printf("\n[*] Pour supprimer le quarantine, relancez avec --remove\n");
    }

    // Afficher techniques
    print_bypass_techniques();

    printf("\n[+] Analyse terminée\n\n");

    return 0;
}
```

### Explications détaillées

1. **Extended Attributes** : macOS utilise xattr pour stocker des métadonnées. `com.apple.quarantine` marque les fichiers téléchargés.

2. **Format quarantine** : `flags;timestamp;app;uuid`
   - flags : Type de quarantine
   - timestamp : Date de téléchargement
   - app : Application ayant téléchargé
   - uuid : Identifiant unique

3. **Bypass Gatekeeper** : En supprimant le quarantine, macOS ne vérifie plus la signature/notarization au premier lancement.

4. **OPSEC** : Cette technique laisse des traces dans les logs système. En Red Team, préférer les méthodes plus furtives (ZIP, DMG).

---

## Résumé des concepts clés

- **Code Signing** : Signature cryptographique prouvant l'authenticité
- **Entitlements** : Permissions spéciales déclarées dans la signature
- **Gatekeeper** : Système de vérification au premier lancement
- **Quarantine** : Attribut marquant les fichiers téléchargés
- **Notarization** : Validation par Apple (scan malware)

## Compilation de tous les exercices

```bash
# Exercice 1
clang -framework Security -o ex1 exercice1_verify_signature.c

# Exercice 2
clang -framework Security -framework CoreFoundation \
      -o ex2 exercice2_extract_entitlements.c

# Exercice 3
clang -framework Security -framework CoreFoundation \
      -o ex3 exercice3_entitlement_scanner.c

# Exercice 4
clang -framework Security -o ex4 exercice4_gatekeeper_bypass.c

# Exécution
./ex1 /Applications/Safari.app
./ex2 /Applications/Safari.app
./ex3
./ex4 ~/Downloads/app.app --remove
```

## Points importants pour Red Team

1. **Reconnaissance** : Scanner les apps pour entitlements dangereux = identifier cibles pour injection
2. **Bypass Gatekeeper** : Plusieurs méthodes (xattr, ZIP, DMG)
3. **Living off the Land** : Utiliser binaires Apple signés (curl, python, osascript)
4. **OPSEC** : xattr laisse traces, préférer méthodes furtives

## Techniques avancées (bonus)

```bash
# Créer signature ad-hoc
codesign -s - malware

# Signer avec entitlements custom
codesign -s - --entitlements ent.plist malware

# Vérifier notarization
spctl -a -vv app.app

# Lister tous les certificats de signature
security find-identity -v -p codesigning
```

---

**Note** : Ces exercices sont à but pédagogique. L'utilisation de techniques de bypass dans un contexte réel nécessite une autorisation explicite dans le cadre d'un test d'intrusion légitime.
