# AMFI - Apple Mobile File Integrity

## Objectifs pédagogiques

À la fin de ce module, vous serez capable de :
- [ ] Comprendre le rôle et le fonctionnement d'AMFI sur macOS
- [ ] Analyser les vérifications de signature de code
- [ ] Identifier les mécanismes de vérification d'intégrité
- [ ] Implémenter des techniques de validation de code signé
- [ ] Comprendre les techniques de contournement (à des fins défensives)

## Prérequis

Avant de commencer ce module, assurez-vous de maîtriser :
- Les bases de la cryptographie (hachage, signatures)
- Le code signing sur macOS
- Les concepts de KEXT et kernel extensions
- L'architecture de sécurité macOS

## Introduction

AMFI (Apple Mobile File Integrity) est un sous-système kernel de macOS qui vérifie l'intégrité et l'authenticité des exécutables avant leur exécution. Initialement développé pour iOS, AMFI a été porté sur macOS pour renforcer la sécurité du système.

### Pourquoi ce sujet est important ?

Imaginez AMFI comme un vigile à l'entrée d'un bâtiment qui vérifie les badges de tous ceux qui veulent entrer. Chaque programme qui veut s'exécuter doit montrer son "badge" (signature de code) pour prouver qu'il est légitime.

Pour un opérateur Red Team, comprendre AMFI est crucial car :
- C'est une barrière majeure à l'exécution de code non signé
- Il bloque de nombreuses techniques d'injection et de modification
- Contourner AMFI nécessite des privilèges kernel ou des exploits
- Il protège contre les malwares et les modifications de binaires système

## Concepts fondamentaux

### Concept 1 : Architecture d'AMFI

```
┌─────────────────────────────────────────────────────────┐
│                    User Space                           │
│                                                         │
│  ┌──────────┐     ┌──────────┐     ┌──────────┐       │
│  │  App 1   │     │  App 2   │     │  App 3   │       │
│  │ (signed) │     │(unsigned)│     │ (signed) │       │
│  └────┬─────┘     └────┬─────┘     └────┬─────┘       │
│       │                │                │              │
│       │   exec()       │   exec()       │   exec()     │
│       ▼                ▼                ▼              │
├───────┼────────────────┼────────────────┼──────────────┤
│       │                │                │              │
│  ┌────▼────────────────▼────────────────▼──────────┐  │
│  │          BSD Layer (execve syscall)             │  │
│  └────────────────────┬────────────────────────────┘  │
│                       │                                │
│                       ▼                                │
│  ┌─────────────────────────────────────────────────┐  │
│  │            AMFI Kernel Extension                │  │
│  │         (AppleMobileFileIntegrity.kext)         │  │
│  └────────────┬────────────────────────────────────┘  │
│               │                                        │
│      ┌────────┼────────┐                              │
│      ▼        ▼        ▼                              │
│  ┌──────┐ ┌──────┐ ┌──────────┐                      │
│  │ CDHash│ │ Team │ │Entitle-  │                      │
│  │Verify │ │  ID  │ │ments     │                      │
│  └──────┘ └──────┘ └──────────┘                      │
│                                                        │
│           Kernel Space                                 │
└────────────────────────────────────────────────────────┘

Résultat de la vérification:
  ├─ ALLOW  → Exécution autorisée
  └─ DENY   → SIGKILL (processus tué)
```

### Concept 2 : Code Directory Hash (CDHash)

Le CDHash est l'empreinte cryptographique unique d'un binaire signé :

```
Binaire exécutable
      │
      ├─ Code Signature (embedded)
      │    │
      │    ├─ Code Directory
      │    │    ├─ Hash de chaque page de code
      │    │    ├─ Identifier (bundle ID)
      │    │    ├─ Team ID
      │    │    └─ Entitlements
      │    │
      │    ├─ CMS Signature
      │    │    └─ Signature du Code Directory
      │    │
      │    └─ Requirements
      │         └─ Règles de validation
      │
      └─ SHA256(Code Directory) = CDHash
```

### Concept 3 : Niveaux de vérification AMFI

AMFI applique différents niveaux de strictness selon la configuration :

| Mode | Description | Impact |
|------|-------------|--------|
| **Strict** | Tout doit être signé par Apple ou développeurs approuvés | Production (SIP actif) |
| **Permissive** | Autorise code non signé avec restrictions | Développement |
| **Disabled** | Désactivé (nécessite SIP off) | Testing/Debug |

### Concept 4 : Entitlements et privilèges

Les entitlements sont des permissions spéciales accordées aux applications signées :

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "...">
<plist version="1.0">
<dict>
    <!-- Accès au hardware (caméra, micro) -->
    <key>com.apple.security.device.camera</key>
    <true/>

    <!-- Désactivation de la sandbox -->
    <key>com.apple.security.app-sandbox</key>
    <false/>

    <!-- Injection de code (debugger) -->
    <key>com.apple.security.cs.debugger</key>
    <true/>

    <!-- Accès réseau sortant -->
    <key>com.apple.security.network.client</key>
    <true/>
</dict>
</plist>
```

## Mise en pratique

### Étape 1 : Vérifier la signature d'un binaire

```c
// check_signature.c
#include <Security/Security.h>
#include <stdio.h>

int check_code_signature(const char *path) {
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(
        kCFAllocatorDefault,
        (const UInt8 *)path,
        strlen(path),
        false
    );

    if (!url) {
        fprintf(stderr, "Erreur création URL\n");
        return -1;
    }

    SecStaticCodeRef staticCode = NULL;
    OSStatus status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &staticCode);
    CFRelease(url);

    if (status != errSecSuccess) {
        fprintf(stderr, "Erreur création SecStaticCode: %d\n", status);
        return -1;
    }

    // Vérifier la signature
    SecCSFlags flags = kSecCSStrictValidate | kSecCSCheckAllArchitectures;
    status = SecStaticCodeCheckValidity(staticCode, flags, NULL);

    if (status == errSecSuccess) {
        printf("[+] Signature valide\n");

        // Extraire les informations de signature
        CFDictionaryRef info = NULL;
        status = SecCodeCopySigningInformation(
            staticCode,
            kSecCSSigningInformation,
            &info
        );

        if (status == errSecSuccess && info) {
            // Afficher le Team ID
            CFStringRef teamID = CFDictionaryGetValue(info, kSecCodeInfoTeamIdentifier);
            if (teamID) {
                char team[256];
                CFStringGetCString(teamID, team, sizeof(team), kCFStringEncodingUTF8);
                printf("    Team ID: %s\n", team);
            }

            // Afficher l'identifier
            CFStringRef identifier = CFDictionaryGetValue(info, kSecCodeInfoIdentifier);
            if (identifier) {
                char ident[256];
                CFStringGetCString(identifier, ident, sizeof(ident), kCFStringEncodingUTF8);
                printf("    Identifier: %s\n", ident);
            }

            // Vérifier si c'est un binaire platform (Apple)
            CFNumberRef platformBinary = CFDictionaryGetValue(info, kSecCodeInfoPlatformIdentifier);
            if (platformBinary) {
                printf("    Platform Binary: YES\n");
            }

            CFRelease(info);
        }
    } else {
        printf("[-] Signature invalide ou absente: %d\n", status);
    }

    CFRelease(staticCode);
    return (status == errSecSuccess) ? 0 : -1;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <path_to_binary>\n", argv[0]);
        return 1;
    }

    return check_code_signature(argv[1]);
}
```

**Compilation :**
```bash
clang -framework Security -framework CoreFoundation \
      -o check_signature check_signature.c

# Tester avec un binaire système
./check_signature /bin/ls

# Tester avec votre propre app
./check_signature /Applications/YourApp.app/Contents/MacOS/YourApp
```

### Étape 2 : Extraire les entitlements d'un binaire

```c
// extract_entitlements.c
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>

void print_entitlements(const char *path) {
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(
        kCFAllocatorDefault,
        (const UInt8 *)path,
        strlen(path),
        false
    );

    SecStaticCodeRef staticCode = NULL;
    OSStatus status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &staticCode);
    CFRelease(url);

    if (status != errSecSuccess) {
        fprintf(stderr, "Erreur: %d\n", status);
        return;
    }

    // Copier les entitlements
    CFDictionaryRef entitlements = NULL;
    status = SecCodeCopySigningInformation(
        staticCode,
        kSecCSRequirementInformation,
        &entitlements
    );

    if (status == errSecSuccess && entitlements) {
        // Récupérer le dictionnaire des entitlements
        CFDictionaryRef ents = CFDictionaryGetValue(entitlements, kSecCodeInfoEntitlementsDict);

        if (ents) {
            printf("Entitlements trouvés:\n");

            // Convertir en XML pour affichage
            CFDataRef xmlData = CFPropertyListCreateData(
                kCFAllocatorDefault,
                ents,
                kCFPropertyListXMLFormat_v1_0,
                0,
                NULL
            );

            if (xmlData) {
                const UInt8 *bytes = CFDataGetBytePtr(xmlData);
                CFIndex length = CFDataGetLength(xmlData);
                fwrite(bytes, 1, length, stdout);
                CFRelease(xmlData);
            }
        } else {
            printf("Aucun entitlement trouvé\n");
        }

        CFRelease(entitlements);
    } else {
        printf("Impossible d'extraire les entitlements\n");
    }

    CFRelease(staticCode);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <binary>\n", argv[0]);
        return 1;
    }

    print_entitlements(argv[1]);
    return 0;
}
```

### Étape 3 : Vérifier l'état d'AMFI sur le système

```c
// check_amfi.c
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <stdbool.h>

bool is_amfi_enabled() {
    int mib[2] = {CTL_KERN, KERN_OSRELEASE};
    char version[256];
    size_t size = sizeof(version);

    if (sysctl(mib, 2, version, &size, NULL, 0) != 0) {
        return false;
    }

    // Vérifier via un autre sysctl (moins direct)
    // Note: Il n'y a pas de sysctl direct pour AMFI
    // On vérifie plutôt SIP qui inclut AMFI

    uint32_t csops_flags = 0;

    // Alternative: vérifier les flags de codesigning du processus actuel
    // Si AMFI est actif, certains flags seront présents

    return true; // AMFI est généralement toujours actif sur macOS moderne
}

void check_sip_status() {
    FILE *fp = popen("csrutil status", "r");
    if (fp == NULL) {
        fprintf(stderr, "Erreur exécution csrutil\n");
        return;
    }

    char buffer[256];
    printf("Status SIP (includes AMFI):\n");
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        printf("  %s", buffer);
    }

    pclose(fp);
}

void check_codesigning_flags() {
    // Vérifier les flags de code signing du processus actuel
    printf("\nVérification des flags de code signing:\n");

    uint32_t flags = 0;
    pid_t pid = getpid();

    // Note: csops() est une fonction privée, utilisons une approche alternative

    // Vérifier via codesign utility
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "codesign -dvvv /proc/%d/file 2>&1", pid);

    FILE *fp = popen(cmd, "r");
    if (fp) {
        char buffer[512];
        while (fgets(buffer, sizeof(buffer), fp)) {
            if (strstr(buffer, "flags=") ||
                strstr(buffer, "runtime") ||
                strstr(buffer, "hard") ||
                strstr(buffer, "kill")) {
                printf("  %s", buffer);
            }
        }
        pclose(fp);
    }
}

int main() {
    printf("=== AMFI Status Check ===\n\n");

    if (is_amfi_enabled()) {
        printf("[+] AMFI est probablement actif\n\n");
    }

    check_sip_status();
    check_codesigning_flags();

    printf("\n=== Recommandations ===\n");
    printf("- AMFI est intégré à SIP et ne peut pas être désactivé séparément\n");
    printf("- Pour le développement, utilisez des signatures de développeur valides\n");
    printf("- Les entitlements doivent être explicitement déclarés\n");

    return 0;
}
```

### Étape 4 : Signer un binaire avec entitlements

```bash
#!/bin/bash
# sign_with_entitlements.sh

BINARY="$1"
ENTITLEMENTS="$2"

if [ -z "$BINARY" ] || [ -z "$ENTITLEMENTS" ]; then
    echo "Usage: $0 <binary> <entitlements.plist>"
    exit 1
fi

# Créer un entitlement de base si non fourni
if [ ! -f "$ENTITLEMENTS" ]; then
    cat > "$ENTITLEMENTS" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
    <true/>
    <key>com.apple.security.cs.disable-library-validation</key>
    <true/>
</dict>
</plist>
EOF
    echo "[+] Fichier d'entitlements créé: $ENTITLEMENTS"
fi

# Signer le binaire
echo "[*] Signature du binaire avec entitlements..."
codesign --force --sign - \
         --entitlements "$ENTITLEMENTS" \
         --deep \
         "$BINARY"

if [ $? -eq 0 ]; then
    echo "[+] Signature réussie!"
    echo "[*] Vérification:"
    codesign -dvvv "$BINARY" 2>&1 | grep -E "(Signature|flags|entitlements)"
else
    echo "[-] Erreur lors de la signature"
    exit 1
fi
```

## Application offensive

### Contexte Red Team

AMFI représente une barrière significative pour les opérations Red Team sur macOS :

**Défis posés par AMFI :**

1. **Exécution de payloads non signés**
   - Les binaires non signés sont tués par AMFI
   - Nécessite soit une signature valide, soit un bypass

2. **Injection de code**
   - AMFI bloque l'injection dans des processus signés
   - L'entitlement `com.apple.security.cs.allow-unsigned-executable-memory` est requis

3. **Modification de binaires**
   - Toute modification invalide la signature
   - Le binaire modifié ne s'exécutera pas

**Techniques de contournement (recherche uniquement) :**

1. **Exploitation de binaires signés légitimes**
   ```c
   // Abuser d'un binaire Apple signé pour exécuter du code
   // Exemple: utiliser /usr/bin/python pour exécuter du code
   system("/usr/bin/python -c 'import os; os.system(\"/path/to/payload\")'");
   ```

2. **Signature ad-hoc avec entitlements permissifs**
   ```bash
   # Signer avec des entitlements qui permettent l'exécution de code
   codesign -s - --entitlements permissive.plist payload
   ```

3. **Exploitation de processus avec entitlements permissifs**
   - Chercher des processus signés avec des entitlements dangereux
   - Injecter du code dans ces processus

4. **Bypass via vulnérabilités kernel**
   - Exploiter une vuln kernel pour désactiver AMFI
   - Modifier les structures de données AMFI en mémoire kernel

### Considérations OPSEC

**Détection des tentatives de bypass AMFI :**

```bash
# Surveiller les violations AMFI dans les logs
log stream --predicate 'eventMessage contains "AMFI"' --level debug

# Chercher des processus avec des violations de signature
ps aux | while read line; do
    pid=$(echo $line | awk '{print $2}')
    codesign -dvvv /proc/$pid/file 2>&1 | grep -i "invalid\|unsigned"
done

# Vérifier les binaires modifiés récemment
find /Applications -type f -mtime -1 -exec codesign -v {} \; 2>&1 | grep -i invalid
```

**Indicateurs de compromission :**
- Processus avec signatures invalides mais toujours en exécution
- Modifications de binaires Apple
- Utilisation d'entitlements suspects (`cs.debugger`, `task_for_pid-allow`)
- Tentatives répétées d'exécution de code non signé

**Recommandations Red Team :**

1. **Privilégier les binaires signés**
   - Utilisez des certificats de développeur valides
   - Ou abusez des binaires Apple existants

2. **Living off the land**
   - Utilisez des outils système signés (python, ruby, osascript)
   - Évitez de déposer de nouveaux binaires

3. **Minimiser la surface d'attaque**
   - Code en mémoire uniquement (fileless)
   - Scripts interprétés plutôt que binaires compilés

## Résumé

- AMFI (Apple Mobile File Integrity) vérifie l'intégrité et l'authenticité des exécutables
- Il utilise les signatures de code, le CDHash et les entitlements
- AMFI bloque l'exécution de code non signé et invalide les signatures modifiées
- Les entitlements définissent les privilèges spéciaux d'une application
- AMFI est intégré à SIP et ne peut pas être désactivé sans désactiver SIP
- Pour les opérations Red Team, comprendre AMFI est crucial pour développer des payloads viables
- Les techniques de bypass nécessitent soit des exploits kernel, soit l'abus de binaires signés
- La détection des violations AMFI se fait via les logs système et la vérification de signatures

## Ressources complémentaires

- [Apple - Code Signing Guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/)
- [Jonathan Levin - AMFI Internals](http://newosxbook.com/articles/AMFI.html)
- [Siguza - AMFI Deep Dive](https://siguza.github.io/AMFI/)
- [Patrick Wardle - Bypassing AMFI](https://objectiveby.com/resources/)
- [Apple - Hardened Runtime](https://developer.apple.com/documentation/security/hardened_runtime)
- [codesign man page](https://ss64.com/osx/codesign.html)

---

**Navigation**
- [Module précédent](../M11_kext_basics/)
- [Module suivant](../M13_http_client_macos/)
