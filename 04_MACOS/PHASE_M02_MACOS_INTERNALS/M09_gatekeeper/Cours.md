# Cours : Gatekeeper - Quarantine & Notarization Bypass

## 1. Introduction - Le Gardien de macOS

### 1.1 Qu'est-ce que Gatekeeper ?

**Gatekeeper** est un système de sécurité macOS introduit dans **OS X Mountain Lion (10.8)** en 2012. Il empêche l'exécution d'applications non signées ou non approuvées par Apple.

**Analogie simple** :
```ascii
Imaginez un club privé avec un videur :

┌─────────────────────────────────────────┐
│         CLUB macOS                      │
│                                         │
│  ┌───────────┐                          │
│  │           │                          │
│  │ GATEKEEPER│ ← "Videur" du club       │
│  │  (Videur) │                          │
│  └─────┬─────┘                          │
│        │                                │
│        ▼                                │
│  ┌─────────────────┐                    │
│  │ VÉRIFICATIONS : │                    │
│  │ 1. Signature ?  │                    │
│  │ 2. Notarization?│                    │
│  │ 3. Quarantine ? │                    │
│  └─────────────────┘                    │
│        │                                │
│   ┌────┴────┐                           │
│   ▼         ▼                           │
│ AUTORISÉ  BLOQUÉ                        │
└─────────────────────────────────────────┘
```

### 1.2 Les Trois Mécanismes de Protection

Gatekeeper combine **trois** systèmes :

1. **Code Signing** : L'app est-elle signée ?
2. **Notarization** : Apple a-t-elle vérifié l'app ?
3. **Quarantine** : L'app vient-elle d'Internet ?

```ascii
FLUX DE VÉRIFICATION GATEKEEPER :

Utilisateur double-clique sur app.app
         │
         ▼
┌────────────────────────┐
│  1. QUARANTINE FLAG    │
│  com.apple.quarantine  │ ← Fichier vient d'Internet ?
└────────┬───────────────┘
         │ OUI
         ▼
┌────────────────────────┐
│  2. CODE SIGNATURE     │
│  Developer ID ?        │ ← App signée par développeur ?
└────────┬───────────────┘
         │ OUI
         ▼
┌────────────────────────┐
│  3. NOTARIZATION       │
│  Apple approved ?      │ ← Apple a scanné l'app ?
└────────┬───────────────┘
         │ OUI
         ▼
    EXÉCUTION AUTORISÉE
```

### 1.3 Pourquoi Gatekeeper existe ?

**Avant Gatekeeper** (pré-2012) :
- N'importe quelle app pouvait s'exécuter
- Malwares facilement installés
- Utilisateurs trompés par fake apps

**Problème** : MacDefender, Flashback, autres malwares

**Solution Gatekeeper** :
- Bloquer apps non signées
- Forcer la notarization
- Alerter l'utilisateur

## 2. Mécanisme 1 : Quarantine

### 2.1 Qu'est-ce que Quarantine ?

Quand vous téléchargez un fichier depuis Internet, macOS lui ajoute un **extended attribute** (xattr) :

```c
com.apple.quarantine
```

Cet attribut indique :
- D'où vient le fichier (URL)
- Quand il a été téléchargé
- Quelle app l'a téléchargé (Safari, curl, etc.)

### 2.2 Voir les Attributs Quarantine

```bash
# Télécharger une app
curl -o app https://example.com/app

# Voir les extended attributes
xattr app

# Sortie :
com.apple.quarantine

# Voir le contenu
xattr -p com.apple.quarantine app

# Sortie :
0083;64f5e2a5;Safari;E6B7F8A4-9D1C-4E5F-B8A0-1234567890AB
```

Format : `flags;timestamp;app;UUID`

### 2.3 Structure du Flag Quarantine

```c
// Flags (premier champ)
#define QTN_FLAG_DOWNLOAD       0x0001  // Téléchargé
#define QTN_FLAG_SANDBOX        0x0002  // Sandboxé
#define QTN_FLAG_HARD           0x0004  // Quarantine stricte
#define QTN_FLAG_USER_APPROVED  0x0040  // Approuvé par utilisateur
```

### 2.4 Vérifier Quarantine en C

```c
#include <sys/xattr.h>
#include <stdio.h>

int check_quarantine(const char *path) {
    char buf[1024];
    ssize_t size = getxattr(path, "com.apple.quarantine", buf, sizeof(buf), 0, 0);

    if (size > 0) {
        printf("[!] File has quarantine flag: %.*s\n", (int)size, buf);
        return 1;
    } else if (size == -1 && errno == ENOATTR) {
        printf("[+] No quarantine flag\n");
        return 0;
    } else {
        perror("getxattr");
        return -1;
    }
}
```

## 3. Mécanisme 2 : Code Signing

### 3.1 Developer ID

Pour qu'une app passe Gatekeeper, elle doit être signée avec un **Developer ID** :

```bash
# Vérifier signature
codesign -dv app.app

# Sortie :
Executable=/path/to/app.app/Contents/MacOS/app
Identifier=com.example.app
Format=app bundle with Mach-O universal (x86_64 arm64)
Authority=Developer ID Application: John Doe (ABCD123456)
```

### 3.2 Types de Signatures

| Type | Description | Gatekeeper |
|------|-------------|------------|
| **Unsigned** | Pas de signature | Bloqué |
| **Ad-hoc** | `codesign -s -` | Bloqué |
| **Development** | Certificat dev | Bloqué |
| **Developer ID** | Certificat production | Autorisé |
| **App Store** | Signé par Apple | Autorisé |

### 3.3 Vérifier Signature en C

```c
#include <Security/CodeSigning.h>

int check_signature(const char *path) {
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL,
        (const UInt8 *)path, strlen(path), false);

    SecStaticCodeRef code = NULL;
    OSStatus status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);

    if (status != errSecSuccess) {
        printf("[!] Not signed\n");
        CFRelease(url);
        return 0;
    }

    // Vérifier signature valide
    status = SecStaticCodeCheckValidity(code, kSecCSDefaultFlags, NULL);

    if (status == errSecSuccess) {
        printf("[+] Valid signature\n");
        CFRelease(code);
        CFRelease(url);
        return 1;
    } else {
        printf("[!] Invalid signature\n");
        CFRelease(code);
        CFRelease(url);
        return 0;
    }
}
```

## 4. Mécanisme 3 : Notarization

### 4.1 Qu'est-ce que la Notarization ?

Depuis **macOS Catalina (10.15)**, Apple exige que les apps soient **notariées** :

1. Développeur soumet l'app à Apple
2. Apple scanne l'app (malware, conformité)
3. Apple retourne un "ticket" de notarization
4. Ticket attaché à l'app (stapling)

```ascii
PROCESSUS NOTARIZATION :

Développeur                          Apple
    │                                  │
    ├─ 1. Upload app ──────────────────▶│
    │                                  │
    │                            ┌─────┴─────┐
    │                            │  SCAN     │
    │                            │  - Malware│
    │                            │  - APIs   │
    │                            └─────┬─────┘
    │                                  │
    │◀── 2. Notarization ticket ───────┤
    │                                  │
    ├─ 3. Staple ticket to app         │
    │                                  │
    ▼                                  ▼
  app.app (notarisée)           Validation OK
```

### 4.2 Vérifier Notarization

```bash
# Vérifier si app est notariée
spctl -a -vv app.app

# Sortie si notariée :
app.app: accepted
source=Notarized Developer ID
origin=Developer ID Application: John Doe (ABCD123456)

# Sortie si non notariée :
app.app: rejected
source=no usable signature
```

### 4.3 Vérifier Notarization en C

```c
#include <Security/Security.h>

int check_notarization(const char *path) {
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL,
        (const UInt8 *)path, strlen(path), false);

    SecStaticCodeRef code = NULL;
    SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);

    // Vérifier si notarisé
    CFDictionaryRef info = NULL;
    SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info);

    if (info) {
        // Chercher clé "notarization"
        CFDictionaryRef dict = CFDictionaryGetValue(info, kSecCodeInfoPList);
        // ... parser plist

        CFRelease(info);
    }

    CFRelease(code);
    CFRelease(url);
    return 0;
}
```

## 5. Bypass Gatekeeper - Techniques

### 5.1 Supprimer le Flag Quarantine

**Méthode la plus simple** :

```bash
# Supprimer l'attribut quarantine
xattr -d com.apple.quarantine app.app

# Ou supprimer TOUS les xattr
xattr -c app.app
```

En C :

```c
#include <sys/xattr.h>

int remove_quarantine(const char *path) {
    if (removexattr(path, "com.apple.quarantine", 0) == 0) {
        printf("[+] Quarantine removed\n");
        return 0;
    } else {
        perror("removexattr");
        return -1;
    }
}
```

### 5.2 ZIP Archive Trick

Créer une archive ZIP **avant** que quarantine soit appliqué :

```bash
# Créer app sans quarantine
curl -o app https://example.com/app
xattr -c app  # Supprimer quarantine

# Créer archive ZIP
zip -r app.zip app

# L'archive n'a PAS de quarantine
# Quand l'utilisateur décompresse, app n'aura pas quarantine
```

### 5.3 DMG Trick

Monter un DMG et copier l'app hors du DMG :

```bash
# Télécharger DMG
curl -o app.dmg https://example.com/app.dmg

# Le DMG a quarantine, mais pas les fichiers DEDANS
hdiutil attach app.dmg
cp -r /Volumes/App/App.app ~/Applications/
hdiutil detach /Volumes/App
```

### 5.4 AppleScript / osascript Bypass

Utiliser AppleScript pour ouvrir l'app (bypass Gatekeeper) :

```bash
osascript -e 'tell application "Terminal" to do script "/path/to/malicious_app"'
```

### 5.5 Browser Exploit (Auto-Open)

Configurer Safari pour auto-ouvrir certains fichiers après téléchargement :

```bash
# Safari peut auto-ouvrir .zip, .dmg
# Si app est dans .zip, elle s'ouvre sans prompt Gatekeeper
```

### 5.6 App Translocation Bypass

macOS "transloc" déplace les apps téléchargées dans un dossier temporaire. Bypass :

```bash
# Déplacer app dans /Applications (désactive translocation)
mv ~/Downloads/App.app /Applications/
```

## 6. Détection de Gatekeeper en Red Team

### 6.1 Vérifier si Gatekeeper est Actif

```bash
# Vérifier statut Gatekeeper
spctl --status

# Sortie :
assessments enabled

# Ou :
assessments disabled
```

En C :

```c
#include <stdlib.h>

int is_gatekeeper_enabled() {
    FILE *fp = popen("spctl --status", "r");
    if (fp == NULL) return -1;

    char buf[128];
    if (fgets(buf, sizeof(buf), fp) != NULL) {
        if (strstr(buf, "enabled") != NULL) {
            pclose(fp);
            return 1;  // Activé
        }
    }

    pclose(fp);
    return 0;  // Désactivé
}
```

### 6.2 Vérifier Quarantine d'un Fichier

```c
#include <sys/xattr.h>

int has_quarantine(const char *path) {
    char buf[1024];
    ssize_t size = getxattr(path, "com.apple.quarantine", buf, sizeof(buf), 0, 0);

    if (size > 0) {
        return 1;  // A quarantine
    } else if (size == -1 && errno == ENOATTR) {
        return 0;  // Pas de quarantine
    }

    return -1;  // Erreur
}
```

## 7. Code Complet - Gatekeeper Checker

```c
// gatekeeper_checker.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/xattr.h>
#include <errno.h>

#define GREEN   "\x1b[32m"
#define RED     "\x1b[31m"
#define YELLOW  "\x1b[33m"
#define RESET   "\x1b[0m"

void print_banner() {
    printf("╔═══════════════════════════════════╗\n");
    printf("║   macOS Gatekeeper Checker        ║\n");
    printf("╚═══════════════════════════════════╝\n\n");
}

int check_gatekeeper_status() {
    FILE *fp = popen("spctl --status 2>/dev/null", "r");
    if (fp == NULL) {
        printf(RED "[!]" RESET " Could not check Gatekeeper status\n");
        return -1;
    }

    char buf[128];
    if (fgets(buf, sizeof(buf), fp) != NULL) {
        if (strstr(buf, "enabled") != NULL) {
            printf(GREEN "[+]" RESET " Gatekeeper: ENABLED\n");
            pclose(fp);
            return 1;
        } else if (strstr(buf, "disabled") != NULL) {
            printf(RED "[!]" RESET " Gatekeeper: DISABLED\n");
            pclose(fp);
            return 0;
        }
    }

    pclose(fp);
    return -1;
}

int check_quarantine(const char *path) {
    char buf[1024];
    ssize_t size = getxattr(path, "com.apple.quarantine", buf, sizeof(buf), 0, 0);

    if (size > 0) {
        printf(YELLOW "[!]" RESET " File has quarantine flag: %s\n", path);
        printf("    Content: %.*s\n", (int)size, buf);
        return 1;
    } else if (size == -1 && errno == ENOATTR) {
        printf(GREEN "[+]" RESET " No quarantine flag: %s\n", path);
        return 0;
    } else {
        printf(RED "[!]" RESET " Error checking quarantine: %s\n", strerror(errno));
        return -1;
    }
}

int remove_quarantine(const char *path) {
    if (removexattr(path, "com.apple.quarantine", 0) == 0) {
        printf(GREEN "[+]" RESET " Quarantine removed: %s\n", path);
        return 0;
    } else {
        printf(RED "[!]" RESET " Failed to remove quarantine: %s\n", strerror(errno));
        return -1;
    }
}

void print_bypass_techniques() {
    printf("\n" YELLOW "[*]" RESET " Gatekeeper Bypass Techniques:\n\n");
    printf("1. Remove quarantine attribute:\n");
    printf("   xattr -d com.apple.quarantine app.app\n\n");

    printf("2. ZIP archive trick:\n");
    printf("   zip -r app.zip app.app\n");
    printf("   (ZIP created without quarantine)\n\n");

    printf("3. DMG trick:\n");
    printf("   Files inside DMG don't inherit quarantine\n\n");

    printf("4. AppleScript bypass:\n");
    printf("   osascript -e 'tell app \"Terminal\" to do script \"./app\"'\n\n");

    printf("5. Move to /Applications:\n");
    printf("   mv app.app /Applications/\n\n");
}

int main(int argc, char *argv[]) {
    print_banner();

    // Vérifier statut Gatekeeper
    printf(YELLOW "[*]" RESET " Checking Gatekeeper status:\n");
    check_gatekeeper_status();
    printf("\n");

    // Vérifier quarantine d'un fichier (si fourni)
    if (argc > 1) {
        printf(YELLOW "[*]" RESET " Checking quarantine for: %s\n", argv[1]);
        int has_qtn = check_quarantine(argv[1]);

        if (has_qtn == 1 && argc > 2 && strcmp(argv[2], "--remove") == 0) {
            printf("\n" YELLOW "[*]" RESET " Removing quarantine...\n");
            remove_quarantine(argv[1]);
        }
    }

    // Afficher techniques de bypass
    print_bypass_techniques();

    return 0;
}
```

**Compilation** :

```bash
clang -o gk_check gatekeeper_checker.c
./gk_check /path/to/app.app
./gk_check /path/to/app.app --remove  # Supprimer quarantine
```

## 8. Implications Red Team

### 8.1 Reconnaissance

```ascii
PHASE 1 : RECON

1. Vérifier Gatekeeper status
   $ spctl --status

2. Identifier fichiers avec quarantine
   $ find ~/Downloads -name "*.app" -exec xattr -p com.apple.quarantine {} \;

3. Tester bypass techniques

4. Identifier apps signées mais pas notariées
```

### 8.2 Stratégies d'Attaque

```ascii
Si Gatekeeper ACTIVÉ :
├─ Supprimer quarantine (xattr -d)
├─ Utiliser ZIP trick
├─ Exploiter auto-open Safari
├─ Utiliser AppleScript bypass
└─ Social engineering (demander à l'utilisateur de clic droit > Ouvrir)

Si Gatekeeper DÉSACTIVÉ :
├─ Exécution directe possible
└─ Aucune vérification
```

### 8.3 OPSEC

1. **Éviter** de laisser traces de `xattr -d` dans l'historique
2. **Utiliser** ZIP ou DMG pour livraison
3. **Préférer** apps signées (même ad-hoc)
4. **Tester** sur VM avant déploiement

## 9. Résumé

| Aspect | Description |
|--------|-------------|
| **Quoi** | Système de vérification d'apps avant exécution |
| **Depuis** | macOS Mountain Lion 10.8 (2012) |
| **Vérifie** | Quarantine, Signature, Notarization |
| **Bypass** | xattr -d, ZIP, DMG, AppleScript |
| **Red Team** | Supprimer quarantine, utiliser archives |

### Points Clés

- Gatekeeper = 3 mécanismes (Quarantine + Signature + Notarization)
- Quarantine = extended attribute `com.apple.quarantine`
- Bypass le plus simple : `xattr -d`
- ZIP/DMG tricks pour éviter quarantine
- Vérifier avec `spctl --status`

## 10. Ressources

- [Apple Gatekeeper Documentation](https://support.apple.com/en-us/HT202491)
- [Notarization Guide](https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution)
- [Objective-See: Gatekeeper Bypasses](https://objective-see.com/blog.html)

---

**Navigation**
- [Module précédent](../M08_sip/)
- [Module suivant](../M10_endpoint_security/)
