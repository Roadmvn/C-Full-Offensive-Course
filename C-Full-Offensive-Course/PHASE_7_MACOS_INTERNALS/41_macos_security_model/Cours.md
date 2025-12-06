# Cours : Code Signing et PAC (Pointer Authentication)

## 1. Code Signing macOS - La Signature Numérique

### 1.1 Qu'est-ce que le Code Signing ?

Le **code signing** (signature de code) est un mécanisme de sécurité qui garantit :
1. **Authenticité** : Le code provient bien du développeur déclaré
2. **Intégrité** : Le code n'a pas été modifié depuis la signature

**Analogie** : Comme un **sceau de cire** sur une lettre historique :
- Prouve qui l'a envoyée (authenticité)
- Prouve qu'elle n'a pas été ouverte (intégrité)

### 1.2 Pourquoi Apple Force le Code Signing ?

Depuis **macOS Catalina** (2019), tous les exécutables doivent être signés pour :
- **Empêcher les malwares** : Code non signé = suspect
- **Traçabilité** : Savoir qui a créé le logiciel
- **Contrôle** : Apple peut révoquer des certificats
- **Notarization** : Validation par Apple avant distribution

```ascii
SANS CODE SIGNING (Avant) :

┌──────────────┐
│  Malware.exe │  ← N'importe qui peut créer et distribuer
└──────────────┘
       ↓
   Double-clic
       ↓
   EXÉCUTÉ !  ← Aucune vérification


AVEC CODE SIGNING (Maintenant) :

┌──────────────┐
│  App.exe     │
│  + Signature │  ← Signature cryptographique
└──────────────┘
       ↓
   Double-clic
       ↓
┌─────────────────────────┐
│  macOS vérifie :        │
│  1. Signature valide ?  │
│  2. Certificat valide ? │
│  3. Pas modifié ?       │
└────────┬────────────────┘
         │
    OUI  │  NON
         ↓    ↓
    EXÉCUTÉ  BLOQUÉ !
```

### 1.3 Comment Fonctionne la Signature ?

**Processus de signature** :

```ascii
ÉTAPE 1 : Créer un hash du binaire
┌──────────────┐
│  Binary.exe  │
│  (Code)      │
└──────┬───────┘
       │ SHA-256
       ↓
┌──────────────┐
│  Hash        │
│  a3f5b8...   │  ← Empreinte unique du code
└──────┬───────┘

ÉTAPE 2 : Chiffrer le hash avec la clé privée
       │
       ↓ RSA Encryption (clé privée)
┌──────────────┐
│  Signature   │
│  Chiffrée    │
└──────┬───────┘

ÉTAPE 3 : Attacher au binaire
       │
       ↓
┌──────────────────┐
│  Binary.exe      │
│  + Signature     │  ← Binaire signé
│  + Certificat    │
└──────────────────┘

VÉRIFICATION (par macOS) :

┌──────────────────┐
│  Binary + Sign   │
└──────┬───────────┘
       │
       ↓ Déchiffrer avec clé publique
┌──────────────┐
│  Hash        │
│  (déclaré)   │
└──────┬───────┘
       │
       ↓ Comparer
┌──────────────┐
│  Hash        │
│  (calculé)   │  ← Recalculer hash du binaire
└──────┬───────┘
       │
       ↓
   MATCH ? → OUI = Intègre ✅
             NON = Modifié ❌
```

### 1.4 Types de Signatures

#### Ad-Hoc Signature (Développement)

```bash
codesign -s - mybinary
```

- **Usage** : Développement local
- **Validité** : Seulement sur votre Mac
- **Certificat** : Aucun (auto-signé)
- **Distribution** : ❌ Impossible

#### Developer ID Signature

```bash
codesign -s "Developer ID Application: Your Name" mybinary
```

- **Usage** : Distribution hors App Store
- **Validité** : Tous les Mac
- **Certificat** : Obtenu via Apple Developer Program ($99/an)
- **Distribution** : ✅ Possible (avec Gatekeeper)

#### App Store Signature

- **Usage** : Applications sur Mac App Store
- **Validité** : Tous les Mac
- **Certificat** : Apple Developer Program
- **Distribution** : ✅ Via App Store uniquement

### Structure

```ascii
Binary + Signature → Code Directory Hash → Certificat
```

### Vérifier une Signature

```bash
codesign -dv /bin/ls
codesign --verify --verbose /bin/ls
```

### Signer un Binaire

```bash
# Signature ad-hoc (développement)
codesign -s - mybinary

# Avec certificat
codesign -s "Developer ID" mybinary

# Options
codesign -s - --deep --force mybinary
```

### Entitlements

Permissions spécifiques (sandbox, debugging, etc).

```bash
# Voir entitlements
codesign -d --entitlements - /bin/ls

# Signer avec entitlements
codesign -s - --entitlements entitlements.plist mybinary
```

## 2. PAC (Pointer Authentication Codes)

### Introduction

Mécanisme hardware ARM64 pour protéger les pointeurs contre corruption/ROP.

### Principe

```ascii
Pointeur Original : 0x00007FF812345678
        +
Context (modifier) : SP, FP, etc.
        ↓
PAC (64 bits supérieurs) : 0xABCD7FF812345678
```

### Instructions ARM64

```asm
# Signer un pointeur
PACIASP        // Sign X30 (LR) with SP as context
PACIBSP        // Sign X30 with B key

# Authentifier
AUTIASP        // Authenticate X30 with SP
AUTIBSP        // Authenticate with B key

# Générique
PACIA  X0, X1  // Sign X0 with X1 as context
AUTIA  X0, X1  // Authenticate X0
```

### En Pratique

```asm
.global _main
_main:
    PACIASP          // Sign LR avant fonction
    stp x29, x30, [sp, #-16]!
    
    // ... code ...
    
    ldp x29, x30, [sp], #16
    AUTIASP          // Authenticate LR avant ret
    ret
```

### Vérifier PAC Support

```c
#include <sys/sysctl.h>

int has_pac() {
    int value = 0;
    size_t size = sizeof(value);
    sysctlbyname("hw.optional.arm.FEAT_PAuth", &value, &size, NULL, 0);
    return value;
}
```

## 3. Bypass Techniques

### Code Signing

**Désactiver SIP** (System Integrity Protection) :
```bash
csrutil disable  # En mode recovery
```

**Injection avant signature** : Modifier puis re-signer.

### PAC

**Leak du PAC** : Si on peut lire un pointeur signé, on peut le réutiliser.

**Brute Force** : 16 bits de PAC = 65536 possibilités.

**Gadgets sans PAC** : Chercher du code legacy sans PAC.

## 4. Protection

### Hardened Runtime

```bash
codesign -s - --options=runtime mybinary
```

Actuve :
- Library Validation
- Disable DYLD env vars
- Force code signature

### Notarization

Validation par Apple (requise pour distribution).

```bash
xcrun altool --notarize-app --file app.zip
```

## 5. Exploitation

### Bypass Code Signing

1. **Disable AMFI** (Apple Mobile File Integrity)
2. **Kernel Patch** (modification noyau)
3. **Injection précoce** (avant vérification)

### PAC Bypass (Recherche)

- JOP (Jump-Oriented Programming)
- Gadgets avec `XPACI` (strip PAC)
- Corruption limitée

## Ressources

- [Code Signing Guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/)
- [PAC ARM Documentation](https://developer.arm.com/documentation/102445/0100/)

