# Cours : System Integrity Protection (SIP)

## 1. Introduction - La Forteresse macOS

### 1.1 Qu'est-ce que SIP ?

**System Integrity Protection (SIP)** est une fonctionnalité de sécurité introduite dans **macOS El Capitan (10.11)** en 2015. C'est comme un **garde du corps** qui protège les parties critiques du système d'exploitation.

**Analogie simple** :
```ascii
Imaginez votre Mac comme une banque :

┌────────────────────────────────────────┐
│         BANQUE (macOS)                 │
├────────────────────────────────────────┤
│  COFFRE-FORT (Protégé par SIP)         │
│  ┌──────────────────────────────────┐  │
│  │ /System/                         │  │ ← SIP protège
│  │ /usr/ (sauf /usr/local/)         │  │
│  │ Applications système             │  │
│  │ Kernel extensions                │  │
│  └──────────────────────────────────┘  │
│                                        │
│  ZONE PUBLIQUE (Non protégée)          │
│  ┌──────────────────────────────────┐  │
│  │ /Users/                          │  │ ← Libre accès
│  │ /usr/local/                      │  │
│  │ /Applications/ (tierces)         │  │
│  └──────────────────────────────────┘  │
└────────────────────────────────────────┘
```

### 1.2 Pourquoi SIP existe ?

Avant SIP, **même root** pouvait :
- Modifier `/System/Library/`
- Remplacer des binaires système
- Injecter des KEXTs malveillants
- Altérer le kernel

**Problème** : Malwares rootkits pouvaient s'installer profondément dans le système.

**Solution SIP** : Même root ne peut plus toucher aux zones protégées.

### 1.3 Comment SIP fonctionne ?

SIP est **implémenté dans le kernel** (XNU) et vérifié au démarrage :

```ascii
DÉMARRAGE macOS :

┌──────────┐
│   BOOT   │
│   ROM    │ ← Firmware (T2/M1 Secure Enclave)
└────┬─────┘
     │
     ▼
┌──────────┐
│BootLoader│
│  (iBoot) │ ← Vérifie signature kernel
└────┬─────┘
     │
     ▼
┌──────────┐
│  Kernel  │
│   XNU    │ ← Active SIP
└────┬─────┘
     │
     ▼ SIP est maintenant actif
┌──────────────────────────────────┐
│ Protection des chemins :         │
│ - /System/                       │
│ - /usr/ (sauf /usr/local/)       │
│ - Applications système           │
│ - Kernel extensions (KEXT)       │
│ - nvram boot-args                │
└──────────────────────────────────┘
```

## 2. Fonctionnement Technique de SIP

### 2.1 Les Flags SIP

SIP est contrôlé par un **bitmap** de flags dans la NVRAM :

```c
// Définis dans <sys/csr.h>

#define CSR_ALLOW_UNTRUSTED_KEXTS           0x1
#define CSR_ALLOW_UNRESTRICTED_FS           0x2
#define CSR_ALLOW_TASK_FOR_PID              0x4
#define CSR_ALLOW_KERNEL_DEBUGGER           0x8
#define CSR_ALLOW_APPLE_INTERNAL            0x10
#define CSR_ALLOW_UNRESTRICTED_DTRACE       0x20
#define CSR_ALLOW_UNRESTRICTED_NVRAM        0x40
#define CSR_ALLOW_DEVICE_CONFIGURATION      0x80
#define CSR_ALLOW_ANY_RECOVERY_OS           0x100
#define CSR_ALLOW_UNAPPROVED_KEXTS          0x200
```

**Valeur par défaut** : `0x0` (tout bloqué)
**SIP désactivé** : `0x3FF` (tout autorisé)

### 2.2 Architecture de Protection

```ascii
┌────────────────────────────────────────────────────┐
│              ESPACE UTILISATEUR                    │
│                                                    │
│  ┌──────────┐        ┌──────────┐                 │
│  │ Process  │──────▶ │ Syscall  │                 │
│  │ (root)   │        │ open()   │                 │
│  └──────────┘        └────┬─────┘                 │
└────────────────────────────┼──────────────────────┘
                             │
                             ▼
┌────────────────────────────────────────────────────┐
│              KERNEL SPACE (XNU)                    │
│                                                    │
│  ┌────────────────────────────────────┐            │
│  │  SIP CHECK                         │            │
│  │  1. Chemin dans liste protégée ?   │            │
│  │  2. Process a entitlement ?        │            │
│  │  3. Flags SIP autorisent ?         │            │
│  └────────┬───────────────────────────┘            │
│           │                                        │
│           ├─ OUI ──▶ EACCES (Permission denied)   │
│           │                                        │
│           └─ NON ──▶ Continuer opération          │
└────────────────────────────────────────────────────┘
```

### 2.3 Fichiers Protégés

SIP protège via une **liste blanche** dans le kernel :

```c
// Chemins protégés par SIP
static const char *sip_protected_paths[] = {
    "/System/",
    "/usr/",           // Sauf /usr/local/
    "/bin/",
    "/sbin/",
    "/var/db/",
    NULL
};

// Exceptions (non protégées)
static const char *sip_exceptions[] = {
    "/usr/local/",
    "/System/Library/User Template/",
    NULL
};
```

### 2.4 Vérifier l'État de SIP

```bash
# Vérifier si SIP est activé
csrutil status

# Sortie si activé :
System Integrity Protection status: enabled.

# Sortie si désactivé :
System Integrity Protection status: disabled.
```

En C :

```c
#include <sys/csr.h>

int check_sip() {
    uint32_t flags;

    // Récupérer config SIP
    if (csr_check(CSR_ALLOW_UNRESTRICTED_FS) == 0) {
        printf("SIP filesystem protection: DISABLED\n");
        return 0;
    } else {
        printf("SIP filesystem protection: ENABLED\n");
        return 1;
    }
}
```

## 3. Bypass SIP - Techniques d'Attaque

### 3.1 Désactivation Officielle (Légitime)

**Méthode** : Démarrer en Recovery Mode

```ascii
STEPS :

1. Redémarrer Mac
   ┌─────────────────┐
   │  Maintenir      │
   │  Cmd + R        │ ← Au démarrage
   └─────────────────┘

2. Recovery Mode
   ┌─────────────────┐
   │  Utilitaires    │
   │  Terminal       │
   └─────────────────┘

3. Terminal :
   $ csrutil disable

   Successfully disabled System Integrity Protection.
   Please restart the machine for changes to take effect.

4. Redémarrer

5. SIP désactivé !
```

**Limitation** : Nécessite **accès physique** au Mac.

### 3.2 Bypass via Entitlements

Certains processus Apple ont des **entitlements** qui permettent de bypass SIP :

```xml
<!-- Entitlement pour bypass SIP -->
<key>com.apple.rootless.install</key>
<true/>
```

**Processus privilégiés** :
- `system_installd`
- `softwareupdate`
- `pkgd`

**Technique d'attaque** : Exploiter un processus avec entitlement.

### 3.3 Bypass via Permissions TCC

TCC (Transparency, Consent, and Control) peut parfois override SIP pour certaines opérations.

### 3.4 Bypass via Boot-args (Intel uniquement)

Sur **Mac Intel**, on peut modifier les boot-args en Recovery :

```bash
# En Recovery Mode
nvram boot-args="rootless=0"

# Redémarrer
reboot
```

**Note** : Ne fonctionne **PAS** sur Apple Silicon (M1/M2/M3).

### 3.5 Bypass via Vulnérabilités Kernel

Exploitation de bugs dans XNU pour désactiver SIP en runtime.

**Exemple historique** : CVE-2016-1757 (tpwn)

```c
// Exploitation conceptuelle
void disable_sip_via_kernel_exploit() {
    // 1. Exploiter vulnérabilité kernel
    // 2. Obtenir kernel read/write
    // 3. Trouver adresse csr_config
    // 4. Modifier flags SIP

    uint32_t *csr_config = find_csr_config_address();
    *csr_config = 0x3FF;  // Désactiver SIP
}
```

## 4. Détection de SIP en Red Team

### 4.1 Vérification Automatique

```c
#include <stdio.h>
#include <sys/csr.h>

void check_sip_status() {
    printf("[*] Checking SIP status...\n");

    // Filesystem protection
    if (csr_check(CSR_ALLOW_UNRESTRICTED_FS) == 0) {
        printf("[!] SIP filesystem protection: DISABLED\n");
    } else {
        printf("[+] SIP filesystem protection: ENABLED\n");
    }

    // KEXT loading
    if (csr_check(CSR_ALLOW_UNTRUSTED_KEXTS) == 0) {
        printf("[!] SIP KEXT protection: DISABLED\n");
    } else {
        printf("[+] SIP KEXT protection: ENABLED\n");
    }

    // task_for_pid()
    if (csr_check(CSR_ALLOW_TASK_FOR_PID) == 0) {
        printf("[!] SIP task_for_pid protection: DISABLED\n");
    } else {
        printf("[+] SIP task_for_pid protection: ENABLED\n");
    }
}
```

### 4.2 Test d'Écriture

```c
#include <fcntl.h>
#include <errno.h>

int test_sip_write() {
    // Tenter d'écrire dans /System/
    int fd = open("/System/test_sip", O_WRONLY | O_CREAT, 0644);

    if (fd == -1) {
        if (errno == EACCES || errno == EPERM) {
            printf("[+] SIP is protecting /System/\n");
            return 1;
        }
    } else {
        printf("[!] SIP is NOT protecting /System/\n");
        close(fd);
        unlink("/System/test_sip");
        return 0;
    }
}
```

## 5. Contournement pour Red Team

### 5.1 Travailler dans les Zones Non-Protégées

Au lieu d'attaquer `/System/`, utiliser :

```ascii
ZONES ACCESSIBLES (même avec SIP) :

/Users/*/                 ← Home directories
/usr/local/               ← Installations tierces
/Library/LaunchAgents/    ← Persistence utilisateur
/Applications/            ← Apps tierces
/tmp/                     ← Temporaire
/private/var/tmp/         ← Temporaire
```

### 5.2 Persistence sans Toucher /System/

```bash
# LaunchAgent dans /Library/ (non protégé)
cat > ~/Library/LaunchAgents/com.apple.update.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.update</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/implant</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
EOF

# Charger
launchctl load ~/Library/LaunchAgents/com.apple.update.plist
```

### 5.3 Injection de Dylib (DYLD_INSERT_LIBRARIES)

SIP **bloque** `DYLD_INSERT_LIBRARIES` pour les binaires système, mais **pas** pour les apps tierces :

```bash
# Ne fonctionne PAS (SIP bloque)
DYLD_INSERT_LIBRARIES=/tmp/evil.dylib /bin/ls

# Fonctionne (app tierce)
DYLD_INSERT_LIBRARIES=/tmp/evil.dylib /Applications/Firefox.app/Contents/MacOS/firefox
```

## 6. Code Complet - SIP Checker

```c
// sip_checker.c
#include <stdio.h>
#include <sys/csr.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

void print_banner() {
    printf("╔═══════════════════════════════════╗\n");
    printf("║   macOS SIP Status Checker        ║\n");
    printf("╚═══════════════════════════════════╝\n\n");
}

int check_csr_flag(uint32_t flag, const char *name) {
    if (csr_check(flag) == 0) {
        printf("  [!] %-30s DISABLED\n", name);
        return 0;
    } else {
        printf("  [+] %-30s ENABLED\n", name);
        return 1;
    }
}

void check_all_sip_flags() {
    printf("[*] Checking SIP flags:\n\n");

    check_csr_flag(CSR_ALLOW_UNTRUSTED_KEXTS, "KEXT Protection");
    check_csr_flag(CSR_ALLOW_UNRESTRICTED_FS, "Filesystem Protection");
    check_csr_flag(CSR_ALLOW_TASK_FOR_PID, "task_for_pid Protection");
    check_csr_flag(CSR_ALLOW_KERNEL_DEBUGGER, "Kernel Debugger Protection");
    check_csr_flag(CSR_ALLOW_UNRESTRICTED_DTRACE, "DTrace Protection");
    check_csr_flag(CSR_ALLOW_UNRESTRICTED_NVRAM, "NVRAM Protection");
}

void test_protected_paths() {
    printf("\n[*] Testing protected paths:\n\n");

    const char *paths[] = {
        "/System/test_sip",
        "/usr/bin/test_sip",
        "/usr/local/test_sip",
        "/tmp/test_sip",
        NULL
    };

    for (int i = 0; paths[i] != NULL; i++) {
        int fd = open(paths[i], O_WRONLY | O_CREAT, 0644);

        if (fd == -1) {
            if (errno == EACCES || errno == EPERM || errno == EROFS) {
                printf("  [+] %-30s PROTECTED\n", paths[i]);
            } else {
                printf("  [?] %-30s Error: %d\n", paths[i], errno);
            }
        } else {
            printf("  [!] %-30s WRITABLE\n", paths[i]);
            close(fd);
            unlink(paths[i]);
        }
    }
}

int main() {
    print_banner();
    check_all_sip_flags();
    test_protected_paths();

    printf("\n[*] SIP check complete.\n");
    return 0;
}
```

**Compilation** :

```bash
clang -o sip_checker sip_checker.c
./sip_checker
```

## 7. Implications Red Team

### 7.1 Reconnaissance

```ascii
PHASE 1 : RECONNAISSANCE

1. Vérifier SIP status
   $ csrutil status

2. Identifier zones non-protégées

3. Chercher processus avec entitlements
   $ codesign -d --entitlements - /path/to/app

4. Analyser permissions TCC
   $ tccutil reset All
```

### 7.2 Stratégies d'Attaque

```ascii
Si SIP ACTIVÉ (défaut) :
├─ Travailler dans /usr/local/, /tmp/, ~
├─ Exploiter apps tierces (pas protégées)
├─ Persistence via LaunchAgents utilisateur
├─ Injection dans processus non-système
└─ Social engineering (demander mot de passe admin)

Si SIP DÉSACTIVÉ (rare) :
├─ Rootkit possible
├─ KEXT malveillant
├─ Modification binaires système
└─ Persistence profonde
```

## 8. Détection et OPSEC

### 8.1 Logs à Éviter

```bash
# SIP violations sont loggées dans :
/var/log/system.log

# Exemple :
kernel: AMFI: denying load of /System/test (SIP protected)
```

### 8.2 Recommandations OPSEC

1. **Ne jamais tenter de modifier /System/** si SIP actif
2. **Utiliser les zones non-protégées**
3. **Éviter csrutil** en runtime (log suspect)
4. **Préférer TCC bypass** à SIP bypass
5. **Exploiter apps tierces** plutôt que système

## 9. Résumé

| Aspect | Description |
|--------|-------------|
| **Quoi** | Protection kernel-level des fichiers système |
| **Depuis** | macOS El Capitan 10.11 (2015) |
| **Protège** | /System/, /usr/, KEXTs, nvram |
| **Bypass** | Recovery Mode, entitlements, kernel exploit |
| **Red Team** | Travailler dans zones non-protégées |

### Points Clés

- SIP = couche de protection **au niveau kernel**
- Même **root ne peut pas** modifier zones protégées
- Vérifier avec `csrutil status`
- En C : `csr_check()` pour tester flags
- **Red Team** : éviter /System/, utiliser /usr/local/ et ~

## 10. Ressources

- [Apple SIP Documentation](https://support.apple.com/en-us/HT204899)
- [XNU Source - csr.h](https://opensource.apple.com/source/xnu/)
- [Bypassing SIP (Objective-See)](https://objective-see.com/blog.html)

---

**Navigation**
- [Module précédent](../M07_tcc/)
- [Module suivant](../M09_gatekeeper/)
