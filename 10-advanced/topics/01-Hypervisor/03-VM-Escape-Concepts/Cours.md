# Module A03 : Concepts d'Évasion de VM (VM Escape)

## Objectifs pédagogiques

À la fin de ce module, vous serez capable de :
- [ ] Comprendre ce qu'est un VM escape et ses implications
- [ ] Identifier les surfaces d'attaque d'un hyperviseur
- [ ] Connaître les vulnérabilités historiques majeures
- [ ] Analyser les vecteurs d'attaque classiques
- [ ] Appliquer ces concepts dans un contexte Red Team

## Prérequis

Avant de commencer ce module, assurez-vous de maîtriser :
- Les bases du langage C (variables, fonctions, pointeurs)
- Module A01 : Virtualisation basics (VMX, EPT, VMCS)
- Module A02 : VM Detection
- Notions de sécurité mémoire (buffer overflow, use-after-free)
- Architecture x86/x64

## Introduction

Un **VM escape** est une vulnérabilité permettant à du code s'exécutant dans une machine virtuelle guest de s'échapper et d'exécuter du code sur l'hôte. C'est le Saint Graal de l'exploitation de virtualisation.

### Pourquoi ce sujet est important ?

Imaginez une prison (la VM) avec des murs épais (l'hyperviseur). Un VM escape, c'est trouver un tunnel secret pour s'évader de la prison et accéder à la ville entière (l'hôte).

Pour un Red Teamer :
- **Privilege escalation ultime** : Passer de guest à host = contrôle total
- **Persistence** : Compromettre l'hôte = compromettre toutes les VMs
- **Cloud attacks** : AWS, Azure, GCP utilisent la virtualisation

Pour un défenseur :
- **Isolation critique** : La virtualisation est la base de la sécurité cloud
- **Bug bounty** : Les VM escapes valent $100k+ chez les vendors
- **Threat modeling** : Comprendre les risques réels

## 1. Qu'est-ce qu'un VM Escape ?

### 1.1 Définition

Un VM escape exploite une faille dans :
- L'hyperviseur lui-même (KVM, Xen, VMware)
- Les périphériques émulés (carte réseau, GPU, USB)
- Les canaux de communication (shared folders, clipboard)

```
État initial:                  Après VM Escape:
┌──────────────┐              ┌──────────────┐
│  Guest VM    │              │  Guest VM    │
│  (Attacker)  │              │  shellcode   │
├──────────────┤              ├──────────────┤
│ Hyperviseur  │              │ Hyperviseur  │ <-- Code injecté
├──────────────┤              ├──────────────┤
│   Host OS    │              │   Host OS    │ <-- Compromis
└──────────────┘              └──────────────┘
```

### 1.2 Impact

```
┌─────────────────────────────────────────┐
│         Impact d'un VM Escape           │
├─────────────────────────────────────────┤
│ Guest compromis                         │
│   ↓                                     │
│ Exploitation de bug hyperviseur         │
│   ↓                                     │
│ Code execution sur Host                 │
│   ↓                                     │
│ ┌─────────────────────────────────────┐│
│ │ • Accès à toutes les VMs            ││
│ │ • Vol de données sensibles          ││
│ │ • Persistance sur l'infrastructure  ││
│ │ • Pivot vers d'autres machines      ││
│ └─────────────────────────────────────┘│
└─────────────────────────────────────────┘
```

## 2. Surface d'Attaque d'un Hyperviseur

### 2.1 Composants vulnérables

```
┌────────────────────────────────────────────────┐
│              Surface d'attaque                  │
├─────────────────────┬──────────────────────────┤
│ Périphériques       │ - Carte réseau (e1000)   │
│ Émulés              │ - GPU (VGA, 3D)          │
│                     │ - Stockage (IDE, SCSI)   │
│                     │ - USB, Audio             │
├─────────────────────┼──────────────────────────┤
│ Paravirtualisation  │ - VirtIO                 │
│                     │ - VMware Tools           │
│                     │ - Guest Additions        │
├─────────────────────┼──────────────────────────┤
│ Communication       │ - Shared folders         │
│ Guest-Host          │ - Clipboard              │
│                     │ - Drag & Drop            │
├─────────────────────┼──────────────────────────┤
│ Hyperviseur Core    │ - VMX handling           │
│                     │ - EPT violations         │
│                     │ - MMIO/PIO traps         │
└─────────────────────┴──────────────────────────┘
```

### 2.2 Vecteurs d'attaque

```c
// Exemple conceptuel : buffer overflow dans device émulé

// Code vulnérable dans l'émulation d'une carte réseau (hyperviseur)
void process_network_packet(uint8_t *packet, size_t len) {
    char buffer[512];  // Buffer fixe

    // Vulnérabilité : pas de vérification de taille
    memcpy(buffer, packet, len);  // <-- Overflow si len > 512

    // ... traitement ...
}

// Exploit depuis le guest
void exploit_network_device(void) {
    // Créer un paquet de 1024 octets pour overflow
    uint8_t evil_packet[1024];

    // Remplir avec payload + ROP chain
    // ... craft exploit ...

    // Envoyer via DMA vers le device émulé
    send_to_device(evil_packet, sizeof(evil_packet));

    // L'hyperviseur traite le paquet → overflow → RCE
}
```

## 3. Historique des VM Escapes Célèbres

### 3.1 VENOM (2015) - CVE-2015-3456

Flaw dans le contrôleur floppy QEMU.

```
Vulnérabilité :
- Émulation floppy disk (legacy)
- Buffer overflow dans FIFO
- Depuis le guest, envoyer commandes malformées

Impact :
- VM Escape sur QEMU/KVM, Xen
- RCE sur l'hôte
```

**Concept** :

```c
// Code vulnérable (simplifié)
#define FIFO_SIZE 512
uint8_t fifo_buffer[FIFO_SIZE];
int fifo_pos = 0;

void floppy_receive_data(uint8_t data) {
    // Pas de check de bounds !
    fifo_buffer[fifo_pos++] = data;  // <-- Overflow
}

// Exploit : envoyer > 512 octets
for (int i = 0; i < 1024; i++) {
    outb(FLOPPY_PORT, payload[i]);  // Déclenche floppy_receive_data
}
```

### 3.2 CloudBorne (2018) - CVE-2018-3646

Attaque Spectre variant dans les hyperviseurs.

```
Principe :
- L1 Terminal Fault (L1TF)
- Leak de mémoire host via cache L1
- Bypass EPT protections

Impact :
- Lecture mémoire du host depuis guest
- Vol de clés, données sensibles
- Affecte Intel CPUs
```

### 3.3 Pwn2Own VMware (2017)

Exploitation de l'émulation 3D (SVGA II).

```
Vulnérabilité :
- Use-after-free dans vmware_svga
- Heap spray + ROP
- Escape de guest → host

Exploit chain :
1. Heap spray dans guest
2. Trigger use-after-free via SVGA commands
3. Contrôle RIP de l'hyperviseur
4. ROP pour désactiver SMEP/SMAP
5. Shellcode sur host
```

## 4. Catégories de Vulnérabilités

### 4.1 Memory Corruption

La plus courante.

```
Types :
- Buffer overflow
- Use-after-free (UAF)
- Double-free
- Out-of-bounds read/write
- Integer overflow → heap overflow

Exemple (UAF) :
┌──────────────────────────────────────┐
│ 1. Allouer objet A                   │
│ 2. Guest libère A                    │
│ 3. Hyperviseur free(A)               │
│ 4. Guest réalloue → objet B en A    │
│ 5. Guest utilise encore A            │
│    → Contrôle objet B                │
└──────────────────────────────────────┘
```

**Code d'exemple** :

```c
// Émulation USB (vulnérable)
typedef struct {
    void (*callback)(void);
    uint8_t data[256];
} usb_packet_t;

usb_packet_t *packet = NULL;

void usb_alloc_packet(void) {
    packet = malloc(sizeof(usb_packet_t));
    packet->callback = &default_handler;
}

void usb_free_packet(void) {
    free(packet);
    // Bug : pas de packet = NULL (dangling pointer)
}

void usb_process(void) {
    if (packet) {
        packet->callback();  // <-- UAF si free puis process
    }
}

// Exploit depuis guest :
// 1. Trigger usb_alloc_packet()
// 2. Trigger usb_free_packet()
// 3. Spray heap pour réoccuper la zone
// 4. Trigger usb_process() → RIP control
```

### 4.2 Logic Bugs

Erreurs dans la logique métier.

```c
// Exemple : race condition dans shared folder

// Thread 1 (guest)
void guest_read_file(char *filename) {
    int fd = open_shared(filename);  // Ouvre /etc/passwd
    // ... switch de contexte ...
    read(fd, buffer, 1024);          // Lit le contenu
}

// Thread 2 (attacker guest)
void exploit_race(void) {
    // Pendant le switch de contexte
    symlink("/etc/shadow", "/shared/passwd");  // Change le lien
}

// Résultat : lit /etc/shadow au lieu de passwd
```

### 4.3 Confused Deputy

L'hyperviseur fait une action non intentionnelle.

```
Scénario :
┌──────────────────────────────────────┐
│ Guest demande : "Lis mon fichier X"  │
│        ↓                              │
│ Hyperviseur vérifie : X appartient   │
│ au guest                              │
│        ↓                              │
│ TOCTOU (Time Of Check Time Of Use)   │
│        ↓                              │
│ Guest change X → lien vers /etc/shadow│
│        ↓                              │
│ Hyperviseur lit /etc/shadow          │
└──────────────────────────────────────┘
```

## 5. Techniques d'Exploitation

### 5.1 Heap Spray

Remplir le heap pour contrôler l'allocation.

```c
// Dans le guest
void heap_spray(void) {
    // Allouer 1000 buffers avec le même contenu
    for (int i = 0; i < 1000; i++) {
        uint64_t *buf = malloc(0x1000);

        // Remplir avec ROP gadgets
        for (int j = 0; j < 0x1000/8; j++) {
            buf[j] = 0x41414141;  // Adresse contrôlée
        }

        // Envoyer au hyperviseur via DMA/MMIO
        send_to_hypervisor(buf);
    }

    // Trigger UAF → forte probabilité de tomber sur notre spray
}
```

### 5.2 ROP (Return Oriented Programming)

Bypasser DEP/NX.

```c
// Trouver des gadgets dans l'hyperviseur
// Exemple : QEMU binary

// gadget1: pop rdi; ret
// gadget2: pop rsi; ret
// gadget3: pop rdx; ret
// gadget4: call execve

uint64_t rop_chain[] = {
    0x00000000004a5b0f,  // pop rdi; ret
    (uint64_t)"/bin/sh",  // arg1
    0x00000000004a5b10,  // pop rsi; ret
    0x0,                  // arg2 = NULL
    0x00000000004a5b11,  // pop rdx; ret
    0x0,                  // arg3 = NULL
    0x0000000000439e40,  // execve
};

// Overflow pour écrire ROP chain sur la stack
```

### 5.3 Information Leak

Leaker des adresses pour bypasser ASLR.

```c
// Exploit un out-of-bounds read
void leak_hypervisor_address(void) {
    // Device MMIO vulnérable
    volatile uint32_t *mmio = map_device_mmio();

    // Lire hors bounds (ex: offset -8)
    uint64_t leaked = *(uint64_t*)(mmio - 2);

    printf("[+] Leaked address : 0x%lx\n", leaked);

    // Calculer base de l'hyperviseur
    uint64_t hypervisor_base = leaked - KNOWN_OFFSET;

    // Calculer adresses des gadgets ROP
    // ...
}
```

## 6. Protections et Contournements

### 6.1 Protections côté hyperviseur

```
┌───────────────────────────────────────────┐
│        Protections modernes               │
├───────────────────┬───────────────────────┤
│ ASLR/PIE          │ Randomiser adresses   │
│ DEP/NX            │ Stack non-exécutable  │
│ SMEP/SMAP         │ Isolation kernel/user │
│ CFI               │ Control Flow Integrity│
│ Seccomp           │ Sandbox syscalls      │
│ Namespaces        │ Isolation ressources  │
└───────────────────┴───────────────────────┘
```

### 6.2 Contournements

```
ASLR → Information leak
DEP/NX → ROP
SMEP → ROP pour désactiver CR4.SMEP
CFI → Data-oriented programming
```

**Exemple : Bypass SMEP** :

```c
// SMEP empêche le kernel d'exécuter du code user
// Contournement : désactiver SMEP via ROP

uint64_t rop_disable_smep[] = {
    POP_RCX_RET,        // pop rcx; ret
    0x407f0,            // nouvelle valeur CR4 (SMEP off)
    MOV_CR4_RCX_RET,    // mov cr4, rcx; ret
    SHELLCODE_ADDR,     // Sauter au shellcode
};
```

## 7. Détection et Mitigation

### 7.1 Détection d'exploitation

```c
// Ajouter des canaris dans les structures critiques
typedef struct {
    uint64_t canary1;
    void (*callback)(void);
    uint8_t data[256];
    uint64_t canary2;
} protected_packet_t;

#define CANARY_VALUE 0xDEADBEEFCAFEBABE

void init_packet(protected_packet_t *p) {
    p->canary1 = CANARY_VALUE;
    p->canary2 = CANARY_VALUE;
}

void process_packet(protected_packet_t *p) {
    // Vérifier l'intégrité
    if (p->canary1 != CANARY_VALUE || p->canary2 != CANARY_VALUE) {
        log_alert("CORRUPTION DETECTED! Possible exploit attempt");
        abort();
    }

    p->callback();
}
```

### 7.2 Fuzzing pour trouver des bugs

```bash
# Utiliser AFL pour fuzzer QEMU devices
afl-fuzz -i input/ -o output/ -m none -- \
  qemu-system-x86_64 -device floppy -drive file=@@
```

## 8. Applications Offensives

### 8.1 Scénario Red Team : Cloud Escape

```
Objectif : Compromission multi-tenant cloud

Étapes :
1. Louer une VM sur AWS/Azure
2. Identifier l'hyperviseur (Xen/KVM/Hyper-V)
3. Trouver ou acheter 0day VM escape
4. Exploiter depuis la VM guest
5. Accéder à l'hôte physique
6. Pivoter vers d'autres VMs clients
7. Vol de données, persistence
```

### 8.2 Proof of Concept : Trigger Crash

```c
// POC pour crash un hyperviseur (educational)
#include <stdio.h>
#include <fcntl.h>
#include <sys/io.h>

#define VULN_DEVICE_PORT 0x2000

int main(void) {
    // Obtenir accès aux ports I/O (nécessite root dans guest)
    if (ioperm(VULN_DEVICE_PORT, 8, 1) != 0) {
        perror("ioperm");
        return 1;
    }

    printf("[*] Triggering vulnerability...\n");

    // Envoyer séquence malformée
    for (int i = 0; i < 1024; i++) {
        outb(0x41, VULN_DEVICE_PORT);  // Overflow le buffer
    }

    printf("[!] If hypervisor crashes, vulnerability confirmed\n");

    return 0;
}
```

## 9. Considérations OPSEC

### 9.1 Pour l'attaquant

- **0-day value** : Ne pas brûler un VM escape sur une cible mineure
- **Detection** : Les crashes hyperviseur sont loggés (vigilance)
- **Forensics** : Effacer traces dans les logs host après escape

### 9.2 Pour le défenseur

- **Patch management** : Mettre à jour hyperviseurs régulièrement
- **Least privilege** : Désactiver devices non utilisés
- **Monitoring** : Alerter sur crashes/anomalies hyperviseur
- **Segmentation** : Isoler VMs sensibles sur hôtes dédiés

## Résumé

- VM Escape = exploitation pour sortir d'une VM et compromettre l'hôte
- Surface d'attaque : devices émulés, paravirtualisation, shared services
- Vulnérabilités historiques : VENOM, CloudBorne, Pwn2Own escapes
- Types de bugs : memory corruption, logic bugs, race conditions
- Techniques : heap spray, ROP, information leak
- Protections : ASLR, DEP, SMEP, CFI
- Impact : compromission multi-tenant en environnement cloud

## Checklist

- [ ] Comprendre la différence entre guest et host compromise
- [ ] Connaître les composants vulnérables d'un hyperviseur
- [ ] Identifier les CVEs majeures de VM escape
- [ ] Comprendre heap spray et ROP
- [ ] Savoir comment mitiger les risques (défense)
- [ ] Connaître l'impact en environnement cloud

## Exercices

Voir `exercice.md` pour les défis pratiques :
1. Analyser un patch de VM escape (diff CVE)
2. Setup un lab de fuzzing QEMU device
3. Étudier un exploit Pwn2Own

## Ressources complémentaires

- "The Art of Leaks" (Phrack) : https://phrack.org/issues/71/8.html
- Pwn2Own VMware Escapes : https://www.zerodayinitiative.com/
- QEMU Security : https://wiki.qemu.org/SecurityProcess
- "Virtualization under attack" (Black Hat)

---

**Navigation**
- [Module précédent : VM Detection](../02-VM-Detection/)
- [Module suivant : Hyperjacking Theory](../04-Hyperjacking-Theory/)
