# Solutions : Registres et Instructions x64

## Solution Exercice 1 : Swap avec XOR

```c
#include <stdio.h>
#include <stdint.h>

void swap_registres(uint64_t *a, uint64_t *b) {
    __asm__ __volatile__ (
        "mov rax, [%0]\n\t"      // RAX = *a
        "mov rbx, [%1]\n\t"      // RBX = *b
        "xor rax, rbx\n\t"       // RAX = a ^ b
        "xor rbx, rax\n\t"       // RBX = b ^ (a ^ b) = a
        "xor rax, rbx\n\t"       // RAX = (a ^ b) ^ a = b
        "mov [%0], rax\n\t"      // *a = b
        "mov [%1], rbx"          // *b = a
        :
        : "r" (a), "r" (b)
        : "rax", "rbx", "memory"
    );
}

// Alternative avec XCHG (plus simple)
void swap_xchg(uint64_t *a, uint64_t *b) {
    __asm__ __volatile__ (
        "mov rax, [%0]\n\t"
        "xchg rax, [%1]\n\t"     // Échange atomique RAX <-> [b]
        "mov [%0], rax"
        :
        : "r" (a), "r" (b)
        : "rax", "memory"
    );
}

// Test
int main() {
    uint64_t x = 42, y = 100;
    printf("Avant: x=%lu, y=%lu\n", x, y);
    swap_registres(&x, &y);
    printf("Après: x=%lu, y=%lu\n", x, y);
    return 0;
}
```

---

## Solution Exercice 2 : Calcul avec LEA

```c
#include <stdio.h>
#include <stdint.h>

uint64_t calcul_lea(uint64_t x) {
    uint64_t resultat;
    
    // x*7 = x*8 - x = (x << 3) - x
    // Méthode 1 : Utiliser LEA pour x*8 puis soustraire
    __asm__ __volatile__ (
        "lea rax, [%1*8]\n\t"       // RAX = x * 8
        "sub rax, %1\n\t"           // RAX = x*8 - x = x*7
        "add rax, 15\n\t"           // RAX = x*7 + 15
        "mov %0, rax"
        : "=r" (resultat)
        : "r" (x)
        : "rax"
    );
    
    return resultat;
}

// Méthode alternative : tout avec LEA
uint64_t calcul_lea_v2(uint64_t x) {
    uint64_t resultat;
    
    __asm__ __volatile__ (
        // x*7 = x + x*2 + x*4
        "lea rax, [%1 + %1*2]\n\t"  // RAX = x*3
        "lea rax, [rax + %1*4]\n\t" // RAX = x*3 + x*4 = x*7
        "lea %0, [rax + 15]"        // resultat = x*7 + 15
        : "=r" (resultat)
        : "r" (x)
        : "rax"
    );
    
    return resultat;
}

// Test
int main() {
    for (uint64_t x = 0; x <= 10; x++) {
        uint64_t attendu = x * 7 + 15;
        uint64_t obtenu = calcul_lea(x);
        printf("x=%lu: attendu=%lu, obtenu=%lu %s\n", 
               x, attendu, obtenu, 
               attendu == obtenu ? "OK" : "ERREUR");
    }
    return 0;
}
```

---

## Solution Exercice 3 : Compteur de bits (popcount)

```c
#include <stdio.h>
#include <stdint.h>

// Version avec boucle
int popcount_asm(uint64_t valeur) {
    int count;
    
    __asm__ __volatile__ (
        "xor eax, eax\n\t"          // count = 0
        "test %1, %1\n\t"           // Si valeur == 0, skip
        "jz done\n\t"
        "loop_start:\n\t"
        "mov rbx, %1\n\t"
        "and rbx, 1\n\t"            // Isoler le bit de poids faible
        "add eax, ebx\n\t"          // count += bit
        "shr %1, 1\n\t"             // valeur >>= 1
        "jnz loop_start\n\t"        // Continuer si valeur != 0
        "done:\n\t"
        "mov %0, eax"
        : "=r" (count), "+r" (valeur)
        :
        : "rax", "rbx", "cc"
    );
    
    return count;
}

// Version optimisée avec POPCNT (si supporté par le CPU)
int popcount_fast(uint64_t valeur) {
    int count;
    
    __asm__ __volatile__ (
        "popcnt %0, %1"
        : "=r" (count)
        : "r" (valeur)
    );
    
    return count;
}

// Test
int main() {
    uint64_t tests[] = {0, 1, 0xFF, 0xFFFFFFFF, 0xAAAAAAAAAAAAAAAA};
    
    for (int i = 0; i < 5; i++) {
        int count = popcount_asm(tests[i]);
        printf("popcount(0x%lx) = %d\n", tests[i], count);
    }
    return 0;
}
```

---

## Solution Exercice 4 : Détection d'overflow

```c
#include <stdio.h>
#include <stdint.h>

typedef struct {
    int64_t resultat;
    int overflow;
} AddResult;

AddResult addition_safe(int64_t a, int64_t b) {
    AddResult res;
    
    __asm__ __volatile__ (
        "mov rax, %2\n\t"
        "add rax, %3\n\t"
        "mov %0, rax\n\t"
        "seto %1"                   // Set byte if Overflow
        : "=r" (res.resultat), "=r" (res.overflow)
        : "r" (a), "r" (b)
        : "rax", "cc"
    );
    
    // Convertir de byte à int proprement
    res.overflow = res.overflow & 1;
    
    return res;
}

// Test
int main() {
    // Test sans overflow
    AddResult r1 = addition_safe(100, 200);
    printf("100 + 200 = %ld (overflow: %d)\n", r1.resultat, r1.overflow);
    
    // Test avec overflow positif
    AddResult r2 = addition_safe(INT64_MAX, 1);
    printf("INT64_MAX + 1 = %ld (overflow: %d)\n", r2.resultat, r2.overflow);
    
    // Test avec overflow négatif
    AddResult r3 = addition_safe(INT64_MIN, -1);
    printf("INT64_MIN + (-1) = %ld (overflow: %d)\n", r3.resultat, r3.overflow);
    
    // Test limite sans overflow
    AddResult r4 = addition_safe(INT64_MAX - 10, 10);
    printf("(INT64_MAX-10) + 10 = %ld (overflow: %d)\n", r4.resultat, r4.overflow);
    
    return 0;
}
```

---

## Solution Exercice 5 : Décodeur XOR

```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>

void xor_decode(unsigned char *data, size_t len, unsigned char key) {
    __asm__ __volatile__ (
        "mov rcx, %1\n\t"           // RCX = longueur
        "mov rsi, %0\n\t"           // RSI = pointeur data
        "movzx rdx, %2\n\t"         // RDX = clé (étendue à 64 bits)
        "test rcx, rcx\n\t"         // Si len == 0, sortir
        "jz xor_done\n\t"
        "xor_loop:\n\t"
        "xor byte ptr [rsi], dl\n\t" // XOR avec la clé
        "inc rsi\n\t"               // data++
        "dec rcx\n\t"               // len--
        "jnz xor_loop\n\t"          // Continuer si len > 0
        "xor_done:"
        :
        : "r" (data), "r" (len), "r" (key)
        : "rcx", "rsi", "rdx", "memory", "cc"
    );
}

// Version optimisée traitant 8 bytes à la fois
void xor_decode_fast(unsigned char *data, size_t len, unsigned char key) {
    // Créer une clé 64-bit (key répété 8 fois)
    uint64_t key64 = key;
    key64 |= key64 << 8;
    key64 |= key64 << 16;
    key64 |= key64 << 32;
    
    size_t i = 0;
    
    // Traiter 8 bytes à la fois
    while (i + 8 <= len) {
        __asm__ __volatile__ (
            "mov rax, [%0]\n\t"
            "xor rax, %1\n\t"
            "mov [%0], rax"
            :
            : "r" (data + i), "r" (key64)
            : "rax", "memory"
        );
        i += 8;
    }
    
    // Traiter les bytes restants
    while (i < len) {
        data[i] ^= key;
        i++;
    }
}

// Test
int main() {
    // Encoder "Hello World!" avec XOR 0x41
    unsigned char original[] = "Hello World!";
    unsigned char encoded[13];
    unsigned char decoded[13];
    
    // Encoder
    memcpy(encoded, original, 13);
    xor_decode(encoded, 12, 0x41);
    
    printf("Original: %s\n", original);
    printf("Encodé (hex): ");
    for (int i = 0; i < 12; i++) {
        printf("%02x ", encoded[i]);
    }
    printf("\n");
    
    // Décoder
    memcpy(decoded, encoded, 13);
    xor_decode(decoded, 12, 0x41);
    printf("Décodé: %s\n", decoded);
    
    // Test avec la chaîne de l'exercice
    unsigned char test[] = {0x32, 0x24, 0x22, 0x33, 0x24, 0x37, 0x00}; // "secret" ^ 0x41
    printf("\nTest exercice:\n");
    printf("Avant décodage (hex): ");
    for (int i = 0; i < 6; i++) printf("%02x ", test[i]);
    printf("\n");
    
    xor_decode(test, 6, 0x41);
    printf("Après décodage: %s\n", test);
    
    return 0;
}
```

---

## Points clés à retenir

1. **XOR swap** : Technique classique pour échanger sans variable temporaire
2. **LEA** : Puissant pour les calculs rapides sans affecter les flags
3. **POPCNT** : Instruction moderne très rapide pour compter les bits
4. **SETO/SETC** : Permet de capturer les flags dans un registre
5. **Optimisation** : Traiter plusieurs bytes à la fois quand possible

## Erreurs courantes

- Oublier d'initialiser RDX avant DIV
- Ne pas déclarer les registres modifiés dans le clobber list
- Confondre les tailles de registres (RAX vs EAX vs AX)
- Oublier que certaines instructions modifient les flags
