# Module 02 - Variables et Types : La mémoire démystifiée

## Pourquoi tu dois maîtriser ça

```c
// En reverse
mov eax, [rbp-0x4]    // C'est quoi ce -0x4 ? → Offset d'un int (4 bytes)

// En exploitation
char buffer[64];
int is_admin = 0;     // Écris 68 bytes dans buffer → is_admin écrasé

// En shellcode
unsigned char sc[] = { 0xff, 0xc0 };  // Pourquoi unsigned ? → 0xff signed = -1 = bugs
```

**Sans maîtriser les types, tu ne peux ni reverser, ni exploiter, ni coder.**

---

## La RAM en 30 secondes

```
Adresse       Contenu (1 byte)
┌──────────┬────────┐
│ 0x1000   │  0x41  │  ← 'A'
├──────────┼────────┤
│ 0x1001   │  0x42  │  ← 'B'
├──────────┼────────┤
│ 0x1002   │  0x00  │  ← null
└──────────┴────────┘
```

- Chaque case = **1 byte** (8 bits, valeurs 0-255)
- Chaque case a une **adresse unique**
- C'est tout.

> **Lire un dump GDB :**
> ```
> 0x7fffe000: 0x48 0x65 0x6c 0x6c 0x6f 0x00
>             H    e    l    l    o    \0   → "Hello"
> ```

---

## Les types entiers

### Tailles et limites

| Type | Taille | Unsigned (0 à...) | Signed (min à max) |
|------|--------|-------------------|-------------------|
| `char` | 1 byte | 0 → 255 | -128 → 127 |
| `short` | 2 bytes | 0 → 65,535 | -32,768 → 32,767 |
| `int` | 4 bytes | 0 → ~4 milliards | ~-2 → +2 milliards |
| `long` | 8 bytes | 0 → ~18 quintillions | ±9 quintillions |

> **Formule :** N bits → unsigned: `0` à `2^N - 1` | signed: `-2^(N-1)` à `2^(N-1) - 1`

### Types Windows (tu les verras partout)

```c
BYTE   = unsigned char      // 1 byte  - données brutes
WORD   = unsigned short     // 2 bytes - offsets PE
DWORD  = unsigned long      // 4 bytes - handles, PIDs
QWORD  = unsigned __int64   // 8 bytes - adresses 64-bit
LPVOID = void*              // pointeur - buffers
```

```c
// Utilisation réelle
DWORD pid = GetCurrentProcessId();
HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
LPVOID addr = VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
```

### Types à taille fixe (stdint.h) - TOUJOURS UTILISER

```c
#include <stdint.h>

uint8_t   val1;   // 1 byte,  non signé (0-255)
int8_t    val2;   // 1 byte,  signé
uint16_t  val3;   // 2 bytes, non signé
uint32_t  val4;   // 4 bytes, non signé
uint64_t  val5;   // 8 bytes, non signé
```

> **Pourquoi ?** `int` = 4 bytes sur x86... mais 2 sur certains systèmes. `uint32_t` = TOUJOURS 4 bytes.

---

## Signed vs Unsigned : LE piège

### La différence

```
Même bits, interprétation différente :

0xFF (11111111) :
  - unsigned char → 255
  - signed char   → -1

Pourquoi ? Le bit de poids fort = signe en signed.
```

### Le bug classique en shellcode

```c
// ❌ MAUVAIS
char shellcode[] = { 0x90, 0xff, 0xc0 };
if (shellcode[1] > 0) { ... }  // FAUX ! 0xff signed = -1, pas > 0

// ✅ BON
unsigned char shellcode[] = { 0x90, 0xff, 0xc0 };
if (shellcode[1] > 0) { ... }  // VRAI ! 0xff unsigned = 255 > 0
```

**Règle : Shellcode, bytes bruts, données binaires → TOUJOURS `unsigned char` ou `uint8_t`**

---

## Integer Overflow : L'exploitation

### Le concept

```c
unsigned char count = 255;
count = count + 1;    // count = 0  (wrap around)

signed char value = 127;
value = value + 1;    // value = -128 (wrap around)
```

```
     254 → 255 → 0 → 1      (unsigned wrap)
     126 → 127 → -128 → -127 (signed wrap)
```

### Vulnérabilité classique

```c
void copy_data(unsigned int num_elements) {
    if (num_elements > 1000) return;  // Check de sécurité

    // OVERFLOW : num_elements * sizeof(struct) peut wrap à 0
    size_t total = num_elements * sizeof(struct element);  // 8 bytes par élément

    char* buf = malloc(total);  // Alloue 0 bytes si overflow !

    // Écrit num_elements éléments → BUFFER OVERFLOW
    for (int i = 0; i < num_elements; i++) {
        buf[i] = data[i];  // Boom
    }
}
```

> **Attaque :** `num_elements = 0x20000001`, `total = 0x20000001 * 8 = 0x100000008` → tronqué à `0x8` sur 32-bit.

---

## Endianness : L'ordre des bytes

### Little Endian (x86, x64, ARM) - Ce que tu utilises

```
Valeur : 0x12345678

En mémoire :
Addr   +0     +1     +2     +3
     ┌──────┬──────┬──────┬──────┐
     │ 0x78 │ 0x56 │ 0x34 │ 0x12 │  ← LSB first (petit bout d'abord)
     └──────┴──────┴──────┴──────┘
```

### Big Endian (Réseau, certains RISC)

```
Valeur : 0x12345678

En mémoire :
Addr   +0     +1     +2     +3
     ┌──────┬──────┬──────┬──────┐
     │ 0x12 │ 0x34 │ 0x56 │ 0x78 │  ← MSB first (gros bout d'abord)
     └──────┴──────┴──────┴──────┘
```

### Application : Lire un dump mémoire

```
(gdb) x/4xb &my_int
0x7fffe100: 0x39 0x30 0x00 0x00

Valeur = ? → Little endian, lire à l'envers : 0x00003039 = 12345
```

### Application : Écrire une adresse dans un exploit

```c
// Cible : écrire 0x7fff1234 dans un buffer (x86)
unsigned char exploit[] = {
    'A', 'A', 'A', 'A',           // Padding
    0x34, 0x12, 0xff, 0x7f        // Adresse en LITTLE ENDIAN
};
// CPU lit : 0x7fff1234 ✓
```

### Application : Analyse réseau (Big Endian)

```
Paquet TCP capturé :
00 50 11 5C ...
       ↑
Port source = 0x0050 = 80 (HTTP)
Port dest   = 0x115C = 4444 (listener)
```

### Fonctions de conversion

```c
#include <arpa/inet.h>  // ou <winsock2.h> sur Windows

htons(4444);   // Host to Network Short (little → big)
htonl(addr);   // Host to Network Long
ntohs(port);   // Network to Host Short (big → little)
ntohl(addr);   // Network to Host Long
```

---

## sizeof() : Calculer les offsets

```c
printf("char:  %zu\n", sizeof(char));    // 1
printf("int:   %zu\n", sizeof(int));     // 4
printf("long:  %zu\n", sizeof(long));    // 8
printf("ptr:   %zu\n", sizeof(void*));   // 8 (x64)
```

### Application : Exploit d'une struct

```c
struct User {
    char name[32];      // Offset 0,  taille 32
    int age;            // Offset 32, taille 4
    int is_admin;       // Offset 36, taille 4
};

// Pour écraser is_admin depuis name :
char exploit[40];
memset(exploit, 'A', 36);          // Remplir jusqu'à is_admin
*(int*)(exploit + 36) = 1;         // is_admin = 1
```

> **`offsetof(struct, member)`** = offset d'un membre dans une struct.

---

## Variables non initialisées : Le leak

```c
// ❌ VULNÉRABLE
void check_password(char* input) {
    int authenticated;  // Contient GARBAGE (données précédentes)

    if (strcmp(input, "secret") == 0) {
        authenticated = 1;
    }

    if (authenticated) {  // Peut être vrai par HASARD
        grant_access();
    }
}

// ✅ SAFE
int authenticated = 0;  // TOUJOURS initialiser
```

> **Le garbage peut contenir des données sensibles** de fonctions précédentes → info leak potentiel.

---

## Exercices pratiques

### Exo 1 : Lire un dump (5 min)

```
Dump : 0x41 0x00 0x00 0x00 0x42 0x43 0x00 0x00
```
1. Quel est l'int aux bytes 0-3 ? (little endian)
2. Quel est le short aux bytes 4-5 ?

### Exo 2 : Integer overflow (5 min)

```c
unsigned short len = 65530;
len = len + 10;  // Quelle valeur ?
```

### Exo 3 : Écrire une adresse (5 min)

Écris `0xdeadbeef` en little endian dans un buffer.

### Exo 4 : Calculer un offset (10 min)

```c
struct Packet {
    uint32_t magic;
    uint16_t length;
    uint8_t  type;
    uint8_t  flags;
    char     data[256];
};
```
À quel offset commence `data` ?

---

## Checklist

```
□ Je sais lire un dump hexa et identifier les valeurs
□ Je connais les tailles : char=1, short=2, int=4, long=8
□ Je comprends signed vs unsigned et pourquoi utiliser unsigned char
□ Je sais convertir little endian ↔ big endian
□ Je connais les types Windows (BYTE, WORD, DWORD)
□ Je sais calculer des offsets avec sizeof
□ Je comprends l'integer overflow et comment l'exploiter
□ J'initialise TOUJOURS mes variables
```

---

## Glossaire express

| Terme | Définition |
|-------|------------|
| **LSB** | Least Significant Byte - byte de poids faible |
| **MSB** | Most Significant Byte - byte de poids fort |
| **Little Endian** | LSB stocké en premier (x86/x64) |
| **Big Endian** | MSB stocké en premier (réseau) |
| **Integer Overflow** | Valeur dépasse la limite → wrap around |
| **size_t** | Type pour les tailles (unsigned, 8 bytes sur x64) |
| **stdint.h** | Header avec types à taille garantie (uint32_t, etc.) |
| **DWORD** | Type Windows = unsigned 32-bit |

---

## Prochaine étape

**Module suivant →** [03 - Opérateurs](../03_operators/)

---

**Temps lecture :** 8 min | **Pratique :** 25 min
