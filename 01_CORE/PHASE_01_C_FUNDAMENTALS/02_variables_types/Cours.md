# Module 02 : Variables et Types - La mémoire démystifiée

## Objectifs

À la fin de ce module, tu seras capable de :
- Comprendre comment la mémoire RAM fonctionne réellement
- Maîtriser les types de données C et leur représentation binaire
- Comprendre signed vs unsigned et pourquoi c'est crucial en exploitation
- Manipuler l'endianness pour l'analyse mémoire et réseau
- Identifier les vulnérabilités liées aux types (integer overflow)

---

## Partie 0 : Pourquoi ce module est CRUCIAL pour l'offensive

Avant de plonger dans la théorie, comprends pourquoi tu DOIS maîtriser les variables et types :

### En Reverse Engineering
```
Quand tu ouvres un binaire dans IDA ou Ghidra, tu vois :
   mov eax, [rbp-0x4]    ; C'est quoi ce -0x4 ?

Réponse : C'est l'offset d'une variable locale (int = 4 bytes)
Sans comprendre les types, tu ne peux pas reverser.
```

### En Exploitation (Buffer Overflow)
```c
char buffer[64];      // 64 bytes réservés
int is_admin = 0;     // 4 bytes juste après

// Si tu écris 68 bytes dans buffer...
// Tu écrases is_admin !
```

### En Malware Development
```c
// Un shellcode est une suite de bytes
unsigned char shellcode[] = { 0x31, 0xc0, 0x50, 0x68, ... };

// Pourquoi unsigned ? Parce que 0xFF en signed = -1
// Et ça cause des bugs de comparaison !
```

### En Analyse de Protocoles
```
Paquet TCP capturé :
00 50 11 5C ...

C'est quoi ? Port source (2 bytes big-endian) = 0x0050 = 80
           Port dest (2 bytes big-endian) = 0x115C = 4444
```

**Si tu ne maîtrises pas ce module, tu seras bloqué pour TOUT le reste.**

---

## Partie 1 : La mémoire RAM - Ta zone de travail

### C'est quoi la RAM ?

La RAM (Random Access Memory) est une grille géante de cases numérotées. Chaque case :
- A une **adresse unique** (son numéro)
- Peut stocker **1 byte** (8 bits, valeurs 0-255)
- Est accessible instantanément (d'où "Random Access")

```
La RAM vue simplement :

Adresse     Contenu (1 byte chacun)
┌──────────┬────────┐
│ 0x0000   │  0x00  │
├──────────┼────────┤
│ 0x0001   │  0x00  │
├──────────┼────────┤
│ 0x0002   │  0x41  │  ← Ici il y a la valeur 65 (caractère 'A')
├──────────┼────────┤
│ 0x0003   │  0x00  │
├──────────┼────────┤
│   ...    │  ...   │
├──────────┼────────┤
│ 0xFFFF...│  0x00  │
└──────────┴────────┘
```

### Pourquoi les adresses sont en hexadécimal ?

Rappel du Module 01 : l'hexa est compact.

```
Adresse en décimal : 140737488355328
Adresse en hexa    : 0x7FFFFFFFE000

Lequel préfères-tu lire dans un debugger ?
```

### APPLICATION OFFENSIVE : Lecture de dump mémoire

Quand tu utilises un debugger (GDB, x64dbg, WinDbg), tu vois :

```
(gdb) x/16xb 0x7fffffffe000
0x7fffffffe000: 0x48 0x65 0x6c 0x6c 0x6f 0x00 0x00 0x00
0x7fffffffe008: 0x41 0x41 0x41 0x41 0x42 0x42 0x42 0x42

Interprétation :
- 0x48 0x65 0x6c 0x6c 0x6f = "Hello" (codes ASCII)
- 0x00 = null terminator de la string
- 0x41 0x41 0x41 0x41 = "AAAA" (pattern de test pour overflow)
- 0x42 0x42 0x42 0x42 = "BBBB"
```

---

## Partie 2 : Les bytes - L'unité fondamentale

### C'est quoi un byte ?

Un **byte** (octet en français) = 8 bits = la plus petite unité adressable.

```
1 byte = 8 bits

┌───┬───┬───┬───┬───┬───┬───┬───┐
│ 1 │ 0 │ 1 │ 0 │ 0 │ 0 │ 0 │ 1 │  = 161 en décimal = 0xA1 en hexa
└───┴───┴───┴───┴───┴───┴───┴───┘
  │   │   │   │   │   │   │   │
 128  64  32  16  8   4   2   1   (poids de chaque bit)

Calcul : 128 + 32 + 1 = 161
```

### Pourquoi 8 bits ?

- 8 bits = 2^8 = **256 valeurs possibles** (0 à 255)
- Suffisant pour tous les caractères ASCII (0-127) + caractères étendus
- Divisible par 2, 4 : pratique pour les calculs binaires

### APPLICATION OFFENSIVE : Le byte en shellcode

Un shellcode est une suite de bytes qui représentent des instructions machine :

```c
// Chaque byte est un opcode ou une donnée
unsigned char shellcode[] = {
    0x31, 0xc0,             // xor eax, eax     (2 bytes)
    0x50,                   // push eax         (1 byte)
    0x68, 0x2f, 0x2f, 0x73, 0x68,  // push "//sh" (5 bytes)
    0x68, 0x2f, 0x62, 0x69, 0x6e,  // push "/bin" (5 bytes)
    // ...
};

// Taille totale : compte les bytes !
// sizeof(shellcode) te donne la taille
```

**Pourquoi c'est important ?**
- Chaque byte compte (taille limitée dans les exploits)
- Tu dois savoir lire les opcodes en hexa
- Tu dois calculer les offsets en bytes

---

## Partie 3 : Les variables - Nommer la mémoire

### C'est quoi une variable ?

Une variable, c'est un **nom** que tu donnes à une zone mémoire.

```c
int age = 25;
```

Ce qui se passe :
1. Le compilateur réserve 4 bytes (taille d'un `int`)
2. Il note que "age" = adresse 0x7fffe100 (exemple)
3. Il écrit 25 dans ces 4 bytes

```
Sans variable (assembleur) :
   mov DWORD PTR [rbp-0x4], 25    ; Met 25 à l'adresse rbp-4

Avec variable (C) :
   int age = 25;                   ; Même chose, mais lisible !
```

### Déclaration vs Initialisation

```c
// Déclaration SEULE (dangereux !)
int x;              // x contient une valeur ALÉATOIRE (garbage)

// Déclaration + Initialisation (recommandé)
int y = 0;          // y contient 0, c'est sûr

// Pourquoi c'est dangereux ?
printf("%d\n", x);  // Affiche n'importe quoi !
                    // Peut leaker des données sensibles
```

### VULNÉRABILITÉ : Utilisation de variable non initialisée

```c
// Code vulnérable
void check_password(char* input) {
    int authenticated;  // NON INITIALISÉ !

    if (strcmp(input, "secret") == 0) {
        authenticated = 1;
    }

    if (authenticated) {  // BUG : peut être vrai par hasard !
        grant_access();
    }
}

// Fix :
int authenticated = 0;  // TOUJOURS initialiser !
```

---

## Partie 4 : Les types entiers - Tailles et limites

### Pourquoi les types existent ?

Le type dit au compilateur :
1. **Combien de bytes** réserver
2. **Comment interpréter** ces bytes

```c
char c = 65;    // 1 byte  → stocke 0x41 → peut être vu comme 'A'
int i = 65;     // 4 bytes → stocke 0x00000041
```

### Tableau des types entiers

| Type | Taille | Min (signed) | Max (signed) | Max (unsigned) |
|------|--------|--------------|--------------|----------------|
| `char` | 1 byte | -128 | 127 | 255 |
| `short` | 2 bytes | -32,768 | 32,767 | 65,535 |
| `int` | 4 bytes | -2,147,483,648 | 2,147,483,647 | 4,294,967,295 |
| `long` | 8 bytes | -2^63 | 2^63 - 1 | 2^64 - 1 |

### Comment retenir les limites ?

```
Pour un type de N bits :
- Unsigned : 0 à 2^N - 1
- Signed   : -2^(N-1) à 2^(N-1) - 1

Exemples :
- char (8 bits)  : unsigned 0-255, signed -128 à 127
- short (16 bits): unsigned 0-65535, signed -32768 à 32767
- int (32 bits)  : unsigned 0 à ~4 milliards, signed ~-2 à +2 milliards
```

### APPLICATION OFFENSIVE : Types Windows API

En développement Windows (malware, outils), tu verras ces types :

```c
// Types Windows (définis dans windows.h)
typedef unsigned char   BYTE;     // 1 byte  - pour les données brutes
typedef unsigned short  WORD;     // 2 bytes - pour les offsets PE
typedef unsigned long   DWORD;    // 4 bytes - pour les handles, PIDs
typedef unsigned __int64 QWORD;   // 8 bytes - pour les adresses 64-bit
typedef void*           LPVOID;   // pointeur - pour les buffers
typedef wchar_t*        LPWSTR;   // string Unicode

// Utilisation réelle :
DWORD pid = GetCurrentProcessId();           // PID du process
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
LPVOID addr = VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
```

**Pourquoi ces noms ?**
- `BYTE` : évident, 1 byte
- `WORD` : historique 16-bit (un "mot" machine)
- `DWORD` : Double WORD = 32 bits
- `QWORD` : Quad WORD = 64 bits

---

## Partie 5 : Signed vs Unsigned - Le piège classique

### La différence fondamentale

```
UNSIGNED (sans signe) : tous les bits = valeur
┌───┬───┬───┬───┬───┬───┬───┬───┐
│ 1 │ 1 │ 1 │ 1 │ 1 │ 1 │ 1 │ 1 │ = 255
└───┴───┴───┴───┴───┴───┴───┴───┘

SIGNED (avec signe) : bit de poids fort = signe
┌───┬───┬───┬───┬───┬───┬───┬───┐
│ 1 │ 1 │ 1 │ 1 │ 1 │ 1 │ 1 │ 1 │ = -1 (complément à deux)
└───┴───┴───┴───┴───┴───┴───┴───┘
  ↑
  Bit de signe (1 = négatif)
```

### Le complément à deux (pour les curieux)

Comment -1 devient `0xFF` (11111111) ?

```
Pour obtenir -N en complément à deux :
1. Écrire N en binaire
2. Inverser tous les bits
3. Ajouter 1

Exemple pour -1 :
1. 1 en binaire    = 00000001
2. Inverser        = 11111110
3. Ajouter 1       = 11111111 = 0xFF

Vérification : 0xFF en unsigned = 255, en signed = -1
```

### VULNÉRABILITÉ : Integer Overflow

L'overflow se produit quand une valeur dépasse la limite du type :

```c
// Overflow unsigned
unsigned char count = 255;
count = count + 1;    // count = 0 (wrap around)

// Overflow signed
signed char value = 127;
value = value + 1;    // value = -128 (wrap around)
```

**Schéma de l'overflow unsigned (8 bits) :**
```
254 → 255 → 0 → 1 → 2 → ...
        ↑    ↑
      Max  Overflow!
```

### EXPLOITATION : Integer Overflow Attack

```c
// Code vulnérable (simplifié)
void copy_data(char* src, unsigned short len) {
    // Vérification de sécurité
    if (len > 1024) {
        printf("Too big!\n");
        return;
    }

    char buffer[1024];

    // BUG : len + 1 peut overflow !
    // Si len = 65535 (0xFFFF), alors len + 1 = 0
    memcpy(buffer, src, len + 1);
}

// Attaque :
// Envoyer len = 65535
// La vérification passe (65535 < 1024 ? Non... wait)
// En fait non, cet exemple est mal choisi.

// Meilleur exemple :
void allocate_buffer(unsigned int num_elements) {
    // Vérification : max 1000 éléments
    if (num_elements > 1000) return;

    // OVERFLOW : si sizeof(element) = 8 et num_elements = 0x20000000
    // total = 0x20000000 * 8 = 0x100000000 = OVERFLOW sur 32 bits = 0
    size_t total = num_elements * sizeof(struct element);

    char* buf = malloc(total);  // Alloue 0 bytes !
    // ... mais on écrit num_elements éléments = buffer overflow
}
```

### APPLICATION OFFENSIVE : Signed vs Unsigned en shellcode

```c
// MAUVAIS : signed char peut causer des bugs
char shellcode[] = { 0x90, 0xff, 0xc0 };
// 0xff en signed = -1, comparaisons foireuses possibles

// BON : unsigned char pour les bytes bruts
unsigned char shellcode[] = { 0x90, 0xff, 0xc0 };
// 0xff en unsigned = 255, comportement prévisible

// Exemple de bug :
char bad = 0xff;
if (bad > 0) {          // FAUX ! -1 n'est pas > 0
    execute_shellcode();
}

unsigned char good = 0xff;
if (good > 0) {         // VRAI ! 255 > 0
    execute_shellcode();
}
```

---

## Partie 6 : L'Endianness - L'ordre des bytes

### Le problème

Un `int` (4 bytes) contient la valeur `0x12345678`.
Dans quel ordre sont stockés les bytes en mémoire ?

### Little Endian (x86, x64, ARM moderne)

Le byte de **poids faible** (Least Significant Byte) est stocké **en premier** (à l'adresse basse).

```
Valeur : 0x12345678

Adresse   Contenu
0x1000    0x78    ← LSB (poids faible) en premier
0x1001    0x56
0x1002    0x34
0x1003    0x12    ← MSB (poids fort) en dernier

Mnémotechnique : "Little end first" = le petit bout d'abord
```

### Big Endian (Réseau, PowerPC, certains ARM)

Le byte de **poids fort** (Most Significant Byte) est stocké **en premier**.

```
Valeur : 0x12345678

Adresse   Contenu
0x1000    0x12    ← MSB en premier
0x1001    0x34
0x1002    0x56
0x1003    0x78    ← LSB en dernier

Mnémotechnique : "Big end first" = le gros bout d'abord
```

### Comparaison visuelle

```
Nombre : 0x12345678

Little Endian (x86/x64) :          Big Endian (réseau) :
┌──────┬──────┬──────┬──────┐      ┌──────┬──────┬──────┬──────┐
│ 0x78 │ 0x56 │ 0x34 │ 0x12 │      │ 0x12 │ 0x34 │ 0x56 │ 0x78 │
└──────┴──────┴──────┴──────┘      └──────┴──────┴──────┴──────┘
Addr:  +0     +1     +2     +3     Addr:  +0     +1     +2     +3
```

### APPLICATION OFFENSIVE : Reverse Engineering

Quand tu analyses un dump mémoire sur x86/x64 :

```
(gdb) x/4xb &my_int
0x7fffe100: 0x39 0x30 0x00 0x00

Q: Quelle est la valeur de my_int ?
A: En little endian, on lit à l'envers : 0x00003039 = 12345 en décimal
```

### APPLICATION OFFENSIVE : Analyse de paquets réseau

Les protocoles réseau utilisent **Big Endian** (Network Byte Order) :

```
Paquet TCP capturé (hex dump) :
00 50 11 5C ...

Interprétation :
- Bytes 0-1 : Port source = 0x0050 = 80 (HTTP)
- Bytes 2-3 : Port destination = 0x115C = 4444 (ton listener !)
```

### Fonctions de conversion

```c
#include <arpa/inet.h>  // Linux
// ou #include <winsock2.h>  // Windows

// Host to Network (little → big)
uint16_t htons(uint16_t hostshort);   // short (2 bytes)
uint32_t htonl(uint32_t hostlong);    // long (4 bytes)

// Network to Host (big → little)
uint16_t ntohs(uint16_t netshort);
uint32_t ntohl(uint32_t netlong);

// Exemple pratique : reverse shell
struct sockaddr_in addr;
addr.sin_port = htons(4444);          // Convertir le port
addr.sin_addr.s_addr = inet_addr("192.168.1.100");  // IP
```

### APPLICATION OFFENSIVE : Écriture d'adresse dans un exploit

```c
// Tu veux écrire l'adresse 0x7fff1234 dans un buffer
// Sur x86 (little endian), tu dois l'écrire à l'envers :

unsigned char exploit[] = {
    'A', 'A', 'A', 'A',  // Padding
    'A', 'A', 'A', 'A',  // Plus de padding
    0x34, 0x12, 0xff, 0x7f  // Adresse en little endian !
};

// En mémoire : ... 34 12 ff 7f
// CPU lit :    0x7fff1234 ✓
```

---

## Partie 7 : sizeof() - Connaître les tailles

### Utilisation basique

```c
#include <stdio.h>

int main() {
    printf("char   : %zu bytes\n", sizeof(char));    // 1
    printf("short  : %zu bytes\n", sizeof(short));   // 2
    printf("int    : %zu bytes\n", sizeof(int));     // 4
    printf("long   : %zu bytes\n", sizeof(long));    // 8
    printf("void*  : %zu bytes\n", sizeof(void*));   // 8 (sur x64)

    // sizeof sur une variable
    int x = 42;
    printf("x      : %zu bytes\n", sizeof(x));       // 4

    // sizeof sur un tableau
    char buf[100];
    printf("buf    : %zu bytes\n", sizeof(buf));     // 100

    return 0;
}
```

**Note :** `%zu` est le format pour `size_t` (le type retourné par sizeof).

### APPLICATION OFFENSIVE : Calcul d'offsets

```c
struct User {
    char name[32];      // Offset 0, taille 32
    int age;            // Offset 32, taille 4
    int is_admin;       // Offset 36, taille 4
};  // Taille totale : 40 bytes

// Pour écraser is_admin depuis name :
// Il faut écrire 32 + 4 = 36 bytes de padding, puis la valeur
char exploit[40];
memset(exploit, 'A', 36);           // Padding
*(int*)(exploit + 36) = 1;          // is_admin = 1

// Vérification avec sizeof :
printf("Offset de is_admin : %zu\n",
       offsetof(struct User, is_admin));  // 36
```

---

## Partie 8 : Types à taille fixe (stdint.h)

### Le problème

La taille des types peut varier selon la plateforme :
- `int` = 4 bytes sur x86/x64... mais 2 bytes sur certains microcontrôleurs !
- `long` = 4 bytes sur Windows 64-bit, 8 bytes sur Linux 64-bit !

### La solution : stdint.h

```c
#include <stdint.h>

// Types de taille GARANTIE
int8_t   val1;   // Exactement 8 bits, signé
uint8_t  val2;   // Exactement 8 bits, non signé
int16_t  val3;   // Exactement 16 bits, signé
uint16_t val4;   // Exactement 16 bits, non signé
int32_t  val5;   // Exactement 32 bits, signé
uint32_t val6;   // Exactement 32 bits, non signé
int64_t  val7;   // Exactement 64 bits, signé
uint64_t val8;   // Exactement 64 bits, non signé
```

### APPLICATION OFFENSIVE : Shellcode et structures PE/ELF

```c
#include <stdint.h>

// Structure du header PE (simplifiée)
typedef struct {
    uint16_t Machine;              // 2 bytes - type de CPU
    uint16_t NumberOfSections;     // 2 bytes - nombre de sections
    uint32_t TimeDateStamp;        // 4 bytes - date de compilation
    uint32_t PointerToSymbolTable; // 4 bytes
    uint32_t NumberOfSymbols;      // 4 bytes
    uint16_t SizeOfOptionalHeader; // 2 bytes
    uint16_t Characteristics;      // 2 bytes - flags
} IMAGE_FILE_HEADER;  // Total : 20 bytes, TOUJOURS

// Sans stdint.h, les tailles pourraient varier = parsing cassé !
```

---

## Partie 9 : Résumé et checklist

### Ce que tu dois retenir

| Concept | Point clé |
|---------|-----------|
| RAM | Tableau de bytes, chacun avec une adresse |
| Variable | Nom donné à une zone mémoire |
| Type | Définit taille + interprétation |
| Signed | Peut être négatif, 1 bit pour le signe |
| Unsigned | Toujours ≥ 0, tous les bits = valeur |
| Overflow | Quand on dépasse les limites → wrap around |
| Little Endian | LSB first (x86/x64) |
| Big Endian | MSB first (réseau) |
| sizeof | Retourne la taille en bytes |
| stdint.h | Types de taille garantie |

### Checklist offensive

- [ ] Je sais lire un dump mémoire en hexa
- [ ] Je sais calculer les limites d'un type (2^N)
- [ ] Je comprends pourquoi utiliser `unsigned char` pour les shellcodes
- [ ] Je sais convertir entre little et big endian
- [ ] Je connais les types Windows (BYTE, WORD, DWORD)
- [ ] Je sais utiliser sizeof pour calculer des offsets
- [ ] Je comprends comment l'integer overflow peut être exploité

---

## Exercices pratiques

Voir [exercice.md](exercice.md)

## Code exemple

Voir [example.c](example.c)

---

**Module suivant** : [03 - Opérateurs](../03_operators/)
