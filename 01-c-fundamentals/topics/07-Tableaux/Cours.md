# 08 - Tableaux (Arrays)

## 🎯 Ce que tu vas apprendre

- Ce qu'est un tableau et comment il est stocké en mémoire
- Comment déclarer et initialiser des tableaux
- Accéder aux éléments d'un tableau
- Les tableaux multidimensionnels (2D, 3D)
- Pourquoi les tableaux commencent à l'index 0
- La relation entre tableaux et pointeurs

## 📚 Théorie

### Concept 1 : C'est quoi un tableau ?

**C'est quoi ?**
Un tableau (array) est une collection d'éléments du MÊME type, stockés de manière CONTIGUË en mémoire.

**Pourquoi ça existe ?**
Au lieu de créer 100 variables séparées (`age1`, `age2`, ..., `age100`), tu peux créer un seul tableau `ages[100]`.

**Comment ça marche ?**

Un tableau réserve un bloc continu de mémoire pour stocker N éléments.

```c
int numbers[5];  // Réserve 5 * 4 bytes = 20 bytes consécutifs
```

**Représentation en mémoire** :
```
int numbers[5] = {10, 20, 30, 40, 50};

Mémoire (little endian) :
Adresse    Contenu      Représentation
0x1000  │ 0x0A 0x00... │ numbers[0] = 10
0x1004  │ 0x14 0x00... │ numbers[1] = 20
0x1008  │ 0x1E 0x00... │ numbers[2] = 30
0x100C  │ 0x28 0x00... │ numbers[3] = 40
0x1010  │ 0x32 0x00... │ numbers[4] = 50

┌──────┬──────┬──────┬──────┬──────┐
│  10  │  20  │  30  │  40  │  50  │  (Vue logique)
└──────┴──────┴──────┴──────┴──────┘
   [0]    [1]    [2]    [3]    [4]

Contiguïté : Les éléments se suivent sans trou
```

### Concept 2 : Pourquoi l'index commence à 0 ?

**C'est quoi le principe ?**

En C, l'index représente le **décalage (offset)** depuis le début du tableau.

```c
int arr[5];

arr[0]  →  adresse_de_base + (0 * sizeof(int))
arr[1]  →  adresse_de_base + (1 * sizeof(int))
arr[2]  →  adresse_de_base + (2 * sizeof(int))
arr[3]  →  adresse_de_base + (3 * sizeof(int))
arr[4]  →  adresse_de_base + (4 * sizeof(int))
```

**Schéma** :
```
Adresse de base : 0x1000

arr[0] : 0x1000 + (0 × 4) = 0x1000
arr[1] : 0x1000 + (1 × 4) = 0x1004
arr[2] : 0x1000 + (2 × 4) = 0x1008
arr[3] : 0x1000 + (3 × 4) = 0x100C
arr[4] : 0x1000 + (4 × 4) = 0x1010
```

**Pourquoi c'est efficace ?**
- Calcul simple : `adresse = base + (index * taille_élément)`
- Pas de soustraction nécessaire

### Concept 3 : Déclaration et initialisation

**Déclaration simple** :
```c
int numbers[5];  // 5 entiers (valeurs aléatoires)
```

**Déclaration avec initialisation** :
```c
int numbers[5] = {10, 20, 30, 40, 50};
```

**Taille automatique** :
```c
int numbers[] = {10, 20, 30};  // Taille = 3 (déduite)
```

**Initialisation partielle** :
```c
int numbers[5] = {10, 20};  // {10, 20, 0, 0, 0}
// Les éléments non spécifiés sont mis à 0
```

**Initialiser tout à zéro** :
```c
int numbers[100] = {0};  // Tous les éléments à 0
```

**Exemples** :
```c
// Ports communs
int ports[3] = {80, 443, 22};

// Shellcode bytes
unsigned char shellcode[] = {
    0x90, 0x90, 0x90, 0x90,  // NOP sled
    0x31, 0xc0,              // xor eax, eax
    0x50,                    // push eax
    0xff, 0xe4               // jmp esp
};
```

### Concept 4 : Accès aux éléments

**Lecture** :
```c
int ports[] = {80, 443, 22};

int first = ports[0];   // 80
int second = ports[1];  // 443
int third = ports[2];   // 22
```

**Modification** :
```c
ports[1] = 8080;  // ports devient {80, 8080, 22}
```

**ATTENTION : Pas de vérification de limites**

En C, il n'y a AUCUNE vérification automatique. Tu peux accéder hors des limites :

```c
int arr[3] = {1, 2, 3};

int x = arr[10];  // COMPORTEMENT INDÉFINI
                  // Peut retourner n'importe quoi
                  // Peut crasher le programme

arr[10] = 42;     // Écrit en dehors du tableau
                  // Écrase d'autres variables
                  // Buffer overflow !
```

**Schéma d'un overflow** :
```
Tableau arr[3] en mémoire :
┌────┬────┬────┐
│ 1  │ 2  │ 3  │  arr[0], arr[1], arr[2]
└────┴────┴────┘
                ↓ Autres variables

Accès arr[10] :
┌────┬────┬────┬────┬────┬────┬────┬────┬────┬────┬────┐
│ 1  │ 2  │ 3  │ ?  │ ?  │ ?  │ ?  │ ?  │ ?  │ ?  │ ?  │
└────┴────┴────┴────┴────┴────┴────┴────┴────┴────┴────┘
                                                     ↑
                                                  arr[10]
                                            Accès hors limites !
```

### Concept 5 : Taille d'un tableau avec sizeof

**C'est quoi ?**

`sizeof(tableau)` retourne la taille TOTALE en bytes. Pour obtenir le nombre d'éléments :

```c
int arr[] = {10, 20, 30, 40};

int total_bytes = sizeof(arr);           // 16 bytes (4 int × 4 bytes)
int element_size = sizeof(arr[0]);       // 4 bytes (1 int)
int num_elements = sizeof(arr) / sizeof(arr[0]);  // 4 éléments
```

**Schéma** :
```
arr[] = {10, 20, 30, 40}

sizeof(arr)      = 16 bytes (toute l'array)
sizeof(arr[0])   = 4 bytes  (un élément)

Nombre d'éléments = 16 / 4 = 4
```

**Exemple complet** :
```c
int ports[] = {80, 443, 22, 21, 3389};
int size = sizeof(ports) / sizeof(ports[0]);

for (int i = 0; i < size; i++) {
    printf("Port[%d] = %d\n", i, ports[i]);
}
```

**ATTENTION** : sizeof() ne fonctionne que sur les tableaux statiques (pas les pointeurs).

```c
void func(int arr[]) {
    int size = sizeof(arr) / sizeof(arr[0]);  // FAUX !
    // arr est un pointeur ici, pas un tableau
    // sizeof(arr) = sizeof(void*) = 8 bytes (sur x64)
}
```

### Concept 6 : Parcourir un tableau

**Méthode classique** :
```c
int numbers[] = {10, 20, 30, 40, 50};
int size = 5;

for (int i = 0; i < size; i++) {
    printf("%d\n", numbers[i]);
}
```

**Avec calcul automatique de la taille** :
```c
int numbers[] = {10, 20, 30, 40, 50};

for (int i = 0; i < sizeof(numbers)/sizeof(numbers[0]); i++) {
    printf("%d\n", numbers[i]);
}
```

### Concept 7 : Tableaux multidimensionnels (2D)

**C'est quoi ?**
Un tableau de tableaux. Visualise-le comme une grille (lignes et colonnes).

**Déclaration** :
```c
int matrix[3][4];  // 3 lignes, 4 colonnes
```

**Initialisation** :
```c
int matrix[3][3] = {
    {1, 2, 3},
    {4, 5, 6},
    {7, 8, 9}
};
```

**Accès** :
```c
int value = matrix[1][2];  // Ligne 1, colonne 2 → 6
```

**Visualisation** :
```
matrix[3][3] :
       Col 0  Col 1  Col 2
Row 0    1      2      3
Row 1    4      5      6
Row 2    7      8      9

matrix[1][2] = 6
```

**En mémoire (stockage row-major)** :
```
Logiquement :
┌───┬───┬───┐
│ 1 │ 2 │ 3 │ Ligne 0
├───┼───┼───┤
│ 4 │ 5 │ 6 │ Ligne 1
├───┼───┼───┤
│ 7 │ 8 │ 9 │ Ligne 2
└───┴───┴───┘

En mémoire (contiguë) :
┌───┬───┬───┬───┬───┬───┬───┬───┬───┐
│ 1 │ 2 │ 3 │ 4 │ 5 │ 6 │ 7 │ 8 │ 9 │
└───┴───┴───┴───┴───┴───┴───┴───┴───┘
 [0][0] ↑       [1][0] ↑       [2][0] ↑
```

**Parcourir un tableau 2D** :
```c
int matrix[3][3] = {
    {1, 2, 3},
    {4, 5, 6},
    {7, 8, 9}
};

for (int i = 0; i < 3; i++) {        // Lignes
    for (int j = 0; j < 3; j++) {    // Colonnes
        printf("%d ", matrix[i][j]);
    }
    printf("\n");
}

// Output :
// 1 2 3
// 4 5 6
// 7 8 9
```

### Concept 8 : Tableaux et pointeurs

**Relation fondamentale** :

En C, le nom d'un tableau est un **pointeur constant** vers le premier élément.

```c
int arr[5] = {10, 20, 30, 40, 50};

printf("%p\n", arr);       // Adresse de arr[0]
printf("%p\n", &arr[0]);   // Même adresse
```

**Accès avec pointeur** :
```c
int arr[] = {10, 20, 30};

printf("%d\n", arr[0]);    // 10
printf("%d\n", *arr);      // 10 (même chose)
printf("%d\n", arr[1]);    // 20
printf("%d\n", *(arr+1));  // 20 (même chose)
```

**Schéma** :
```
arr[3] = {10, 20, 30}

Adresse : 0x1000

arr      → pointe vers 0x1000
&arr[0]  → 0x1000
arr + 1  → 0x1004 (avance de sizeof(int))
arr + 2  → 0x1008

*arr      = arr[0] = 10
*(arr+1)  = arr[1] = 20
*(arr+2)  = arr[2] = 30
```

### Concept 9 : Copier un tableau

**ATTENTION** : Tu ne peux PAS copier un tableau avec `=` !

```c
int src[3] = {1, 2, 3};
int dst[3];

dst = src;  // ERREUR DE COMPILATION !
```

**Méthode 1 : Boucle manuelle** :
```c
for (int i = 0; i < 3; i++) {
    dst[i] = src[i];
}
```

**Méthode 2 : memcpy** :
```c
#include <string.h>

memcpy(dst, src, sizeof(src));
```

### Concept 10 : Tableaux de caractères (strings)

En C, les strings sont des tableaux de `char` terminés par `\0`.

```c
char name[] = "Hello";
// Équivalent à :
char name[] = {'H', 'e', 'l', 'l', 'o', '\0'};
```

**Représentation en mémoire** :
```
name[] = "Hello"

┌───┬───┬───┬───┬───┬───┐
│ H │ e │ l │ l │ o │\0 │
└───┴───┴───┴───┴───┴───┘
 [0] [1] [2] [3] [4] [5]

Taille : 6 bytes (5 caractères + \0)
```

## 🔍 Visualisation : Calcul d'adresse

```c
int arr[10];
printf("Base address: %p\n", arr);
printf("arr[5] address: %p\n", &arr[5]);
```

**Calcul** :
```
Base : 0x1000

arr[5] = Base + (5 × sizeof(int))
       = 0x1000 + (5 × 4)
       = 0x1000 + 20
       = 0x1014

┌────────────────────────────────┐
│ arr[0] arr[1] ... arr[5] ...   │
│ 0x1000 0x1004    0x1014        │
└────────────────────────────────┘
                    ↑
                 +20 bytes
```

## 🎯 Application Red Team

### 1. Stockage de shellcode

```c
unsigned char shellcode[] = {
    0x90, 0x90, 0x90, 0x90,  // NOP sled
    0x31, 0xc0,              // xor eax, eax
    0x50,                    // push eax
    0x48, 0xbb, 0x2f, 0x62,  // mov rbx, "/bin/sh"
    0x69, 0x6e, 0x2f, 0x73,
    0x68,
    0x53,                    // push rbx
    0x48, 0x89, 0xe7,        // mov rdi, rsp
    0x48, 0x31, 0xf6,        // xor rsi, rsi
    0x48, 0x31, 0xd2,        // xor rdx, rdx
    0xb0, 0x3b,              // mov al, 59
    0x0f, 0x05               // syscall
};

int size = sizeof(shellcode);
printf("Shellcode size: %d bytes\n", size);
```

### 2. Liste de wordlist pour brute-force

```c
char* passwords[] = {
    "admin",
    "password",
    "123456",
    "root",
    "toor",
    "qwerty"
};

int count = sizeof(passwords) / sizeof(passwords[0]);

for (int i = 0; i < count; i++) {
    if (try_login("admin", passwords[i])) {
        printf("Password found: %s\n", passwords[i]);
        break;
    }
}
```

### 3. Parsing de structures binaires

```c
// Header IPv4
unsigned char packet[] = {
    0x45, 0x00, 0x00, 0x3c,  // Version, IHL, ToS, Total Length
    0x1c, 0x46, 0x40, 0x00,  // ID, Flags, Fragment Offset
    0x40, 0x06, 0xb1, 0xe6,  // TTL, Protocol, Checksum
    // ...
};

unsigned char version = (packet[0] >> 4) & 0x0F;  // Version
unsigned char ihl = packet[0] & 0x0F;             // Header length
unsigned char ttl = packet[8];                     // TTL
unsigned char protocol = packet[9];                // Protocol
```

### 4. ROPchain (Return-Oriented Programming)

```c
unsigned long ropchain[] = {
    0x00000000004005a3,  // pop rdi; ret
    0x0000000000601040,  // @ .data
    0x00000000004005a1,  // pop rsi; ret
    0x0000000000000000,  // NULL
    0x0000000000400430,  // execve() PLT
};

int chain_len = sizeof(ropchain) / sizeof(ropchain[0]);
```

### 5. Buffer de données réseau

```c
#define BUFFER_SIZE 4096
unsigned char recv_buffer[BUFFER_SIZE];

int bytes_read = recv(sock, recv_buffer, BUFFER_SIZE, 0);
if (bytes_read > 0) {
    process_data(recv_buffer, bytes_read);
}
```

### 6. Tableau 2D pour grille de scan

```c
// Scanner un sous-réseau 192.168.x.y
int scan_results[256][256] = {0};  // 0 = down, 1 = up

for (int x = 0; x < 256; x++) {
    for (int y = 1; y < 256; y++) {
        char ip[16];
        sprintf(ip, "192.168.%d.%d", x, y);
        if (ping(ip)) {
            scan_results[x][y] = 1;
            printf("Host UP: %s\n", ip);
        }
    }
}
```

### 7. XOR encoding d'un payload

```c
unsigned char payload[] = {/* shellcode here */};
unsigned char key[] = {0xDE, 0xAD, 0xBE, 0xEF};
int payload_len = sizeof(payload);
int key_len = sizeof(key);

// Encoder
for (int i = 0; i < payload_len; i++) {
    payload[i] ^= key[i % key_len];
}
```

### 8. Buffer overflow exploitation

```c
char vulnerable_buffer[64];
char exploit[] =
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  // 40 bytes padding
    "AAAAAAAAAAAAAAAAAAAAAAAAA"                 // 24 bytes padding
    "\x78\x56\x34\x12";                         // Return address (little endian)

memcpy(vulnerable_buffer, exploit, sizeof(exploit));
// Écrase la return address sur la stack
```

## 📝 Points clés à retenir

- Un tableau est une collection d'éléments du MÊME type stockés de manière CONTIGUË
- Les indices commencent à 0 (représentent un offset)
- Pas de vérification de limites : accès hors limites = comportement indéfini
- `sizeof(arr) / sizeof(arr[0])` donne le nombre d'éléments
- Le nom du tableau = pointeur constant vers le premier élément
- On ne peut pas copier un tableau avec `=`, utiliser une boucle ou memcpy()
- Tableaux 2D : stockés en mémoire de manière row-major (ligne par ligne)
- Les strings sont des tableaux de char terminés par `\0`
- Les tableaux sont cruciaux pour stocker shellcodes, payloads, ROP chains

## ➡️ Prochaine étape

Maintenant que tu maîtrises les tableaux, tu vas apprendre à manipuler les [strings (chaînes de caractères)](../09_strings/)

---

**Exercices** : Voir [exercice.txt](exercice.txt)
**Code exemple** : Voir [example.c](example.c)
