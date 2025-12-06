# Cours : Structures et Unions

## Objectif du Module

Maîtriser les structures (struct) pour regrouper des données logiquement, comprendre les unions (overlay mémoire), utiliser typedef pour simplifier le code, gérer le padding et l'alignement mémoire, créer des structures imbriquées, et utiliser bit fields pour économiser de la mémoire. Application Red Team : parsing de headers PE/ELF.

---

## 1. Structures (struct) - Regroupement Logique

### 1.1 Le Problème : Données Éparpillées

```c
// MAUVAIS : variables éparpillées
char nom1[50] = "Alice";
int age1 = 20;
float note1 = 15.5;

char nom2[50] = "Bob";
int age2 = 22;
float note2 = 14.0;

// Impossible de passer "un étudiant" à une fonction !
```

### 1.2 La Solution : struct

```c
// Créer un type "Etudiant"
struct Etudiant {
    char nom[50];
    int age;
    float note;
};

// Créer des variables de ce type
struct Etudiant alice = {"Alice", 20, 15.5};
struct Etudiant bob = {"Bob", 22, 14.0};

// Facile à passer aux fonctions
void afficher(struct Etudiant e) {
    printf("%s : %d ans, note %.1f\n", e.nom, e.age, e.note);
}
```

**Schéma mémoire :**
```
struct Etudiant alice :

┌─────────────────────────────────────────┐
│ Adresse : 0x1000                        │
│ ┌──────────────────┐                    │
│ │ nom[50]          │  50 bytes          │
│ │ "Alice\0..."     │  (0x1000-0x1031)   │
│ └──────────────────┘                    │
│ ┌──────────────────┐                    │
│ │ age              │  4 bytes (int)     │
│ │  20              │  (0x1034-0x1037)   │
│ └──────────────────┘                    │
│ ┌──────────────────┐                    │
│ │ note             │  4 bytes (float)   │
│ │  15.5            │  (0x1038-0x103B)   │
│ └──────────────────┘                    │
└─────────────────────────────────────────┘

Total : 58 bytes (+ padding possible)
```

### 1.3 Accès aux Membres

**Avec variable directe : opérateur `.`**
```c
struct Etudiant alice;
alice.age = 20;           // Écriture
printf("%d\n", alice.age);  // Lecture
```

**Avec pointeur : opérateur `->`**
```c
struct Etudiant *ptr = &alice;
ptr->age = 21;            // Équivaut à (*ptr).age = 21
printf("%d\n", ptr->age);
```

**Schéma des opérateurs :**
```
┌───────────────┐
│ alice         │  Variable directe
│  ├─ nom       │
│  ├─ age: 20   │  ← alice.age
│  └─ note      │
└───────────────┘

        ptr = 0x1000
           ↓
┌───────────────┐
│ alice         │  Via pointeur
│  ├─ nom       │
│  ├─ age: 20   │  ← ptr->age
│  └─ note      │
└───────────────┘

alice.age  → accès direct
ptr->age   → accès via pointeur
```

---

## 2. Padding et Alignement Mémoire

### 2.1 Le Problème du Padding

Le compilateur ajoute des bytes vides pour aligner les données.

```c
struct Example {
    char a;    // 1 byte
    int b;     // 4 bytes
    char c;    // 1 byte
};

printf("Taille : %zu\n", sizeof(struct Example));
// Affiche 12 (pas 6 !)
```

**Pourquoi 12 au lieu de 6 ?**

```
SANS PADDING (naïf) - 6 bytes :
┌───┬───┬───┬───┬───┬───┐
│ a │ b │ b │ b │ b │ c │
└───┴───┴───┴───┴───┴───┘
  1   4               1

AVEC PADDING (réel) - 12 bytes :
┌───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┐
│ a │PAD│PAD│PAD│ b │ b │ b │ b │ c │PAD│PAD│PAD│
└───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┘
  1   3 padding  4 bytes (int)  1   3 padding

Adresses :
0x00 : a
0x01-03 : PADDING (alignement pour b)
0x04-07 : b (int aligné sur 4 bytes)
0x08 : c
0x09-0B : PADDING (alignement struct entière)
```

### 2.2 Pourquoi le CPU Veut de l'Alignement ?

Le CPU lit la mémoire par blocs de 4 ou 8 bytes. Si les données sont alignées, c'est plus rapide.

```
CPU lit par blocs de 4 bytes :

Bloc 0      Bloc 1      Bloc 2      Bloc 3
┌────────┬────────┬────────┬────────┐
│  0-3   │  4-7   │  8-11  │ 12-15  │
└────────┴────────┴────────┴────────┘

Si int est à l'adresse 4 (aligné) :
→ 1 seule lecture (Bloc 1)

Si int est à l'adresse 2 (non-aligné) :
→ 2 lectures (Bloc 0 + Bloc 1) + reconstruction = LENT
```

### 2.3 Optimiser l'Ordre des Champs

```c
// MAUVAIS : Beaucoup de padding
struct Bad {
    char a;    // 1 + 3 padding
    int b;     // 4
    char c;    // 1 + 3 padding
    int d;     // 4
};  // Total : 16 bytes

// BON : Moins de padding
struct Good {
    int b;     // 4
    int d;     // 4
    char a;    // 1
    char c;    // 1 + 2 padding
};  // Total : 12 bytes
```

**Règle : Ordonner par taille décroissante (gros → petits)**

---

## 3. typedef - Simplifier les Déclarations

### 3.1 Sans typedef (verbeux)

```c
struct Etudiant {
    char nom[50];
    int age;
};

struct Etudiant alice;   // Doit écrire "struct" à chaque fois
struct Etudiant bob;
struct Etudiant *ptr;
```

### 3.2 Avec typedef (concis)

```c
typedef struct {
    char nom[50];
    int age;
} Etudiant;  // Alias créé

Etudiant alice;   // Plus de "struct" !
Etudiant bob;
Etudiant *ptr;
```

**Comparaison :**
```
SANS typedef :          AVEC typedef :
struct Etudiant alice;  Etudiant alice;
struct Etudiant bob;    Etudiant bob;
struct Etudiant *ptr;   Etudiant *ptr;

→ Plus court et lisible
```

---

## 4. Structures Imbriquées

```c
struct Adresse {
    char rue[100];
    int numero;
    char ville[50];
};

struct Personne {
    char nom[50];
    int age;
    struct Adresse domicile;  // Structure dans structure
};

int main() {
    struct Personne p;
    strcpy(p.nom, "Alice");
    p.age = 25;
    strcpy(p.domicile.rue, "Rue de la Paix");
    p.domicile.numero = 42;
    strcpy(p.domicile.ville, "Paris");

    printf("%s habite au %d %s, %s\n",
           p.nom, p.domicile.numero, p.domicile.rue, p.domicile.ville);
    return 0;
}
```

**Schéma mémoire :**
```
struct Personne p :

┌──────────────────────────────────────┐
│ nom[50] : "Alice"                    │
├──────────────────────────────────────┤
│ age : 25                             │
├──────────────────────────────────────┤
│ domicile (struct Adresse) :          │
│  ├─ rue[100] : "Rue de la Paix"     │
│  ├─ numero : 42                      │
│  └─ ville[50] : "Paris"              │
└──────────────────────────────────────┘

Accès :
p.nom                  → "Alice"
p.age                  → 25
p.domicile.rue         → "Rue de la Paix"
p.domicile.numero      → 42
p.domicile.ville       → "Paris"
```

---

## 5. Unions - Overlay Mémoire

### 5.1 Qu'est-ce qu'une union ?

Une union permet de stocker PLUSIEURS types DANS LA MÊME zone mémoire (un seul actif à la fois).

```c
union Data {
    int i;
    float f;
    char str[20];
};

printf("Taille union : %zu\n", sizeof(union Data));
// Affiche 20 (la taille du plus gros membre)
```

### 5.2 Overlay Mémoire

```
struct (membres séparés) :
┌────────┬────────┬────────┐
│ int i  │float f │char[20]│
└────────┴────────┴────────┘
  4 bytes  4 bytes  20 bytes = 28 bytes

union (membres superposés) :
┌────────────────────────┐
│ int i                  │
│ float f                │  ← Tous partagent
│ char str[20]           │     la MÊME mémoire
└────────────────────────┘
         20 bytes (le plus gros)
```

**Exemple :**
```c
union Data d;

d.i = 42;
printf("int : %d\n", d.i);  // 42

d.f = 3.14;
printf("float : %f\n", d.f);  // 3.14
printf("int : %d\n", d.i);    // GARBAGE ! (écrasé par f)

strcpy(d.str, "Hello");
printf("str : %s\n", d.str);  // "Hello"
printf("int : %d\n", d.i);    // GARBAGE !
```

### 5.3 Cas d'Usage : Type-Punning

```c
union FloatInt {
    float f;
    unsigned int i;
};

union FloatInt fi;
fi.f = 3.14;

printf("Float : %f\n", fi.f);           // 3.14
printf("Bits : 0x%08X\n", fi.i);        // 0x4048F5C3
// Voir la représentation binaire du float !
```

---

## 6. Bit Fields - Économie Mémoire

### 6.1 Déclarer des Champs de Bits

```c
struct Flags {
    unsigned int is_admin : 1;     // 1 bit
    unsigned int is_logged : 1;    // 1 bit
    unsigned int permissions : 3;  // 3 bits
    unsigned int reserved : 27;    // 27 bits
};  // Total : 32 bits = 4 bytes
```

**Schéma :**
```
4 bytes (32 bits) :
┌─┬─┬───┬───────────────────────────┐
│A│L│PER│      RESERVED (27)        │
└─┴─┴───┴───────────────────────────┘
 1  1  3           27 bits

A = is_admin (1 bit)
L = is_logged (1 bit)
PER = permissions (3 bits → valeurs 0-7)
```

**Utilisation :**
```c
struct Flags f = {0};
f.is_admin = 1;
f.is_logged = 1;
f.permissions = 5;  // rwx-r-x (101 en binaire)

printf("Admin : %d\n", f.is_admin);       // 1
printf("Permissions : %d\n", f.permissions);  // 5
```

---

## 7. Application Red Team

### 7.1 Parsing de Headers PE (Windows)

```c
typedef struct {
    unsigned short e_magic;    // "MZ" signature
    // ... autres champs ...
    unsigned int e_lfanew;     // Offset vers PE header
} IMAGE_DOS_HEADER;

typedef struct {
    unsigned int Signature;    // "PE\0\0"
    // ... FILE_HEADER ...
    // ... OPTIONAL_HEADER ...
} IMAGE_NT_HEADERS;

// Lire un fichier PE
FILE *f = fopen("program.exe", "rb");
IMAGE_DOS_HEADER dos_header;
fread(&dos_header, sizeof(IMAGE_DOS_HEADER), 1, f);

if (dos_header.e_magic == 0x5A4D) {  // "MZ"
    printf("PE valide\n");
    fseek(f, dos_header.e_lfanew, SEEK_SET);
    IMAGE_NT_HEADERS nt_headers;
    fread(&nt_headers, sizeof(IMAGE_NT_HEADERS), 1, f);
    // ... analyser les sections ...
}
fclose(f);
```

### 7.2 Parsing de Headers ELF (Linux)

```c
#include <elf.h>

typedef struct {
    unsigned char e_ident[16];  // Magic number
    uint16_t e_type;            // Type (ET_EXEC, ET_DYN, etc.)
    uint16_t e_machine;         // Architecture
    uint32_t e_version;
    uint64_t e_entry;           // Entry point
    // ... autres champs ...
} Elf64_Ehdr;

FILE *f = fopen("./program", "rb");
Elf64_Ehdr elf_header;
fread(&elf_header, sizeof(Elf64_Ehdr), 1, f);

if (elf_header.e_ident[0] == 0x7F &&
    elf_header.e_ident[1] == 'E' &&
    elf_header.e_ident[2] == 'L' &&
    elf_header.e_ident[3] == 'F') {
    printf("ELF valide\n");
    printf("Entry point : 0x%lx\n", elf_header.e_entry);
}
fclose(f);
```

### 7.3 Union pour Network Packets

```c
typedef struct {
    unsigned char version : 4;   // IPv4 = 4
    unsigned char ihl : 4;       // Header length
    unsigned char tos;           // Type of service
    unsigned short total_len;
    // ...
} IPv4Header;

union Packet {
    unsigned char raw[1500];     // Raw bytes
    IPv4Header ipv4;             // Interprété comme IPv4
};

// Recevoir packet
union Packet pkt;
recv(sock, pkt.raw, sizeof(pkt.raw), 0);

// Parser
if (pkt.ipv4.version == 4) {
    printf("IPv4 packet\n");
    printf("Length : %d\n", pkt.ipv4.total_len);
}
```

---

## 8. Checklist de Compréhension

- [ ] Différence entre `.` et `->` ?
- [ ] Pourquoi le padding existe ?
- [ ] Comment optimiser l'ordre des champs ?
- [ ] Utilité de typedef ?
- [ ] Différence struct vs union ?
- [ ] À quoi servent les bit fields ?
- [ ] Comment parser un header binaire ?

---

## 9. Exercices Pratiques

Voir `exercice.txt` pour :
- Créer une structure Personne complète
- Optimiser le padding
- Parser un header PE/ELF
- Implémenter une linked list

**Astuce Debug :**
```c
// Voir le padding
#include <stddef.h>
printf("Offset nom : %zu\n", offsetof(struct Etudiant, nom));
printf("Offset age : %zu\n", offsetof(struct Etudiant, age));
```

---

**Prochaine étape :** Module 15 - Fichiers I/O (fopen/fread/fwrite, modes d'ouverture, parsing fichiers binaires).
