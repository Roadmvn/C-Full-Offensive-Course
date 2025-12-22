# Module 03 : Opérateurs - Manipulation des données

## Objectifs

À la fin de ce module, tu seras capable de :
- Utiliser tous les opérateurs arithmétiques et logiques en C
- Maîtriser les opérateurs bitwise (XOR, AND, OR, shifts)
- Implémenter un chiffrement XOR simple
- Manipuler des flags et des masques binaires
- Comprendre les opérateurs utilisés dans le code offensif

---

## Partie 0 : Pourquoi les opérateurs sont CRUCIAUX en offensive

### XOR Encryption - La base de l'obfuscation

```c
// Chiffrer une string pour éviter la détection
unsigned char key = 0x41;
char msg[] = "secret";

for (int i = 0; msg[i]; i++) {
    msg[i] ^= key;  // XOR avec la clé
}
// msg est maintenant chiffré, invisible avec 'strings'
```

### Flag Manipulation - API Windows

```c
// Allocation de mémoire exécutable pour shellcode
LPVOID addr = VirtualAlloc(
    NULL,
    4096,
    MEM_COMMIT | MEM_RESERVE,  // Combinaison de flags avec OR
    PAGE_EXECUTE_READWRITE
);
```

### Bit Masking - Extraction de données

```c
// Extraire les bytes d'une adresse
uint32_t addr = 0x12345678;
uint8_t byte0 = addr & 0xFF;         // = 0x78
uint8_t byte1 = (addr >> 8) & 0xFF;  // = 0x56
```

**Sans maîtriser les opérateurs, tu ne pourras pas :**
- Écrire du code d'obfuscation
- Manipuler les flags des API système
- Parser des structures binaires
- Comprendre le code assembleur

---

## Partie 1 : Opérateurs arithmétiques

### Les opérateurs de base

| Opérateur | Nom | Exemple | Résultat |
|-----------|-----|---------|----------|
| `+` | Addition | `5 + 3` | `8` |
| `-` | Soustraction | `5 - 3` | `2` |
| `*` | Multiplication | `5 * 3` | `15` |
| `/` | Division | `7 / 3` | `2` (division entière) |
| `%` | Modulo | `7 % 3` | `1` (reste) |

### Attention à la division entière !

```c
int a = 7, b = 3;
int result = a / b;      // = 2, pas 2.33 !
// La partie décimale est tronquée

// Pour avoir un résultat décimal :
float result_f = (float)a / b;  // = 2.333...
```

### L'opérateur modulo (%) - Applications offensives

Le modulo retourne le **reste** de la division.

```c
7 % 3 = 1   // car 7 = 3*2 + 1
8 % 4 = 0   // car 8 = 4*2 + 0 (division exacte)
```

**APPLICATION OFFENSIVE : Rotation de clés**

```c
// Chiffrement avec plusieurs clés en rotation
unsigned char keys[] = {0x41, 0x42, 0x43, 0x44};
int key_len = 4;

for (int i = 0; i < data_len; i++) {
    data[i] ^= keys[i % key_len];  // Cycle à travers les clés
}
// i % 4 donne : 0, 1, 2, 3, 0, 1, 2, 3, 0, ...
```

### Incrémentation et décrémentation

```c
int x = 5;

// Pré-incrémentation : incrémente PUIS retourne
int a = ++x;  // x devient 6, a = 6

// Post-incrémentation : retourne PUIS incrémente
int b = x++;  // b = 6, PUIS x devient 7

// Même logique pour -- (décrémentation)
```

**Où tu verras ça ?**
```c
// Parcours de buffer (très courant)
while (*ptr++) { }  // Avance ptr après chaque itération

// Compteurs
for (int i = 0; i < len; i++) { }
```

---

## Partie 2 : Opérateurs de comparaison

| Opérateur | Signification | Exemple | Résultat |
|-----------|---------------|---------|----------|
| `==` | Égal à | `5 == 5` | `1` (vrai) |
| `!=` | Différent de | `5 != 3` | `1` (vrai) |
| `<` | Inférieur | `3 < 5` | `1` (vrai) |
| `>` | Supérieur | `3 > 5` | `0` (faux) |
| `<=` | Inférieur ou égal | `5 <= 5` | `1` (vrai) |
| `>=` | Supérieur ou égal | `3 >= 5` | `0` (faux) |

### ATTENTION : `=` vs `==`

```c
// ERREUR CLASSIQUE
if (x = 5) { }   // ASSIGNE 5 à x, puis teste si x != 0 (toujours vrai !)

// CORRECT
if (x == 5) { }  // COMPARE x avec 5
```

**Astuce défensive : Mettre la constante à gauche**
```c
if (5 == x) { }  // Si tu tapes = au lieu de ==, erreur de compilation !
```

### Résultat des comparaisons

En C, une comparaison retourne :
- `1` si vrai
- `0` si faux

```c
int result = (5 > 3);  // result = 1
int result2 = (2 > 9); // result2 = 0
```

---

## Partie 3 : Opérateurs logiques

| Opérateur | Nom | Signification |
|-----------|-----|---------------|
| `&&` | AND logique | Vrai si LES DEUX sont vrais |
| `\|\|` | OR logique | Vrai si AU MOINS UN est vrai |
| `!` | NOT logique | Inverse la valeur |

### Table de vérité

```
AND (&&)           OR (||)            NOT (!)
A   B   A&&B       A   B   A||B       A    !A
0   0    0         0   0    0         0     1
0   1    0         0   1    1         1     0
1   0    0         1   0    1
1   1    1         1   1    1
```

### Exemples pratiques

```c
int age = 25;
int has_id = 1;

// AND : les deux conditions doivent être vraies
if (age >= 18 && has_id) {
    printf("Accès autorisé\n");
}

// OR : au moins une condition doit être vraie
if (age < 18 || !has_id) {
    printf("Accès refusé\n");
}

// NOT : inverse
if (!authenticated) {
    printf("Veuillez vous connecter\n");
}
```

### Short-circuit evaluation

Le C évalue de gauche à droite et s'arrête dès que le résultat est connu.

```c
// AND : si le premier est faux, pas besoin de tester le second
if (ptr != NULL && ptr->value > 0) { }
// Si ptr est NULL, ptr->value n'est JAMAIS évalué (évite le crash)

// OR : si le premier est vrai, pas besoin de tester le second
if (is_admin || check_permission()) { }
// Si is_admin est vrai, check_permission() n'est jamais appelée
```

**APPLICATION OFFENSIVE : Anti-debug**
```c
// Si une des vérifications échoue, on s'arrête
if (IsDebuggerPresent() || check_timing() || check_breakpoints()) {
    exit(1);  // Debugger détecté
}
```

---

## Partie 4 : Opérateurs bitwise - LE CŒUR DE L'OFFENSIVE

Les opérateurs bitwise travaillent sur les bits individuels.

### Rappel : représentation binaire

```
Décimal   Binaire
   0      00000000
   1      00000001
   5      00000101
  15      00001111
 255      11111111
```

### AND bitwise (`&`)

Chaque bit du résultat est 1 seulement si LES DEUX bits correspondants sont 1.

```
    0b11001010  (202)
  & 0b10101100  (172)
  ─────────────
    0b10001000  (136)
```

```c
unsigned char a = 0b11001010;  // 202
unsigned char b = 0b10101100;  // 172
unsigned char result = a & b;  // 136
```

**APPLICATION OFFENSIVE : Masquage / Extraction de bits**

```c
// Extraire le byte de poids faible d'un int
uint32_t value = 0x12345678;
uint8_t low_byte = value & 0xFF;  // = 0x78

// Vérifier si un bit spécifique est activé
if (flags & FLAG_ADMIN) {
    // Le flag admin est présent
}

// Extraire les 4 bits de poids faible
uint8_t nibble = value & 0x0F;
```

### OR bitwise (`|`)

Chaque bit du résultat est 1 si AU MOINS UN des bits correspondants est 1.

```
    0b11001010  (202)
  | 0b10101100  (172)
  ─────────────
    0b11101110  (238)
```

**APPLICATION OFFENSIVE : Combinaison de flags**

```c
// Windows API : combiner des flags avec OR
DWORD access = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION;

// Permissions fichier Unix
mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP;  // rw-r-----

// Activer un bit spécifique
flags = flags | FLAG_ACTIVE;
// Ou plus court :
flags |= FLAG_ACTIVE;
```

### XOR bitwise (`^`) - LE PLUS IMPORTANT

Chaque bit du résultat est 1 si les bits correspondants sont DIFFÉRENTS.

```
    0b11001010  (202)
  ^ 0b10101100  (172)
  ─────────────
    0b01100110  (102)
```

**Propriété magique du XOR : il s'annule lui-même !**

```
A ^ B ^ B = A

Exemple :
  0x41 ^ 0xFF = 0xBE  (chiffrement)
  0xBE ^ 0xFF = 0x41  (déchiffrement)
```

**APPLICATION OFFENSIVE : XOR Encryption**

```c
// Chiffrer une string
void xor_encrypt(unsigned char *data, int len, unsigned char key) {
    for (int i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

// Déchiffrer = même opération !
void xor_decrypt(unsigned char *data, int len, unsigned char key) {
    for (int i = 0; i < len; i++) {
        data[i] ^= key;  // Identique !
    }
}

// Utilisation
char secret[] = "password";
xor_encrypt(secret, strlen(secret), 0x42);  // Chiffré
// secret est maintenant illisible avec 'strings'

xor_decrypt(secret, strlen(secret), 0x42);  // Déchiffré
// secret = "password" à nouveau
```

**APPLICATION OFFENSIVE : Échange sans variable temporaire**

```c
// Classique (avec temp)
int temp = a;
a = b;
b = temp;

// Avec XOR (sans temp)
a ^= b;  // a = a ^ b
b ^= a;  // b = b ^ (a ^ b) = a
a ^= b;  // a = (a ^ b) ^ a = b
```

### NOT bitwise (`~`)

Inverse tous les bits.

```
  ~ 0b11001010  (202)
  ─────────────
    0b00110101  (53 en unsigned, -203 en signed)
```

**APPLICATION OFFENSIVE : Créer des masques**

```c
// Effacer des bits spécifiques
flags = flags & ~FLAG_TO_REMOVE;
// ~FLAG_TO_REMOVE inverse les bits du flag, puis AND efface ces positions
```

### Shift Left (`<<`)

Décale tous les bits vers la gauche, remplit avec des 0 à droite.
**Équivalent à multiplier par 2^n.**

```
    0b00000101  (5)
 << 2
  ─────────────
    0b00010100  (20)   // 5 * 4 = 20
```

```c
int x = 5;
int result = x << 2;  // = 20 (5 * 2^2)
```

**APPLICATION OFFENSIVE : Construire des valeurs**

```c
// Construire une adresse 32-bit à partir de 4 bytes
uint8_t b0 = 0x78, b1 = 0x56, b2 = 0x34, b3 = 0x12;
uint32_t addr = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
// addr = 0x12345678

// Créer des flags/masks
#define FLAG_BIT_0  (1 << 0)   // 0x01
#define FLAG_BIT_1  (1 << 1)   // 0x02
#define FLAG_BIT_7  (1 << 7)   // 0x80
```

### Shift Right (`>>`)

Décale tous les bits vers la droite.
**Équivalent à diviser par 2^n.**

```
    0b00010100  (20)
 >> 2
  ─────────────
    0b00000101  (5)    // 20 / 4 = 5
```

**APPLICATION OFFENSIVE : Extraction de bytes**

```c
// Extraire les bytes d'une valeur 32-bit
uint32_t value = 0x12345678;

uint8_t byte0 = value & 0xFF;           // 0x78
uint8_t byte1 = (value >> 8) & 0xFF;    // 0x56
uint8_t byte2 = (value >> 16) & 0xFF;   // 0x34
uint8_t byte3 = (value >> 24) & 0xFF;   // 0x12
```

---

## Partie 5 : Opérateurs d'affectation composés

Ces opérateurs combinent une opération avec une affectation.

| Opérateur | Équivalent |
|-----------|------------|
| `x += y` | `x = x + y` |
| `x -= y` | `x = x - y` |
| `x *= y` | `x = x * y` |
| `x /= y` | `x = x / y` |
| `x %= y` | `x = x % y` |
| `x &= y` | `x = x & y` |
| `x \|= y` | `x = x \| y` |
| `x ^= y` | `x = x ^ y` |
| `x <<= y` | `x = x << y` |
| `x >>= y` | `x = x >> y` |

**Utilisation courante**

```c
// XOR encryption compact
for (int i = 0; i < len; i++) {
    data[i] ^= key;
}

// Ajouter un flag
flags |= NEW_FLAG;

// Retirer un flag
flags &= ~OLD_FLAG;

// Toggle un flag (inverser)
flags ^= TOGGLE_FLAG;
```

---

## Partie 6 : L'opérateur ternaire

Syntaxe : `condition ? valeur_si_vrai : valeur_si_faux`

```c
// Équivalent à if-else en une ligne
int max = (a > b) ? a : b;

// Classique if-else
int max;
if (a > b) {
    max = a;
} else {
    max = b;
}
```

**APPLICATION OFFENSIVE : Code compact**

```c
// Détection rapide
int is_debugged = IsDebuggerPresent() ? 1 : 0;

// Sélection conditionnelle
char* status = (connected) ? "online" : "offline";
```

---

## Partie 7 : Priorité des opérateurs

Du plus prioritaire au moins prioritaire :

```
1. () [] -> .           (Parenthèses, accès)
2. ! ~ ++ -- + - * &    (Unaires)
3. * / %                (Multiplication, division)
4. + -                  (Addition, soustraction)
5. << >>                (Shifts)
6. < <= > >=            (Comparaisons)
7. == !=                (Égalité)
8. &                    (AND bitwise)
9. ^                    (XOR bitwise)
10. |                   (OR bitwise)
11. &&                  (AND logique)
12. ||                  (OR logique)
13. ?:                  (Ternaire)
14. = += -= etc.        (Affectation)
```

**RÈGLE D'OR : En cas de doute, utilise des parenthèses !**

```c
// Ambigu
int result = a & b == c;  // & ou == en premier ?

// Clair
int result = a & (b == c);  // Intention explicite
int result = (a & b) == c;  // Autre intention
```

---

## Partie 8 : Applications offensives complètes

### XOR Encryption avec clé multi-bytes

```c
void xor_crypt(unsigned char *data, size_t len,
               unsigned char *key, size_t key_len) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key[i % key_len];  // Clé cyclique
    }
}

// Utilisation
unsigned char shellcode[] = { 0x90, 0x90, 0x31, 0xc0 };
unsigned char key[] = { 0x41, 0x42, 0x43, 0x44 };

xor_crypt(shellcode, sizeof(shellcode), key, sizeof(key));
// Shellcode maintenant chiffré

xor_crypt(shellcode, sizeof(shellcode), key, sizeof(key));
// Shellcode déchiffré (même opération)
```

### Manipulation de flags Windows

```c
// Ouvrir un process avec les droits nécessaires pour injection
DWORD access = PROCESS_CREATE_THREAD |    // Créer thread
               PROCESS_VM_OPERATION |      // Modifier mémoire
               PROCESS_VM_WRITE |          // Écrire mémoire
               PROCESS_VM_READ;            // Lire mémoire

HANDLE hProcess = OpenProcess(access, FALSE, pid);

// Allouer mémoire exécutable
DWORD alloc_type = MEM_COMMIT | MEM_RESERVE;
DWORD protect = PAGE_EXECUTE_READWRITE;

LPVOID addr = VirtualAllocEx(
    hProcess,
    NULL,
    shellcode_size,
    alloc_type,
    protect
);
```

### Extraction d'adresse pour shellcode

```c
// Convertir une adresse 64-bit en bytes (little endian)
uint64_t target_addr = 0x7FFF12345678;
unsigned char addr_bytes[8];

for (int i = 0; i < 8; i++) {
    addr_bytes[i] = (target_addr >> (i * 8)) & 0xFF;
}

// addr_bytes = { 0x78, 0x56, 0x34, 0x12, 0xFF, 0x7F, 0x00, 0x00 }
```

### Vérifier/Modifier des bits spécifiques

```c
#define FLAG_ADMIN     (1 << 0)  // 0x01
#define FLAG_LOGGED    (1 << 1)  // 0x02
#define FLAG_VERIFIED  (1 << 2)  // 0x04

unsigned char user_flags = 0;

// Ajouter des flags
user_flags |= FLAG_LOGGED;
user_flags |= FLAG_VERIFIED;

// Vérifier un flag
if (user_flags & FLAG_ADMIN) {
    printf("User is admin\n");
}

// Retirer un flag
user_flags &= ~FLAG_LOGGED;

// Toggle un flag
user_flags ^= FLAG_ADMIN;  // Active si inactif, désactive si actif
```

---

## Partie 9 : Résumé et checklist

### Tableau récapitulatif des opérateurs bitwise

| Opérateur | Utilisation offensive |
|-----------|----------------------|
| `&` (AND) | Masquage, extraction de bits, vérification de flags |
| `\|` (OR) | Combinaison de flags, activation de bits |
| `^` (XOR) | Chiffrement, obfuscation, échange de valeurs |
| `~` (NOT) | Création de masques pour effacement |
| `<<` (Left shift) | Construction de valeurs, création de flags |
| `>>` (Right shift) | Extraction de bytes, division rapide |

### Checklist offensive

- [ ] Je sais implémenter un chiffrement XOR simple
- [ ] Je comprends comment combiner des flags avec OR
- [ ] Je sais extraire des bytes avec shift et masque
- [ ] Je connais la propriété d'annulation du XOR (A ^ B ^ B = A)
- [ ] Je sais manipuler des bits individuels (set, clear, toggle)
- [ ] Je comprends la différence entre opérateurs logiques (&&) et bitwise (&)

---

## Exercices pratiques

Voir [exercice.md](exercice.md)

## Code exemple

Voir [example.c](example.c)

---

**Module suivant** : [04 - Control Flow](../04_control_flow/)
