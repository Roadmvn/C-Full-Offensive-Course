# Cours 03 : La Mémoire

## Introduction

La mémoire est le terrain de jeu de la sécurité offensive. Les buffer overflows, les heap sprays, les injections de code - tout cela repose sur une compréhension profonde de comment la mémoire est organisée et utilisée.

---

## La Mémoire RAM

La RAM (Random Access Memory) est la mémoire de travail de l'ordinateur. Contrairement au disque dur, elle est :

- **Volatile** : S'efface quand l'ordinateur s'éteint
- **Rapide** : Accès en nanosecondes (vs millisecondes pour un disque)
- **Adressable** : Chaque byte a une adresse unique

```
┌─────────────────────────────────────────────────────────────────┐
│                    HIÉRARCHIE MÉMOIRE                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│     Vitesse        Type              Taille     Coût            │
│     ────────────────────────────────────────────────            │
│     ▲              Registres CPU      ~64-128B   $$$$$          │
│     │              Cache L1           ~32-64KB   $$$$           │
│     │              Cache L2           ~256KB     $$$            │
│     │              Cache L3           ~8-32MB    $$             │
│     │              RAM                ~8-64GB    $              │
│     ▼              Disque (SSD/HDD)   ~256GB-TB  ¢              │
│                                                                 │
│     Le CPU essaie d'abord les niveaux rapides (cache)          │
│     avant d'accéder à la RAM                                   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Adressage Mémoire

### Adresses Virtuelles vs Physiques

```
┌─────────────────────────────────────────────────────────────────┐
│                MÉMOIRE VIRTUELLE                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Processus A              Processus B                           │
│  ┌──────────────┐         ┌──────────────┐                      │
│  │ 0x00400000   │         │ 0x00400000   │  ← Même adresse     │
│  │ code         │         │ code         │    virtuelle        │
│  └──────┬───────┘         └──────┬───────┘                      │
│         │                        │                              │
│         │    Traduction MMU      │                              │
│         ▼                        ▼                              │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    RAM PHYSIQUE                          │   │
│  ├──────────────────────────────────────────────────────────┤   │
│  │ 0x10000000  │ 0x20000000  │ 0x30000000  │ ...           │   │
│  │ (Proc A)    │ (Proc B)    │ (Système)   │               │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                 │
│  → Chaque processus a son propre espace d'adressage            │
│  → Isolation entre processus                                    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### L'Espace d'Adressage d'un Processus

Chaque processus a un espace d'adressage virtuel complet :

**32 bits** : 0x00000000 à 0xFFFFFFFF (4 GB)
**64 bits** : 0x0000000000000000 à 0xFFFFFFFFFFFFFFFF (théoriquement 16 EB)

---

## Organisation de la Mémoire d'un Processus

Voici comment la mémoire d'un programme est organisée :

```
┌─────────────────────────────────────────────────────────────────┐
│              LAYOUT MÉMOIRE D'UN PROCESSUS                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   Adresses hautes (0xFFFFFFFF en 32 bits)                       │
│   ┌─────────────────────────────────────────┐                   │
│   │              KERNEL SPACE               │  Réservé OS       │
│   │         (Non accessible user)           │                   │
│   ├─────────────────────────────────────────┤ ← 0xC0000000      │
│   │                STACK                    │                   │
│   │     (Pile - Variables locales)          │  ↓ Croît vers     │
│   │     ┌───────────────────────────┐       │    le bas         │
│   │     │ Arguments de fonction     │       │                   │
│   │     │ Adresses de retour        │       │                   │
│   │     │ Variables locales         │       │                   │
│   │     └───────────────────────────┘       │                   │
│   │               │                         │                   │
│   │               ▼                         │                   │
│   │            (espace libre)               │                   │
│   │               ▲                         │                   │
│   │               │                         │                   │
│   │     ┌───────────────────────────┐       │                   │
│   │     │ Blocs alloués dynamiquement│      │                   │
│   ├─────┴───────────────────────────┴───────┤                   │
│   │                HEAP                     │  ↑ Croît vers     │
│   │       (Tas - Allocation dynamique)      │    le haut        │
│   ├─────────────────────────────────────────┤                   │
│   │                BSS                      │                   │
│   │   (Variables globales non initialisées) │                   │
│   ├─────────────────────────────────────────┤                   │
│   │               DATA                      │                   │
│   │    (Variables globales initialisées)    │                   │
│   ├─────────────────────────────────────────┤                   │
│   │               TEXT                      │                   │
│   │          (Code exécutable)              │                   │
│   └─────────────────────────────────────────┘ ← 0x08048000      │
│   Adresses basses (0x00000000)                 (Linux x86)      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Détail de chaque segment

#### 1. TEXT (Code)

```
┌─────────────────────────────────────────────────────────────────┐
│                     SEGMENT TEXT                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Contient :  Instructions machine du programme                  │
│  Permissions : Lecture + Exécution (R-X)                       │
│  Modifiable : Non (en principe)                                │
│                                                                 │
│  C'est ici que se trouve votre code compilé :                  │
│                                                                 │
│  0x08048000: 55                   push ebp                      │
│  0x08048001: 89 e5                mov ebp, esp                  │
│  0x08048003: 83 ec 10             sub esp, 0x10                 │
│  ...                                                            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### 2. DATA (Données initialisées)

```
┌─────────────────────────────────────────────────────────────────┐
│                     SEGMENT DATA                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Contient :  Variables globales/statiques INITIALISÉES         │
│  Permissions : Lecture + Écriture (RW-)                        │
│                                                                 │
│  Exemple en C :                                                 │
│                                                                 │
│  int global_var = 42;        // → dans DATA                    │
│  char message[] = "Hello";   // → dans DATA                    │
│                                                                 │
│  Les valeurs initiales sont stockées dans l'exécutable         │
│  et copiées en mémoire au chargement.                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### 3. BSS (Données non initialisées)

```
┌─────────────────────────────────────────────────────────────────┐
│                     SEGMENT BSS                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Contient :  Variables globales/statiques NON INITIALISÉES     │
│  Permissions : Lecture + Écriture (RW-)                        │
│  Valeur initiale : Zéro (garanti par le système)               │
│                                                                 │
│  Exemple en C :                                                 │
│                                                                 │
│  int counter;                // → dans BSS (initialisé à 0)    │
│  char buffer[1024];          // → dans BSS                     │
│                                                                 │
│  Le BSS ne prend pas d'espace dans le fichier exécutable.      │
│  Seule la taille est stockée.                                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### 4. HEAP (Tas)

```
┌─────────────────────────────────────────────────────────────────┐
│                        HEAP                                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Contient :  Mémoire allouée dynamiquement                     │
│  Gestion :   malloc(), calloc(), realloc(), free()             │
│  Direction : Croît vers les adresses HAUTES                    │
│                                                                 │
│  Exemple en C :                                                 │
│                                                                 │
│  int *ptr = malloc(sizeof(int) * 100);  // → dans HEAP         │
│  char *str = strdup("Hello");           // → dans HEAP         │
│                                                                 │
│  ┌────────────────────────────────────────────────────┐         │
│  │ Header │   Données utilisateur    │ Padding       │         │
│  │ (métadonnées allocation)          │               │         │
│  └────────────────────────────────────────────────────┘         │
│                                                                 │
│  ATTENTION : Le heap est une cible pour les exploits           │
│  (heap overflow, use-after-free, double-free)                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### 5. STACK (Pile)

```
┌─────────────────────────────────────────────────────────────────┐
│                        STACK                                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Contient :  Variables locales, arguments, adresses retour     │
│  Gestion :   Automatique (PUSH/POP)                            │
│  Direction : Croît vers les adresses BASSES (↓)                │
│                                                                 │
│  Registre ESP/RSP : Pointe vers le sommet de la pile           │
│  Registre EBP/RBP : Base de la stack frame courante            │
│                                                                 │
│  STACK FRAME (pour une fonction) :                             │
│                                                                 │
│   Adresses hautes                                               │
│   ┌─────────────────────────────┐                               │
│   │  Arguments (arg3, arg2...)  │  Empilés par l'appelant      │
│   ├─────────────────────────────┤                               │
│   │  Adresse de retour          │  Empilée par CALL            │
│   ├─────────────────────────────┤ ← EBP pointe ici             │
│   │  EBP sauvegardé             │  Ancien base pointer         │
│   ├─────────────────────────────┤                               │
│   │  Variable locale 1          │                               │
│   │  Variable locale 2          │                               │
│   │  ...                        │                               │
│   └─────────────────────────────┘ ← ESP pointe ici             │
│   Adresses basses                                               │
│                                                                 │
│  C'est LA cible classique des buffer overflows !               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## La Stack en Détail

La pile est fondamentale pour l'exploitation. Voyons son fonctionnement en détail.

### Opérations PUSH et POP

```
┌─────────────────────────────────────────────────────────────────┐
│                    PUSH et POP                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  PUSH EAX (empiler la valeur de EAX)                           │
│  ─────────────────────────────────────                          │
│  1. ESP = ESP - 4         (décrémenter le pointeur)            │
│  2. [ESP] = EAX           (écrire la valeur)                   │
│                                                                 │
│  Avant PUSH :              Après PUSH :                         │
│  ┌───────────┐             ┌───────────┐                        │
│  │    ...    │             │    ...    │                        │
│  ├───────────┤             ├───────────┤                        │
│  │           │ ← ESP       │           │                        │
│  └───────────┘             ├───────────┤                        │
│                            │  valeur   │ ← ESP (nouvelle pos)  │
│                            └───────────┘                        │
│                                                                 │
│  POP EBX (dépiler vers EBX)                                    │
│  ──────────────────────────                                     │
│  1. EBX = [ESP]           (lire la valeur)                     │
│  2. ESP = ESP + 4         (incrémenter le pointeur)            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Exemple d'Appel de Fonction

```c
int add(int a, int b) {
    int result = a + b;
    return result;
}

int main() {
    int x = add(5, 3);
    return 0;
}
```

État de la pile lors de l'appel :

```
┌─────────────────────────────────────────────────────────────────┐
│           ÉVOLUTION DE LA STACK PENDANT L'APPEL                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. Avant l'appel (dans main)                                  │
│     ┌─────────────────────┐                                     │
│     │ Variables de main   │                                     │
│     └─────────────────────┘ ← ESP                               │
│                                                                 │
│  2. Push des arguments (droite à gauche en cdecl)              │
│     ┌─────────────────────┐                                     │
│     │ Variables de main   │                                     │
│     ├─────────────────────┤                                     │
│     │      3 (b)          │                                     │
│     ├─────────────────────┤                                     │
│     │      5 (a)          │                                     │
│     └─────────────────────┘ ← ESP                               │
│                                                                 │
│  3. CALL add (push adresse retour, jump)                       │
│     ┌─────────────────────┐                                     │
│     │ Variables de main   │                                     │
│     ├─────────────────────┤                                     │
│     │      3 (b)          │                                     │
│     ├─────────────────────┤                                     │
│     │      5 (a)          │                                     │
│     ├─────────────────────┤                                     │
│     │ Adresse retour      │  ← Où retourner après add()        │
│     └─────────────────────┘ ← ESP                               │
│                                                                 │
│  4. Prologue de add() : push ebp; mov ebp, esp; sub esp, N     │
│     ┌─────────────────────┐                                     │
│     │ Variables de main   │                                     │
│     ├─────────────────────┤                                     │
│     │      3 (b)          │  [EBP+12]                           │
│     ├─────────────────────┤                                     │
│     │      5 (a)          │  [EBP+8]                            │
│     ├─────────────────────┤                                     │
│     │ Adresse retour      │  [EBP+4]                            │
│     ├─────────────────────┤                                     │
│     │ EBP sauvegardé      │ ← EBP pointe ici                   │
│     ├─────────────────────┤                                     │
│     │ result (var locale) │  [EBP-4]                            │
│     └─────────────────────┘ ← ESP                               │
│                                                                 │
│  5. Épilogue : mov esp, ebp; pop ebp; ret                      │
│     → Restaure l'état d'avant l'appel                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Le Heap en Détail

Le heap est géré par des allocateurs mémoire (comme glibc's ptmalloc).

### Structure d'un chunk malloc (glibc)

```
┌─────────────────────────────────────────────────────────────────┐
│                  CHUNK MALLOC (glibc)                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   Chunk alloué :                                                │
│   ┌─────────────────────────────────────────────────────┐       │
│   │ prev_size (si chunk précédent est libre)            │       │
│   ├─────────────────────────────────────────────────────┤       │
│   │ size | A | M | P                                    │       │
│   │      │   │   │                                      │       │
│   │      │   │   └── PREV_INUSE (chunk précédent utilisé)│      │
│   │      │   └────── IS_MMAPPED (alloué via mmap)       │       │
│   │      └────────── NON_MAIN_ARENA                     │       │
│   ├─────────────────────────────────────────────────────┤       │
│   │                                                     │       │
│   │             DONNÉES UTILISATEUR                     │       │
│   │        (ce que malloc() retourne)                   │       │
│   │                                                     │       │
│   └─────────────────────────────────────────────────────┘       │
│                                                                 │
│   Chunk libre :                                                 │
│   ┌─────────────────────────────────────────────────────┐       │
│   │ prev_size                                           │       │
│   ├─────────────────────────────────────────────────────┤       │
│   │ size | flags                                        │       │
│   ├─────────────────────────────────────────────────────┤       │
│   │ fd (forward pointer vers chunk libre suivant)       │       │
│   ├─────────────────────────────────────────────────────┤       │
│   │ bk (backward pointer vers chunk libre précédent)    │       │
│   ├─────────────────────────────────────────────────────┤       │
│   │ (espace non utilisé)                                │       │
│   └─────────────────────────────────────────────────────┘       │
│                                                                 │
│   Les chunks libres sont dans des "bins" (listes chaînées)     │
│   → Manipulation des pointeurs fd/bk = exploitation possible   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Endianness (Boutisme)

L'ordre dans lequel les bytes sont stockés en mémoire :

```
┌─────────────────────────────────────────────────────────────────┐
│                      ENDIANNESS                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Valeur à stocker : 0x12345678                                 │
│                                                                 │
│  LITTLE-ENDIAN (x86, x64)          BIG-ENDIAN (réseau, SPARC)  │
│  Le byte de poids faible           Le byte de poids fort       │
│  est stocké à l'adresse basse      est stocké à l'adresse basse│
│                                                                 │
│  Adresse  Valeur                   Adresse  Valeur              │
│  0x1000   0x78  ← LSB              0x1000   0x12  ← MSB        │
│  0x1001   0x56                     0x1001   0x34               │
│  0x1002   0x34                     0x1002   0x56               │
│  0x1003   0x12  ← MSB              0x1003   0x78  ← LSB        │
│                                                                 │
│  Moyen mnémotechnique :                                         │
│  Little-endian : "petit bout en premier" (le petit bout =      │
│                   le byte de poids faible)                      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Important pour les exploits** : Quand vous écrivez une adresse 0x08041234 dans un buffer sur x86, vous devez l'écrire à l'envers : `\x34\x12\x04\x08`

---

## Alignement Mémoire

Les données doivent souvent être alignées sur des frontières spécifiques :

```
┌─────────────────────────────────────────────────────────────────┐
│                    ALIGNEMENT MÉMOIRE                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Règle générale : une donnée de N bytes doit être à une        │
│  adresse divisible par N                                        │
│                                                                 │
│  Type         Taille    Alignement                              │
│  ──────────────────────────────────                             │
│  char         1 byte    1 byte                                  │
│  short        2 bytes   2 bytes                                 │
│  int          4 bytes   4 bytes                                 │
│  long (64b)   8 bytes   8 bytes                                 │
│  pointeur     4/8 bytes 4/8 bytes                               │
│                                                                 │
│  Exemple de structure avec padding :                            │
│                                                                 │
│  struct exemple {                                               │
│      char a;      // offset 0, 1 byte                          │
│      // padding 3 bytes                                         │
│      int b;       // offset 4, 4 bytes                          │
│      char c;      // offset 8, 1 byte                          │
│      // padding 3 bytes                                         │
│  };              // taille totale : 12 bytes (pas 6!)          │
│                                                                 │
│  ┌───┬───────────┬───────────────┬───┬───────────┐             │
│  │ a │  padding  │       b       │ c │  padding  │             │
│  └───┴───────────┴───────────────┴───┴───────────┘             │
│   0   1   2   3   4   5   6   7   8   9  10  11                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Protections Mémoire Modernes

Les systèmes modernes ont des protections contre l'exploitation :

```
┌─────────────────────────────────────────────────────────────────┐
│                 PROTECTIONS MÉMOIRE                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  DEP/NX (Data Execution Prevention / No-eXecute)               │
│  ────────────────────────────────────────────────               │
│  • Les pages de données ne peuvent pas être exécutées          │
│  • Empêche l'exécution de shellcode sur la stack/heap          │
│  • Contournement : ROP (Return-Oriented Programming)           │
│                                                                 │
│  ASLR (Address Space Layout Randomization)                     │
│  ────────────────────────────────────────                       │
│  • Les segments sont placés à des adresses aléatoires          │
│  • L'attaquant ne peut pas prédire les adresses                │
│  • Contournement : fuites d'information, brute force           │
│                                                                 │
│  Stack Canaries / Stack Cookies                                │
│  ──────────────────────────────                                 │
│  • Valeur aléatoire placée avant l'adresse de retour           │
│  • Vérifiée avant le RET                                       │
│  • Buffer overflow détecté si canary modifié                   │
│  • Contournement : lecture du canary, format strings           │
│                                                                 │
│  RELRO (Relocation Read-Only)                                  │
│  ────────────────────────────                                   │
│  • GOT (Global Offset Table) en lecture seule                  │
│  • Empêche l'écrasement des pointeurs de fonctions             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Applications en Sécurité Offensive

### Buffer Overflow sur la Stack

```
┌─────────────────────────────────────────────────────────────────┐
│              BUFFER OVERFLOW CLASSIQUE                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Code vulnérable :                                              │
│  void vulnerable(char *input) {                                 │
│      char buffer[64];                                           │
│      strcpy(buffer, input);  // Pas de vérification de taille! │
│  }                                                              │
│                                                                 │
│  Stack avant overflow :        Stack après overflow :           │
│  ┌────────────────────┐        ┌────────────────────┐           │
│  │  return address    │        │  0xDEADBEEF       │ ← Écrasé! │
│  ├────────────────────┤        ├────────────────────┤           │
│  │  saved EBP         │        │  AAAAAAAAAAAAAAAA │            │
│  ├────────────────────┤        ├────────────────────┤           │
│  │                    │        │  AAAAAAAAAAAAAAAA │            │
│  │  buffer[64]        │        │  AAAAAAAAAAAAAAAA │            │
│  │                    │        │  AAAAAAAAAAAAAAAA │            │
│  └────────────────────┘        └────────────────────┘           │
│                                                                 │
│  Quand la fonction retourne, EIP = 0xDEADBEEF                  │
│  → Exécution redirigée vers notre code !                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Heap Overflow

```
┌─────────────────────────────────────────────────────────────────┐
│                  HEAP OVERFLOW                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  char *a = malloc(64);                                          │
│  char *b = malloc(64);                                          │
│  strcpy(a, input);  // Overflow!                               │
│                                                                 │
│  Heap avant :                  Heap après overflow :            │
│  ┌────────────────┐            ┌────────────────┐               │
│  │ chunk a header │            │ chunk a header │               │
│  ├────────────────┤            ├────────────────┤               │
│  │ data a (64b)   │            │ AAAAAAAAAAAAA  │               │
│  ├────────────────┤            ├────────────────┤               │
│  │ chunk b header │ ← Intact   │ AAAAAAAAAAAAA  │ ← Écrasé!    │
│  ├────────────────┤            ├────────────────┤               │
│  │ data b (64b)   │            │ données         │               │
│  └────────────────┘            └────────────────┘               │
│                                                                 │
│  Modification des métadonnées = exploitation lors du free()    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Résumé

```
┌─────────────────────────────────────────────────────────────────┐
│                        POINTS CLÉS                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  • La mémoire virtuelle isole les processus                    │
│                                                                 │
│  • Layout : TEXT | DATA | BSS | HEAP → ← STACK | KERNEL        │
│                                                                 │
│  • Stack : Croît vers le bas, gérée automatiquement            │
│    → Cible classique des buffer overflows                      │
│                                                                 │
│  • Heap : Croît vers le haut, gérée par malloc/free            │
│    → Vulnérable aux heap overflows, use-after-free             │
│                                                                 │
│  • Little-endian : bytes inversés (0x1234 → \x34\x12)          │
│                                                                 │
│  • Protections : DEP/NX, ASLR, Canaries, RELRO                 │
│                                                                 │
│  • Comprendre la mémoire = pouvoir l'exploiter                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Navigation

| Précédent | Suivant |
|-----------|---------|
| [02 - Le Processeur](02-processeur.md) | [04 - Le Système d'Exploitation](04-systeme-exploitation.md) |
