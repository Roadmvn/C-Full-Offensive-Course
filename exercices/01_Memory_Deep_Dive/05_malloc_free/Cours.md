# Cours : malloc() et free() - Gestion Dynamique de la Mémoire

## 1. Introduction - Stack vs Heap : Les Deux Zones Mémoire

### 1.1 Le Problème des Tableaux Statiques

```c
int ages[100];  // Réserve TOUJOURS 100 × 4 = 400 bytes
```

**Problèmes** :
- ❌ Si vous n'utilisez que 10 éléments → **90% de gaspillage**
- ❌ Si vous avez besoin de 200 éléments → **Impossible**
- ❌ Taille fixée à la compilation

**Question** : Comment avoir un tableau dont la taille s'adapte aux besoins ?

**Réponse** : **Allocation dynamique** avec `malloc()` !

### 1.2 Les Deux Zones Mémoire d'un Programme

```ascii
┌─────────────────────────────────────────────────────┐
│            MÉMOIRE D'UN PROCESSUS                   │
├─────────────────────────────────────────────────────┤
│                                                     │
│  📚 CODE SEGMENT (.text)                            │
│  ├─ Votre code compilé (instructions machine)      │
│  └─ Taille FIXE (ne change jamais)                 │
│                                                     │
├─────────────────────────────────────────────────────┤
│                                                     │
│  📊 DATA SEGMENT (.data, .bss)                      │
│  ├─ Variables globales                             │
│  └─ Taille FIXE                                    │
│                                                     │
├─────────────────────────────────────────────────────┤
│                                                     │
│  🏔️ HEAP (Tas)                                      │
│  ├─ Allocations dynamiques (malloc)                │
│  ├─ Grandit vers LE HAUT ↑                         │
│  └─ Taille VARIABLE                                │
│     ↑↑↑ Croissance ↑↑↑                             │
│      ...espace libre...                            │
│      ↓↓↓ Croissance ↓↓↓                            │
│  ├─ Variables locales                              │
│  ├─ Paramètres de fonctions                        │
│  ├─ Grandit vers LE BAS ↓                          │
│  └─ Taille VARIABLE                                │
│  📚 STACK (Pile)                                    │
│                                                     │
└─────────────────────────────────────────────────────┘  Adresses hautes
```

**Différences Clés** :

| Aspect | STACK | HEAP |
|--------|-------|------|
| **Gestion** | Automatique | Manuelle (malloc/free) |
| **Durée** | Variable locale (courte) | Tant que vous voulez |
| **Taille** | Limitée (~8 MB) | Presque illimitée |
| **Vitesse** | Très rapide | Plus lent |
| **Ordre** | LIFO (dernier entré, premier sorti) | Aléatoire |

### 1.3 Analogie Complète

**STACK** = Pile d'assiettes sur un plateau
- Vous posez une assiette (variable locale créée)
- Fonction termine → assiette retirée automatiquement
- Rapide, mais taille limitée du plateau

**HEAP** = Grand entrepôt
- Vous demandez un espace (malloc)
- Il reste là jusqu'à ce que vous le libériez (free)
- Beaucoup d'espace, mais vous devez gérer

## 2. malloc() - Réserver de la Mémoire

### 2.1 Syntaxe et Signification

```c
void* malloc(size_t size);
```

**Décortiquons** :

```ascii
void*  malloc  (size_t size)
 │      │        │
 │      │        └─ Nombre de BYTES à allouer
 │      │
 │      └─ Nom de la fonction ("memory allocation")
 │
 └─ Retourne un pointeur générique (void*)
    vers le bloc alloué
```

### 2.2 Que Se Passe-t-il Exactement ?

```ascii
AVANT malloc() :

HEAP (vide) :
┌───────────────────────────────────┐
│                                   │
│  ... espace libre ...             │
│  ... espace libre ...             │
│  ... espace libre ...             │
│                                   │
└───────────────────────────────────┘

═══════════════════════════════════════

APPEL : void *ptr = malloc(12);

"Hey système, j'ai besoin de 12 bytes !"

═══════════════════════════════════════

APRÈS malloc() :

HEAP :
┌───────────────────────────────────┐
│  ... espace libre ...             │
├───────────────────────────────────┤
│  ┌─────────────────────────────┐  │  ← Bloc réservé
│  │  12 bytes alloués           │  │
│  │  Adresse: 0x5000            │  │
│  │  Contenu: ??? (garbage)     │  │  ← Non initialisé !
│  └─────────────────────────────┘  │
├───────────────────────────────────┤
│  ... espace libre ...             │
└───────────────────────────────────┘
         ↑
         │
    ptr = 0x5000 (adresse retournée)
```

**Important** : malloc() retourne l'**adresse** du bloc, pas le bloc lui-même !

### 2.3 Vérifier si malloc() a Réussi

```c
int *ptr = malloc(sizeof(int) * 100);

if (ptr == NULL) {
    printf("ERREUR : Pas assez de mémoire !\n");
    exit(1);
}
```

**Pourquoi vérifier ?**

```ascii
SCÉNARIOS D'ÉCHEC :

1. Plus de mémoire RAM disponible
   ┌──────────────┐
   │  HEAP PLEIN  │  ← malloc() ne peut pas allouer
   └──────────────┘
   Retourne → NULL

2. Demande trop grande
   malloc(999999999999)  ← Impossible
   Retourne → NULL

3. Corruption du Heap
   Métadonnées corrompues
   Retourne → NULL

TOUJOURS VÉRIFIER LE RETOUR !
if (ptr == NULL) { /* gérer erreur */ }
```

### 2.4 Calculer la Taille avec sizeof()

```ascii
EXEMPLES :

malloc(sizeof(int))              → 4 bytes
   ├─ 1 entier

malloc(sizeof(int) * 10)         → 40 bytes
   ├─ 10 entiers

malloc(sizeof(char) * 100)       → 100 bytes
   ├─ 100 caractères (chaîne)

malloc(sizeof(struct Person))    → Variable
   ├─ Dépend de la taille de la structure

┌─────────────────────────────────────────┐
│  RÈGLE D'OR :                           │
│  malloc(sizeof(TYPE) × nombre_elements) │
└─────────────────────────────────────────┘
```

## 3. free() - Libérer la Mémoire

### 3.1 Pourquoi free() est OBLIGATOIRE ?

```ascii
SANS free() - MEMORY LEAK (Fuite Mémoire) :

Début programme :
HEAP: ▓░░░░░░░░░░░░  (10% utilisé)

Après 100 malloc() sans free() :
HEAP: ▓▓▓▓▓▓▓▓▓▓▓░  (90% utilisé)

Après 1000 malloc() sans free() :
HEAP: ▓▓▓▓▓▓▓▓▓▓▓▓  (100% utilisé)
       ↓
  PLUS DE MÉMOIRE !
  Programme CRASH
```

### 3.2 Utilisation de free()

```c
int *ptr = malloc(sizeof(int));
*ptr = 42;
// ... utilisation ...
free(ptr);  // Libérer la mémoire
ptr = NULL; // Bonne pratique : mettre à NULL après free
```

```ascii
AVANT free(ptr) :

HEAP :
┌───────────────────────────────────┐
│  ... espace libre ...             │
├───────────────────────────────────┤
│  ┌─────────────────────────────┐  │
│  │ Bloc alloué (4 bytes)       │  │ ← ptr = 0x5000
│  │ Valeur: 42                  │  │
│  └─────────────────────────────┘  │
├───────────────────────────────────┤
│  ... espace libre ...             │
└───────────────────────────────────┘

═══════════════════════════════════════

APRÈS free(ptr) :

HEAP :
┌───────────────────────────────────┐
│  ... espace libre ...             │
├───────────────────────────────────┤
│  ┌─────────────────────────────┐  │
│  │ ░░ LIBÉRÉ ░░                │  │ ← Disponible à nouveau
│  │ (peut être réutilisé)       │  │
│  └─────────────────────────────┘  │
├───────────────────────────────────┤
│  ... espace libre ...             │
└───────────────────────────────────┘

ptr pointe toujours vers 0x5000 (dangling pointer !)
→ Mettre ptr = NULL pour sécuriser
```

### 3.3 Les Pièges Mortels (Erreurs Courantes)

#### Piège 1 : Oublier de free()

```c
for (int i = 0; i < 1000000; i++) {
    int *ptr = malloc(1024);  // Alloue 1 KB
    // ... utilisation ...
    // OUBLI de free(ptr) !
}
// Résultat : 1 GB de RAM gaspillée !
```

#### Piège 2 : Double Free

```c
int *ptr = malloc(sizeof(int));
free(ptr);
free(ptr);  // ❌ ERREUR : Déjà libéré !
// Résultat : CRASH ou comportement imprévisible
```

```ascii
VISUALISATION DU PROBLÈME :

Après premier free() :
HEAP :
┌────────────┐
│ LIBÉRÉ ✅  │  ← Marqué comme disponible
└────────────┘

Après second free() :
HEAP :
┌────────────┐
│ CORROMPU❌ │  ← Métadonnées du Heap détruites
└────────────┘
   ↓
CRASH
```

#### Piège 3 : Use-After-Free

```c
int *ptr = malloc(sizeof(int));
*ptr = 42;
free(ptr);
printf("%d\n", *ptr);  // ❌ ERREUR : Mémoire libérée !
```

```ascii
APRÈS free(ptr) :

ptr = 0x5000  (contient toujours l'adresse)
         ↓
0x5000  ┌────────┐
        │  ???   │  ← Mémoire libérée (contenu indéfini)
        └────────┘  ← Peut être réutilisée par malloc()

Accéder ici = DANGEREUX
```

## 4. Cycle de Vie Complet - Exemple Visuel

```ascii
═══════════════════════════════════════════════════════════
ÉTAPE 1 : DÉCLARATION
═══════════════════════════════════════════════════════════

Code : int *ptr;

STACK :                   HEAP :
┌──────────┐              ┌─────────────────┐
│ ptr      │              │                 │
│   ???    │  ← Garbage   │  ... vide ...   │
└──────────┘              └─────────────────┘

═══════════════════════════════════════════════════════════
ÉTAPE 2 : ALLOCATION
═══════════════════════════════════════════════════════════

Code : ptr = malloc(sizeof(int));

STACK :                   HEAP :
┌──────────┐              ┌─────────────────┐
│ ptr      │     ┌───────→│  ┌───────────┐  │
│ 0x5000   │─────┘        │  │  4 bytes  │  │  0x5000
└──────────┘              │  │  ???      │  │  ← Alloué
                          │  └───────────┘  │
                          └─────────────────┘

═══════════════════════════════════════════════════════════
ÉTAPE 3 : UTILISATION
═══════════════════════════════════════════════════════════

Code : *ptr = 42;

STACK :                   HEAP :
┌──────────┐              ┌─────────────────┐
│ ptr      │     ┌───────→│  ┌───────────┐  │
│ 0x5000   │─────┘        │  │  4 bytes  │  │  0x5000
└──────────┘              │  │   42      │  │  ← Valeur écrite
                          │  └───────────┘  │
                          └─────────────────┘

═══════════════════════════════════════════════════════════
ÉTAPE 4 : LIBÉRATION
═══════════════════════════════════════════════════════════

Code : free(ptr);

STACK :                   HEAP :
┌──────────┐              ┌─────────────────┐
│ ptr      │              │  ┌───────────┐  │
│ 0x5000   │───┐          │  │░ LIBÉRÉ ░│  │  0x5000
└──────────┘   │          │  │░░░░░░░░░░│  │  ← Disponible
               │          │  └───────────┘  │
               │          └─────────────────┘
               │
               └─ DANGLING POINTER !
                  (pointe vers mémoire libérée)

═══════════════════════════════════════════════════════════
ÉTAPE 5 : SÉCURISATION
═══════════════════════════════════════════════════════════

Code : ptr = NULL;

STACK :                   HEAP :
┌──────────┐              ┌─────────────────┐
│ ptr      │              │  ┌───────────┐  │
│ NULL     │  ✅ Sûr      │  │░ LIBÉRÉ ░│  │  0x5000
└──────────┘              │  └───────────┘  │
                          └─────────────────┘

Maintenant ptr ne pointe plus vers rien (safe)
```

## 5. sizeof() - Calculer les Tailles

### 5.1 Qu'est-ce que sizeof() ?

`sizeof()` est un **opérateur** (pas une fonction) qui retourne la taille en **bytes**.

```ascii
sizeof(TYPE) ou sizeof(variable)
       │              │
       │              └─ Taille d'une variable spécifique
       └─ Taille d'un type

EXEMPLES :

sizeof(char)      = 1  byte
sizeof(int)       = 4  bytes
sizeof(float)     = 4  bytes
sizeof(double)    = 8  bytes
sizeof(int*)      = 8  bytes (sur système 64-bit)
sizeof(void*)     = 8  bytes
```

### 5.2 Calcul Visuel pour malloc()

```c
int *tableau = malloc(sizeof(int) * 10);
```

```ascii
CALCUL :

sizeof(int) × 10
    ↓        ↓
    4    ×  10
    ↓
   40 bytes

HEAP :
┌────────────────────────────────────────────┐
│  ┌──────────────────────────────────────┐  │
│  │  40 bytes alloués                    │  │
│  │  = 10 × 4 bytes                      │  │
│  │  = 10 entiers                        │  │
│  ├────┬────┬────┬────┬────┬────┬────┬  │  │
│  │ [0]│ [1]│ [2]│ [3]│ [4]│...│ [9]│  │  │
│  └────┴────┴────┴────┴────┴────┴────┴──┘  │
│  ↑                                         │
│  tableau = 0x5000                          │
└────────────────────────────────────────────┘

tableau[0] = *(tableau + 0) = *0x5000 = adresse 0x5000
tableau[1] = *(tableau + 1) = *0x5004 = adresse 0x5004
tableau[2] = *(tableau + 2) = *0x5008 = adresse 0x5008
...
```

## 6. calloc() - malloc() avec Initialisation

### 6.1 Différence avec malloc()

```c
void* calloc(size_t nmemb, size_t size);
```

```ascii
malloc()  : Alloue mémoire,   contenu INDÉFINI (garbage)
calloc()  : Alloue mémoire ET met tout à ZÉRO

EXEMPLE :

int *arr1 = malloc(sizeof(int) * 5);
→ arr1[0] = ???, arr1[1] = ???, ... (garbage)

int *arr2 = calloc(5, sizeof(int));
→ arr2[0] = 0, arr2[1] = 0, ... (initialisé)
```

**Visualisation** :

```ascii
malloc(20) :
┌────┬────┬────┬────┬────┐
│ ?? │ ?? │ ?? │ ?? │ ?? │  ← Contenu aléatoire
└────┴────┴────┴────┴────┘

calloc(5, 4) :
┌────┬────┬────┬────┬────┐
│  0 │  0 │  0 │  0 │  0 │  ← Tout à zéro
└────┴────┴────┴────┴────┘
```

## 7. realloc() - Redimensionner un Bloc

### 7.1 Agrandir ou Rétrécir

```c
int *arr = malloc(sizeof(int) * 5);  // 5 éléments
// ... besoin de plus ...
arr = realloc(arr, sizeof(int) * 10);  // Agrandir à 10
```

```ascii
SCÉNARIO 1 : Espace disponible après le bloc

AVANT realloc() :
┌──────────┬─────────────┐
│ 5 ints   │  libre      │
└──────────┴─────────────┘
  ↑
 arr

APRÈS realloc() :
┌────────────────────────┐
│ 10 ints (étendu)       │  ← Même adresse !
└────────────────────────┘
  ↑
 arr (inchangé)

═══════════════════════════════════════

SCÉNARIO 2 : Pas d'espace (bloc déplacé)

AVANT realloc() :
┌──────────┬──────┐
│ 5 ints   │occupé│
└──────────┴──────┘
  ↑
 arr = 0x5000

realloc() trouve un nouveau bloc :
┌──────────┬──────┬────────────────────────┐
│ 5 ints   │occupé│         libre          │
│ (ancien) │      │                        │
└──────────┴──────┴────────────────────────┘
                   ↑
                   Nouveau bloc ici

APRÈS realloc() :
┌──────────┬──────┬────────────────────────┐
│░░░░░░░░░░│occupé│  10 ints (nouveau)     │
│░ LIBÉRÉ ░│      │  (données copiées)     │
└──────────┴──────┴────────────────────────┘
                   ↑
                  arr = 0x7000 (nouvelle adresse)

C'est pourquoi : arr = realloc(arr, ...)
(l'adresse peut changer !)
```

## 8. Bonnes Pratiques - Check-list

```ascii
✅ TOUJOURS vérifier si malloc() retourne NULL
✅ TOUJOURS free() ce que vous malloc()
✅ Mettre le pointeur à NULL après free()
✅ Ne JAMAIS free() deux fois
✅ Ne JAMAIS utiliser après free()
✅ Utiliser sizeof(TYPE) au lieu de nombres en dur
✅ Libérer dans l'ordre inverse de l'allocation (pour structures complexes)
```

## Ressources

- [malloc(3)](https://man7.org/linux/man-pages/man3/malloc.3.html)
- [Memory Management](https://en.cppreference.com/w/c/memory)

