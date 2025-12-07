# 06 - Conditions

## 🎯 Ce que tu vas apprendre

- Comment contrôler le flux d'exécution du programme
- Les structures if, else if, else
- Le switch-case pour tester plusieurs valeurs
- Les valeurs "vraies" et "fausses" en C
- Comment le processeur exécute les conditions

## 📚 Théorie

### Concept 1 : C'est quoi une condition ?

**C'est quoi ?**
Une condition permet à ton programme de prendre des décisions : exécuter du code seulement SI une certaine situation est vraie.

**Pourquoi ça existe ?**
Sans conditions, ton programme exécuterait toujours le même code dans le même ordre. Les conditions permettent de réagir différemment selon la situation.

**Comment ça marche ?**

Le processeur évalue une expression. Si elle est vraie (≠ 0), il exécute le bloc de code. Sinon, il le saute.

```c
if (age >= 18) {
    printf("Accès autorisé\n");
}
```

**En assembleur (ce que fait le CPU)** :
```
1. Compare age avec 18
2. Si age < 18 : saute après le bloc
3. Sinon : exécute le printf
4. Continue après le bloc
```

### Concept 2 : Structure if-else

**Syntaxe de base** :
```c
if (condition) {
    // Code exécuté si condition vraie
}
```

**Avec else** :
```c
if (condition) {
    // Si vrai
} else {
    // Si faux
}
```

**Avec else if (multiple tests)** :
```c
if (condition1) {
    // Si condition1 vraie
} else if (condition2) {
    // Si condition2 vraie
} else {
    // Si aucune vraie
}
```

**Exemple concret** :
```c
int score = 85;

if (score >= 90) {
    printf("Excellent\n");
} else if (score >= 75) {
    printf("Bien\n");           // ← Exécuté
} else if (score >= 50) {
    printf("Passable\n");
} else {
    printf("Insuffisant\n");
}
```

**Flux d'exécution** :
```
score = 85

Test 1 : score >= 90 ?
         85 >= 90 → Faux
         ↓ Passe au suivant

Test 2 : score >= 75 ?
         85 >= 75 → Vrai
         ↓ Exécute le bloc
         printf("Bien\n");
         ↓ Sort du if (ne teste pas les autres)

Résultat : "Bien"
```

### Concept 3 : Vrai et Faux en C

**C'est quoi le piège ?**

En C (avant C99), il n'y a pas de type `bool`. Les conditions fonctionnent ainsi :
- `0` = FAUX
- Toute autre valeur = VRAI

```c
if (0) {
    // Jamais exécuté
}

if (1) {
    // Toujours exécuté
}

if (42) {
    // Toujours exécuté (42 ≠ 0)
}

int x = 5;
if (x) {
    // Exécuté (5 ≠ 0)
}

int* ptr = NULL;  // NULL = 0
if (ptr) {
    // Pas exécuté (NULL = 0 = faux)
}

if (!ptr) {
    // Exécuté (! inverse : !0 = 1 = vrai)
    printf("Pointeur NULL\n");
}
```

**Représentation binaire** :
```
Faux : 0 = 0b00000000
Vrai : Tout sauf 0
       1 = 0b00000001
      42 = 0b00101010
     -5 = 0b11111011 (négatif ≠ 0 → vrai)
```

### Concept 4 : Opérateurs de comparaison (rappel)

| Opérateur | Signification | Résultat |
|-----------|---------------|----------|
| `==` | Égal à | 1 si égal, 0 sinon |
| `!=` | Différent de | 1 si différent, 0 sinon |
| `>` | Supérieur à | 1 si >, 0 sinon |
| `<` | Inférieur à | 1 si <, 0 sinon |
| `>=` | Supérieur ou égal | 1 si >=, 0 sinon |
| `<=` | Inférieur ou égal | 1 si <=, 0 sinon |

**Exemples** :
```c
int x = 10;
int result;

result = (x == 10);  // result = 1 (vrai)
result = (x != 5);   // result = 1 (vrai)
result = (x > 20);   // result = 0 (faux)
```

### Concept 5 : Conditions composées (&&, ||)

**Combiner plusieurs tests** :

```c
// AND (&&) : TOUTES les conditions doivent être vraies
if (age >= 18 && age < 65) {
    printf("Adulte en âge de travailler\n");
}

// OR (||) : AU MOINS UNE condition doit être vraie
if (role == 1 || role == 2) {
    printf("Admin ou Moderator\n");
}

// Combinaison
if ((age > 18 && hasLicense) || isAdmin) {
    printf("Peut conduire\n");
}
```

**Short-circuit** :

Le C évalue de gauche à droite et s'arrête dès que le résultat est connu.

```c
// Avec && : si le premier est faux, pas besoin de tester les autres
if (ptr != NULL && ptr->value == 42) {
    // Sûr : si ptr est NULL, ptr->value n'est PAS évalué
}

// Avec || : si le premier est vrai, pas besoin de tester les autres
if (x == 0 || y / x > 10) {
    // Sûr : si x==0, y/x n'est PAS évalué (évite division par 0)
}
```

**Schéma d'évaluation** :
```
Expression : (a > 5) && (b < 10)

Si a = 3 :
   (3 > 5) → Faux
   ↓
   Court-circuit : ne teste pas (b < 10)
   ↓
   Retourne Faux

Si a = 7 :
   (7 > 5) → Vrai
   ↓
   Continue : teste (b < 10)
   ↓
   Retourne le résultat de (b < 10)
```

### Concept 6 : switch-case

**C'est quoi ?**
Une alternative à if-else pour tester une variable contre plusieurs valeurs fixes.

**Syntaxe** :
```c
switch (variable) {
    case valeur1:
        // Code si variable == valeur1
        break;
    case valeur2:
        // Code si variable == valeur2
        break;
    default:
        // Code si aucune correspondance
        break;
}
```

**Exemple** :
```c
int day = 3;

switch (day) {
    case 1:
        printf("Lundi\n");
        break;
    case 2:
        printf("Mardi\n");
        break;
    case 3:
        printf("Mercredi\n");  // ← Exécuté
        break;
    case 4:
        printf("Jeudi\n");
        break;
    default:
        printf("Jour invalide\n");
        break;
}
```

**IMPORTANT : Le break est OBLIGATOIRE**

Sans `break`, le code continue dans les cases suivants (fall-through) :

```c
int x = 2;
switch (x) {
    case 1:
        printf("Un\n");
    case 2:
        printf("Deux\n");   // Exécuté
    case 3:
        printf("Trois\n");  // Exécuté aussi (pas de break !)
    default:
        printf("Défaut\n"); // Exécuté aussi !
}

// Output :
// Deux
// Trois
// Défaut
```

**Fall-through intentionnel (cas rare)** :
```c
switch (character) {
    case 'a':
    case 'e':
    case 'i':
    case 'o':
    case 'u':
        printf("Voyelle\n");
        break;
    default:
        printf("Consonne\n");
        break;
}
```

### Concept 7 : Conditions imbriquées

**C'est quoi ?**
Des if à l'intérieur d'autres if.

```c
if (hasAccount) {
    if (password == correctPassword) {
        if (hasPermission) {
            printf("Accès accordé\n");
        } else {
            printf("Permission refusée\n");
        }
    } else {
        printf("Mot de passe incorrect\n");
    }
} else {
    printf("Compte inexistant\n");
}
```

**Simplification avec &&** :
```c
// Au lieu de :
if (hasAccount) {
    if (password == correctPassword) {
        if (hasPermission) {
            // ...
        }
    }
}

// Plus simple :
if (hasAccount && password == correctPassword && hasPermission) {
    // ...
}
```

## 🔍 Visualisation : Jump Tables (switch en assembleur)

**Comment le switch-case fonctionne en interne** :

Le compilateur crée une **jump table** (table de sauts) :

```c
switch (x) {
    case 0: printf("Zero\n"); break;
    case 1: printf("One\n"); break;
    case 2: printf("Two\n"); break;
}
```

**En assembleur (simplifié)** :
```
Jump table :
┌───────┬─────────────┐
│ Case  │  Adresse    │
├───────┼─────────────┤
│   0   │  0x400500   │ → Code pour case 0
│   1   │  0x400520   │ → Code pour case 1
│   2   │  0x400540   │ → Code pour case 2
└───────┴─────────────┘

1. Lit x
2. Cherche x dans la table
3. Saute à l'adresse correspondante
```

**Avantage** : Très rapide (O(1)), même avec beaucoup de cases.

## 🎯 Application Red Team

### 1. Vérifier les privilèges

```c
if (getuid() == 0) {
    printf("Running as root\n");
    // Exploitation avancée
} else {
    printf("Need root privileges\n");
    // Escalade de privilèges
}
```

### 2. Détecter l'architecture

```c
if (sizeof(void*) == 8) {
    printf("64-bit architecture\n");
    // Utiliser shellcode x64
} else {
    printf("32-bit architecture\n");
    // Utiliser shellcode x86
}
```

### 3. Parser des protocoles réseau

```c
unsigned char tcp_flags = packet[13];

// Vérifier les flags TCP
if (tcp_flags & 0x02) {  // SYN flag
    printf("SYN packet detected\n");
}

if ((tcp_flags & 0x12) == 0x12) {  // SYN+ACK
    printf("SYN-ACK packet\n");
}
```

### 4. Switch pour parser des opcodes

```c
unsigned char opcode = memory[ip];

switch (opcode) {
    case 0x90:  // NOP
        ip++;
        break;
    case 0x31:  // XOR
        execute_xor();
        break;
    case 0x50:  // PUSH
        push_stack();
        break;
    case 0xFF:  // JMP
        ip = get_jump_target();
        break;
    default:
        printf("Unknown opcode: 0x%02x\n", opcode);
        break;
}
```

### 5. Sandbox detection

```c
// Détecter un environnement virtuel
if (cores < 2 || ram < 4096 || disk < 80) {
    printf("Sandbox detected, exiting\n");
    exit(0);  // Ne pas exécuter le payload
}
```

### 6. Vérifier la réponse d'une API

```c
HANDLE proc = OpenProcess(...);
if (proc == NULL) {
    DWORD error = GetLastError();
    switch (error) {
        case ERROR_ACCESS_DENIED:
            printf("Need higher privileges\n");
            break;
        case ERROR_INVALID_PARAMETER:
            printf("Invalid PID\n");
            break;
        default:
            printf("Error: %lu\n", error);
            break;
    }
} else {
    // Injection de code
}
```

### 7. Adaptation selon l'OS

```c
#if defined(_WIN32)
    if (version >= 10) {
        // Windows 10+
        use_windows10_exploit();
    } else {
        use_windows7_exploit();
    }
#elif defined(__linux__)
    if (kernel_version >= 5.0) {
        use_modern_exploit();
    }
#endif
```

### 8. Defensive coding (éviter les crashes)

```c
// Vérifier les pointeurs avant utilisation
if (ptr != NULL && ptr->data != NULL) {
    process(ptr->data);
} else {
    fprintf(stderr, "Invalid pointer\n");
    return ERROR_INVALID_POINTER;
}
```

## 📝 Points clés à retenir

- `if (condition)` exécute le code seulement si la condition est vraie
- En C : 0 = faux, tout le reste = vrai
- `else if` permet de tester plusieurs conditions
- `else` est le "sinon" final
- `switch-case` teste une variable contre plusieurs valeurs fixes
- Le `break` est obligatoire dans switch (sinon fall-through)
- `&&` = ET (toutes vraies), `||` = OU (au moins une vraie)
- Short-circuit : évaluation s'arrête dès que le résultat est connu
- Toujours vérifier les pointeurs avant de les déréférencer
- Les conditions sont essentielles pour adapter le code selon l'environnement

## ➡️ Prochaine étape

Maintenant que tu sais prendre des décisions, tu vas apprendre à répéter des actions avec les [boucles](../07_loops/)

---

**Exercices** : Voir [exercice.txt](exercice.txt)
**Code exemple** : Voir [example.c](example.c)
