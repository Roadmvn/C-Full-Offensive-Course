# Cours : Les Chaînes de Caractères (Strings)

## 🎯 Objectif du Module
Maîtriser la manipulation des chaînes en C, comprendre les dangers des fonctions non-sécurisées, et apprendre les bonnes pratiques pour éviter les vulnérabilités.

---

## 1. Rappel : Qu'est-ce qu'une String en C ?

En C, il n'existe **pas de type `string`** natif (contrairement à Python ou Java).
Une chaîne de caractères est un **tableau de `char`** terminé par `\0` (NULL byte).

```c
char name[] = "Alice";
```

**Représentation mémoire :**
```
┌───┬───┬───┬───┬───┬────┐
│ A │ l │ i │ c │ e │ \0 │
└───┴───┴───┴───┴───┴────┘
  ↑                   ↑
name[0]            name[5]
```

**Point clé :** `\0` (valeur 0) marque la **fin** de la chaîne. Sans lui, les fonctions ne savent pas où s'arrêter.

---

## 2. Déclaration et Initialisation

### 2.1 Tableau de Caractères (Stack)
```c
char name[6] = "Alice";  // Taille explicite (5 caractères + '\0')
```

### 2.2 Taille Automatique
```c
char name[] = "Alice";  // Le compilateur calcule la taille (6)
```

### 2.3 Pointeur vers String Littérale (Read-Only)
```c
char *name = "Alice";  // Stocké dans la section .rodata (non modifiable)
```

**Différence cruciale :**
```c
char arr[] = "Alice";  // Modifiable (sur la Stack)
char *ptr = "Alice";   // NON modifiable (section .rodata)

arr[0] = 'B';  // OK
ptr[0] = 'B';  // CRASH (Segmentation Fault)
```

---

## 3. La Bibliothèque `<string.h>`

### 3.1 Fonctions Essentielles

| Fonction        | Rôle                                    | Danger        |
|-----------------|-----------------------------------------|---------------|
| `strlen(s)`     | Retourne la longueur (sans `\0`)        | Aucun         |
| `strcpy(d, s)`  | Copie `s` dans `d`                      | ⚠️ Overflow   |
| `strncpy(d, s, n)` | Copie au max `n` octets              | ⚠️ Pas de `\0`|
| `strcat(d, s)`  | Concatène `s` à la fin de `d`           | ⚠️ Overflow   |
| `strcmp(s1, s2)`| Compare deux chaînes                    | Aucun         |
| `strchr(s, c)`  | Trouve le caractère `c` dans `s`        | Aucun         |

---

## 4. Dangers et Vulnérabilités

### 4.1 `strcpy()` : La Fonction Dangereuse

```c
char buffer[8];
strcpy(buffer, "Hello, World!");  // "Hello, World!" fait 13 caractères + '\0' = 14
                                   // On déborde de 6 octets !
```

**Problème :** `strcpy()` **ne vérifie pas** si la destination est assez grande.

**Résultat :**
- Écrasement de variables adjacentes.
- Corruption de l'adresse de retour → Exploit possible.

### 4.2 Alternative Sécurisée : `strncpy()`

```c
char buffer[8];
strncpy(buffer, "Hello, World!", 7);
buffer[7] = '\0';  // IMPORTANT : Ajouter \0 manuellement
```

**Piège :** `strncpy()` ne garantit **pas** l'ajout de `\0` si la source est trop longue.

### 4.3 `gets()` : La Pire Fonction Ever

```c
char buffer[64];
gets(buffer);  // EXTRÊMEMENT DANGEREUX
```

**Pourquoi ?**
- Aucune limite de taille.
- L'utilisateur peut envoyer 1000 octets → Buffer Overflow garanti.
- **Fonction supprimée des standards modernes** (C11).

**Alternative :** `fgets()`
```c
char buffer[64];
fgets(buffer, sizeof(buffer), stdin);  // Limite à 64 octets
```

---

## 5. Visualisation : Buffer Overflow via `strcpy()`

### 5.1 Code Vulnérable
```c
void vulnerable(char *input) {
    char buffer[8];
    strcpy(buffer, input);  // Aucune vérification
}
```

### 5.2 État Mémoire

**Input Normal : "Hi"**
```
Stack Layout:
0x7ffe10  [ Adresse de Retour ]
0x7ffe08  [ Saved RBP        ]
0x7ffe00  [ "Hi\0"           ]  ← buffer[8]
          [ (vide)           ]
```

**Input Malveillant : "AAAAAAAAAAAAAAAA" (16 A)**
```
Stack Layout:
0x7ffe10  [ 0x4141414141414141 ]  ← ÉCRASÉ ("AAAAAAAA")
0x7ffe08  [ 0x4141414141414141 ]  ← Saved RBP écrasé
0x7ffe00  [ "AAAAAAAA"        ]  ← buffer[8] + débordement
```

**Résultat :** L'adresse de retour est écrasée → Contrôle du flux d'exécution.

---

## 6. Manipulation Avancée

### 6.1 Parcourir une Chaîne avec un Pointeur
```c
char *str = "Hello";
while (*str != '\0') {
    printf("%c ", *str);
    str++;  // Avance d'un caractère
}
```

### 6.2 Calculer la Longueur Manuellement
```c
int my_strlen(char *str) {
    int len = 0;
    while (str[len] != '\0') {
        len++;
    }
    return len;
}
```

### 6.3 Copie Sécurisée Manuelle
```c
void safe_copy(char *dest, const char *src, int dest_size) {
    int i = 0;
    while (i < dest_size - 1 && src[i] != '\0') {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';  // Toujours terminer par \0
}
```

---

## 7. Le Terminateur `\0` : Pourquoi C'est Critique ?

### 7.1 Oubli du `\0`
```c
char buffer[5] = {'H', 'e', 'l', 'l', 'o'};  // Pas de \0
printf("%s\n", buffer);  // Affiche "Hello" + GARBAGE
```

**Problème :** `printf("%s")` lit jusqu'à trouver un `\0`. S'il n'y en a pas, il continue de lire la mémoire (fuite d'information).

### 7.2 Exploitation : Information Leak
```c
char password[16] = "secret123";
char buffer[8];
// Oubli du \0 dans buffer
printf("Buffer: %s\n", buffer);  // Peut afficher le mot de passe si la mémoire est adjacente
```

---

## 8. Comparaison de Chaînes

### 8.1 `strcmp()` : Comparaison Lexicographique
```c
int result = strcmp("apple", "banana");
if (result < 0)  printf("apple vient avant banana\n");
```

**Retour :**
- `0` si égales.
- `< 0` si s1 < s2.
- `> 0` si s1 > s2.

### 8.2 Erreur Classique : Comparaison avec `==`
```c
char *s1 = "Hello";
char *s2 = "Hello";
if (s1 == s2)  // FAUX : Compare les adresses, pas le contenu
```

**Correct :**
```c
if (strcmp(s1, s2) == 0)  // Compare le contenu
```

---

## 9. Chaînes Dynamiques (Heap)

### 9.1 Allocation avec `malloc()`
```c
char *str = (char*)malloc(20 * sizeof(char));
if (str == NULL) {
    // Gestion d'erreur
}
strcpy(str, "Hello");
printf("%s\n", str);
free(str);  // Libération obligatoire
```

### 9.2 Duplication avec `strdup()`
```c
char *original = "Hello";
char *copy = strdup(original);  // Alloue + copie
free(copy);
```

---

## 10. Application Red Team

### 10.1 Format String Attack
```c
char buffer[128];
scanf("%s", buffer);
printf(buffer);  // DANGEREUX : buffer contrôlé par l'utilisateur
```

**Exploit :**
- Input : `%x %x %x` → Lit la pile (fuite d'adresses).
- Input : `%n` → Écrit en mémoire.

### 10.2 Buffer Overflow dans des Malwares
Les malwares utilisent des buffer overflows pour :
- Injecter du shellcode.
- Détourner le flux d'exécution.
- Bypasser les protections (canaries, ASLR).

---

## 11. Bonnes Pratiques

1. **Toujours utiliser les versions sécurisées :**
   - `strncpy()` au lieu de `strcpy()`.
   - `fgets()` au lieu de `gets()`.
   - `snprintf()` au lieu de `sprintf()`.

2. **Vérifier les limites :**
   ```c
   if (strlen(input) < sizeof(buffer)) {
       strcpy(buffer, input);
   }
   ```

3. **Toujours ajouter `\0` :**
   ```c
   buffer[sizeof(buffer) - 1] = '\0';
   ```

4. **Utiliser `sizeof()` plutôt que des constantes :**
   ```c
   fgets(buffer, sizeof(buffer), stdin);
   ```

---

## 12. Checklist de Compréhension

- [ ] Quelle est la différence entre `char arr[]` et `char *ptr` ?
- [ ] Pourquoi `\0` est-il obligatoire ?
- [ ] Quel est le danger de `strcpy()` ?
- [ ] Pourquoi `gets()` est-elle interdite ?
- [ ] Comment comparer deux chaînes correctement ?
- [ ] Que se passe-t-il si on oublie `\0` ?

---

## 13. Exercices Pratiques

Consultez `exercice.txt` pour :
1. Implémenter `strlen()`, `strcpy()` manuellement.
2. Exploiter un buffer overflow avec `strcpy()`.
3. Comparer des chaînes sans `strcmp()`.
4. Créer des chaînes dynamiques avec `malloc()`.

---

**Prochaine étape :** Module `03_pointeurs_intro` (Relation approfondie entre pointeurs et chaînes).

