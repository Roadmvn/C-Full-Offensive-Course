# 01 - Hello World

## 🎯 Ce que tu vas apprendre

- Ce qu'est un programme informatique
- Comment fonctionne la compilation en C
- La structure de base d'un programme C
- Afficher du texte à l'écran avec printf()
- Compiler et exécuter ton premier programme

## 📚 Théorie

### Concept 1 : Qu'est-ce qu'un programme ?

**C'est quoi ?**
Un programme, c'est une suite d'instructions que ton ordinateur va exécuter dans l'ordre. Imagine une recette de cuisine : tu suis les étapes une par une pour obtenir un plat.

**Pourquoi ça existe ?**
Sans programme, ton ordinateur ne sait rien faire. Un programme lui dit exactement quoi faire : afficher du texte, calculer, se connecter à internet, etc.

**Comment ça marche ?**
1. Tu écris du code en C (langage humain-lisible)
2. Le compilateur transforme ton code en langage machine (binaire : 0 et 1)
3. Le processeur exécute ces instructions binaires

```
Code C (.c) → [Compilation] → Binaire exécutable → [Exécution] → Résultat
hello.c     → gcc           → hello              → ./hello     → Hello World!
```

### Concept 2 : La compilation

**C'est quoi ?**
La compilation, c'est la transformation de ton code C (texte lisible) en un fichier exécutable (binaire) que ton ordinateur peut exécuter.

**Pourquoi ça existe ?**
Le processeur de ton ordinateur ne comprend que le langage binaire (0 et 1). Le compilateur est le traducteur entre ton code et ce que comprend le processeur.

**Comment ça marche ?**
```bash
gcc hello.c -o hello
```

- `gcc` : Le compilateur (GNU Compiler Collection)
- `hello.c` : Ton fichier source (code C)
- `-o hello` : Nom du fichier de sortie (output)
- Résultat : Un fichier exécutable `hello`

**Schéma du processus** :
```
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│  hello.c    │──>   │     gcc     │──>   │   hello     │
│  (source)   │      │(compilateur)│      │(exécutable) │
│   Texte     │      │             │      │   Binaire   │
└─────────────┘      └─────────────┘      └─────────────┘
```

### Concept 3 : Structure minimale d'un programme C

**C'est quoi ?**
Tout programme C doit avoir au minimum cette structure :

```c
#include <stdio.h>

int main() {
    return 0;
}
```

**Explication ligne par ligne** :

**Ligne 1 : `#include <stdio.h>`**
- C'est quoi ? Une directive de préprocesseur qui inclut une bibliothèque
- stdio = STandarD Input Output (entrée/sortie standard)
- Cette ligne donne accès à des fonctions comme `printf()`, `scanf()`
- Sans cette ligne, tu ne peux pas afficher de texte à l'écran

**Ligne 3 : `int main()`**
- C'est quoi ? La fonction principale, le point d'entrée du programme
- Quand tu exécutes ton programme, c'est ici que ça commence
- `int` = cette fonction retourne un nombre entier
- `main` = nom obligatoire de la fonction principale
- `()` = liste des paramètres (vide ici)

**Ligne 4 : `return 0;`**
- C'est quoi ? Le code de retour du programme
- `0` = tout s'est bien passé (convention universelle)
- Autre valeur (1, 2, etc.) = une erreur s'est produite
- Ce code est lu par le système d'exploitation

**Pourquoi return 0 ?**
Le système d'exploitation (Windows, Linux, macOS) exécute ton programme. Quand il se termine, le système veut savoir si tout s'est bien passé. 0 = succès, autre = erreur.

```
Programme termine avec 0 → Système : "OK, tout va bien"
Programme termine avec 1 → Système : "Erreur détectée"
```

### Concept 4 : La fonction printf()

**C'est quoi ?**
`printf()` est une fonction qui affiche du texte dans le terminal.

**Pourquoi ça existe ?**
Pour communiquer avec l'utilisateur. Sans printf(), ton programme tournerait en silence, impossible de savoir ce qu'il fait.

**Comment ça marche ?**

```c
printf("Hello World!\n");
```

- `printf` = nom de la fonction (print formatted = afficher formaté)
- `"Hello World!\n"` = texte à afficher (entre guillemets)
- `\n` = retour à la ligne (newline)
- `;` = fin de l'instruction (obligatoire en C)

**Caractères spéciaux** :

| Code | Signification | Exemple |
|------|---------------|---------|
| `\n` | Retour à la ligne | `"Hello\nWorld"` → 2 lignes |
| `\t` | Tabulation | `"Nom:\tAlice"` → `Nom:    Alice` |
| `\\` | Backslash littéral | `"C:\\Program"` → `C:\Program` |
| `\"` | Guillemet littéral | `"Il dit \"Salut\""` → `Il dit "Salut"` |

**Exemple concret** :

```c
#include <stdio.h>

int main() {
    printf("Hello World!\n");
    printf("Bienvenue en C\n");
    return 0;
}
```

Output :
```
Hello World!
Bienvenue en C
```

## 🔍 Processus complet : du code à l'exécution

```
1. ÉCRITURE
   Tu écris hello.c :
   ┌──────────────────────┐
   │ #include <stdio.h>   │
   │ int main() {         │
   │   printf("Hi!\n");   │
   │   return 0;          │
   │ }                    │
   └──────────────────────┘

2. COMPILATION
   gcc hello.c -o hello
   ┌──────────────────────┐
   │ Preprocessing        │  → Inclut stdio.h
   │ Compilation          │  → Transforme en assembleur
   │ Assembly             │  → Transforme en code machine
   │ Linking              │  → Lie les bibliothèques
   └──────────────────────┘
   Résultat : hello (binaire)

3. EXÉCUTION
   ./hello
   ┌──────────────────────┐
   │ Système charge le    │
   │ binaire en mémoire   │
   │ Exécute main()       │
   │ Appelle printf()     │
   │ Affiche "Hi!"        │
   │ Return 0 au système  │
   └──────────────────────┘
   Output : Hi!
```

## 🎯 Application Red Team

**Pourquoi c'est crucial ?**

### 1. Compilation et analyse de binaires
Quand tu analyses un malware, tu dois comprendre comment il a été compilé. Le processus de compilation laisse des traces (symboles de debug, strings, patterns).

### 2. Point d'entrée
`main()` est le point d'entrée classique, MAIS :
- Un malware peut masquer son vrai point d'entrée
- En Windows : `WinMain` ou `DllMain`
- Techniques avancées : constructeurs C++ avant main()
- En analyse reverse, trouver le vrai point d'entrée est crucial

### 3. Code de retour
Les codes de retour permettent la communication entre processus :
```c
// Script bash qui exploite le code de retour
./exploit
if [ $? -eq 0 ]; then
    echo "Exploitation réussie"
    ./post_exploit
fi
```

### 4. Strings et détection
`printf("Hello")` laisse la string "Hello" dans le binaire :
```bash
strings malware.exe | grep "Hello"
```
Les malwares obfusquent leurs strings pour éviter la détection :
```c
// Au lieu de :
printf("Connecting to C2...");

// Version obfusquée :
char msg[] = {0x43, 0x6f, 0x6e, 0x6e, ...};  // Encodé
printf("%s", decode(msg));
```

### 5. Bibliothèques et dépendances
`#include <stdio.h>` crée une dépendance. Un malware veut être autonome :
- Utiliser des syscalls directs au lieu de printf()
- Statiquement lier les libs (pas de .dll/.so externes)
- Techniques d'évasion : pas de includes standards

## 📝 Points clés à retenir

- Un programme C commence TOUJOURS par `main()`
- `#include <stdio.h>` est nécessaire pour printf()
- `return 0;` indique que tout s'est bien passé
- La compilation transforme ton code en binaire exécutable
- `gcc hello.c -o hello` compile ton programme
- `./hello` exécute le binaire produit
- `\n` = retour à la ligne dans printf()

## ➡️ Prochaine étape

Maintenant que tu comprends la structure de base, tu vas apprendre à manipuler des données avec les [variables et types](../02_variables_types/)

---

**Exercices** : Voir [exercice.txt](exercice.txt)
**Code exemple** : Voir [example.c](example.c)
