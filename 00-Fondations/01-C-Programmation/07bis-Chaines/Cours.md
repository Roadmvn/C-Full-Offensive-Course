# Module 08 - Strings (Chaînes de caractères)

## Pourquoi tu dois maîtriser ça

```bash
$ strings ton_implant.exe | head -5
http://c2.malware.com
cmd.exe /c whoami
CreateRemoteThread
VirtualAllocEx
PWNED
```

> **`strings`** = outil qui extrait le texte lisible d'un binaire. Premier réflexe de tout analyste.

**Ton implant vient de se faire griller en 2 secondes.**

Les strings en clair = **signature gratuite** pour les analystes.

---

## L'essentiel en 30 secondes

```c
char msg[] = "Hello";   // 6 bytes : H-e-l-l-o-\0
                        //                    ↑ OBLIGATOIRE
```

```
Mémoire :
┌───┬───┬───┬───┬───┬────┐
│ H │ e │ l │ l │ o │ \0 │  ← Le \0 = "c'est fini"
└───┴───┴───┴───┴───┴────┘
```

> **`\0`** (null terminator) = byte à 0x00. C'est comme ça que les fonctions C savent où s'arrêter. Sans lui → lecture infinie → crash.

**String = tableau de char + `\0` à la fin.** C'est tout.

---

## Le piège qui te grille

### CE QUE FONT LES DÉBUTANTS
```c
char* c2_url = "http://evil.com/beacon";
char* cmd = "cmd.exe /c net user hacker P@ss /add";
```

### CE QUE VOIT L'ANALYSTE
```bash
$ strings malware.exe
http://evil.com/beacon      ← GRILLÉ
cmd.exe /c net user...      ← GRILLÉ
```

> **Pourquoi visible ?** `"texte"` dans le code → stocké dans **`.rodata`** (read-only data). Cette section est EN CLAIR dans le binaire.

> **YARA** = outil de détection par patterns. Les analystes écrivent des règles genre "si contient 'evil.com' → malware". Tes strings = leurs règles.

**Résultat :** Signature YARA en 5 min, ton implant est mort.

---

## Où vont tes données ?

```
TON BINAIRE (.exe / ELF)
┌───────────┬─────────────────────────────────────┐
│ .text     │ Code compilé (instructions CPU)     │
├───────────┼─────────────────────────────────────┤
│ .rodata   │ Strings "en dur" → VISIBLE          │ ← PROBLÈME
├───────────┼─────────────────────────────────────┤
│ .data     │ Variables globales initialisées     │
├───────────┼─────────────────────────────────────┤
│ .bss      │ Variables globales non init (→ 0)   │
└───────────┴─────────────────────────────────────┘

RUNTIME (à l'exécution)
┌───────────┬─────────────────────────────────────┐
│ Stack     │ Variables locales, adresses retour  │ ← SAFE
├───────────┼─────────────────────────────────────┤
│ Heap      │ malloc() / allocations dynamiques   │
└───────────┴─────────────────────────────────────┘
```

> **Stack** = mémoire temporaire créée à l'exécution. Ce que tu construis sur la stack **n'apparaît PAS** dans `strings`.

---

## TECHNIQUE 1 : Stack Strings

**Principe :** Construire la string sur la **stack** au runtime → invisible dans le binaire.

```c
// ❌ Détectable (va dans .rodata)
char* cmd = "cmd.exe";

// ✅ Invisible (construit sur la stack)
char cmd[8];
cmd[0] = 'c';
cmd[1] = 'm';
cmd[2] = 'd';
cmd[3] = '.';
cmd[4] = 'e';
cmd[5] = 'x';
cmd[6] = 'e';
cmd[7] = '\0';
```

**Pourquoi ça marche ?**
```
BINAIRE:                       EXÉCUTION:
.rodata = (vide)               Stack = ['c','m','d','.','e','x','e','\0']
```

Le binaire contient des instructions `mov`, pas la string.

**Vérification :**
```bash
$ strings binary.exe | grep cmd
(rien)  ← PARFAIT
```

### Version compacte
```c
char cmd[] = {'c','m','d','.','e','x','e','\0'};
```

> **Attention :** `char cmd[] = "cmd.exe"` → VA dans .rodata ! Seule la syntaxe `{'c','m','d'...}` force la stack.

---

## TECHNIQUE 2 : XOR Runtime

**Principe :** Stocker chiffré, déchiffrer à l'exécution.

> **XOR** = opération réversible. `A ^ K = B` et `B ^ K = A`. Même clé pour chiffrer/déchiffrer.

```c
// "cmd.exe" XOR 0x41 (calculé offline)
// 'c'(0x63) ^ 0x41 = 0x22, 'm'(0x6D) ^ 0x41 = 0x2C, etc.
unsigned char enc[] = {0x22, 0x2C, 0x25, 0x6F, 0x24, 0x39, 0x24, 0x00};

// Décodeur simple
void xor_decode(unsigned char* data, int len, unsigned char key) {
    for (int i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

// Utilisation
xor_decode(enc, 7, 0x41);  // enc devient "cmd.exe"
system((char*)enc);
```

**Dans le binaire :** `0x22 0x2C 0x25...` → Charabia pour l'analyste.

> **Limite :** XOR simple = cassable par outils avancés. Pour du vrai maldev → RC4, AES. Mais XOR = bon début.

---

## TECHNIQUE 3 : Macro compile-time

```c
#define KEY 0x55
#define E(c) ((c) ^ KEY)  // Encode à la compilation

char secret[] = {
    E('p'), E('a'), E('s'), E('s'),
    E('w'), E('o'), E('r'), E('d'), '\0'
};

// Runtime : décode
for (int i = 0; secret[i]; i++) secret[i] ^= KEY;
// secret = "password"
```

> **Macro** = remplacement AVANT compilation. `E('p')` devient `('p' ^ 0x55)` → le compilateur stocke le résultat chiffré.

---

## char* vs char[] : LA différence

```c
char* str1 = "Hello";    // Pointeur → .rodata (READ-ONLY)
char str2[] = "Hello";   // Tableau → copié sur stack (MODIFIABLE)
```

```
char* str1 = "Hello"           char str2[] = "Hello"

Stack:                         Stack:
┌──────────┐                   ┌───┬───┬───┬───┬───┬───┐
│ 0x400500 │───┐               │ H │ e │ l │ l │ o │\0 │
└──────────┘   │               └───┴───┴───┴───┴───┴───┘
               ▼                      ↑ MODIFIABLE
.rodata:
┌───┬───┬───┬───┬───┬───┐
│ H │ e │ l │ l │ o │\0 │  ← READ-ONLY
└───┴───┴───┴───┴───┴───┘
```

```c
str1[0] = 'X';  // ❌ SEGFAULT (zone read-only)
str2[0] = 'X';  // ✅ OK → "Xello"
```

> **SEGFAULT** (Segmentation Fault) = accès mémoire interdit. Le kernel te kill.

---

## Fonctions string.h (mémo)

| Besoin | Fonction | Retour | Danger |
|--------|----------|--------|--------|
| Longueur | `strlen(s)` | `size_t` | - |
| Copier | `strcpy(dst, src)` | `dst` | **OVERFLOW** |
| Copier safe | `strncpy(dst, src, n)` | `dst` | Oublie `\0` |
| Concat | `strcat(a, b)` | `a` | **OVERFLOW** |
| Comparer | `strcmp(a, b)` | 0 si égales | - |
| Chercher char | `strchr(s, 'x')` | ptr ou NULL | - |
| Chercher substr | `strstr(s, "sub")` | ptr ou NULL | - |
| Remplir | `memset(p, val, n)` | `p` | - |
| Copier bytes | `memcpy(dst, src, n)` | `dst` | - |

> **`size_t`** = entier non-signé pour les tailles. 64-bit = 8 bytes. Printf : `%zu`.

### Règle d'or

```c
// ❌ JAMAIS
strcpy(buffer, user_input);

// ✅ TOUJOURS
strncpy(buffer, user_input, sizeof(buffer) - 1);
buffer[sizeof(buffer) - 1] = '\0';
```

> **`sizeof(buffer) - 1`** = laisse 1 byte pour `\0`. Buffer de 8 → copie max 7 chars.

---

## Buffer Overflow Express

```c
char buf[8];
strcpy(buf, "AAAAAAAAAAAAAAAAAAAA");  // 20 chars dans 8 bytes
```

```
Stack AVANT:              Stack APRÈS:
┌────────────┐            ┌────────────┐
│ buf[8]     │            │ AAAAAAAA   │
├────────────┤            ├────────────┤
│ RBP        │            │ AAAAAAAA   │ ← ÉCRASÉ
├────────────┤            ├────────────┤
│ RET addr   │            │ AAAA...    │ ← EXPLOIT
└────────────┘            └────────────┘
```

> **RBP** (Base Pointer) = adresse du stack frame précédent.
> **RET addr** = où retourner après la fonction. Contrôle ça → contrôle l'exécution.

→ Détails au Module 18 (Buffer Overflow)

---

## Lecture de strings (input utilisateur)

### scanf - DANGEREUX
```c
char name[50];
scanf("%s", name);        // ❌ Pas de limite → overflow
scanf("%49s", name);      // ✅ Limite à 49 chars + \0
```

### fgets - RECOMMANDÉ
```c
char name[50];
fgets(name, sizeof(name), stdin);         // Limite stricte
name[strcspn(name, "\n")] = '\0';         // Retire le \n
```

> **`strcspn(name, "\n")`** = index du premier `\n` trouvé. On le remplace par `\0`.

---

## Applications offensives

### Command Injection
```c
char cmd[100] = "ping ";
strcat(cmd, user_input);  // ❌ DANGEREUX
system(cmd);

// Si user_input = "127.0.0.1; cat /etc/passwd"
// Exécute : ping 127.0.0.1; cat /etc/passwd
```

### Path Traversal
```c
char path[256] = "/var/www/uploads/";
strcat(path, filename);

// filename = "../../../etc/passwd"
// path = "/var/www/uploads/../../../etc/passwd" = "/etc/passwd"
```

### Timing Attack (comparaison)
```c
// ❌ Vulnérable (strcmp s'arrête au premier char différent)
if (strcmp(password, input) == 0) { ... }

// ✅ Temps constant
int secure_cmp(const char* a, const char* b, size_t len) {
    volatile unsigned char diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff;  // 0 si égales
}
```

> **Timing attack** = mesurer le temps de réponse pour deviner la bonne valeur byte par byte.

---

## Exercices pratiques

### Exo 1 : Audit (2 min)
```bash
gcc -o test test.c
strings test | grep -iE "http|cmd|password|admin|shell"
```
Résultat ? → Applique les techniques pour le cacher.

### Exo 2 : Stack string (5 min)
Construis `"powershell.exe"` invisible au `strings`.

### Exo 3 : XOR encoder (8 min)
```c
void xor_encode(char* data, int len, char key);
void xor_decode(char* data, int len, char key);

// Test : encode puis decode doit retrouver l'original
```

### Exo 4 : String safe copy (5 min)
Écris `safe_strcpy(dst, src, max_len)` qui :
- Copie au max `max_len - 1` chars
- Ajoute TOUJOURS le `\0`
- Retourne le nombre de chars copiés

---

## Checklist

```
□ Je sais ce qu'est .rodata et pourquoi c'est dangereux
□ Je sais construire une stack string
□ Je sais XOR une string au runtime
□ J'ai testé mon binaire avec strings
□ Je comprends char* vs char[]
□ Je n'utilise JAMAIS strcpy() sans limite
```

---

## Glossaire express

| Terme | Définition | Impact |
|-------|------------|--------|
| `.rodata` | Section read-only du binaire | Strings visibles |
| `Stack` | Mémoire runtime temporaire | Stack strings = invisible |
| `\0` | Null byte (0x00) | Fin de string |
| `SEGFAULT` | Accès mémoire interdit | Crash |
| `XOR` | Chiffrement réversible | Cacher strings |
| `size_t` | Type pour les tailles | Non-signé, 8 bytes (64-bit) |
| `RET addr` | Adresse de retour | Overflow → contrôle exec |
| `YARA` | Outil de signatures | Détecte tes strings |

---

## Prochaine étape

**Module suivant →** [09 - Pointeurs Basics](../09_pointers_basics/)

---

**Temps lecture :** 7 min | **Pratique :** 20 min
