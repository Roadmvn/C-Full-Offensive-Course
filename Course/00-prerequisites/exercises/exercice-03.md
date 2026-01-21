# Exercice 03 : Analyse de Stack

## Objectif
Comprendre l'organisation de la pile (stack) et les stack frames.

---

## Partie 1 : Schématisation de Stack Frames

Pour le code suivant, dessinez l'état de la pile après l'appel à `fonction_b` :

```c
void fonction_b(int x, int y) {
    int local_b = x + y;
    // ← État de la pile à analyser ici
}

void fonction_a(int n) {
    int local_a = 10;
    fonction_b(local_a, n);
}

int main() {
    int var_main = 5;
    fonction_a(var_main);
    return 0;
}
```

Questions :
1. Combien de stack frames sont actives ?
2. Dans quel ordre sont empilés les arguments de `fonction_b` (cdecl) ?
3. Où se trouve `local_a` par rapport à EBP de `fonction_a` ?
4. Où se trouve l'adresse de retour de `fonction_b` ?

---

## Partie 2 : Lecture d'une Stack Frame

Voici un dump de la pile pendant l'exécution d'une fonction :

```
Adresse      Valeur         Description
──────────────────────────────────────────────
0xFFFFD000:  0x00000005     ?
0xFFFFD004:  0x00000003     ?
0xFFFFD008:  0x0804850A     ?
0xFFFFD00C:  0xFFFFD028     ?
0xFFFFD010:  0x00000008     ?
0xFFFFD014:  0xDEADBEEF     ?
0xFFFFD018:  0x00000000     ?

EBP = 0xFFFFD00C
ESP = 0xFFFFD010
```

Sachant qu'on est dans une fonction avec ce prologue :
```nasm
push ebp
mov ebp, esp
sub esp, 12       ; Espace pour 3 variables locales (4 bytes chacune)
```

Questions :
1. Quelle est l'adresse de retour ?
2. Quels sont les deux arguments passés à la fonction ?
3. Quelle est la valeur de la première variable locale ([EBP-4]) ?
4. L'ancien EBP sauvegardé pointe vers où ?

---

## Partie 3 : Calcul d'Offsets

Pour cette structure de stack frame :

```
┌────────────────────────┐  Adresses hautes
│    Argument 3          │  [EBP + 16]
│    Argument 2          │  [EBP + 12]
│    Argument 1          │  [EBP + 8]
│    Adresse retour      │  [EBP + 4]
│    EBP sauvegardé      │  [EBP]      ← EBP pointe ici
│    Variable locale 1   │  [EBP - 4]
│    Variable locale 2   │  [EBP - 8]
│    Buffer[20]          │  [EBP - 28]
└────────────────────────┘  Adresses basses ← ESP
```

Questions :
1. Si EBP = 0xFFFFD100, quelle est l'adresse de l'argument 1 ?
2. Quelle est l'adresse du début du buffer ?
3. Combien de bytes séparent le début du buffer de l'adresse de retour ?
4. Si on écrit 40 bytes dans le buffer, que va-t-on écraser ?

---

## Partie 4 : Buffer Overflow Théorique

Considérez ce code vulnérable :

```c
void vulnerable(char *input) {
    char buffer[64];
    strcpy(buffer, input);
}
```

Stack frame de `vulnerable` :

```
┌────────────────────────┐
│    *input (argument)   │  [EBP + 8]
│    Adresse retour      │  [EBP + 4]
│    EBP sauvegardé      │  [EBP]
│    buffer[64]          │  [EBP - 64]
└────────────────────────┘  ← ESP
```

Questions :
1. Combien de bytes faut-il écrire pour atteindre l'EBP sauvegardé ?
2. Combien de bytes pour atteindre l'adresse de retour ?
3. Si on veut écraser l'adresse de retour avec `0xDEADBEEF`, quelle chaîne envoyer ? (en notation)
4. Comment la chaîne doit-elle être ordonnée en mémoire (little-endian) ?

---

## Partie 5 : Stack Canaries

Les canaries protègent contre les buffer overflows :

```
┌────────────────────────┐
│    Argument            │  [EBP + 8]
│    Adresse retour      │  [EBP + 4]
│    EBP sauvegardé      │  [EBP]
│    Canary (0x12345600) │  [EBP - 4]
│    buffer[64]          │  [EBP - 68]
└────────────────────────┘
```

Questions :
1. Pourquoi le canary contient-il souvent un byte NULL (0x00) ?
2. Combien de bytes faut-il pour écraser le canary depuis le buffer ?
3. Comment le système détecte-t-il qu'un overflow a eu lieu ?
4. Comment un attaquant pourrait-il contourner cette protection ?

---

## Partie 6 : Exercice de Synthèse

Analysez cette trace d'exécution GDB :

```
(gdb) info registers
eax            0x5
ebx            0xf7fa7000
ecx            0xffffd140
edx            0xffffd164
esp            0xffffd0f0
ebp            0xffffd108
esi            0x0
edi            0x0
eip            0x8048456

(gdb) x/20x $esp
0xffffd0f0: 0x00000001 0x00000002 0x00000003 0x00000004
0xffffd100: 0x00000005 0x41414141 0xffffd128 0x08048490
0xffffd110: 0x0000000a 0x00000014 0xf7fa7000 0x00000000
0xffffd120: 0x00000000 0xf7e1a286 0x00000001 0xffffd1b4
0xffffd130: 0xffffd1bc 0x00000000 0x00000000 0x00000000
```

Questions :
1. Où se trouve le EBP sauvegardé dans le dump ?
2. Quelle est l'adresse de retour de la fonction courante ?
3. Que représente la valeur 0x41414141 ?
4. Combien de variables locales de 4 bytes sont entre ESP et le EBP sauvegardé ?
5. Quelles sont les valeurs des deux premiers arguments de la fonction ?

---

## Auto-évaluation

Avant de voir les solutions :

- [ ] Vous comprenez l'ordre d'empilement (arguments, retour, EBP, locales)
- [ ] Vous savez calculer les offsets par rapport à EBP
- [ ] Vous comprenez comment un buffer overflow écrase l'adresse de retour
- [ ] Vous connaissez le rôle des stack canaries

---

## Solutions

→ Voir [../solutions/solution-03.md](../solutions/solution-03.md)
