# Solutions Exercice 03 : Analyse de Stack

---

## Partie 1 : Schématisation de Stack Frames

```
┌─────────────────────────────────────────────────┐  Adresses hautes
│                STACK FRAME DE main               │
│  ┌────────────────────────────────────────────┐ │
│  │  var_main = 5                 [EBP_main-4] │ │
│  │  EBP sauvegardé (de _start)               │ │← EBP_main
│  │  Adresse retour vers _start               │ │
│  └────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────┤
│              STACK FRAME DE fonction_a           │
│  ┌────────────────────────────────────────────┐ │
│  │  var_main (arg n = 5)           [EBP_a+8] │ │
│  │  Adresse retour vers main       [EBP_a+4] │ │
│  │  EBP_main sauvegardé            [EBP_a]   │ │← EBP_a
│  │  local_a = 10                   [EBP_a-4] │ │
│  └────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────┤
│              STACK FRAME DE fonction_b           │
│  ┌────────────────────────────────────────────┐ │
│  │  n = 5 (arg y)                  [EBP_b+12]│ │
│  │  local_a = 10 (arg x)           [EBP_b+8] │ │
│  │  Adresse retour vers fonction_a [EBP_b+4] │ │
│  │  EBP_a sauvegardé               [EBP_b]   │ │← EBP_b
│  │  local_b = 15                   [EBP_b-4] │ │← ESP
│  └────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────┘  Adresses basses
```

### Réponses :

1. **Combien de stack frames actives ?**
   - **3 stack frames** : main, fonction_a, fonction_b

2. **Ordre des arguments (cdecl) :**
   - Empilés de **droite à gauche**
   - `n` (5) empilé d'abord, puis `local_a` (10)
   - Donc en mémoire : `local_a` est à l'adresse plus basse (plus proche de EBP)

3. **Où est local_a par rapport à EBP de fonction_a ?**
   - À **[EBP_a - 4]**

4. **Où est l'adresse de retour de fonction_b ?**
   - À **[EBP_b + 4]**

---

## Partie 2 : Lecture d'une Stack Frame

```
Adresse      Valeur         Description
──────────────────────────────────────────────
0xFFFFD000:  0x00000005     Argument 2 (y = 5)
0xFFFFD004:  0x00000003     Argument 1 (x = 3)
0xFFFFD008:  0x0804850A     Adresse de retour
0xFFFFD00C:  0xFFFFD028     EBP sauvegardé ← EBP pointe ici
0xFFFFD010:  0x00000008     Variable locale 1 [EBP-4] ← ESP
0xFFFFD014:  0xDEADBEEF     Variable locale 2 [EBP-8]
0xFFFFD018:  0x00000000     Variable locale 3 [EBP-12]
```

### Réponses :

1. **Adresse de retour :**
   - **0x0804850A** (à [EBP+4] = 0xFFFFD008)

2. **Arguments passés :**
   - Argument 1 : **3** (à [EBP+8])
   - Argument 2 : **5** (à [EBP+12])

3. **Première variable locale [EBP-4] :**
   - **8** (0x00000008)

4. **L'ancien EBP pointe vers :**
   - **0xFFFFD028** (EBP de la fonction appelante)

---

## Partie 3 : Calcul d'Offsets

```
EBP = 0xFFFFD100

┌────────────────────────┐
│    Argument 3          │  0xFFFFD110 [EBP + 16]
│    Argument 2          │  0xFFFFD10C [EBP + 12]
│    Argument 1          │  0xFFFFD108 [EBP + 8]
│    Adresse retour      │  0xFFFFD104 [EBP + 4]
│    EBP sauvegardé      │  0xFFFFD100 [EBP]
│    Variable locale 1   │  0xFFFFD0FC [EBP - 4]
│    Variable locale 2   │  0xFFFFD0F8 [EBP - 8]
│    Buffer[20]          │  0xFFFFD0E4 [EBP - 28] début
│      ...               │
│    (fin du buffer)     │  0xFFFFD0F7 [EBP - 9]
└────────────────────────┘
```

### Réponses :

1. **Adresse de l'argument 1 :**
   - EBP + 8 = 0xFFFFD100 + 8 = **0xFFFFD108**

2. **Adresse du début du buffer :**
   - EBP - 28 = 0xFFFFD100 - 0x1C = **0xFFFFD0E4**

3. **Bytes entre buffer et adresse de retour :**
   - Buffer commence à EBP - 28
   - Adresse de retour à EBP + 4
   - Distance = 28 + 4 = **32 bytes**

4. **Si on écrit 40 bytes depuis le buffer :**
   - 20 bytes : remplissent le buffer
   - 8 bytes : écrasent les variables locales
   - 4 bytes : écrasent l'EBP sauvegardé
   - 4 bytes : écrasent l'adresse de retour
   - 4 bytes : écrasent l'argument 1

---

## Partie 4 : Buffer Overflow Théorique

```
┌────────────────────────┐
│    *input (argument)   │  [EBP + 8]
│    Adresse retour      │  [EBP + 4]
│    EBP sauvegardé      │  [EBP]
│    buffer[64]          │  [EBP - 64] début
│                        │  [EBP - 1]  fin
└────────────────────────┘
```

### Réponses :

1. **Bytes pour atteindre EBP sauvegardé :**
   - Buffer de 64 bytes
   - **64 bytes** pour remplir le buffer, puis on atteint EBP

2. **Bytes pour atteindre l'adresse de retour :**
   - 64 bytes (buffer) + 4 bytes (EBP) = **68 bytes**

3. **Chaîne pour écraser avec 0xDEADBEEF :**
   ```
   [64 bytes de padding] + [4 bytes EBP] + [0xDEADBEEF]
   = "A" × 68 + "\xEF\xBE\xAD\xDE"
   ```
   En notation Python :
   ```python
   payload = b"A" * 68 + b"\xEF\xBE\xAD\xDE"
   ```

4. **Ordre en little-endian :**
   - 0xDEADBEEF s'écrit : **\xEF\xBE\xAD\xDE**
   - Le byte de poids faible (0xEF) en premier

---

## Partie 5 : Stack Canaries

```
┌────────────────────────┐
│    Argument            │
│    Adresse retour      │
│    EBP sauvegardé      │
│    Canary (0x12345600) │  ← Protection
│    buffer[64]          │
└────────────────────────┘
```

### Réponses :

1. **Pourquoi un byte NULL dans le canary ?**
   - Empêche les fonctions comme `strcpy()` de continuer à copier
   - `strcpy` s'arrête au premier NULL (0x00)
   - L'attaquant ne peut pas simplement écrire la vraie valeur du canary
   - Protège contre les overflows basés sur les chaînes de caractères

2. **Bytes pour écraser le canary :**
   - Buffer de 64 bytes
   - **64 bytes** pour atteindre le canary

3. **Détection de l'overflow :**
   - Avant le `ret`, le compilateur génère du code qui vérifie le canary
   - Compare la valeur actuelle avec la valeur originale (stockée ailleurs)
   - Si différente → appel à `__stack_chk_fail()` → programme terminé

4. **Contournements possibles :**
   - **Fuite d'information** : lire le canary via une vulnérabilité format string
   - **Brute force** : Deviner le canary (rare, mais possible sur certains systèmes)
   - **Écrasement non-linéaire** : Si on peut écrire à une adresse arbitraire
   - **Fork servers** : Le canary reste identique dans les processus forkés

---

## Partie 6 : Exercice de Synthèse

```
ESP = 0xffffd0f0
EBP = 0xffffd108

0xffffd0f0: 0x00000001 0x00000002 0x00000003 0x00000004  [ESP]
0xffffd100: 0x00000005 0x41414141 0xffffd128 0x08048490  [EBP-8]
            ↑local2    ↑local1?   ↑EBP svgd  ↑ret addr   [EBP][EBP+4]
0xffffd110: 0x0000000a 0x00000014 ...                    [EBP+8][EBP+12]
            ↑arg1(10)  ↑arg2(20)
```

### Réponses :

1. **EBP sauvegardé dans le dump :**
   - À l'adresse 0xffffd108 (là où EBP pointe)
   - Valeur = **0xffffd128**

2. **Adresse de retour :**
   - À EBP+4 = 0xffffd10C
   - Valeur = **0x08048490**

3. **0x41414141 représente :**
   - 0x41 = 'A' en ASCII
   - **"AAAA"** - typiquement un padding de test pour overflow
   - C'est à [EBP-4], donc une variable locale

4. **Variables locales entre ESP et EBP :**
   - ESP = 0xffffd0f0
   - EBP = 0xffffd108
   - Différence = 0x18 = 24 bytes
   - **6 variables de 4 bytes** (ou un mélange de tailles)

5. **Deux premiers arguments :**
   - Argument 1 [EBP+8] = **10** (0x0000000a)
   - Argument 2 [EBP+12] = **20** (0x00000014)

---

## Schéma Récapitulatif

```
         Adresses hautes
              │
              ▼
┌────────────────────────────────┐
│  Arguments (empilés RTL)       │
│  arg2, arg1                    │
├────────────────────────────────┤
│  Adresse de retour             │  ← Cible du buffer overflow
├────────────────────────────────┤
│  EBP sauvegardé                │  ← EBP pointe ici
├────────────────────────────────┤
│  [Canary si activé]            │  ← Protection
├────────────────────────────────┤
│  Variables locales             │
│  (croissent vers le bas)       │
├────────────────────────────────┤
│  Buffer                        │  ← Point d'entrée overflow
│  (adresse la plus basse)       │  ← ESP après allocation
└────────────────────────────────┘
              │
              ▼
        Adresses basses
```

---

## Navigation

| Retour | Exercice suivant |
|--------|------------------|
| [Exercice 03](../exercices/exercice-03.md) | [Exercice 04 - Quiz](../exercices/exercice-04.md) |
