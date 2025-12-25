# Solutions Quiz Complet - Module 00

---

## Section A : Systèmes de Numération

### A1. 0xCAFE en décimal
**51966**
- C(12)×4096 + A(10)×256 + F(15)×16 + E(14)×1
- = 49152 + 2560 + 240 + 14 = 51966

### A2. 173 en binaire
**10101101**
- 173 = 128+32+8+4+1 = 10101101

### A3. 10110011 en hexadécimal
**0xB3**
- 1011 = B, 0011 = 3

### A4. Espace adressable 32 bits
**4 GB (4 294 967 296 bytes)**
- 2^32 = 4 294 967 296

### A5. 0xF0 XOR 0x0F
**0xFF**
- 11110000 XOR 00001111 = 11111111

### A6. 0x12345678 en little-endian
**78 56 34 12**
- Byte de poids faible en premier

### A7. Valeur max d'un byte non signé
**255**
- 2^8 - 1 = 255

### A8. 52 6F 6F 74 en ASCII
**"Root"**
- 52='R', 6F='o', 6F='o', 74='t'

### A9. Magic bytes 4D 5A
**Exécutable Windows (PE/MZ)**
- "MZ" = Mark Zbikowski

---

## Section B : Le Processeur

### B1. Registre de la prochaine instruction
**EIP (ou RIP en 64 bits)**
- Extended Instruction Pointer

### B2. Registre du sommet de pile
**ESP (ou RSP en 64 bits)**
- Extended Stack Pointer

### B3. Flag si EAX == EBX
**ZF (Zero Flag)**
- CMP fait EAX - EBX, si égaux le résultat est 0, donc ZF=1

### B4. Différence MOV vs PUSH
**MOV copie une valeur vers une destination. PUSH empile sur la stack (décrémente ESP puis écrit).**

### B5. XOR EAX, EAX
**Met EAX à zéro** (tout nombre XOR lui-même = 0)
- Plus compact que MOV EAX, 0

### B6. Cycle fetch-decode-execute
1. **Fetch** : Lire l'instruction à l'adresse EIP depuis la mémoire
2. **Decode** : Interpréter l'instruction (opcode, opérandes)
3. **Execute** : Effectuer l'opération et mettre à jour EIP

### B7. Convention cdecl
- Arguments empilés de **droite à gauche**
- L'**appelant** nettoie la pile après le retour
- Valeur de retour dans **EAX**

---

## Section C : La Mémoire

### C1. 5 segments principaux
1. **TEXT** (code exécutable)
2. **DATA** (données initialisées)
3. **BSS** (données non initialisées)
4. **HEAP** (allocation dynamique)
5. **STACK** (pile)

### C2. Direction de croissance de la pile
**Vers les adresses basses** (vers le bas)

### C3. Direction de croissance du heap
**Vers les adresses hautes** (vers le haut)

### C4. Variables globales initialisées
**Segment DATA**

### C5. Variables locales d'une fonction
**Sur la STACK** (pile)

### C6. Contenu d'une stack frame
1. Arguments de la fonction
2. Adresse de retour
3. EBP sauvegardé (ancien base pointer)
4. Variables locales
5. (Optionnel : canary de protection)

### C7. ASLR
**Address Space Layout Randomization**
- Randomise les adresses de chargement des segments en mémoire
- Empêche l'attaquant de prédire les adresses
- Protection contre les exploits utilisant des adresses codées en dur

### C8. Buffer overflow et redirection
1. L'attaquant fournit plus de données que le buffer ne peut contenir
2. Les données débordent et écrasent les zones adjacentes en mémoire
3. Sur la pile, après le buffer se trouve l'EBP sauvegardé puis l'adresse de retour
4. En écrasant l'adresse de retour avec une adresse contrôlée
5. Quand la fonction fait RET, le CPU saute à l'adresse de l'attaquant
6. → Exécution de code arbitraire (shellcode, ROP chain, etc.)

---

## Section D : Le Système d'Exploitation

### D1. Qu'est-ce qu'un processus ?
**Un programme en cours d'exécution** avec son propre espace d'adressage, ses ressources (fichiers ouverts, etc.) et son contexte d'exécution.

### D2. Ring 0 vs Ring 3
- **Ring 0** : Mode noyau, accès complet au matériel, toutes les instructions
- **Ring 3** : Mode utilisateur, accès limité, doit utiliser les syscalls

### D3. Appel système (syscall)
**Interface permettant aux programmes utilisateur de demander des services au noyau** (lecture fichier, création processus, allocation mémoire, etc.)
- Transition Ring 3 → Ring 0

### D4. /proc/[pid]/maps
**Les mappages mémoire du processus** : régions de mémoire virtuelle, permissions, et fichiers mappés (bibliothèques, etc.)

### D5. Bit SUID
**Le programme s'exécute avec les privilèges du propriétaire** (souvent root), pas de l'utilisateur qui le lance.
- Cible classique pour l'élévation de privilèges

### D6. 3 méthodes IPC
(3 parmi) :
- Pipes / Named pipes (FIFO)
- Sockets
- Shared memory
- Message queues
- Signaux
- Semaphores

### D7. Mémoire virtuelle et sécurité
- **Isolation** : chaque processus a son propre espace d'adressage
- Un processus ne peut pas accéder à la mémoire d'un autre
- Empêche la lecture/modification des données d'autres processus
- Permet au noyau de contrôler les permissions (R/W/X)

---

## Section E : Compilation et Exécution

### E1. 4 étapes de compilation
1. **Préprocesseur** (traite #include, #define)
2. **Compilateur** (C → assembleur)
3. **Assembleur** (assembleur → code objet)
4. **Éditeur de liens** (objets → exécutable)

### E2. Rôle du préprocesseur
- Traite les directives `#include` (inclusion de fichiers)
- Traite les `#define` (remplacement de macros)
- Gère la compilation conditionnelle (`#ifdef`, `#endif`)
- Supprime les commentaires

### E3. Liaison statique vs dynamique
- **Statique** : tout le code des bibliothèques est inclus dans l'exécutable (gros fichier, autonome)
- **Dynamique** : seules les références sont incluses, les bibliothèques sont chargées à l'exécution (petit fichier, dépendances)

### E4. GOT (Global Offset Table)
**Table contenant les adresses des fonctions des bibliothèques dynamiques.**
- Initialement contient l'adresse du résolveur
- Remplie avec les vraies adresses après résolution
- Cible d'exploitation : écraser une entrée = rediriger les appels

### E5. Magic 7F 45 4C 46
**Fichier ELF** (Executable and Linkable Format)
- 0x7F suivi de "ELF" en ASCII
- Format exécutable de Linux/Unix

### E6. gcc -S source.c
**Compile jusqu'à l'assembleur** et s'arrête
- Produit un fichier .s contenant le code assembleur
- Utile pour étudier ce que le compilateur génère

---

## Barème de Notation

| Section | Points Possibles |
|---------|------------------|
| A1 | 2 |
| A2 | 2 |
| A3 | 2 |
| A4 | 2 |
| A5 | 2 |
| A6 | 2 |
| A7 | 2 |
| A8 | 3 |
| A9 | 3 |
| **Total A** | **20** |
| B1 | 2 |
| B2 | 2 |
| B3 | 2 |
| B4 | 3 |
| B5 | 3 |
| B6 | 4 |
| B7 | 4 |
| **Total B** | **20** |
| C1 | 2 |
| C2 | 2 |
| C3 | 2 |
| C4 | 3 |
| C5 | 3 |
| C6 | 4 |
| C7 | 4 |
| C8 | 5 |
| **Total C** | **25** |
| D1 | 2 |
| D2 | 2 |
| D3 | 3 |
| D4 | 3 |
| D5 | 3 |
| D6 | 3 |
| D7 | 4 |
| **Total D** | **20** |
| E1 | 2 |
| E2 | 2 |
| E3 | 3 |
| E4 | 3 |
| E5 | 2 |
| E6 | 3 |
| **Total E** | **15** |
| **TOTAL GÉNÉRAL** | **100** |

---

## Navigation

| Retour | Module suivant |
|--------|----------------|
| [Exercice 04](../exercices/exercice-04.md) | [Module 01](../../module-01-premier-contact/) |
