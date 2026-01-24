# Exercice 04 : Quiz Complet - Module 00

## Instructions
Ce quiz couvre tous les concepts du Module 00. Répondez sans regarder les cours. Un score de 80% ou plus indique que vous êtes prêt pour le Module 01.

---

## Section A : Systèmes de Numération (20 points)

### A1. (2 pts) Convertissez 0xCAFE en décimal.

### A2. (2 pts) Convertissez 173 en binaire (8 bits).

### A3. (2 pts) Convertissez 10110011 en hexadécimal.

### A4. (2 pts) Combien de bytes peut adresser un système 32 bits ?

### A5. (2 pts) Quel est le résultat de 0xF0 XOR 0x0F ?

### A6. (2 pts) En little-endian, comment est stocké 0x12345678 ?

### A7. (2 pts) Quelle est la valeur maximale d'un byte non signé ?

### A8. (3 pts) Décodez cette séquence ASCII : 52 6F 6F 74

### A9. (3 pts) Quel type de fichier commence par 4D 5A ?

---

## Section B : Le Processeur (20 points)

### B1. (2 pts) Quel registre contient l'adresse de la prochaine instruction ?

### B2. (2 pts) Quel registre pointe vers le sommet de la pile ?

### B3. (2 pts) Après CMP EAX, EBX, quel flag est mis à 1 si EAX == EBX ?

### B4. (3 pts) Quelle est la différence entre MOV et PUSH ?

### B5. (3 pts) Que fait l'instruction "XOR EAX, EAX" ?

### B6. (4 pts) Expliquez le cycle fetch-decode-execute en 3 étapes.

### B7. (4 pts) En convention cdecl, comment sont passés les arguments ?

---

## Section C : La Mémoire (25 points)

### C1. (2 pts) Nommez les 5 segments principaux de la mémoire d'un processus.

### C2. (2 pts) Dans quelle direction croît la pile (stack) ?

### C3. (2 pts) Dans quelle direction croît le tas (heap) ?

### C4. (3 pts) Où sont stockées les variables globales initialisées ?

### C5. (3 pts) Où sont stockées les variables locales d'une fonction ?

### C6. (4 pts) Qu'est-ce qui est stocké dans une stack frame ?
Liste au moins 4 éléments.

### C7. (4 pts) Qu'est-ce que l'ASLR et quel problème résout-il ?

### C8. (5 pts) Expliquez comment un buffer overflow sur la pile permet de rediriger l'exécution.

---

## Section D : Le Système d'Exploitation (20 points)

### D1. (2 pts) Qu'est-ce qu'un processus ?

### D2. (2 pts) Quelle est la différence entre Ring 0 et Ring 3 ?

### D3. (3 pts) Qu'est-ce qu'un appel système (syscall) ?

### D4. (3 pts) Que contient /proc/[pid]/maps sur Linux ?

### D5. (3 pts) Que signifie le bit SUID sur un exécutable Linux ?

### D6. (3 pts) Nommez 3 méthodes de communication inter-processus (IPC).

### D7. (4 pts) Pourquoi la mémoire virtuelle est-elle importante pour la sécurité ?

---

## Section E : Compilation et Exécution (15 points)

### E1. (2 pts) Quelles sont les 4 étapes de la compilation C ?

### E2. (2 pts) Que fait le préprocesseur ?

### E3. (3 pts) Quelle est la différence entre liaison statique et dynamique ?

### E4. (3 pts) Qu'est-ce que la GOT (Global Offset Table) ?

### E5. (2 pts) Que signifie le magic number 7F 45 4C 46 ?

### E6. (3 pts) Que fait la commande "gcc -S source.c" ?

---

## Barème

| Section | Points | Votre Score |
|---------|--------|-------------|
| A - Numération | 20 | ___ |
| B - Processeur | 20 | ___ |
| C - Mémoire | 25 | ___ |
| D - Système | 20 | ___ |
| E - Compilation | 15 | ___ |
| **Total** | **100** | ___ |

**Interprétation :**
- 90-100 : Excellent, prêt pour le Module 01
- 80-89 : Bien, quelques révisions recommandées
- 70-79 : Correct, revoir les sections faibles
- < 70 : Retravailler le Module 00 avant de continuer

---

## Solutions

→ Voir [../solutions/solution-04.md](../solutions/solution-04.md)
