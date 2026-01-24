# Exercice : Registres et Instructions x64

## Objectif

Mettre en pratique les connaissances sur les registres x64 et les instructions de base en créant un programme qui effectue des opérations en assembleur inline.

---

## Exercice 1 : Manipulation de registres (Facile)

Écris une fonction `swap_registres` qui échange les valeurs de deux variables en utilisant uniquement des instructions assembleur (sans variable temporaire C).

```c
void swap_registres(uint64_t *a, uint64_t *b) {
    // Utilise XOR ou XCHG en assembleur inline
    // pour échanger *a et *b
}
```

**Indice** : Tu peux utiliser soit `xchg`, soit la technique XOR swap :
```
XOR A, B
XOR B, A  
XOR A, B
```

---

## Exercice 2 : Calcul optimisé avec LEA (Moyen)

Écris une fonction `calcul_lea` qui calcule `(x * 7) + 15` en utilisant uniquement des instructions LEA (pas de MUL ou IMUL).

```c
uint64_t calcul_lea(uint64_t x) {
    uint64_t resultat;
    // Utilise LEA pour calculer x*7 + 15
    // Rappel : x*7 = x + x*2 + x*4 = x*8 - x
    return resultat;
}
```

---

## Exercice 3 : Compteur de bits à 1 (Moyen)

Implémente une fonction `popcount_asm` qui compte le nombre de bits à 1 dans un entier 64 bits, en utilisant des instructions assembleur.

```c
int popcount_asm(uint64_t valeur) {
    int count;
    // Utilise une boucle avec SHR et ADD
    // ou l'instruction POPCNT si disponible
    return count;
}
```

**Méthode avec boucle** :
1. Initialiser un compteur à 0
2. Tant que la valeur n'est pas 0 :
   - Si le bit de poids faible est 1, incrémenter le compteur
   - Décaler la valeur vers la droite
3. Retourner le compteur

---

## Exercice 4 : Détecteur d'overflow (Avancé)

Écris une fonction qui additionne deux entiers et détecte si un overflow s'est produit en vérifiant le flag OF (Overflow Flag).

```c
typedef struct {
    uint64_t resultat;
    int overflow;   // 1 si overflow, 0 sinon
} AddResult;

AddResult addition_safe(int64_t a, int64_t b) {
    AddResult res;
    // Effectue l'addition
    // Vérifie le flag OF avec SETO
    return res;
}
```

---

## Exercice 5 : Mini-décodeur XOR (Avancé)

Crée un décodeur XOR qui :
1. Prend une chaîne encodée et une clé
2. Décode la chaîne en place
3. Utilise uniquement de l'assembleur inline

```c
void xor_decode(unsigned char *data, size_t len, unsigned char key) {
    // Implémente la boucle de décodage en assembleur
    // XOR chaque byte avec la clé
}

// Test
int main() {
    unsigned char encoded[] = {0x2B, 0x26, 0x23, 0x37, 0x26, 0x37, 0x00}; // "secret" ^ 0x41
    xor_decode(encoded, 6, 0x41);
    printf("Décodé: %s\n", encoded);  // Devrait afficher "secret"
}
```

---

## Critères de réussite

- [ ] Exercice 1 : Les valeurs sont correctement échangées
- [ ] Exercice 2 : Le calcul est correct pour plusieurs valeurs de test
- [ ] Exercice 3 : Le compte de bits est exact
- [ ] Exercice 4 : L'overflow est correctement détecté
- [ ] Exercice 5 : La chaîne est correctement décodée

---

## Compilation

```bash
# Avec GCC (syntaxe Intel)
gcc -o exercice exercice.c -masm=intel

# Avec debug symbols
gcc -g -o exercice exercice.c -masm=intel

# Pour voir l'assembleur généré
gcc -S -masm=intel exercice.c -o exercice.s
```

---

## Bonus : Analyse de code

Compile ton programme avec l'option `-S` et analyse le code assembleur généré par GCC. Compare-le avec ton code inline assembleur.

```bash
gcc -S -O0 -masm=intel -fno-asynchronous-unwind-tables exercice.c
```
