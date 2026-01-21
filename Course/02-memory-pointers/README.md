# Semaine 2 : Memory & Pointers

## Objectif de la semaine

A la fin de cette semaine, tu sauras :
- Comprendre ce qu'est un pointeur et une adresse memoire
- Utiliser l'arithmetique des pointeurs
- Manipuler les tableaux via pointeurs
- Allouer et liberer de la memoire dynamiquement
- Manipuler les chaines de caracteres

## Prerequis

- Semaine 1 validee (quiz >= 8/10)
- Comprendre variables, boucles, fonctions

## Contenu

### Lessons

| Fichier | Sujet | Duree |
|---------|-------|-------|
| `01-pointers-basics.c` | Adresses, declaration, dereferencement | 30 min |
| `02-pointer-arithmetic.c` | Navigation memoire, ptr+1 | 25 min |
| `03-arrays.c` | Relation tableaux/pointeurs | 25 min |
| `04-malloc-free.c` | Allocation dynamique | 30 min |
| `05-strings.c` | Chaines de caracteres, XOR | 30 min |

### Exercices

| Fichier | Difficulte | Description |
|---------|------------|-------------|
| `ex01-swap.c` | ⭐ | Echanger deux valeurs via pointeurs |
| `ex02-array-sum.c` | ⭐⭐ | Somme avec arithmetique pointeurs |
| `ex03-xor-buffer.c` | ⭐⭐⭐ | Chiffrement XOR (technique maldev) |

## Concepts cles

### Operateurs
```c
&variable  // Adresse de (donne un pointeur)
*pointeur  // Dereferencement (donne la valeur)
```

### Allocation
```c
int* p = malloc(n * sizeof(int));  // Alloue
free(p);                            // Libere
p = NULL;                           // Securise
```

### Equivalences
```c
tab[i]  ==  *(tab + i)
&tab[i] ==  tab + i
```

## Lien avec le maldev

| Concept | Usage maldev |
|---------|--------------|
| Pointeurs | Manipulation shellcode, structures PE |
| malloc | Allocation buffer pour payload |
| XOR string | Obfuscation de strings (ex03) |
| Arithmetique | Parsing headers binaires |

## Checklist

- [ ] Lu et compile les 5 lessons
- [ ] Exercice swap complete
- [ ] Exercice array-sum complete
- [ ] Exercice xor-buffer complete
- [ ] Quiz >= 8/10
- [ ] Je comprends & et *
- [ ] Je sais utiliser malloc/free

## Quiz

```bash
python ../../scripts/quiz-runner.py quiz.json
```

---

Temps estime : **5-7 heures**

Prochaine semaine : **Structures et Fichiers**
