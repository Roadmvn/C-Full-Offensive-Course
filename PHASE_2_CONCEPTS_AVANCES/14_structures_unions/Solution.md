SOLUTION EXERCICE 1 : Première structure
```c

```c
#include <stdio.h>
```

struct Rectangle {
    int largeur;
    int hauteur;
};


```c
int main() {
```
    struct Rectangle rect;
    rect.largeur = 10;
    rect.hauteur = 5;

    printf("Rectangle:\n");
    printf("Largeur: %d\n", rect.largeur);
    printf("Hauteur: %d\n", rect.hauteur);

    return 0;
}
```

SOLUTION EXERCICE 2 : Structure avec typedef
```c

```c
#include <stdio.h>
#include <string.h>
```


```c
typedef struct {
    char marque[50];
    char modele[50];
    int annee;
} Voiture;
```


```c
int main() {
```
    Voiture v1, v2;

    strcpy(v1.marque, "Toyota");
    strcpy(v1.modele, "Corolla");
    v1.annee = 2020;

    strcpy(v2.marque, "Honda");
    strcpy(v2.modele, "Civic");
    v2.annee = 2022;

    printf("Voiture 1: %s %s (%d)\n", v1.marque, v1.modele, v1.annee);
    printf("Voiture 2: %s %s (%d)\n", v2.marque, v2.modele, v2.annee);

    return 0;
}
```

SOLUTION EXERCICE 3 : Pointeur vers structure
```c

```c
#include <stdio.h>
```


```c
typedef struct {
    int numero;
```
    float solde;
} Compte;


```c
int main() {
```
    Compte compte1;
    compte1.numero = 12345;
    compte1.solde = 1500.50;

    Compte *ptr = &compte1;

    printf("Numéro de compte: %d\n", ptr->numero);
    printf("Solde: %.2f€\n", ptr->solde);

    return 0;
}
```

SOLUTION EXERCICE 4 : Fonction avec structure
```c

```c
#include <stdio.h>
```

struct Rectangle {
    int largeur;
    int hauteur;
};

int calculer_aire(struct Rectangle r) {
    return r.largeur * r.hauteur;
}


```c
int main() {
```
    struct Rectangle rect = {15, 10};

    int aire = calculer_aire(rect);
    printf("Aire du rectangle: %d\n", aire);

    return 0;
}
```

SOLUTION EXERCICE 5 : Modifier via pointeur
```c

```c
#include <stdio.h>
```


```c
typedef struct {
    int numero;
```
    float solde;
} Compte;


```c
void deposer(Compte *c, float montant) {
```
    c->solde += montant;
}


```c
void retirer(Compte *c, float montant) {
```
    if (c->solde >= montant) {
        c->solde -= montant;
    } else {
        printf("Solde insuffisant\n");
    }
}


```c
int main() {
```
    Compte compte = {12345, 1000.0};

    printf("Solde initial: %.2f€\n", compte.solde);

    deposer(&compte, 500.0);
    printf("Après dépôt: %.2f€\n", compte.solde);

    retirer(&compte, 200.0);
    printf("Après retrait: %.2f€\n", compte.solde);

    return 0;
}
```

SOLUTION EXERCICE 6 : Structure imbriquée
```c

```c
#include <stdio.h>
#include <string.h>
```


```c
typedef struct {
    int jour;
    int mois;
    int annee;
} Date;
```


```c
typedef struct {
    char nom[100];
```
    Date date;
} Evenement;


```c
int main() {
```
    Evenement evt;
    strcpy(evt.nom, "Anniversaire");
    evt.date.jour = 15;
    evt.date.mois = 8;
    evt.date.annee = 2024;

    printf("Événement: %s\n", evt.nom);
    printf("Date: %02d/%02d/%d\n",
           evt.date.jour, evt.date.mois, evt.date.annee);

    return 0;
}
```

SOLUTION EXERCICE 7 : Tableau de structures
```c

```c
#include <stdio.h>
#include <string.h>
```


```c
typedef struct {
    char nom[50];
```
    float note;
} Etudiant;


```c
int main() {
```
    Etudiant classe[5];

    strcpy(classe[0].nom, "Alice");
    classe[0].note = 15.5;

    strcpy(classe[1].nom, "Bob");
    classe[1].note = 12.0;

    strcpy(classe[2].nom, "Charlie");
    classe[2].note = 17.5;

    strcpy(classe[3].nom, "Diana");
    classe[3].note = 14.0;

    strcpy(classe[4].nom, "Eve");
    classe[4].note = 16.0;

    float somme = 0;
    printf("Notes des étudiants:\n");
    for (int i = 0; i < 5; i++) {
        printf("%s: %.1f\n", classe[i].nom, classe[i].note);
        somme += classe[i].note;
    }

    float moyenne = somme / 5;
    printf("\nMoyenne de la classe: %.2f\n", moyenne);

    return 0;
}
```

SOLUTION EXERCICE 8 : Allocation dynamique
```c

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
```


```c
typedef struct {
    char titre[100];
    char auteur[50];
    int annee;
} Livre;
```


```c
int main() {
```
    Livre *livre = malloc(sizeof(Livre));

    if (livre == NULL) {
        printf("Erreur d'allocation\n");
        return 1;
    }

    strcpy(livre->titre, "Le Petit Prince");
    strcpy(livre->auteur, "Antoine de Saint-Exupéry");
    livre->annee = 1943;

    printf("Livre alloué dynamiquement:\n");
    printf("Titre: %s\n", livre->titre);
    printf("Auteur: %s\n", livre->auteur);
    printf("Année: %d\n", livre->annee);

    free(livre);
    livre = NULL;

    return 0;
}
```

