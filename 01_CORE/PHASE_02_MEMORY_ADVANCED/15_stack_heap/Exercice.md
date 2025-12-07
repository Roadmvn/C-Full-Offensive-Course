
### EXERCICE 1 : Premier malloc
Alloue dynamiquement un int, assigne-lui 100, affiche-le, puis libère.
Vérifie que malloc ne retourne pas NULL.
Objectif : Cycle complet malloc/free
[ ] Exercice terminé


### EXERCICE 2 : Tableau dynamique
Demande à l'utilisateur une taille, crée un tableau dynamique de cette taille.
Remplis-le avec des valeurs, affiche-les, puis libère.
Objectif : Allocation basée sur l'entrée utilisateur
[ ] Exercice terminé


### EXERCICE 3 : calloc vs malloc
Alloue un tableau de 10 int avec malloc, puis un autre avec calloc.
Affiche les deux sans les initialiser, observe la différence.
Objectif : Comprendre que calloc initialise à zéro
[ ] Exercice terminé


### EXERCICE 4 : realloc
Crée un tableau de 5 int, remplis-le.
Agrandis-le à 10 avec realloc, ajoute 5 éléments.
Objectif : Redimensionner une allocation
[ ] Exercice terminé


### EXERCICE 5 : Chaîne dynamique
Alloue une chaîne de 100 char, demande une saisie utilisateur.
Copie la saisie dans la chaîne, affiche-la, libère.
Objectif : Allocation pour des chaînes
[ ] Exercice terminé


### EXERCICE 6 : Tableau de chaînes
Crée un tableau de 5 pointeurs char*.
Alloue une chaîne pour chaque pointeur, remplis avec des noms.
Affiche tous les noms, puis libère tout.
Objectif : Allocation multidimensionnelle
[ ] Exercice terminé


### EXERCICE 7 : Détection d'erreur
Tente d'allouer une quantité énorme (comme 1TB).
Gère l'erreur proprement si malloc retourne NULL.
Objectif : Toujours vérifier les erreurs d'allocation
[ ] Exercice terminé


### EXERCICE 8 : Memory leak
Crée intentionnellement un memory leak (malloc sans free).
Puis corrige-le en ajoutant free().
Objectif : Comprendre l'importance de free()
[ ] Exercice terminé

