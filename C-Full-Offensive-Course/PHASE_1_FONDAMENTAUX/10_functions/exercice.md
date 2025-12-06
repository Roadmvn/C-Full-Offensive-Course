==============================================
  MODULE 10 - FONCTIONS - EXERCICES
==============================================

Instructions :
- Coche [x] quand l'exercice est terminé
- Compile et teste chaque exercice
- Ne regarde solution.txt qu'après avoir essayé

==============================================

[ ] Exercice 1 : Fonction simple
------------------------------
Crée une fonction : int subtract(int a, int b)
Elle doit retourner a - b.
Teste-la dans main avec : subtract(10, 3)


[ ] Exercice 2 : Fonction void
------------------------------
Crée une fonction : void print_message()
Elle doit afficher : "Bienvenue dans le Red Team!"
Appelle-la depuis main.


[ ] Exercice 3 : Fonction booléenne
------------------------------
Crée une fonction : int is_positive(int n)
Elle doit retourner 1 si n > 0, sinon 0.
Teste avec plusieurs valeurs.


[ ] Exercice 4 : Fonction avec tableau
------------------------------
Crée une fonction : int sum_array(int arr[], int size)
Elle doit calculer et retourner la somme des éléments.
Teste avec : {10, 20, 30, 40, 50}


[ ] Exercice 5 : Passage par référence
------------------------------
Crée une fonction : void swap(int* a, int* b)
Elle doit échanger les valeurs de a et b.
Teste dans main avec deux variables.


[ ] Exercice 6 : Fonction récursive
------------------------------
Crée une fonction : int power(int base, int exp)
Elle doit calculer base^exp de manière récursive.
Exemple : power(2, 3) = 8


[ ] Exercice 7 : Fonction de validation
------------------------------
Crée une fonction : int is_valid_port(int port)
Elle doit retourner 1 si le port est entre 1 et 65535, sinon 0.
Teste avec plusieurs valeurs.


[ ] Exercice 8 : Fonction d'encodage
------------------------------
Crée une fonction : void rot13(char* str)
Elle doit encoder une string avec ROT13 :
- a->n, b->o, ..., m->z, n->a, ..., z->m
- Pareil pour majuscules

Teste avec : "Hello"
Résultat : "Uryyb"

==============================================
  Compile avec : gcc ton_fichier.c -o prog
  Exécute avec : ./prog
==============================================
