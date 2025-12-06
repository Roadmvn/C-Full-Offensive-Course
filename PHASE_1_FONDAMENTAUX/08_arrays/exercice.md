==============================================
  MODULE 08 - TABLEAUX - EXERCICES
==============================================

Instructions :
- Coche [x] quand l'exercice est terminé
- Compile et teste chaque exercice
- Ne regarde solution.txt qu'après avoir essayé

==============================================

[ ] Exercice 1 : Déclaration et affichage
------------------------------
Crée un tableau : int ports[5] = {80, 443, 22, 21, 3389}
Affiche chaque élément avec son index.


[ ] Exercice 2 : Taille avec sizeof
------------------------------
Crée un tableau : int data[] = {10, 20, 30, 40, 50, 60, 70}
Calcule et affiche le nombre d'éléments avec sizeof.


[ ] Exercice 3 : Somme
------------------------------
Crée un tableau : int numbers[] = {5, 10, 15, 20, 25}
Calcule et affiche la somme de tous les éléments.


[ ] Exercice 4 : Recherche
------------------------------
Crée un tableau : int list[] = {12, 45, 67, 89, 34}
Recherche le nombre 67 et affiche son index.
Si non trouvé, affiche "Non trouvé".


[ ] Exercice 5 : Minimum
------------------------------
Crée un tableau : int temps[] = {23, 18, 31, 15, 27, 12}
Trouve et affiche la température minimale.


[ ] Exercice 6 : Copie de tableau
------------------------------
Crée deux tableaux :
- int src[5] = {1, 2, 3, 4, 5}
- int dst[5]

Copie src dans dst avec une boucle.
Affiche dst pour vérifier.


[ ] Exercice 7 : Tableau 2D
------------------------------
Crée une matrice 2x3 :
int matrix[2][3] = {
    {10, 20, 30},
    {40, 50, 60}
};

Parcours et affiche tous les éléments.


[ ] Exercice 8 : Shellcode XOR
------------------------------
Crée un shellcode :
unsigned char shellcode[] = {0x48, 0x65, 0x6C, 0x6C, 0x6F}  // "Hello"

Encode-le avec XOR 0x42.
Affiche le shellcode encodé en hexadécimal.

==============================================
  Compile avec : gcc ton_fichier.c -o prog
  Exécute avec : ./prog
==============================================
