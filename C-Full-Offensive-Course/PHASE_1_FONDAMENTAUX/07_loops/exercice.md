==============================================
  MODULE 07 - BOUCLES - EXERCICES
==============================================

Instructions :
- Coche [x] quand l'exercice est terminé
- Compile et teste chaque exercice
- Ne regarde solution.txt qu'après avoir essayé

==============================================

[ ] Exercice 1 : for basique
------------------------------
Affiche les nombres de 1 à 10 avec une boucle for.


[ ] Exercice 2 : for avec incrément personnalisé
------------------------------
Affiche tous les multiples de 5 entre 0 et 50.


[ ] Exercice 3 : while
------------------------------
Crée une variable int n = 1
Utilise while pour afficher les puissances de 2 jusqu'à 1024.
(1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024)


[ ] Exercice 4 : do-while
------------------------------
Crée une variable int choice = 0
Utilise do-while pour afficher un menu :
"1. Scan
2. Exploit
3. Quitter
Choix : "
(Simule en mettant choice = 3 après l'affichage pour sortir)


[ ] Exercice 5 : break
------------------------------
Crée une boucle for de 0 à 100.
Sort de la boucle quand i == 42.
Affiche "Nombre secret trouvé : 42".


[ ] Exercice 6 : continue
------------------------------
Affiche les nombres de 1 à 20, mais saute (continue) les multiples de 3.


[ ] Exercice 7 : Somme (accumulateur)
------------------------------
Calcule la somme de tous les nombres de 1 à 100.
Affiche le résultat.


[ ] Exercice 8 : Encodeur XOR
------------------------------
Crée un tableau : unsigned char data[] = {0x41, 0x42, 0x43, 0x44}  // "ABCD"
Clé : unsigned char key = 0x99
Parcours le tableau avec une boucle for et encode chaque byte avec XOR.
Affiche les bytes encodés en hexadécimal.

==============================================
  Compile avec : gcc ton_fichier.c -o prog
  Exécute avec : ./prog
==============================================
