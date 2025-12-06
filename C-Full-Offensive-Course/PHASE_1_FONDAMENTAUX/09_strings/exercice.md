==============================================
  MODULE 09 - STRINGS - EXERCICES
==============================================

Instructions :
- Coche [x] quand l'exercice est terminé
- Compile et teste chaque exercice
- Ne regarde solution.txt qu'après avoir essayé

==============================================

[ ] Exercice 1 : Longueur
------------------------------
Crée une string : char text[] = "Cybersecurity"
Calcule et affiche sa longueur avec strlen().


[ ] Exercice 2 : Copie
------------------------------
Crée deux strings :
- char src[] = "Hello"
- char dst[20]

Copie src dans dst avec strcpy().
Affiche dst.


[ ] Exercice 3 : Concaténation
------------------------------
Crée deux strings :
- char str1[50] = "Red"
- char str2[] = "Team"

Concatène str2 à str1 avec strcat().
Affiche le résultat.


[ ] Exercice 4 : Comparaison
------------------------------
Crée deux strings :
- char pass1[] = "admin"
- char pass2[] = "admin"

Compare-les avec strcmp().
Affiche "Identiques" ou "Différentes".


[ ] Exercice 5 : Recherche de caractère
------------------------------
Crée une string : char email[] = "hacker@domain.com"
Cherche le caractère '@' avec strchr().
Affiche sa position (index).


[ ] Exercice 6 : Recherche de sous-chaîne
------------------------------
Crée une string : char url[] = "https://example.com/admin/panel"
Cherche la sous-chaîne "admin" avec strstr().
Affiche "Trouvé" ou "Non trouvé".


[ ] Exercice 7 : Compter les occurrences
------------------------------
Crée une string : char text[] = "banana"
Compte combien de fois la lettre 'a' apparaît.
Affiche le résultat.


[ ] Exercice 8 : Inverser une string
------------------------------
Crée une string : char word[] = "Reverse"
Inverse-la (sans utiliser de fonction externe).
Affiche le résultat : "esreveR"

==============================================
  Compile avec : gcc ton_fichier.c -o prog
  Exécute avec : ./prog
==============================================
