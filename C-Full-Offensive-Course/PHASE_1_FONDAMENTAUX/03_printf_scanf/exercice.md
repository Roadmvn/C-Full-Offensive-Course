==============================================
  MODULE 03 - PRINTF ET SCANF - EXERCICES
==============================================

[ ] Exercice 1 : Formatage basique
------------------------------
Crée un programme qui affiche :
- Un entier en décimal
- Le même entier en hexadécimal
- Le même entier en octal

Exemple avec 255 :
Décimal : 255
Hexa    : 0xFF
Octal   : 377


[ ] Exercice 2 : Largeur et padding
------------------------------
Affiche le nombre 42 de 3 façons :
1. Aligné à droite sur 10 caractères
2. Aligné à gauche sur 10 caractères
3. Padding avec des 0 sur 5 caractères


[ ] Exercice 3 : Précision des floats
------------------------------
Crée : float price = 19.99
Affiche ce prix avec :
- 0 décimale
- 1 décimale
- 3 décimales


[ ] Exercice 4 : Lecture d'un entier
------------------------------
Demande à l'user d'entrer un port.
Stocke-le dans une variable et affiche :
"Port choisi : XXXX (0xYYYY en hexa)"


[ ] Exercice 5 : Lecture de plusieurs valeurs
------------------------------
Demande à l'user d'entrer 3 nombres séparés par des espaces.
Stocke-les dans x, y, z.
Affiche leur somme.


[ ] Exercice 6 : fgets() sécurisé
------------------------------
Demande le nom d'user (max 20 caractères).
Utilise fgets() au lieu de scanf().
Enlève le '\n' à la fin.
Affiche : "Bienvenue, [nom] !"


[ ] Exercice 7 : Shellcode display
------------------------------
Crée un tableau :
unsigned char payload[] = {0x48, 0x31, 0xDB, 0xCC};

Affiche chaque byte en hexa avec un for loop.
Format : "\x48\x31\xDB\xCC"


[ ] Exercice 8 : Calculateur interactif
------------------------------
Demande 2 nombres et un opérateur (+, -, *, /).
Affiche le résultat de l'opération.

Exemple :
Entre le premier nombre : 10
Entre le second nombre : 5
Entre l'opérateur (+, -, *, /) : +
Résultat : 10 + 5 = 15


==============================================
  ATTENTION : scanf() avec %s est DANGEREUX !
  Privilégie fgets() pour les strings.
==============================================
