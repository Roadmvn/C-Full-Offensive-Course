==============================================
  MODULE 04 - OPÉRATEURS - EXERCICES
==============================================

[ ] Exercice 1 : Arithmétique de base
------------------------------
Crée deux variables : a = 15, b = 4
Affiche les résultats de :
+ (addition)
- (soustraction)
* (multiplication)
/ (division entière)
% (modulo)


[ ] Exercice 2 : Division entière vs flottante
------------------------------
int x = 7, y = 2;
Affiche :
- x / y (division entière)
- (float)x / y (division flottante après cast)


[ ] Exercice 3 : Pré vs Post incrémentation
------------------------------
int counter = 10;

Affiche :
1. counter++ (post-incrémentation)
2. La valeur de counter après
3. ++counter (pré-incrémentation)
4. La valeur de counter après


[ ] Exercice 4 : Comparaisons
------------------------------
Demande deux nombres à l'utilisateur.
Affiche si :
- Le premier est plus grand
- Le second est plus grand
- Ils sont égaux


[ ] Exercice 5 : Logique AND/OR
------------------------------
Demande un âge.
Utilise les opérateurs logiques pour tester :
- Si l'âge est entre 18 et 65 (&&)
- Si l'âge est < 18 OU > 65 (||)


[ ] Exercice 6 : Opérateurs composés
------------------------------
int score = 100;

Utilise les opérateurs composés pour :
1. Ajouter 50 points (+=)
2. Doubler le score (*=)
3. Diviser par 3 (/=)
4. Calculer le reste modulo 10 (%=)

Affiche le score après chaque opération.


[ ] Exercice 7 : Ternaire
------------------------------
Demande un nombre.
Utilise l'opérateur ternaire pour afficher :
"Le nombre est pair" ou "Le nombre est impair"

Astuce : utilise % 2


[ ] Exercice 8 : Calcul d'offset (style offensif)
------------------------------
Tu as :
- unsigned int base_addr = 0x00400000
- unsigned int offset = 0x1234

Calcule et affiche :
- L'adresse finale (base + offset)
- Le numéro de page (offset / 4096)
- L'offset dans la page (offset % 4096)

Affiche tout en hexadécimal.


==============================================
