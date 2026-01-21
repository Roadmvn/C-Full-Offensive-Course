==============================================
  MODULE 05 - BITWISE - EXERCICES
==============================================

Instructions :
- Coche [x] quand l'exercice est terminé
- Compile et teste chaque exercice
- Ne regarde solution.txt qu'après avoir essayé

==============================================

[ ] Exercice 1 : AND simple
------------------------------
Crée deux variables :
- unsigned char a = 0b11110000
- unsigned char b = 0b10101010

Calcule et affiche a & b en décimal.


[ ] Exercice 2 : Masque pour extraire
------------------------------
Tu as : unsigned char ip_octet = 0b11010110 (214)
Utilise un masque AND pour extraire uniquement les 4 bits de gauche.
Affiche le résultat en décimal.


[ ] Exercice 3 : Activer un bit
------------------------------
Tu as : unsigned char flags = 0b00000000
Écris du code pour activer le bit numéro 3 (en partant de 0 à droite).
Affiche le résultat en binaire ou en décimal.


[ ] Exercice 4 : Vérifier si un bit est set
------------------------------
Tu as : unsigned char status = 0b10010100
Écris du code pour vérifier si le bit 4 est activé (1).
Affiche "Bit 4 activé" ou "Bit 4 désactivé".


[ ] Exercice 5 : XOR swap
------------------------------
Crée deux variables : int x = 25, y = 75
Échange leurs valeurs SANS utiliser de variable temporaire (utilise XOR).
Affiche x et y avant et après.


[ ] Exercice 6 : Left shift (multiplication)
------------------------------
Crée : int base = 7
Utilise le left shift pour calculer 7 * 8 (shift de 3 positions).
Affiche le résultat.


[ ] Exercice 7 : Right shift (division)
------------------------------
Crée : int bytes = 1024
Divise par 4 en utilisant le right shift.
Affiche le résultat.


[ ] Exercice 8 : Encodeur XOR
------------------------------
Crée un mini-encodeur XOR :
- Tableau : unsigned char data[] = {0x48, 0x45, 0x4C, 0x4C, 0x4F}  // "HELLO"
- Clé : unsigned char key = 0x13
- Encode chaque byte avec XOR
- Affiche les bytes encodés en hexadécimal
- Décode-les et affiche le résultat

==============================================
  Compile avec : gcc ton_fichier.c -o prog
  Exécute avec : ./prog
==============================================
