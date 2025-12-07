==============================================
  MODULE 02 - VARIABLES ET TYPES - EXERCICES
==============================================

[ ] Exercice 1 : Déclaration basique
------------------------------
Déclare et initialise :
- int pid = 1337
- char grade = 'A'
- float cpu_usage = 75.5

Affiche les 3 variables.


[ ] Exercice 2 : sizeof()
------------------------------
Affiche la taille en bytes de :
- char
- int
- long
- double
- void* (pointeur)


[ ] Exercice 3 : Unsigned vs Signed
------------------------------
Crée :
- int signed_num = -50
- unsigned int unsigned_num = 50

Affiche les deux et explique dans un commentaire
pourquoi unsigned ne peut pas stocker de négatifs.


[ ] Exercice 4 : Overflow test
------------------------------
Crée :
- unsigned char max_byte = 255

Ajoute 1 à max_byte et affiche le résultat.
Que se passe-t-il ? (Indice : overflow)


[ ] Exercice 5 : Constantes
------------------------------
Déclare une constante :
- const int MAX_CONNECTIONS = 100

Essaye de modifier sa valeur (ligne suivante).
Compile. Que dit le compilateur ?


[ ] Exercice 6 : Format hexadécimal
------------------------------
Crée :
- int shellcode_addr = 0x41414141

Affiche cette valeur en :
1. Hexadécimal (0x...)
2. Décimal
3. Unsigned


[ ] Exercice 7 : Bytes array
------------------------------
Crée un tableau de bytes (style shellcode) :
unsigned char payload[] = {0x48, 0x31, 0xC0, 0x90};

Affiche chaque byte en hexa avec un for loop.
Format : "\x48 \x31 \xC0 \x90"


[ ] Exercice 8 : Type casting
------------------------------
Crée :
- int big_num = 300
- char small_num = (char)big_num  // Cast vers char

Affiche small_num. Pourquoi la valeur change-t-elle ?
(Indice : overflow, char = 1 byte)


==============================================
  NOTE : Ces exercices sont fondamentaux pour
  comprendre les buffer overflows et integer
  overflows dans les modules avancés !
==============================================
