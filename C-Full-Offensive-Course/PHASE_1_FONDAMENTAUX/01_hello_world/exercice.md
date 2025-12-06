==============================================
  MODULE 01 - HELLO WORLD - EXERCICES
==============================================

Instructions :
- Coche [x] quand l'exercice est terminé
- Compile et teste chaque exercice
- Ne regarde solution.txt qu'après avoir essayé

==============================================

[ ] Exercice 1 : Hello de base
------------------------------
Crée un programme qui affiche :
"Bonjour, je suis un Red Teamer en formation."


[ ] Exercice 2 : Plusieurs lignes
------------------------------
Affiche 3 lignes avec printf() :
Ligne 1 : "Module 01"
Ligne 2 : "Hello World"
Ligne 3 : "C Programming"


[ ] Exercice 3 : Variables et printf
------------------------------
Crée 2 variables :
- int port = 4444
- char* service = "reverse_shell"

Affiche : "Service: reverse_shell sur le port: 4444"


[ ] Exercice 4 : Formatage hexa
------------------------------
Crée une variable : int payload_size = 512
Affiche-la en décimal ET en hexadécimal :
"Taille: 512 bytes (0x200)"


[ ] Exercice 5 : Adresse mémoire
------------------------------
Crée une variable : int secret = 1337
Affiche son adresse mémoire avec %p
Format : "Variable 'secret' stockée à l'adresse : 0x..."


[ ] Exercice 6 : Tabulation
------------------------------
Affiche un tableau avec des tabulations :
IP              Port    Status
192.168.1.10    80      OPEN
192.168.1.10    443     OPEN


[ ] Exercice 7 : Caractère par caractère
------------------------------
Affiche les caractères 'H', 'A', 'C', 'K' sur une seule ligne
en utilisant %c (un printf par lettre).
Résultat : "HACK"


[ ] Exercice 8 : Code de retour personnalisé
------------------------------
Crée un programme qui :
- Affiche "Erreur : connexion échouée"
- Retourne 1 au lieu de 0 (pour simuler une erreur)

Teste avec : echo $? (Linux/macOS) après l'exécution

==============================================
  Compile avec : gcc ton_fichier.c -o prog
  Exécute avec : ./prog
==============================================
