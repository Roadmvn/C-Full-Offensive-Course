==============================================
  MODULE 06 - CONDITIONS - EXERCICES
==============================================

Instructions :
- Coche [x] quand l'exercice est terminé
- Compile et teste chaque exercice
- Ne regarde solution.txt qu'après avoir essayé

==============================================

[ ] Exercice 1 : if simple
------------------------------
Crée une variable : int port = 443
Si port est égal à 443, affiche "HTTPS détecté".


[ ] Exercice 2 : if-else
------------------------------
Crée une variable : int privilege = 0
Si privilege == 1, affiche "Admin"
Sinon, affiche "User"


[ ] Exercice 3 : if-else if-else
------------------------------
Crée une variable : int error_code = 404
Affiche :
- "Success" si error_code == 200
- "Not Found" si error_code == 404
- "Server Error" si error_code == 500
- "Unknown" sinon


[ ] Exercice 4 : Opérateurs logiques (&&)
------------------------------
Crée deux variables :
- int authenticated = 1
- int has_admin_role = 1

Si les DEUX sont à 1, affiche "Accès autorisé", sinon "Accès refusé".


[ ] Exercice 5 : Opérateurs logiques (||)
------------------------------
Crée : int port = 22
Si port == 22 OU port == 23, affiche "Service SSH/Telnet".


[ ] Exercice 6 : switch-case simple
------------------------------
Crée : int protocol = 6  (6=TCP, 17=UDP, 1=ICMP)
Utilise switch pour afficher le nom du protocole.


[ ] Exercice 7 : Opérateur ternaire
------------------------------
Crée deux variables : int a = 15, b = 30
Utilise l'opérateur ternaire pour trouver le minimum.
Affiche le résultat.


[ ] Exercice 8 : Détection d'architecture
------------------------------
Crée : int arch_bits = 64
Si arch_bits == 32, affiche "x86"
Si arch_bits == 64, affiche "x64"
Sinon, affiche "Architecture inconnue"

==============================================
  Compile avec : gcc ton_fichier.c -o prog
  Exécute avec : ./prog
==============================================
