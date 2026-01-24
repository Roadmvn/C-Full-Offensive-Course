# MODULE 27 : RACE CONDITIONS - EXERCICES

## Exercice 1 : Thread race
[ ] Créer counter partagé
[ ] 2 threads incrémentant
[ ] Observer le résultat incorrect

## Exercice 2 : TOCTOU file
[ ] Créer programme avec access() puis open()
[ ] Script bash changeant file entre deux
[ ] Exploiter la race window

## Exercice 3 : Symlink race
[ ] Programme écrivant dans /tmp
[ ] Remplacer par symlink vers /etc/passwd
[ ] Observer écriture dans fichier sensible

## Exercice 4 : Fix avec locks
[ ] Ajouter pthread_mutex
[ ] Vérifier résultat correct
