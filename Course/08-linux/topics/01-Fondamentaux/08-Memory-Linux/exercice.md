# MODULE L08 : MEMORY LINUX - EXERCICES

## Exercice 1 : mmap() basique
[ ] Allouer 8KB avec mmap() en RW
[ ] Écrire une chaîne dedans
[ ] Afficher l'adresse retournée
[ ] Libérer avec munmap()

## Exercice 2 : Mémoire exécutable
[ ] Créer zone RWX avec mmap()
[ ] Copier shellcode (0xc3 = ret)
[ ] Exécuter le shellcode
[ ] Observer dans /proc/self/maps

## Exercice 3 : mprotect() W^X bypass
[ ] Allouer zone RW (pas X)
[ ] Écrire shellcode dedans
[ ] Changer permissions en RX avec mprotect()
[ ] Exécuter

## Exercice 4 : Parser /proc/self/maps
[ ] Ouvrir /proc/self/maps
[ ] Parser chaque ligne (sscanf)
[ ] Extraire: start, end, perms, pathname
[ ] Afficher tableau formaté

## Exercice 5 : Détecter pages RWX
[ ] Lire /proc/self/maps
[ ] Chercher lignes contenant "rwxp"
[ ] Afficher alerte si trouvé
[ ] Tester avec mmap RWX

## Exercice 6 : Trouver libc base
[ ] Parser /proc/self/maps
[ ] Chercher ligne contenant "libc" et "r-xp"
[ ] Extraire adresse de début
[ ] Afficher base libc

## Exercice 7 : /proc/pid/mem
[ ] Créer processus cible qui dort
[ ] Ouvrir /proc/<PID>/mem
[ ] Lire 4 bytes à une adresse connue
[ ] Comparer avec valeur attendue
