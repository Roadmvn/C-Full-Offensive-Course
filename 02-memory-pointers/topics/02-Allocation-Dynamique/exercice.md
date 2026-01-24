# MODULE 20 : INTEGER OVERFLOW - EXERCICES

## Exercice 1 : Wraparound
[ ] Tester INT_MAX + 1
[ ] Tester UINT_MAX + 1
[ ] Tester 0 - 1 (unsigned)
[ ] Observer les valeurs

## Exercice 2 : Malloc bypass
[ ] Créer fonction vulnerable_alloc
[ ] Trouver valeurs causant overflow
[ ] Allouer petit buffer
[ ] Overflow le buffer

## Exercice 3 : Bounds check bypass
[ ] if (offset + size < max) - vulnérable
[ ] Trouver offset/size causant bypass
[ ] Exploiter

## Exercice 4 : Real exploit
[ ] Analyser CVE utilisant integer overflow
[ ] Reproduire la vulnérabilité
[ ] Créer exploit fonctionnel
