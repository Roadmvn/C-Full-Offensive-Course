# Format String

Les vulnérabilités de format string permettent de lire et écrire en mémoire arbitrairement via printf() avec un format contrôlé par l'attaquant. printf(user_input) au lieu de printf("%s", user_input) permet d'utiliser %x, %s, %n pour leak ou écrire.

⚠️ AVERTISSEMENT : Code éducatif. Uniquement sur tes propres systèmes de test. Usage malveillant est ILLÉGAL.

```c
// Code vulnérable
char input[100];
gets(input);
printf(input);  // VULNÉRABLE !

// Input : "%x %x %x" leak la stack
// Input : "%s" peut crash si pointeur invalide
// Input : "%n" écrit en mémoire
```

## Compilation

```bash
gcc -fno-stack-protector -no-pie -Wno-format-security example.c -o example
./example
```

## Concepts clés

- printf(user_input) interprète %x, %s, %n, etc.
- %x leak des valeurs de la stack (4 bytes)
- %p leak des pointeurs (8 bytes sur x64)
- %s leak une string à l'adresse pointée
- %n écrit le nombre de caractères imprimés à l'adresse pointée
- Exploitation : leak d'adresses, écriture arbitraire en mémoire

## Exploitation

Pour leak la stack : envoyer "%x "*20 pour afficher 20 valeurs. Pour leak une adresse précise : placer l'adresse dans le buffer, puis utiliser %7$s pour lire à cette adresse (7ème argument).

Pour écrire en mémoire : %n écrit le nombre de caractères imprimés. Exemple : printf("AAAA%n", &var) écrit 4 dans var. Avec %hn (2 bytes) et %hhn (1 byte) pour contrôle précis.

Position du buffer sur la stack : tester avec AAAA%x%x%x... jusqu'à voir 0x41414141, compter la position, puis utiliser %N$x pour accès direct.

## Outils

- GDB : examiner la stack
- Python pwntools : fmtstr_payload() génère des payloads automatiquement
- %p pour leak, %n pour écrire
