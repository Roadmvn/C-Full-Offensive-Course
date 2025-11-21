# Buffer Concept

Les buffers sont des zones mémoire de taille fixe. Dépasser leur capacité provoque un buffer overflow, écrasant des données adjacentes et permettant potentiellement l'exécution de code arbitraire.

⚠️ AVERTISSEMENT : Code éducatif. Uniquement sur tes propres systèmes de test. Usage malveillant est ILLÉGAL.

```c
// Code vulnérable démonstratif
char buffer[64];
char secret[32] = "FLAG{secret_data}";

// VULNÉRABLE : pas de vérification de taille
gets(buffer);  // Dangereux !
strcpy(buffer, user_input);  // Dangereux !

// SÉCURISÉ : limitation de taille
fgets(buffer, sizeof(buffer), stdin);
strncpy(buffer, user_input, sizeof(buffer) - 1);
```

## Compilation

```bash
gcc -fno-stack-protector -z execstack example.c -o example
./example
```

## Concepts clés

- Les buffers ont une taille fixe définie à la compilation
- Déborder un buffer écrase la mémoire adjacente (variables, pointeurs, adresses de retour)
- gets() et strcpy() ne vérifient pas les limites
- fgets() et strncpy() permettent de spécifier la taille maximale
- La stack grandit vers les adresses basses sur x86/x64

## Exploitation

Un buffer overflow basique permet d'écraser des variables adjacentes sur la stack. Si un buffer de 64 octets précède une variable "authenticated", écrire 65+ caractères écrasera cette variable.

La stack layout typique place les variables locales les unes après les autres. Un buffer[64] suivi de int authenticated; signifie qu'écrire 64+ octets dans buffer modifiera authenticated.

L'exploitation commence par identifier la distance entre le buffer et la cible. Avec GDB ou en testant, on détermine combien d'octets écraser. Ensuite, on craft un payload de longueur exacte avec les valeurs souhaitées.

Les protections modernes (stack canaries, ASLR, DEP) rendent l'exploitation plus complexe. Ce module utilise -fno-stack-protector pour désactiver les canaries et -z execstack pour permettre l'exécution sur la stack à des fins éducatives.

## Outils

- GDB : debugger pour examiner la mémoire et la stack
- objdump : désassembler le binaire
- hexdump : visualiser les données binaires
- Python/pwntools : générer des payloads
