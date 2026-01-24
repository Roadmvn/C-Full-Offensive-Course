# Module 11 : Structures - Exercices

## Exercice 1 : Structure de base (Facile)

**Objectif** : Définir et utiliser une structure simple.

**Instructions** :
1. Créer une structure `Person` avec :
   - `char name[50]` - Nom
   - `int age` - Age
   - `char email[100]` - Email

2. Dans main :
   - Créer une variable Person
   - Remplir les champs
   - Afficher toutes les informations

**Sortie attendue** :
```
=== Fiche Personne ===
Nom   : John Doe
Age   : 25
Email : john@example.com
```

---

## Exercice 2 : typedef et initialisation (Facile)

**Objectif** : Utiliser typedef et l'initialisation désignée.

**Instructions** :
1. Définir avec typedef une structure `Target` :
   - `char ip[16]`
   - `int port`
   - `int is_open`

2. Créer 3 targets en utilisant différentes méthodes d'initialisation :
   - Initialisation classique (ordre des membres)
   - Initialisation désignée (avec `.membre =`)
   - Initialisation à zéro puis affectation

3. Afficher les 3 targets

**Sortie attendue** :
```
Target 1: 192.168.1.1:80 - OPEN
Target 2: 10.0.0.1:22 - CLOSED
Target 3: 172.16.0.1:443 - OPEN
```

---

## Exercice 3 : Pointeurs vers structures (Facile)

**Objectif** : Manipuler des structures via pointeurs avec `->`.

**Instructions** :
1. Créer une structure `Service` :
   - `char name[32]`
   - `int port`
   - `int running`

2. Créer une fonction `void print_service(Service *s)` qui affiche le service

3. Créer une fonction `void start_service(Service *s)` qui met `running` à 1

4. Dans main :
   - Créer un service "SSH" sur port 22, arrêté
   - L'afficher (via pointeur)
   - Le démarrer (via pointeur)
   - L'afficher à nouveau

**Sortie attendue** :
```
Service: SSH (port 22) - STOPPED
Starting SSH...
Service: SSH (port 22) - RUNNING
```

---

## Exercice 4 : Tableau de structures (Moyen)

**Objectif** : Gérer un tableau de structures.

**Instructions** :
1. Définir une structure `ScanResult` :
   - `char ip[16]`
   - `int port`
   - `char service[32]`
   - `int open`

2. Créer un tableau de 5 résultats de scan

3. Créer une fonction `void display_results(ScanResult *results, int count)` qui :
   - Affiche un en-tête formaté
   - Affiche chaque résultat
   - Compte et affiche le nombre de ports ouverts

**Sortie attendue** :
```
=== Scan Results ===
IP               PORT    SERVICE          STATUS
────────────────────────────────────────────────
192.168.1.1      22      ssh              OPEN
192.168.1.1      80      http             OPEN
192.168.1.1      443     https            CLOSED
192.168.1.2      21      ftp              OPEN
192.168.1.2      3389    rdp              CLOSED

Open ports: 3/5
```

---

## Exercice 5 : Structures imbriquées (Moyen)

**Objectif** : Utiliser des structures imbriquées.

**Instructions** :
1. Définir une structure `Endpoint` :
   - `char ip[16]`
   - `int port`

2. Définir une structure `Connection` qui utilise Endpoint :
   - `Endpoint source`
   - `Endpoint destination`
   - `char protocol[8]`
   - `int bytes_sent`
   - `int bytes_received`

3. Créer une fonction `void print_connection(Connection *conn)`

4. Dans main :
   - Créer une connexion HTTP de 192.168.1.100:45678 vers 10.0.0.1:80
   - Simuler du trafic (bytes_sent=1024, bytes_received=4096)
   - Afficher la connexion

**Sortie attendue** :
```
=== Connection Details ===
Source      : 192.168.1.100:45678
Destination : 10.0.0.1:80
Protocol    : TCP
Sent        : 1024 bytes
Received    : 4096 bytes
```

---

## Exercice 6 : Allocation dynamique (Moyen)

**Objectif** : Allouer des structures dynamiquement.

**Instructions** :
1. Créer une structure `Host` :
   - `char hostname[64]`
   - `char ip[16]`
   - `int *open_ports` (tableau dynamique)
   - `int port_count`

2. Créer `Host *create_host(const char *hostname, const char *ip)`

3. Créer `int add_port(Host *h, int port)` qui ajoute un port (avec realloc)

4. Créer `void print_host(Host *h)`

5. Créer `void destroy_host(Host *h)` qui libère tout

6. Tester avec un host ayant 3 ports ouverts

**Sortie attendue** :
```
=== Host Info ===
Hostname: webserver
IP: 192.168.1.50
Open Ports (3): 22 80 443
```

---

## Exercice 7 : Taille et padding (Moyen)

**Objectif** : Comprendre l'alignement des structures.

**Instructions** :
1. Créer 3 structures avec les mêmes membres mais dans un ordre différent :

```c
struct A { char a; int b; char c; };
struct B { int b; char a; char c; };
struct C { char a; char c; int b; };
```

2. Afficher la taille de chaque structure

3. Créer une version packed de struct A

4. Afficher les offsets de chaque membre pour struct A

**Sortie attendue** :
```
=== Tailles des structures ===
struct A (char, int, char) : 12 bytes
struct B (int, char, char) : 8 bytes
struct C (char, char, int) : 8 bytes
struct A packed            : 6 bytes

=== Offsets dans struct A ===
Offset de a : 0
Offset de b : 4
Offset de c : 8
```

---

## Exercice 8 : Configuration d'implant (Difficile)

**Objectif** : Créer une structure de configuration complète.

**Instructions** :
1. Définir une structure `ImplantConfig` :
   - `char id[32]` - ID unique
   - `char c2_url[128]` - URL du C2
   - `int sleep_time` - Temps entre callbacks (secondes)
   - `int jitter` - Variation en pourcentage
   - `unsigned char xor_key` - Clé d'encodage
   - `int kill_date` - Timestamp d'expiration (0 = pas d'expiration)

2. Créer `void init_config(ImplantConfig *cfg, const char *c2_url)`

3. Créer `void print_config(const ImplantConfig *cfg)`

4. Créer `int calculate_sleep(const ImplantConfig *cfg)` qui retourne le temps avec jitter

5. Créer `int is_expired(const ImplantConfig *cfg)` qui vérifie le kill_date

**Sortie attendue** :
```
=== Implant Configuration ===
ID         : IMP-2024-001
C2 URL     : https://evil.com/api
Sleep      : 60s (±20% jitter)
XOR Key    : 0x42
Kill Date  : Never

Calculated sleep times (5 samples):
  Sleep 1: 52 seconds
  Sleep 2: 67 seconds
  Sleep 3: 48 seconds
  Sleep 4: 71 seconds
  Sleep 5: 58 seconds
```

---

## Exercice 9 : Protocole C2 (Difficile)

**Objectif** : Définir des structures pour un protocole de communication.

**Instructions** :
1. Définir un en-tête commun :
```c
typedef struct {
    uint32_t magic;      // 0xDEADBEEF
    uint16_t version;    // Version du protocole
    uint16_t msg_type;   // Type de message
    uint32_t msg_len;    // Longueur du payload
    uint32_t msg_id;     // ID du message
} C2Header;
```

2. Définir les types de messages :
```c
#define MSG_BEACON      0x0001
#define MSG_TASK        0x0002
#define MSG_RESULT      0x0003
#define MSG_HEARTBEAT   0x0004
```

3. Créer `void build_header(C2Header *h, uint16_t type, uint32_t len)`

4. Créer `int validate_header(C2Header *h)` qui vérifie magic et version

5. Créer `void print_header(C2Header *h)`

6. Tester avec différents types de messages

**Sortie attendue** :
```
=== C2 Protocol Demo ===

Building BEACON message...
┌─────────────────────────────┐
│ Magic    : 0xDEADBEEF       │
│ Version  : 1                │
│ Type     : BEACON (0x0001)  │
│ Length   : 128 bytes        │
│ ID       : 1001             │
└─────────────────────────────┘
Header valid: YES

Building TASK message...
┌─────────────────────────────┐
│ Magic    : 0xDEADBEEF       │
│ Version  : 1                │
│ Type     : TASK (0x0002)    │
│ Length   : 256 bytes        │
│ ID       : 1002             │
└─────────────────────────────┘
Header valid: YES
```

---

## Exercice 10 : Dispatch table avec structures (Difficile)

**Objectif** : Créer une table de commandes complète.

**Instructions** :
1. Définir une structure de commande :
```c
typedef int (*CmdFunc)(const char *args);

typedef struct {
    char name[16];
    char description[64];
    CmdFunc execute;
    int requires_args;
} Command;
```

2. Implémenter au moins 5 commandes :
   - `help` - Liste les commandes
   - `whoami` - Affiche "user: hacker"
   - `pwd` - Affiche "/home/hacker"
   - `echo` - Affiche l'argument
   - `exit` - Retourne -1 pour quitter

3. Créer `Command *find_command(Command *cmds, const char *name)`

4. Créer `int dispatch(Command *cmds, const char *input)` qui :
   - Parse la commande et les arguments
   - Trouve et exécute la commande
   - Gère les erreurs

5. Simuler l'exécution de plusieurs commandes

**Sortie attendue** :
```
=== Command Dispatcher ===

> help
Available commands:
  help     - Show this help message
  whoami   - Show current user
  pwd      - Print working directory
  echo     - Echo the arguments
  exit     - Exit the shell

> whoami
user: hacker

> pwd
/home/hacker

> echo Hello World!
Hello World!

> unknown
Error: Unknown command 'unknown'

> exit
Goodbye!
```

---

## Exercice 11 : Credential harvesting (Difficile)

**Objectif** : Stocker et gérer des credentials.

**Instructions** :
1. Définir une structure `Credential` :
   - `char username[64]`
   - `char password[128]`
   - `char domain[32]`
   - `char source[32]` (ex: "browser", "lsass", "keylog")
   - `time_t timestamp`

2. Définir une structure `CredentialVault` :
   - `Credential *credentials`
   - `int count`
   - `int capacity`

3. Implémenter :
   - `CredentialVault *vault_create(int initial_capacity)`
   - `int vault_add(CredentialVault *v, const char *user, const char *pass, const char *domain, const char *source)`
   - `void vault_search(CredentialVault *v, const char *keyword)`
   - `void vault_dump(CredentialVault *v)`
   - `void vault_destroy(CredentialVault *v)`

4. Tester avec plusieurs credentials

**Sortie attendue** :
```
=== Credential Vault ===
[+] Added: admin@CORP (from browser)
[+] Added: backup_svc@CORP (from lsass)
[+] Added: john.doe@CORP (from keylog)

=== All Credentials ===
[0] admin@CORP:P@ssw0rd123 (browser)
[1] backup_svc@CORP:Summer2024! (lsass)
[2] john.doe@CORP:Welcome1 (keylog)

=== Search: "admin" ===
Found: admin@CORP:P@ssw0rd123
```

---

## Exercice 12 : Packet crafting (Challenge)

**Objectif** : Construire des structures de paquets réseau.

**Instructions** :
1. Définir les structures (packed) :
```c
// Ethernet Header (14 bytes)
typedef struct {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype;
} EthernetHeader;

// IP Header (20 bytes minimum)
typedef struct {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} IPHeader;

// TCP Header (20 bytes minimum)
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
} TCPHeader;
```

2. Créer des fonctions pour construire chaque header

3. Créer une fonction `void craft_syn_packet(...)` qui assemble un paquet SYN complet

4. Créer une fonction `void hexdump_packet(void *packet, int size)`

**Sortie attendue** :
```
=== Crafting SYN Packet ===
Source     : 192.168.1.100:45678
Destination: 10.0.0.1:80
Flags      : SYN

=== Ethernet Header (14 bytes) ===
00 11 22 33 44 55 AA BB CC DD EE FF 08 00

=== IP Header (20 bytes) ===
45 00 00 28 12 34 40 00 40 06 00 00 C0 A8 01 64
0A 00 00 01

=== TCP Header (20 bytes) ===
B2 6E 00 50 00 00 00 01 00 00 00 00 50 02 FF FF
00 00 00 00

=== Full Packet (54 bytes) ===
00 11 22 33 44 55 AA BB CC DD EE FF 08 00 45 00
00 28 12 34 40 00 40 06 00 00 C0 A8 01 64 0A 00
00 01 B2 6E 00 50 00 00 00 01 00 00 00 00 50 02
FF FF 00 00 00 00
```

---

## Exercice 13 : Liste chaînée de tasks (Challenge)

**Objectif** : Implémenter une queue de tâches avec liste chaînée.

**Instructions** :
1. Définir les structures :
```c
typedef enum {
    TASK_PENDING,
    TASK_RUNNING,
    TASK_COMPLETED,
    TASK_FAILED
} TaskStatus;

typedef struct Task {
    uint32_t id;
    char command[64];
    char *result;
    TaskStatus status;
    struct Task *next;
} Task;

typedef struct {
    Task *head;
    Task *tail;
    int count;
    uint32_t next_id;
} TaskQueue;
```

2. Implémenter :
   - `TaskQueue *queue_create(void)`
   - `Task *queue_add(TaskQueue *q, const char *command)`
   - `Task *queue_get_pending(TaskQueue *q)` - Retourne la première tâche pending
   - `void task_complete(Task *t, const char *result, int success)`
   - `void queue_print(TaskQueue *q)`
   - `void queue_destroy(TaskQueue *q)`

3. Simuler le cycle de vie de plusieurs tâches

**Sortie attendue** :
```
=== Task Queue Demo ===

[+] Added task 1: whoami
[+] Added task 2: pwd
[+] Added task 3: ls -la

=== Queue Status ===
Task 1: whoami [PENDING]
Task 2: pwd [PENDING]
Task 3: ls -la [PENDING]
Total: 3 tasks

[*] Processing task 1: whoami
[+] Task 1 completed

[*] Processing task 2: pwd
[+] Task 2 completed

=== Queue Status ===
Task 1: whoami [COMPLETED] -> "root"
Task 2: pwd [COMPLETED] -> "/home/hacker"
Task 3: ls -la [PENDING]
Total: 3 tasks
```

---

## Exercice 14 : Mini Implant Framework (Challenge)

**Objectif** : Combiner tous les concepts dans un framework d'implant.

**Instructions** :
1. Créer un framework avec :
```c
// Configuration
typedef struct {
    char id[32];
    char c2_server[128];
    int port;
    int sleep_time;
} Config;

// Command Handler
typedef int (*Handler)(const char *args, char *output, int output_size);

typedef struct {
    char name[16];
    Handler handler;
} CommandEntry;

// Implant principal
typedef struct {
    Config config;
    CommandEntry *commands;
    int cmd_count;
    int running;
} Implant;
```

2. Implémenter :
   - `Implant *implant_create(const char *c2, int port)`
   - `int implant_register_command(Implant *imp, const char *name, Handler h)`
   - `int implant_execute(Implant *imp, const char *cmd, char *output, int size)`
   - `void implant_run(Implant *imp)` - Boucle principale (simulée)
   - `void implant_destroy(Implant *imp)`

3. Implémenter les commandes : `id`, `sleep`, `checkin`, `exit`

4. Simuler une session d'implant

**Sortie attendue** :
```
=== Implant Framework Demo ===

[*] Creating implant...
[+] Implant created: IMP-001

[*] Registering commands...
[+] Registered: id
[+] Registered: sleep
[+] Registered: checkin
[+] Registered: exit

[*] Starting implant loop...

[<] Command: id
[>] Response: IMP-001

[<] Command: checkin
[>] Response: Checked in to evil.com:443

[<] Command: sleep 30
[>] Response: Sleep time set to 30s

[<] Command: exit
[>] Response: Shutting down...

[*] Implant stopped
```

---

## Barème de difficulté

| Exercice | Difficulté | Concepts clés |
|----------|------------|---------------|
| 1 | Facile | struct, membres, . |
| 2 | Facile | typedef, initialisation |
| 3 | Facile | Pointeurs, -> |
| 4 | Moyen | Tableau de structures |
| 5 | Moyen | Structures imbriquées |
| 6 | Moyen | Allocation dynamique |
| 7 | Moyen | Padding, alignement |
| 8 | Difficile | Configuration d'implant |
| 9 | Difficile | Protocole binaire |
| 10 | Difficile | Dispatch table |
| 11 | Difficile | Credential store |
| 12 | Challenge | Packet crafting |
| 13 | Challenge | Liste chaînée |
| 14 | Challenge | Framework complet |

---

## Conseils

1. **Toujours initialiser** les structures (avec `{0}` ou `memset`)
2. **Utiliser typedef** pour simplifier le code
3. **Passer par pointeur** pour éviter les copies
4. **Utiliser const** quand la structure n'est pas modifiée
5. **Attention au padding** pour les protocoles réseau
6. **Documenter les membres** avec des commentaires

Bonne chance !
