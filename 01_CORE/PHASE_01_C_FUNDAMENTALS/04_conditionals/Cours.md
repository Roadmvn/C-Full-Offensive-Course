# Module 04 : Control Flow - Conditionnelles et Boucles

## Objectifs

À la fin de ce module, tu seras capable de :
- Utiliser if/else et switch pour contrôler le flux d'exécution
- Maîtriser les boucles for, while et do-while
- Comprendre break, continue et goto
- Implémenter des techniques anti-debug basées sur le control flow
- Créer du code obfusqué avec des structures de contrôle

---

## Partie 0 : Pourquoi le Control Flow est CRUCIAL en offensive

### Anti-Debug avec conditions

```c
// Vérification multiple avec boucle
int detected = 0;
for (int i = 0; i < 10; i++) {
    if (IsDebuggerPresent()) {
        detected++;
    }
    Sleep(100);
}

if (detected > 5) {
    // Probablement sous débuggeur - exécution anormale
    exit(1);
}
```

### Obfuscation de flux

```c
// Au lieu de simplement appeler la fonction malveillante...
// On utilise un switch avec des valeurs calculées
int state = (timestamp ^ magic) % 5;
switch(state) {
    case 0: func_a(); break;
    case 1: func_b(); break;
    case 2: func_c(); break;  // <-- la vraie payload
    case 3: func_d(); break;
    case 4: func_e(); break;
}
```

### Boucles pour énumération

```c
// Scanner les ports ouverts
for (int port = 1; port <= 65535; port++) {
    if (is_port_open(target, port)) {
        printf("Port %d ouvert\n", port);
    }
}
```

**Sans maîtriser le control flow, tu ne pourras pas :**
- Implémenter des checks anti-debug efficaces
- Créer du code avec un flux d'exécution imprévisible
- Scanner des cibles efficacement
- Parser des données binaires correctement

---

## Partie 1 : Conditionnelle if/else

### Syntaxe de base

```c
if (condition) {
    // Exécuté si condition est VRAIE (non-zéro)
}
```

En C, une condition est :
- **Vraie** si elle vaut quelque chose de **différent de 0**
- **Fausse** si elle vaut **0** (exactement)

```c
int x = 5;

if (x) {
    printf("x est non-zéro\n");  // Exécuté car x = 5
}

int y = 0;
if (y) {
    printf("y est non-zéro\n");  // NON exécuté car y = 0
}
```

### if/else

```c
int age = 25;

if (age >= 18) {
    printf("Majeur\n");
} else {
    printf("Mineur\n");
}
```

### if/else if/else

```c
int score = 75;

if (score >= 90) {
    printf("Grade A\n");
} else if (score >= 80) {
    printf("Grade B\n");
} else if (score >= 70) {
    printf("Grade C\n");
} else if (score >= 60) {
    printf("Grade D\n");
} else {
    printf("Grade F\n");
}
```

### Conditions imbriquées

```c
int is_admin = 1;
int is_logged = 1;
int is_banned = 0;

if (is_logged) {
    if (!is_banned) {
        if (is_admin) {
            printf("Accès admin accordé\n");
        } else {
            printf("Accès utilisateur accordé\n");
        }
    } else {
        printf("Utilisateur banni\n");
    }
} else {
    printf("Veuillez vous connecter\n");
}
```

### APPLICATION OFFENSIVE : Vérifications de sécurité en chaîne

```c
// Anti-debug multi-checks
int security_check(void) {
    // Check 1 : IsDebuggerPresent
    if (IsDebuggerPresent()) {
        return 0;  // Échec
    }

    // Check 2 : Timing anomaly
    DWORD start = GetTickCount();
    // ... opérations ...
    DWORD elapsed = GetTickCount() - start;

    if (elapsed > 1000) {  // Trop lent = probablement débuggé
        return 0;
    }

    // Check 3 : Breakpoint detection
    unsigned char *func_ptr = (unsigned char*)&security_check;
    if (func_ptr[0] == 0xCC) {  // INT 3 = breakpoint
        return 0;
    }

    return 1;  // Tous les checks passés
}
```

---

## Partie 2 : Switch/Case

### Syntaxe de base

Le switch permet de comparer une valeur avec plusieurs cas possibles.

```c
int choice = 2;

switch (choice) {
    case 1:
        printf("Option 1 sélectionnée\n");
        break;
    case 2:
        printf("Option 2 sélectionnée\n");
        break;
    case 3:
        printf("Option 3 sélectionnée\n");
        break;
    default:
        printf("Option invalide\n");
        break;
}
```

### ATTENTION : Le fall-through

Sans `break`, l'exécution continue dans le case suivant !

```c
int x = 1;

switch (x) {
    case 1:
        printf("Un\n");
        // PAS DE BREAK - fall-through !
    case 2:
        printf("Deux\n");
        // PAS DE BREAK
    case 3:
        printf("Trois\n");
        break;
    default:
        printf("Autre\n");
}

// Output :
// Un
// Deux
// Trois
```

### Fall-through intentionnel

Parfois utile pour grouper des cas :

```c
char c = 'a';

switch (c) {
    case 'a':
    case 'e':
    case 'i':
    case 'o':
    case 'u':
        printf("Voyelle\n");
        break;
    default:
        printf("Consonne\n");
        break;
}
```

### APPLICATION OFFENSIVE : State machine pour obfuscation

```c
// Machine à états pour exécution non-linéaire
int state = 0;
int counter = 0;

while (counter < 100) {
    switch (state) {
        case 0:
            // Décryptage partie 1
            decrypt_chunk(0);
            state = 3;  // Saute au state 3
            break;

        case 1:
            // Exécution payload
            execute_payload();
            state = 4;
            break;

        case 2:
            // Initialisation
            init_environment();
            state = 0;
            break;

        case 3:
            // Décryptage partie 2
            decrypt_chunk(1);
            state = 1;  // Va au state 1
            break;

        case 4:
            // Cleanup et sortie
            cleanup();
            return;

        default:
            state = 2;  // Reset au state 2
            break;
    }
    counter++;
}
```

### APPLICATION OFFENSIVE : Dispatcher de commandes

```c
// Parser de commandes C2
void handle_command(unsigned char cmd) {
    switch (cmd) {
        case 0x01:
            cmd_shell_exec();
            break;
        case 0x02:
            cmd_file_download();
            break;
        case 0x03:
            cmd_file_upload();
            break;
        case 0x04:
            cmd_screenshot();
            break;
        case 0x05:
            cmd_keylogger_start();
            break;
        case 0xFF:
            cmd_self_destruct();
            break;
        default:
            // Commande inconnue - ignorer silencieusement
            break;
    }
}
```

---

## Partie 3 : Boucle for

### Syntaxe de base

```c
for (initialisation; condition; incrémentation) {
    // Corps de la boucle
}
```

Équivalent à :
```c
initialisation;
while (condition) {
    // Corps de la boucle
    incrémentation;
}
```

### Exemples

```c
// Compter de 0 à 9
for (int i = 0; i < 10; i++) {
    printf("%d ", i);
}
// Output: 0 1 2 3 4 5 6 7 8 9

// Compter à rebours
for (int i = 10; i > 0; i--) {
    printf("%d ", i);
}
// Output: 10 9 8 7 6 5 4 3 2 1

// Pas de 2
for (int i = 0; i < 20; i += 2) {
    printf("%d ", i);
}
// Output: 0 2 4 6 8 10 12 14 16 18
```

### Boucles imbriquées

```c
// Matrice 3x3
for (int row = 0; row < 3; row++) {
    for (int col = 0; col < 3; col++) {
        printf("[%d,%d] ", row, col);
    }
    printf("\n");
}
/*
Output:
[0,0] [0,1] [0,2]
[1,0] [1,1] [1,2]
[2,0] [2,1] [2,2]
*/
```

### APPLICATION OFFENSIVE : XOR Decryption

```c
void xor_decrypt(unsigned char *data, size_t len,
                 unsigned char *key, size_t key_len) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key[i % key_len];  // Clé cyclique avec modulo
    }
}
```

### APPLICATION OFFENSIVE : Port Scanner

```c
void scan_ports(const char *target, int start, int end) {
    for (int port = start; port <= end; port++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, target, &addr.sin_addr);

        // Timeout rapide
        struct timeval timeout = {0, 100000};  // 100ms
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            printf("[+] Port %d ouvert\n", port);
        }

        close(sock);
    }
}
```

### APPLICATION OFFENSIVE : Brute force simple

```c
// Générer toutes les combinaisons de 4 chiffres (0000-9999)
void bruteforce_pin(void) {
    for (int i = 0; i < 10000; i++) {
        char pin[5];
        snprintf(pin, sizeof(pin), "%04d", i);  // Format: 0000, 0001, ...

        if (try_pin(pin)) {
            printf("[+] PIN trouvé: %s\n", pin);
            return;
        }
    }
    printf("[-] PIN non trouvé\n");
}
```

---

## Partie 4 : Boucle while

### Syntaxe de base

```c
while (condition) {
    // Exécuté tant que condition est VRAIE
}
```

### Exemples

```c
// Compter jusqu'à 5
int count = 0;
while (count < 5) {
    printf("%d ", count);
    count++;
}
// Output: 0 1 2 3 4

// Boucle infinie
while (1) {
    // Tourne pour toujours
    // Utilise break pour sortir
}
```

### APPLICATION OFFENSIVE : Main loop d'un agent

```c
void agent_main_loop(void) {
    int running = 1;

    while (running) {
        // 1. Check-in avec le C2
        char *command = beacon_checkin();

        // 2. Exécuter la commande reçue
        if (command != NULL) {
            if (strcmp(command, "exit") == 0) {
                running = 0;  // Sortir de la boucle
            } else {
                execute_command(command);
            }
            free(command);
        }

        // 3. Sleep pour éviter la détection
        sleep(get_jitter_sleep());  // Sleep aléatoire
    }

    // Cleanup avant sortie
    cleanup_agent();
}
```

### APPLICATION OFFENSIVE : Read until delimiter

```c
// Lire des données jusqu'à un délimiteur (comme recv jusqu'à \n)
int read_until(int sock, char *buffer, int max_len, char delimiter) {
    int total = 0;
    char c;

    while (total < max_len - 1) {
        int received = recv(sock, &c, 1, 0);

        if (received <= 0) {
            break;  // Erreur ou connexion fermée
        }

        if (c == delimiter) {
            break;  // Délimiteur trouvé
        }

        buffer[total++] = c;
    }

    buffer[total] = '\0';  // Null-terminate
    return total;
}
```

---

## Partie 5 : Boucle do-while

### Syntaxe de base

Différence avec while : le corps est exécuté **au moins une fois** avant de vérifier la condition.

```c
do {
    // Corps exécuté AU MOINS UNE FOIS
} while (condition);
```

### Exemple

```c
int num;

do {
    printf("Entre un nombre positif: ");
    scanf("%d", &num);
} while (num <= 0);

printf("Tu as entré: %d\n", num);
```

### APPLICATION OFFENSIVE : Retry avec backoff

```c
// Tenter une connexion avec retry exponentiel
int connect_with_retry(const char *host, int port) {
    int sock;
    int retry = 0;
    int max_retries = 5;
    int delay = 1;  // Secondes

    do {
        sock = try_connect(host, port);

        if (sock < 0) {
            printf("Échec connexion, retry dans %d sec...\n", delay);
            sleep(delay);
            delay *= 2;  // Backoff exponentiel: 1, 2, 4, 8, 16 sec
            retry++;
        }
    } while (sock < 0 && retry < max_retries);

    return sock;
}
```

---

## Partie 6 : break, continue, goto

### break - Sortir de la boucle

`break` sort immédiatement de la boucle la plus proche.

```c
for (int i = 0; i < 100; i++) {
    if (i == 5) {
        break;  // Sort de la boucle quand i = 5
    }
    printf("%d ", i);
}
// Output: 0 1 2 3 4
```

### continue - Passer à l'itération suivante

`continue` saute le reste du corps et passe à l'itération suivante.

```c
for (int i = 0; i < 10; i++) {
    if (i % 2 == 0) {
        continue;  // Saute les nombres pairs
    }
    printf("%d ", i);
}
// Output: 1 3 5 7 9
```

### goto - Saut inconditionnel

`goto` saute à un label défini. Utile pour la gestion d'erreurs.

```c
int process_data(void) {
    FILE *f = NULL;
    char *buffer = NULL;
    int result = -1;

    f = fopen("data.txt", "r");
    if (f == NULL) {
        goto cleanup;  // Erreur : saute au cleanup
    }

    buffer = malloc(1024);
    if (buffer == NULL) {
        goto cleanup;  // Erreur : saute au cleanup
    }

    // Traitement...
    result = 0;  // Succès

cleanup:  // Label
    if (buffer) free(buffer);
    if (f) fclose(f);
    return result;
}
```

### APPLICATION OFFENSIVE : Anti-debug avec goto

```c
// Obfuscation du flow avec goto
void obfuscated_function(void) {
    int check = 0;

start:
    if (IsDebuggerPresent()) {
        goto decoy;  // Mène vers du code inutile
    }

    check++;
    if (check < 3) {
        goto start;  // Loop sans for/while
    }
    goto payload;

decoy:
    // Code "leurre" qui ne fait rien d'utile
    printf("Nothing to see here\n");
    return;

payload:
    // Le vrai code malveillant
    execute_real_payload();
    return;
}
```

---

## Partie 7 : Techniques anti-debug basées sur le control flow

### Timing checks avec boucle

```c
int timing_check(void) {
    DWORD start = GetTickCount();

    // Opérations qui devraient être rapides
    volatile int sum = 0;
    for (int i = 0; i < 100000; i++) {
        sum += i;
    }

    DWORD elapsed = GetTickCount() - start;

    // En exécution normale : quelques ms
    // Sous debugger (single-step) : beaucoup plus
    if (elapsed > 100) {
        return 1;  // Debugger détecté
    }

    return 0;
}
```

### Multiple redundant checks

```c
int paranoid_check(void) {
    int detections = 0;

    // Check plusieurs fois pour éviter les faux positifs
    for (int i = 0; i < 5; i++) {
        if (IsDebuggerPresent()) {
            detections++;
        }
        Sleep(10);
    }

    // Si détecté plus de 3 fois sur 5 = probablement vrai
    return (detections > 3);
}
```

### Control flow flattening (simplifié)

```c
// Au lieu de :
// if (a) { do_a(); } else { do_b(); } do_c();

// On "aplatit" le flux :
void flattened_flow(int a) {
    int state = 0;
    int done = 0;

    while (!done) {
        switch (state) {
            case 0:
                state = a ? 1 : 2;  // Décision
                break;
            case 1:
                do_a();
                state = 3;
                break;
            case 2:
                do_b();
                state = 3;
                break;
            case 3:
                do_c();
                done = 1;
                break;
        }
    }
}
```

---

## Partie 8 : Patterns offensifs courants

### Pattern : Scanner avec timeout

```c
void scan_network(const char *subnet) {
    for (int host = 1; host < 255; host++) {
        char ip[16];
        snprintf(ip, sizeof(ip), "%s.%d", subnet, host);

        if (ping_host(ip, 100)) {  // 100ms timeout
            printf("[+] Host actif: %s\n", ip);

            // Scanner les ports intéressants
            int ports[] = {22, 80, 443, 445, 3389};
            for (int i = 0; i < 5; i++) {
                if (is_port_open(ip, ports[i])) {
                    printf("    Port %d ouvert\n", ports[i]);
                }
            }
        }
    }
}
```

### Pattern : Parsing de données binaires

```c
void parse_pe_sections(unsigned char *pe_data, size_t size) {
    // Vérifier le magic MZ
    if (pe_data[0] != 'M' || pe_data[1] != 'Z') {
        printf("Pas un PE valide\n");
        return;
    }

    // Obtenir le nombre de sections
    int num_sections = get_pe_num_sections(pe_data);

    printf("Nombre de sections: %d\n", num_sections);

    for (int i = 0; i < num_sections; i++) {
        SECTION_HEADER *section = get_section_header(pe_data, i);

        printf("Section %d: %.8s\n", i, section->Name);
        printf("  Virtual Address: 0x%08X\n", section->VirtualAddress);
        printf("  Size: 0x%08X\n", section->SizeOfRawData);

        // Vérifier si exécutable
        if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            printf("  [!] Section exécutable\n");
        }
    }
}
```

### Pattern : State machine pour protocole

```c
typedef enum {
    STATE_INIT,
    STATE_HANDSHAKE,
    STATE_AUTH,
    STATE_READY,
    STATE_ERROR
} ConnectionState;

void protocol_handler(int sock) {
    ConnectionState state = STATE_INIT;
    char buffer[1024];

    while (state != STATE_READY && state != STATE_ERROR) {
        switch (state) {
            case STATE_INIT:
                if (send_hello(sock)) {
                    state = STATE_HANDSHAKE;
                } else {
                    state = STATE_ERROR;
                }
                break;

            case STATE_HANDSHAKE:
                if (recv_challenge(sock, buffer)) {
                    state = STATE_AUTH;
                } else {
                    state = STATE_ERROR;
                }
                break;

            case STATE_AUTH:
                if (send_credentials(sock, buffer)) {
                    state = STATE_READY;
                } else {
                    state = STATE_ERROR;
                }
                break;

            default:
                state = STATE_ERROR;
                break;
        }
    }

    if (state == STATE_READY) {
        printf("Connexion établie\n");
    } else {
        printf("Erreur de connexion\n");
    }
}
```

---

## Partie 9 : Résumé et checklist

### Tableau récapitulatif

| Structure | Utilisation | Application offensive |
|-----------|-------------|----------------------|
| `if/else` | Décisions simples | Checks de sécurité, validation |
| `switch` | Multiple choix | Dispatcher de commandes, state machines |
| `for` | Itération comptée | Scan, brute force, parsing |
| `while` | Itération conditionnelle | Main loop agent, lecture données |
| `do-while` | Au moins une exécution | Retry, menu interactif |
| `break` | Sortir de boucle | Early exit sur succès/erreur |
| `continue` | Sauter itération | Filtrage, skip erreurs |
| `goto` | Saut direct | Cleanup, obfuscation |

### Checklist offensive

- [ ] Je sais utiliser if/else pour des vérifications de sécurité
- [ ] Je maîtrise switch/case sans oublier les break
- [ ] Je sais implémenter un dispatcher de commandes
- [ ] Je comprends les trois types de boucles et quand les utiliser
- [ ] Je sais scanner des ports avec une boucle for
- [ ] Je peux implémenter une main loop d'agent avec while
- [ ] Je comprends break et continue
- [ ] Je sais utiliser goto pour la gestion d'erreurs
- [ ] Je connais les patterns anti-debug avec timing checks
- [ ] Je comprends le control flow flattening

---

## Exercices pratiques

Voir [exercice.md](exercice.md)

## Code exemple

Voir [example.c](example.c)

---

**Module suivant** : [05 - Functions](../05_functions/)
