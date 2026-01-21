# Module 04 - Control Flow : Conditionnelles et Boucles

## Pourquoi tu dois maîtriser ça

```c
// Sans boucles, tu scannes 5 ports manuellement
scan_port(22); scan_port(80); scan_port(443);

// Avec boucles, tu scannes tout un réseau
for (int port = 1; port <= 65535; port++) {
    scan_port(port);
}

// Sans conditions, pas d'anti-debug
if (IsDebuggerPresent()) exit(1);

// Sans switch, pas de command dispatcher
switch (cmd) {
    case 0x01: shell_exec(); break;
    case 0x02: download(); break;
}
```

**Control flow = la logique de ton implant.**

---

## if/else : Décisions

```c
if (condition) {
    // Exécuté si condition != 0 (vrai)
} else {
    // Exécuté si condition == 0 (faux)
}
```

> En C, **tout ce qui n'est pas 0 est vrai**. `if (5)` = vrai, `if (ptr)` = vrai si ptr non-NULL.

### Chaîne de conditions

```c
int score = 75;

if (score >= 90) {
    printf("A\n");
} else if (score >= 70) {
    printf("C\n");
} else {
    printf("F\n");
}
```

### Application : Anti-debug checks

```c
int security_check(void) {
    // Check 1 : API directe
    if (IsDebuggerPresent()) return 0;

    // Check 2 : Timing (debugger = lent)
    DWORD start = GetTickCount();
    volatile int sum = 0;
    for (int i = 0; i < 100000; i++) sum += i;
    if (GetTickCount() - start > 100) return 0;

    // Check 3 : Breakpoint (0xCC = INT 3)
    if (*(unsigned char*)&security_check == 0xCC) return 0;

    return 1;  // Clean
}
```

---

## switch : Multi-choix

```c
switch (value) {
    case 1:
        // Si value == 1
        break;      // OBLIGATOIRE sinon fall-through !
    case 2:
        // Si value == 2
        break;
    default:
        // Tous les autres cas
        break;
}
```

> **Sans `break`**, l'exécution continue dans le case suivant (fall-through).

### Application : Command dispatcher

```c
void handle_command(unsigned char cmd) {
    switch (cmd) {
        case 0x01: shell_exec(); break;
        case 0x02: file_download(); break;
        case 0x03: file_upload(); break;
        case 0x04: screenshot(); break;
        case 0xFF: self_destruct(); break;
        default: break;  // Ignorer commandes inconnues
    }
}
```

### Application : State machine (obfuscation)

```c
int state = 0;
while (state != 99) {
    switch (state) {
        case 0: decrypt_part1(); state = 2; break;
        case 1: execute_payload(); state = 99; break;
        case 2: decrypt_part2(); state = 1; break;
    }
}
// Flux non-linéaire = plus dur à analyser
```

---

## for : Itérations comptées

```c
for (init; condition; increment) {
    // Corps
}

// Équivalent à :
init;
while (condition) {
    // Corps
    increment;
}
```

### Exemples

```c
// 0 à 9
for (int i = 0; i < 10; i++) { }

// 10 à 1 (décroissant)
for (int i = 10; i > 0; i--) { }

// Par 2
for (int i = 0; i <= 20; i += 2) { }

// Parcours tableau
int arr[] = {1, 2, 3};
for (int i = 0; i < 3; i++) printf("%d ", arr[i]);
```

### Application : Port scanner

```c
for (int port = 1; port <= 1024; port++) {
    if (check_port(target, port)) {
        printf("[+] Port %d OPEN\n", port);
    }
}
```

### Application : XOR decoder

```c
void xor_decode(unsigned char* data, int len, unsigned char key) {
    for (int i = 0; i < len; i++) {
        data[i] ^= key;
    }
}
```

### Boucles imbriquées : Bruteforce

```c
char charset[] = "0123456789";
char pin[4];

for (int i = 0; i < 10; i++) {
    for (int j = 0; j < 10; j++) {
        for (int k = 0; k < 10; k++) {
            pin[0] = charset[i];
            pin[1] = charset[j];
            pin[2] = charset[k];
            pin[3] = '\0';
            if (try_pin(pin)) {
                printf("[+] PIN: %s\n", pin);
                return;
            }
        }
    }
}
// 10 × 10 × 10 = 1000 combinaisons
```

---

## while : Itérations conditionnelles

```c
while (condition) {
    // Tant que condition vraie
}
```

> **Utilise `while`** quand tu ne sais pas combien d'itérations.

### Application : Main loop d'agent C2

```c
int running = 1;
while (running) {
    char* cmd = beacon_checkin();
    if (cmd) {
        if (strcmp(cmd, "exit") == 0) running = 0;
        else execute(cmd);
        free(cmd);
    }
    sleep(get_jitter());  // Sleep aléatoire
}
```

### Application : Attendre un processus

```c
int pid = 0;
while ((pid = find_process("target.exe")) == 0) {
    sleep(1);  // Réessayer chaque seconde
}
printf("[+] Found PID: %d\n", pid);
```

### Boucle infinie

```c
while (1) { }  // Équivalent à for (;;) { }
```

---

## do-while : Au moins une fois

```c
do {
    // Exécuté AU MOINS une fois
} while (condition);  // Note le ; à la fin !
```

### Application : Retry avec backoff

```c
int sock = -1;
int delay = 1;
int attempts = 0;

do {
    sock = try_connect(host, port);
    if (sock < 0) {
        sleep(delay);
        delay *= 2;  // Backoff exponentiel : 1, 2, 4, 8...
        if (delay > 60) delay = 60;
        attempts++;
    }
} while (sock < 0 && attempts < 10);
```

### Application : Menu/Input validation

```c
int choice;
do {
    printf("Choice (1-4): ");
    scanf("%d", &choice);
} while (choice < 1 || choice > 4);
```

---

## break et continue

| Keyword | Action |
|---------|--------|
| `break` | Sort immédiatement de la boucle |
| `continue` | Passe à l'itération suivante |

```c
for (int i = 0; i < 10; i++) {
    if (i == 3) continue;  // Saute i=3
    if (i == 7) break;     // Sort à i=7
    printf("%d ", i);
}
// Output: 0 1 2 4 5 6
```

### Attention : break dans boucles imbriquées

```c
for (int i = 0; i < 3; i++) {
    for (int j = 0; j < 3; j++) {
        if (j == 1) break;  // Sort SEULEMENT de la boucle j
    }
    // i continue normalement
}
```

**Solution pour sortir de plusieurs boucles :**

```c
// Option 1 : Flag
int found = 0;
for (int i = 0; i < 10 && !found; i++) {
    for (int j = 0; j < 10 && !found; j++) {
        if (condition) found = 1;
    }
}

// Option 2 : goto (acceptable ici)
for (int i = 0; i < 10; i++) {
    for (int j = 0; j < 10; j++) {
        if (condition) goto done;
    }
}
done:
    printf("Sorti des deux boucles\n");
```

---

## goto : Gestion d'erreurs

```c
int process_file(void) {
    FILE* f = NULL;
    char* buf = NULL;
    int ret = -1;

    f = fopen("data.txt", "r");
    if (!f) goto cleanup;

    buf = malloc(1024);
    if (!buf) goto cleanup;

    // Traitement...
    ret = 0;

cleanup:
    if (buf) free(buf);
    if (f) fclose(f);
    return ret;
}
```

> **goto** évite la duplication du code de cleanup. Pattern très utilisé dans le kernel Linux.

---

## Patterns offensifs

### Scan avec délai aléatoire (évasion)

```c
for (int port = 1; port <= 1024; port++) {
    scan_port(port);
    usleep((rand() % 500) * 1000);  // 0-500ms aléatoire
}
```

### Pattern search en mémoire

```c
unsigned char* find_sig(unsigned char* mem, int size,
                        unsigned char* sig, int sig_len) {
    for (int i = 0; i <= size - sig_len; i++) {
        int match = 1;
        for (int j = 0; j < sig_len && match; j++) {
            if (mem[i+j] != sig[j]) match = 0;
        }
        if (match) return &mem[i];
    }
    return NULL;
}
```

### Polling avec timeout

```c
time_t start = time(NULL);
int timeout = 30;

while (time(NULL) - start < timeout) {
    if (check_condition()) {
        printf("[+] Success!\n");
        break;
    }
    sleep(1);
}
```

---

## Pièges courants

### Off-by-one

```c
int arr[10];
for (int i = 0; i <= 10; i++) {  // ❌ i <= 10 → accès arr[10] hors limites
    arr[i] = 0;
}
for (int i = 0; i < 10; i++) {   // ✅ i < 10
    arr[i] = 0;
}
```

### Integer overflow dans boucle

```c
for (unsigned char i = 0; i < 256; i++) { }  // ❌ Boucle infinie !
// Quand i=255, i++ → i=0 (wrap), donc toujours < 256
```

### Point-virgule après for

```c
for (int i = 0; i < 10; i++);  // ❌ Boucle vide !
{
    printf("Une seule fois\n");
}
```

---

## Exercices pratiques

### Exo 1 : Port scanner (5 min)
Scanne les ports 20-25, 80, 443 et affiche ceux qui sont "ouverts" (simule avec un tableau).

### Exo 2 : XOR encoder (5 min)
Encode une string avec XOR et affiche en hex.

### Exo 3 : Bruteforce PIN 4 digits (10 min)
Génère toutes les combinaisons 0000-9999.

### Exo 4 : Command dispatcher (10 min)
Implémente un switch qui gère 5 commandes différentes.

---

## Checklist

```
□ Je maîtrise if/else et les conditions chaînées
□ Je comprends switch et le fall-through
□ Je sais quand utiliser for vs while vs do-while
□ Je comprends break et continue
□ Je sais sortir de boucles imbriquées
□ Je connais le pattern goto pour cleanup
□ Je sais éviter les pièges (off-by-one, overflow)
```

---

## Glossaire express

| Terme | Définition |
|-------|------------|
| **Fall-through** | Exécution continue au case suivant sans break |
| **Off-by-one** | Erreur de 1 dans les limites (< vs <=) |
| **Backoff exponentiel** | Délai qui double à chaque retry |
| **State machine** | Flux contrôlé par variable d'état |
| **Polling** | Vérification répétée d'une condition |

---

## Prochaine étape

**Module suivant →** [06 - Fonctions](../06_functions/)

---

**Temps lecture :** 8 min | **Pratique :** 30 min
