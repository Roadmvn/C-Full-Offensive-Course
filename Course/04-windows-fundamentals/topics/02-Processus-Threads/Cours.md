# Cours : Processus et Threads

## 1. Introduction - Programme vs Processus vs Thread

### 1.1 Les Trois Concepts

**Programme** : Fichier exécutable sur le disque (code statique, inerte).
```ascii
┌──────────────┐
│ programme.exe│  ← Fichier sur disque
│ (code mort)  │
└──────────────┘
```

**Processus** : Programme **en exécution** avec sa propre mémoire.
```ascii
PROCESSUS = Programme + Contexte d'Exécution

┌────────────────────────────────┐
│  PROCESSUS (PID: 1234)         │
├────────────────────────────────┤
│  Code (.text segment)          │
│  Données (.data, .bss)         │
│  Heap (malloc)                 │
│  Stack                         │
│  Registres CPU (sauvegardés)   │
│  File descriptors ouverts      │
│  Variables d'environnement     │
└────────────────────────────────┘
```

**Thread** : Fil d'exécution **léger** à l'intérieur d'un processus.
```ascii
PROCESSUS
┌────────────────────────────────┐
│  Mémoire PARTAGÉE :            │
│  ├─ Code                       │
│  ├─ Données globales           │
│  └─ Heap                       │
├────────────────────────────────┤
│  Thread 1         Thread 2     │
│  ├─ Stack 1       ├─ Stack 2   │
│  ├─ PC 1          ├─ PC 2      │
│  └─ Registres 1   └─ Registres 2│
└────────────────────────────────┘
```

### 1.2 Analogie Concrète

**Processus** = Une **maison** complète
- Chaque maison a son propre terrain (mémoire isolée)
- Les maisons ne peuvent pas accéder au terrain des voisines
- Communication nécessite des mécanismes spéciaux (courrier = IPC)

**Thread** = Une **pièce** dans la maison
- Toutes les pièces partagent la maison (mémoire commune)
- Les pièces peuvent facilement communiquer
- Mais il faut synchroniser l'accès aux ressources partagées (mutex = verrou de porte)

### 1.3 Pourquoi C'est Important ?

En **cybersécurité** :
- **Process Injection** : Injecter du code dans un autre processus
- **DLL Injection** : Créer un thread dans un processus distant
- **Privilege Escalation** : Exploiter des processus privilégiés
- **Persistence** : Créer des processus qui survivent au reboot

## 2. Processus - Création avec fork()

### 2.1 Le Syscall fork() - La Mitose Informatique

`fork()` est l'appel système qui **duplique** un processus. C'est comme si le processus se clonait.

**Principe** : Le système d'exploitation crée une **copie exacte** du processus appelant.

```ascii
AVANT fork() :

┌──────────────────────────┐
│  Processus Parent        │
│  PID: 1000               │
│  ├─ Code                 │
│  ├─ Data                 │
│  ├─ Stack                │
│  └─ Heap                 │
└──────────────────────────┘

APRÈS fork() :

┌──────────────────────────┐   ┌──────────────────────────┐
│  Processus Parent        │   │  Processus Enfant        │
│  PID: 1000               │   │  PID: 1001 (nouveau)     │
│  ├─ Code   (identique)   │   │  ├─ Code   (copie)       │
│  ├─ Data   (identique)   │   │  ├─ Data   (copie)       │
│  ├─ Stack  (identique)   │   │  ├─ Stack  (copie)       │
│  └─ Heap   (identique)   │   │  └─ Heap   (copie)       │
└──────────────────────────┘   └──────────────────────────┘
         │                              │
         │ fork() retourne 1001         │ fork() retourne 0
         │ (PID de l'enfant)            │ (je suis l'enfant)
         ↓                              ↓
   Code du parent                   Code de l'enfant
```

### 2.2 Comprendre la Valeur de Retour de fork()

**Fork retourne DEUX FOIS** (c'est magique !) :
- Dans le **parent** : retourne le **PID de l'enfant** (> 0)
- Dans l'**enfant** : retourne **0**
- En cas d'erreur : retourne **-1**

```c
#include <unistd.h>
#include <sys/wait.h>
#include <stdio.h>

pid_t pid = fork();  // ← À partir d'ici, il y a DEUX processus

if (pid == -1) {
    // ERREUR (fork a échoué)
    perror("fork");
    exit(1);
    
} else if (pid == 0) {
    // === CODE DU FILS ===
    printf("🧒 JE SUIS LE FILS\n");
    printf("   Mon PID : %d\n", getpid());
    printf("   PID de mon parent : %d\n", getppid());
    printf("   fork() m'a retourné : %d\n", pid);
    exit(0);  // Le fils se termine
    
} else {
    // === CODE DU PÈRE ===
    printf("👨 JE SUIS LE PÈRE\n");
    printf("   Mon PID : %d\n", getpid());
    printf("   PID de mon fils : %d\n", pid);
    printf("   fork() m'a retourné : %d\n", pid);
    
    wait(NULL);  // Attendre que le fils termine
    printf("👨 Mon fils a terminé\n");
}
```

**Sortie** :
```
👨 JE SUIS LE PÈRE
   Mon PID : 1000
   PID de mon fils : 1001
   fork() m'a retourné : 1001
🧒 JE SUIS LE FILS
   Mon PID : 1001
   PID de mon parent : 1000
   fork() m'a retourné : 0
👨 Mon fils a terminé
```

### 2.3 Copy-on-Write (COW) - Optimisation

Le système d'exploitation ne copie **pas** immédiatement toute la mémoire (trop coûteux).

**Principe** : Les pages mémoire sont **partagées** jusqu'à ce qu'un processus tente de les **modifier**.

```ascii
APRÈS fork() - Mémoire partagée :

Parent                     Enfant
  ↓                          ↓
┌─────────────────────────────┐
│  Page mémoire PARTAGÉE      │
│  (Read-Only temporairement) │
└─────────────────────────────┘

Parent modifie une variable :
  ↓
┌──────────────┐    ┌──────────────┐
│ Copie Parent │    │ Copie Enfant │
│ (modifiée)   │    │ (originale)  │
└──────────────┘    └──────────────┘
```

**C'est pourquoi fork() est rapide même pour de gros processus !**

### Remplacer un Processus (exec)

```c
char *args[] = {"/bin/ls", "-l", NULL};
execve("/bin/ls", args, NULL);
// Si exec réussit, cette ligne n'est JAMAIS atteinte
perror("execve");
```

### Attendre un Processus

```c
int status;
pid_t child_pid = wait(&status);  // Bloque jusqu'à fin d'un enfant

if (WIFEXITED(status)) {
    printf("Terminé avec code: %d\n", WEXITSTATUS(status));
}
```

## 3. Threads (POSIX Threads)

### Créer un Thread

```c
#include <pthread.h>

void* thread_function(void *arg) {
    int *num = (int*)arg;
    printf("Thread: %d\n", *num);
    return NULL;
}

int main() {
    pthread_t thread;
    int data = 42;
    
    pthread_create(&thread, NULL, thread_function, &data);
    pthread_join(thread, NULL);  // Attendre la fin
    
    return 0;
}
```

### Synchronisation avec Mutex

```c
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
int compteur = 0;

void* increment(void *arg) {
    for (int i = 0; i < 1000000; i++) {
        pthread_mutex_lock(&mutex);
        compteur++;
        pthread_mutex_unlock(&mutex);
    }
    return NULL;
}
```

### Condition Variables

```c
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
int ready = 0;

// Thread 1: Attendre
pthread_mutex_lock(&mutex);
while (!ready) {
    pthread_cond_wait(&cond, &mutex);
}
pthread_mutex_unlock(&mutex);

// Thread 2: Signaler
pthread_mutex_lock(&mutex);
ready = 1;
pthread_cond_signal(&cond);
pthread_mutex_unlock(&mutex);
```

## 4. Communication Inter-Processus (IPC)

### Pipes

```c
int pipefd[2];
pipe(pipefd);  // pipefd[0]=lecture, pipefd[1]=écriture

if (fork() == 0) {
    close(pipefd[1]);
    char buf[100];
    read(pipefd[0], buf, sizeof(buf));
    printf("Reçu: %s\n", buf);
} else {
    close(pipefd[0]);
    write(pipefd[1], "Message", 7);
    wait(NULL);
}
```

### Mémoire Partagée

```c
#include <sys/shm.h>

int shmid = shmget(IPC_PRIVATE, 1024, IPC_CREAT | 0666);
char *shared = (char*)shmat(shmid, NULL, 0);

strcpy(shared, "Data partagée");

shmdt(shared);
shmctl(shmid, IPC_RMID, NULL);
```

## 5. Signaux

```c
#include <signal.h>

void handler(int sig) {
    printf("Signal %d reçu\n", sig);
}

signal(SIGINT, handler);  // Ctrl+C
signal(SIGTERM, handler);

kill(pid, SIGTERM);  // Envoyer signal à un processus
```

## 6. Processus vs Threads

| Aspect | Processus | Threads |
|--------|-----------|---------|
| Mémoire | Isolée | Partagée |
| Création | Lourd (fork) | Léger |
| Communication | IPC | Variables partagées |
| Sécurité | Isolé | Race conditions |

## 7. Sécurité

### ⚠️ Race Conditions

```c
// VULNÉRABLE sans mutex
int balance = 1000;

void withdraw(int amount) {
    if (balance >= amount) {  // RACE ICI
        balance -= amount;
    }
}
```

### ⚠️ Deadlock

```c
// Thread 1
pthread_mutex_lock(&mutex_a);
pthread_mutex_lock(&mutex_b);

// Thread 2
pthread_mutex_lock(&mutex_b);  // DEADLOCK !
pthread_mutex_lock(&mutex_a);
```

## 8. Bonnes Pratiques

1. **Toujours** vérifier retours de fork/pthread_create
2. **Attendre** les enfants avec wait()
3. **Protéger** les données partagées avec mutex
4. **Éviter** les deadlocks (ordre cohérent)
5. **Libérer** les ressources (pthread_join, shmdt)

## Ressources

- [fork(2)](https://man7.org/linux/man-pages/man2/fork.2.html)
- [pthread(7)](https://man7.org/linux/man-pages/man7/pthreads.7.html)

