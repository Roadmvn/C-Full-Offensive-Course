# Module L37 : eBPF Basics - Fondamentaux de Extended BPF

## Objectifs pédagogiques

À la fin de ce module, vous serez capable de :
- Comprendre l'architecture et les concepts fondamentaux d'eBPF
- Écrire et compiler des programmes eBPF simples
- Utiliser les BPF maps pour le stockage de données
- Comprendre le rôle du verifier eBPF
- Charger et attacher des programmes eBPF au kernel

## Prérequis

- Connaissances en programmation C
- Bases du kernel Linux (syscalls, structures)
- Module précédent : Rootkits LKM

## Introduction

### C'est quoi eBPF ?

**eBPF (extended Berkeley Packet Filter)** est une technologie révolutionnaire permettant d'exécuter du code sandboxé dans le kernel Linux sans modifier le code source du kernel ni charger de modules.

**Analogie** :
```
Imagine le kernel Linux comme une forteresse impénétrable.
Traditionnellement, pour modifier son comportement :
  - Option 1 : Recompiler le kernel (long, risqué)
  - Option 2 : Charger un LKM (détectable, potentiellement instable)

eBPF = Une porte dérobée sécurisée :
  - Tu soumets un programme au verifier
  - Il vérifie que ton code ne crashera pas le kernel
  - Si approuvé, ton code s'exécute dans le kernel
  - Tu peux observer ET modifier le comportement système

C'est comme avoir un agent infiltré qui peut observer tout
sans déclencher les alarmes de sécurité.
```

### Pourquoi eBPF est important pour le Red Team ?

1. **Furtivité** : Pas de module kernel visible dans `lsmod`
2. **Pas de fichiers sur disque** : Chargé directement en mémoire
3. **Difficile à détecter** : Utilise des mécanismes kernel légitimes
4. **Accès kernel** : Peut hooker pratiquement tout (syscalls, network, etc.)
5. **Performance** : Compilé en JIT, très rapide

## Architecture eBPF

### Vue d'ensemble

```
USER SPACE                              KERNEL SPACE
═══════════                             ════════════

┌─────────────────┐
│  Programme C    │
│  (eBPF source)  │
└────────┬────────┘
         │ Compilation (clang -target bpf)
         ▼
┌─────────────────┐
│  Bytecode eBPF  │
│  (.o / .bpf.o)  │
└────────┬────────┘
         │ bpf() syscall
         ▼
┌─────────────────────────────────────────────────┐
│                   VERIFIER                       │
│                                                  │
│  ✓ Pas de boucles infinies                      │
│  ✓ Pas d'accès mémoire hors limites             │
│  ✓ Pas de code non terminant                    │
│  ✓ Stack limitée (512 bytes)                    │
│                                                  │
│  Si ÉCHEC → Programme rejeté                    │
│  Si SUCCÈS → Programme accepté                  │
└─────────────────────┬───────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────┐
│                  JIT COMPILER                    │
│                                                  │
│  Bytecode eBPF → Code machine natif (x86/ARM)   │
└─────────────────────┬───────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────┐
│              POINT D'ATTACHEMENT                 │
│                                                  │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐           │
│  │Tracepoint│ │ kprobe  │ │ XDP     │ ...       │
│  └─────────┘ └─────────┘ └─────────┘           │
│                                                  │
│  Programme exécuté à chaque événement           │
└─────────────────────────────────────────────────┘
```

### Composants clés

#### 1. Programmes eBPF

Types de programmes disponibles :

| Type | Point d'attachement | Usage offensif |
|------|---------------------|----------------|
| `BPF_PROG_TYPE_KPROBE` | Entrée/sortie de fonctions kernel | Hooking syscalls |
| `BPF_PROG_TYPE_TRACEPOINT` | Points de trace prédéfinis | Monitoring système |
| `BPF_PROG_TYPE_XDP` | Pilote réseau (avant stack) | Filtrage/modification paquets |
| `BPF_PROG_TYPE_SOCKET_FILTER` | Sockets | Sniffing réseau |
| `BPF_PROG_TYPE_CGROUP_SKB` | Cgroups réseau | Exfiltration discrète |
| `BPF_PROG_TYPE_LSM` | Linux Security Module | Bypass sécurité |

#### 2. BPF Maps

Structures de données pour stocker/partager des données :

```
┌─────────────────────────────────────────────────────┐
│                    BPF MAPS                          │
├─────────────────────────────────────────────────────┤
│                                                      │
│  ┌───────────────┐    ┌───────────────┐            │
│  │   HASH MAP    │    │   ARRAY MAP   │            │
│  │               │    │               │            │
│  │  key → value  │    │  index → val  │            │
│  │  pid → data   │    │  [0] [1] [2]  │            │
│  └───────────────┘    └───────────────┘            │
│                                                      │
│  ┌───────────────┐    ┌───────────────┐            │
│  │ PERF_EVENT    │    │  RING BUFFER  │            │
│  │               │    │               │            │
│  │  kernel ──►   │    │  lock-free    │            │
│  │      userspace│    │  streaming    │            │
│  └───────────────┘    └───────────────┘            │
│                                                      │
│  Communication bidirectionnelle kernel ↔ userspace  │
└─────────────────────────────────────────────────────┘
```

Types de maps courants :
- `BPF_MAP_TYPE_HASH` : Table de hachage clé-valeur
- `BPF_MAP_TYPE_ARRAY` : Tableau indexé
- `BPF_MAP_TYPE_RINGBUF` : Buffer circulaire (kernel → userspace)
- `BPF_MAP_TYPE_PERF_EVENT_ARRAY` : Events vers userspace
- `BPF_MAP_TYPE_LPM_TRIE` : Longest prefix match (IP routing)

#### 3. Le Verifier

Le verifier est le gardien qui empêche les programmes malveillants de crasher le kernel :

```
VÉRIFICATIONS DU VERIFIER
═════════════════════════

1. Analyse statique du flux de contrôle
   ├─ Pas de boucles infinies (bounded loops OK depuis kernel 5.3)
   ├─ Tous les chemins terminent
   └─ Pas de code mort/inatteignable

2. Vérification des accès mémoire
   ├─ Pas de déréférencement de pointeurs NULL
   ├─ Accès dans les limites des maps
   └─ Stack limitée à 512 bytes

3. Vérification des types
   ├─ Arguments corrects pour les helpers
   ├─ Types de retour validés
   └─ Pointeurs BTF (BPF Type Format)

4. Complexité limitée
   ├─ Max ~1 million d'instructions vérifiées
   └─ Limite de 4096 instructions par programme
```

## Mise en pratique

### Prérequis système

```bash
# Vérifier si eBPF est supporté
cat /boot/config-$(uname -r) | grep BPF

# Installer les outils
sudo apt install -y clang llvm libbpf-dev linux-headers-$(uname -r)

# Pour les exemples avec bpftrace
sudo apt install -y bpftrace

# Vérifier les capabilities
cat /proc/sys/kernel/unprivileged_bpf_disabled
# 0 = unprivileged users peuvent charger eBPF (rare)
# 1 = root uniquement (défaut)
# 2 = désactivé complètement
```

### Exemple 1 : Programme eBPF minimal (kprobe)

**Objectif** : Tracer tous les appels à `execve` (exécution de programmes)

**Programme eBPF** (`trace_execve.bpf.c`) :

```c
// trace_execve.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Définition de la licence (obligatoire)
char LICENSE[] SEC("license") = "GPL";

// Structure pour les données à envoyer en userspace
struct event {
    __u32 pid;
    __u32 uid;
    char comm[16];
};

// Map pour envoyer les événements vers userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// Programme attaché à l'entrée de sys_execve
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter* ctx) {
    struct event e = {};

    // Récupérer PID et UID
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e.pid = pid_tgid >> 32;
    e.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // Récupérer le nom du processus
    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    // Envoyer l'événement en userspace
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));

    return 0;
}
```

**Programme userspace** (`trace_execve.c`) :

```c
// trace_execve.c - Loader et handler userspace
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

// Structure correspondant à celle du programme eBPF
struct event {
    __u32 pid;
    __u32 uid;
    char comm[16];
};

static volatile bool running = true;

void sig_handler(int sig) {
    running = false;
}

// Callback appelé pour chaque événement
static void handle_event(void *ctx, int cpu, void *data, __u32 size) {
    struct event *e = data;
    printf("[EXECVE] PID: %d, UID: %d, Comm: %s\n", e->pid, e->uid, e->comm);
}

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link = NULL;
    struct perf_buffer *pb = NULL;
    int map_fd;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 1. Charger le programme eBPF compilé
    obj = bpf_object__open_file("trace_execve.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Erreur: impossible d'ouvrir le fichier BPF\n");
        return 1;
    }

    // 2. Charger dans le kernel
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Erreur: impossible de charger le programme BPF\n");
        goto cleanup;
    }

    // 3. Trouver le programme
    prog = bpf_object__find_program_by_name(obj, "trace_execve");
    if (!prog) {
        fprintf(stderr, "Erreur: programme non trouvé\n");
        goto cleanup;
    }

    // 4. Attacher au tracepoint
    link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "Erreur: impossible d'attacher le programme\n");
        link = NULL;
        goto cleanup;
    }

    // 5. Configurer le perf buffer pour recevoir les événements
    map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    pb = perf_buffer__new(map_fd, 8, handle_event, NULL, NULL, NULL);
    if (libbpf_get_error(pb)) {
        fprintf(stderr, "Erreur: impossible de créer le perf buffer\n");
        pb = NULL;
        goto cleanup;
    }

    printf("[*] Trace execve démarrée. Ctrl+C pour arrêter.\n");

    // 6. Boucle principale - poll des événements
    while (running) {
        int err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Erreur polling: %d\n", err);
            break;
        }
    }

cleanup:
    perf_buffer__free(pb);
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}
```

**Compilation** :

```bash
# Compiler le programme eBPF
clang -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu \
    -g -O2 -c trace_execve.bpf.c -o trace_execve.bpf.o

# Compiler le loader userspace
gcc -o trace_execve trace_execve.c -lbpf -lelf -lz

# Exécuter (nécessite root)
sudo ./trace_execve
```

**Sortie attendue** :

```
[*] Trace execve démarrée. Ctrl+C pour arrêter.
[EXECVE] PID: 1234, UID: 1000, Comm: ls
[EXECVE] PID: 1235, UID: 1000, Comm: grep
[EXECVE] PID: 1236, UID: 0, Comm: sudo
...
```

### Exemple 2 : BPF Maps pour stocker des données

```c
// pid_tracker.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

// Hash map pour tracker les PIDs vus
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);         // PID
    __type(value, __u64);       // Compteur d'exécutions
} pid_count SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int track_exec(void *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 *count, init_val = 1;

    // Chercher si le PID existe déjà
    count = bpf_map_lookup_elem(&pid_count, &pid);
    if (count) {
        // Incrémenter le compteur
        __sync_fetch_and_add(count, 1);
    } else {
        // Nouveau PID, initialiser à 1
        bpf_map_update_elem(&pid_count, &pid, &init_val, BPF_ANY);
    }

    return 0;
}
```

### Exemple 3 : Utilisation de bpftrace (rapide)

Pour du prototypage rapide, `bpftrace` permet d'écrire des one-liners :

```bash
# Tracer tous les execve
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_execve { printf("exec: %s (PID %d)\n", comm, pid); }'

# Compter les syscalls par processus
sudo bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }'

# Tracer les ouvertures de fichiers
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_openat { printf("%s ouvre: %s\n", comm, str(args->filename)); }'

# Histogramme de latence read()
sudo bpftrace -e 'kprobe:vfs_read { @start[tid] = nsecs; } kretprobe:vfs_read /@start[tid]/ { @ns = hist(nsecs - @start[tid]); delete(@start[tid]); }'
```

## BPF Helpers

Les helpers sont des fonctions fournies par le kernel, appelables depuis eBPF :

```c
// Helpers courants pour le Red Team

// Obtenir PID/TID
__u64 pid_tgid = bpf_get_current_pid_tgid();
__u32 pid = pid_tgid >> 32;
__u32 tid = pid_tgid & 0xFFFFFFFF;

// Obtenir UID/GID
__u64 uid_gid = bpf_get_current_uid_gid();
__u32 uid = uid_gid & 0xFFFFFFFF;
__u32 gid = uid_gid >> 32;

// Obtenir le nom du processus
char comm[16];
bpf_get_current_comm(&comm, sizeof(comm));

// Obtenir le timestamp
__u64 ts = bpf_ktime_get_ns();

// Lire la mémoire kernel
bpf_probe_read_kernel(&dest, size, src);

// Lire la mémoire userspace
bpf_probe_read_user(&dest, size, user_ptr);

// Lire une string userspace
bpf_probe_read_user_str(&dest, size, user_str);

// Envoyer un événement vers userspace
bpf_perf_event_output(ctx, &map, flags, data, size);

// Opérations sur les maps
bpf_map_lookup_elem(&map, &key);
bpf_map_update_elem(&map, &key, &value, flags);
bpf_map_delete_elem(&map, &key);

// Override de retour (pour kprobes)
bpf_override_return(ctx, -EPERM);  // Retourner une erreur
```

## Application offensive

### Contexte Red Team

**Avantages d'eBPF pour l'attaquant** :

1. **Aucun module visible** :
```bash
lsmod | grep -i bpf    # Rien de suspect
cat /proc/modules      # Pas de traces évidentes
```

2. **Chargement sans fichier permanent** :
```c
// Le programme peut être chargé depuis la mémoire
// Pas de fichier .ko sur le disque
```

3. **Légitimité apparente** :
```
eBPF est utilisé par :
- Outils de monitoring (Prometheus, Datadog)
- Sécurité (Falco, Cilium)
- Performance (bcc, perf)

→ Difficile de distinguer usage légitime vs malveillant
```

### Considérations OPSEC

**Détection possible** :
```bash
# Lister les programmes eBPF chargés
sudo bpftool prog list

# Lister les maps
sudo bpftool map list

# Voir les attachements
sudo bpftool link list
```

**Contre-mesures** :
1. Nommer les programmes de manière légitime
2. Limiter la durée d'exécution
3. Nettoyer après utilisation
4. Éviter les patterns suspects (trop de syscalls hookés)

## Résumé

- **eBPF** permet d'exécuter du code sandboxé dans le kernel Linux
- **Verifier** vérifie la sécurité du code avant exécution
- **BPF Maps** permettent le stockage et la communication kernel↔userspace
- **Helpers** fournissent des fonctions utilitaires (PID, UID, lecture mémoire)
- **Points d'attachement** : kprobes, tracepoints, XDP, sockets, LSM
- **Avantages offensifs** : Furtivité, pas de module visible, légitimité

## Ressources complémentaires

**Documentation officielle** :
- [eBPF.io](https://ebpf.io/) - Site officiel
- [Kernel BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/)
- [libbpf Documentation](https://libbpf.readthedocs.io/)

**Outils** :
- `bpftool` - Outil de gestion eBPF
- `bpftrace` - Langage de scripting eBPF
- `bcc` - BPF Compiler Collection

**Commandes utiles** :
```bash
# Lister les programmes eBPF
sudo bpftool prog list

# Lister les maps
sudo bpftool map list

# Dump d'un programme
sudo bpftool prog dump xlated id <ID>

# Voir les stats
sudo bpftool prog show id <ID>
```

---

**Navigation**
- [Module précédent : Rootkit Linux](../06-Rootkit-Linux/)
- [Module suivant : eBPF Offensive](../08-eBPF-Offensive/)
