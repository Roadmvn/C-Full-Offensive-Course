# Module 08 : Linux Offensive

```
+-------------------------------------------------------------------+
|                                                                     |
|   "Linux n'est pas que pour les serveurs.                          |
|    C'est aussi un terrain d'attaque riche et sous-estime."         |
|                                                                     |
|   Syscalls, ELF, rootkits kernel, eBPF, containers...             |
|   Ce module t'apprend l'offensif cote Linux.                      |
|                                                                     |
+-------------------------------------------------------------------+
```

## Objectifs d'apprentissage

A la fin de ce module, tu sauras :

- Utiliser les syscalls Linux et comprendre le format ELF
- Injecter du code et hooker des syscalls en userland
- Exploiter des vulnerabilites classiques (stack overflow, format string, UAF)
- Ecrire des modules kernel (LKM) et des rootkits
- Developper un C2/beacon adapte a Linux

## Prerequis

- Modules 01-03 (C, Pointeurs, ASM) valides
- Module 05 (Windows Advanced) recommande pour comparer les approches
- Une VM Linux (Ubuntu/Debian) pour tester
- Acces root sur la VM pour les modules kernel

## Contenu du module

Ce module est organise en **6 sections** dans `topics/`.

---

### Section 1 : Fondamentaux (`topics/01-Fondamentaux/`)

| # | Topic | Description |
|---|-------|-------------|
| 01 | Syscalls-Linux | Appels systeme directs (write, open, mmap...) |
| 02 | ELF-Format | Structure des binaires ELF, headers, sections |
| 03 | Ptrace | Tracer et controler un processus |
| 04 | Proc-Filesystem | /proc comme source d'information |
| 05 | Shared-Libraries | .so, LD_PRELOAD, hijacking |
| 06 | Networking-Linux | Sockets POSIX, connexions reseau |
| 07 | Permissions-Capabilities | Permissions Unix, capabilities Linux |
| 08 | Memory-Linux | mmap, mprotect, gestion memoire |

### Section 2 : Internals (`topics/02-Internals/`)

| # | Topic | Description |
|---|-------|-------------|
| 01 | Process-Injection | Injection via ptrace et /proc/pid/mem |
| 02 | Syscall-Hooking-User | Hooking de syscalls en userland |
| 03 | Anti-Debug | Techniques anti-debugging Linux |
| 04 | Sandbox-Linux | Detection de sandbox |
| 05 | PAM-Backdoor | Backdoor via les modules PAM |
| 06 | Shellcode-Linux | Ecrire du shellcode Linux x64 |
| 07 | ROP-Linux | Return-Oriented Programming sous Linux |
| 08 | Heap-Linux | Exploitation du heap (glibc malloc) |

### Section 3 : Exploitation (`topics/03-Shellcoding/`)

| # | Topic | Description |
|---|-------|-------------|
| 01 | Stack-Overflow-Linux | Buffer overflow classique |
| 02 | Format-String-Linux | Exploitation de format strings |
| 03 | Use-After-Free | Exploitation de Use-After-Free |
| 04 | Race-Conditions | Exploiter des race conditions |
| 05 | Kernel-Exploits-Basics | Introduction aux exploits kernel |
| 06 | Dirty-Pipe-Study | Etude de CVE-2022-0847 (Dirty Pipe) |

### Section 4 : Privilege Escalation & Containers (`topics/07-Privilege-Escalation/`)

| # | Topic | Description |
|---|-------|-------------|
| 01 | ROP-Basics | ROP pour escalade de privileges |
| 02 | Container-Basics | Fondamentaux des containers Linux |
| 03 | Docker-Exploitation | Exploitation et evasion Docker |
| 04 | Kubernetes-Basics | Introduction a Kubernetes |
| 05 | Kubernetes-Attacks | Attaques sur clusters Kubernetes |
| 06 | Namespace-Escape | Evasion de namespaces |
| 07 | Cgroup-Escape | Evasion de cgroups |

### Section 5 : Rootkits (`topics/08-Rootkits/`)

| # | Topic | Description |
|---|-------|-------------|
| 01 | LKM-Basics | Ecrire un Loadable Kernel Module |
| 02 | Syscall-Table-Hook | Hooker la table des syscalls |
| 03 | Proc-Hiding-Kernel | Cacher des processus en kernel |
| 04 | File-Hiding-Kernel | Cacher des fichiers en kernel |
| 05 | Network-Hiding | Cacher des connexions reseau |
| 06 | Rootkit-Linux | Rootkit LKM complet |
| 07 | eBPF-Basics | Introduction a eBPF |
| 08 | eBPF-Offensive | Utilisation offensive d'eBPF |

### Section 6 : C2 Development Linux (`topics/09-C2-Development/`)

| # | Topic | Description |
|---|-------|-------------|
| 01 | HTTP-Client-Linux | Client HTTP avec libcurl/sockets |
| 02 | DNS-Linux | Communication C2 via DNS |
| 03 | Beacon-Linux | Beacon adapte a Linux |
| 04 | Persistence-Linux | Crontab, systemd, init.d |
| 05 | Evasion-Linux | Techniques d'evasion Linux |
| 06 | File-Operations | Upload/download de fichiers |
| 07 | Screenshot-Linux | Capture d'ecran (X11/Wayland) |
| 08 | Keylogger-Linux | Keylogger via /dev/input |
| 09 | Credential-Linux | Extraction de credentials |
| 10 | Lateral-Linux | Mouvement lateral (SSH, etc.) |

## Comment travailler

```
1. Commence par les Fondamentaux (section 1)
2. Passe aux Internals (section 2)
3. L'Exploitation (section 3) peut etre faite en parallele
4. Privilege Escalation et Rootkits sont independants
5. Le C2 Development en dernier (il utilise tout le reste)
6. Teste TOUJOURS dans une VM, jamais sur ta machine
```

## Compilation

```bash
# Compilation standard
gcc -o example example.c

# Avec les warnings et debug
gcc -Wall -g -o example example.c

# Pour les modules kernel (LKM)
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules

# Pour les exploits (desactiver les protections en lab)
gcc -fno-stack-protector -z execstack -no-pie -o vuln vuln.c
```

## Checklist

- [ ] Je sais faire des syscalls Linux directement
- [ ] Je comprends le format ELF
- [ ] J'ai injecte du code via ptrace
- [ ] J'ai ecrit du shellcode Linux
- [ ] J'ai exploite un buffer overflow
- [ ] J'ai ecrit un LKM basique
- [ ] J'ai un rootkit qui cache un processus
- [ ] J'ai un beacon Linux fonctionnel

---

Temps estime : **25-35 heures**

Prochain module : [09 - macOS](../09-macos/)
