# Cours : Memory Mapping (mmap)

## 1. Introduction - Fichiers et Mémoire

### 1.1 Le Problème avec read()/write()

Normalement, pour lire un fichier, on utilise `read()` :

```c
// Méthode traditionnelle
int fd = open("big_file.dat", O_RDONLY);
char buffer[4096];

while (read(fd, buffer, 4096) > 0) {
    process(buffer);  // Traiter les données
}
```

**Problème** : À chaque appel `read()` :
1. **Syscall** : Transition user → kernel (lent)
2. **Copie** : Données copiées du kernel vers votre buffer
3. **Répéter** : Pour chaque bloc de 4 KB

```ascii
AVEC read() :

DISQUE           KERNEL          USER SPACE
┌────────┐      ┌────────┐      ┌────────┐
│ File   │ ───→ │ Buffer │ ───→ │ Buffer │  ← 2 copies !
│ 100 MB │      │ Kernel │      │ User   │
└────────┘      └────────┘      └────────┘
    ↑               ↑               ↑
   Lent          Syscall        Copie
```

### 1.2 La Solution : Memory Mapping

**mmap()** permet de **mapper** le fichier directement dans votre espace mémoire.

```ascii
AVEC mmap() :

DISQUE                    USER SPACE
┌────────┐               ┌────────┐
│ File   │ ────mmap────→ │ Pointer│
│ 100 MB │               │  │     │
└────────┘               └──┼─────┘
                            │
Accès DIRECT                ↓
(pas de copie)          data[1000]  ← Lit directement depuis disque !
```

**Avantages** :
- ✅ **Pas de copie** : Accès direct au fichier
- ✅ **Pas de syscall** répété : Un seul `mmap()` au début
- ✅ **Lazy loading** : Chargé seulement quand accédé
- ✅ **Cache kernel** : Pages partagées entre processus

## 2. Principe Détaillé - Mémoire Virtuelle

### 2.1 Pages Mémoire

La mémoire est divisée en **pages** (généralement 4 KB ou 16 KB sur ARM64).

```ascii
MÉMOIRE VIRTUELLE (ce que votre programme voit) :

┌──────────┐  0x0000000000000000
│  Code    │  ← Votre programme
├──────────┤  0x0000000100000000
│  Data    │
├──────────┤  
│  Heap    │  ← malloc()
├──────────┤
│  ...     │
├──────────┤
│  mmap    │  ← Fichier mappé ici !
│  region  │
├──────────┤
│  Stack   │  ← Variables locales
└──────────┘  0x00007FFFFFFFFFFF

FICHIER SUR DISQUE :
┌──────────┐
│ Page 0   │ ←──┐
├──────────┤    │
│ Page 1   │ ←──┼── Mappé dans mémoire virtuelle
├──────────┤    │
│ Page 2   │ ←──┘
├──────────┤
│ Page 3   │
└──────────┘
```

### 2.2 Comment ça Marche ?

**Étape 1** : Appel `mmap()`
```c
void *addr = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
```

**Étape 2** : Le kernel crée une **table de mapping**
```ascii
┌──────────────────────────────────────┐
│  Page Table (Table de pages)        │
├────────────┬─────────────────────────┤
│ Addr Virt  │ Fichier + Offset        │
├────────────┼─────────────────────────┤
│ 0x7f000000 │ file.txt, offset 0      │ ← Page 0
│ 0x7f001000 │ file.txt, offset 4096   │ ← Page 1
│ 0x7f002000 │ file.txt, offset 8192   │ ← Page 2
│ ...        │ ...                     │
└────────────┴─────────────────────────┘
```

**Étape 3** : Accès aux données
```c
char first_byte = ((char*)addr)[0];  // Accès à offset 0
```

**Étape 4** : Page Fault → Chargement automatique
```ascii
1. CPU essaie d'accéder à 0x7f000000
2. MMU (Memory Management Unit) vérifie : "Page pas en RAM"
3. **PAGE FAULT** (interruption)
4. Kernel intervient :
   - Lit 4 KB depuis file.txt offset 0
   - Place en RAM
   - Met à jour page table
5. Retour au code utilisateur
6. Accès réussit (transparentne pour le programme)
```

**C'est du "lazy loading"** : Les pages sont chargées **seulement quand accédées** !

### 2.3 Pourquoi C'est Rapide ?

```ascii
SCÉNARIO : Lire un fichier de 100 MB

AVEC read() :
┌─────────────────────┐
│ 1. open()           │  Syscall 1
│ 2. read(4KB)        │  Syscall 2
│ 3. read(4KB)        │  Syscall 3
│ ...                 │
│ 25,600. read(4KB)   │  Syscall 25,600 !
│ 25,601. close()     │  Syscall 25,601
└─────────────────────┘
Total : 25,601 syscalls ❌

AVEC mmap() :
┌─────────────────────┐
│ 1. open()           │  Syscall 1
│ 2. mmap()           │  Syscall 2
│ 3. accès direct...  │  (pas de syscall, page faults auto)
│ 4. munmap()         │  Syscall 3
│ 5. close()          │  Syscall 4
└─────────────────────┘
Total : 4 syscalls ✅

Gain : ~6400x moins de syscalls !
```

## 3. mmap() - Créer un Mapping

```c
#include <sys/mman.h>
#include <fcntl.h>

int fd = open("file.txt", O_RDWR);
struct stat st;
fstat(fd, &st);

void *addr = mmap(
    NULL,                    // Adresse (NULL = kernel choisit)
    st.st_size,             // Taille
    PROT_READ | PROT_WRITE, // Protection
    MAP_SHARED,             // Flags
    fd,                     // File descriptor
    0                       // Offset
);

if (addr == MAP_FAILED) {
    perror("mmap");
    exit(1);
}

// Accès direct !
char *data = (char*)addr;
printf("Premier char: %c\n", data[0]);
data[0] = 'X';  // Modification écrite sur disque

munmap(addr, st.st_size);
close(fd);
```

## 4. Protection

| Flag | Description |
|------|-------------|
| PROT_READ | Lecture |
| PROT_WRITE | Écriture |
| PROT_EXEC | Exécution |
| PROT_NONE | Aucun accès |

## 5. Flags

### MAP_SHARED vs MAP_PRIVATE

```c
// MAP_SHARED : Modifications visibles par autres processus
void *shared = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                    MAP_SHARED, fd, 0);

// MAP_PRIVATE : Copy-on-write (modifications privées)
void *private = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE, fd, 0);
```

### MAP_ANONYMOUS

Mapping sans fichier (mémoire pure).

```c
void *mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

// Équivalent à malloc() mais pages alignées
```

## 6. Mémoire Partagée avec mmap

```c
// Processus 1 : Créer
int fd = shm_open("/myshm", O_CREAT | O_RDWR, 0666);
ftruncate(fd, 4096);

void *shared = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                    MAP_SHARED, fd, 0);

strcpy(shared, "Data partagée");

// Processus 2 : Accéder
int fd = shm_open("/myshm", O_RDWR, 0666);
void *shared = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                    MAP_SHARED, fd, 0);

printf("Data: %s\n", (char*)shared);

shm_unlink("/myshm");
```

## 7. Changer Protection

```c
void *addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

// Rendre exécutable
mprotect(addr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);

// Copier shellcode
memcpy(addr, shellcode, shellcode_len);

// Exécuter
void (*func)() = (void(*)())addr;
func();
```

## 8. Synchronisation

```c
// Forcer écriture sur disque
msync(addr, size, MS_SYNC);

// Informer le kernel
madvise(addr, size, MADV_SEQUENTIAL);  // Accès séquentiel
madvise(addr, size, MADV_RANDOM);      // Accès aléatoire
madvise(addr, size, MADV_WILLNEED);    // Précharger
```

## 9. Exploitation

### Shellcode Loader

```c
unsigned char shellcode[] = "\x48\x31\xc0...";

void *mem = mmap(NULL, sizeof(shellcode),
                 PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

memcpy(mem, shellcode, sizeof(shellcode));

void (*func)() = (void(*)())mem;
func();  // Exécute le shellcode
```

### Process Injection via mmap

```c
// Dans processus cible
void *remote = mmap(NULL, shellcode_len,
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

// Écrire shellcode
process_vm_writev(pid, ...);

// Créer thread à cette adresse
// (nécessite ptrace ou autre)
```

## 10. File Mapping pour Performance

```c
// Au lieu de :
FILE *fp = fopen("huge.dat", "r");
while (fread(buffer, 1, 4096, fp)) {
    process(buffer);
}

// Utiliser mmap (plus rapide) :
int fd = open("huge.dat", O_RDONLY);
struct stat st;
fstat(fd, &st);

char *data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

for (size_t i = 0; i < st.st_size; i++) {
    process(data[i]);  // Accès direct
}

munmap(data, st.st_size);
```

## 11. Sécurité

### ⚠️ PROT_EXEC + PROT_WRITE

Pages RWX = dangereux (shellcode injection).

```c
// Préférer : RW → copier → RX
void *mem = mmap(..., PROT_READ | PROT_WRITE, ...);
memcpy(mem, code, size);
mprotect(mem, size, PROT_READ | PROT_EXEC);  // W→X
```

### ⚠️ ASLR

mmap() respecte ASLR (randomise adresses).

### ⚠️ Huge Pages

Pour performance, mais attention sécurité.

```c
void *addr = mmap(NULL, 2*1024*1024,  // 2 MB
                  PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB,
                  -1, 0);
```

## 12. Comparaison

| Méthode | Performance | Use Case |
|---------|-------------|----------|
| read()/write() | Moyen | Petits fichiers |
| **mmap()** | **Rapide** | **Gros fichiers, random access** |
| sendfile() | Très rapide | Transfert fichier→socket |

## 13. Bonnes Pratiques

1. **Toujours** munmap() après usage
2. **Vérifier** MAP_FAILED
3. **Éviter** RWX simultanément
4. **Utiliser** pour gros fichiers (> 1 MB)
5. **Préférer** MAP_PRIVATE pour lecture

## Ressources

- [mmap(2)](https://man7.org/linux/man-pages/man2/mmap.2.html)
- [mprotect(2)](https://man7.org/linux/man-pages/man2/mprotect.2.html)

