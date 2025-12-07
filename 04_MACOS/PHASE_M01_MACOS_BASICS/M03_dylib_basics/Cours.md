# Cours : Dylib Injection (macOS)

## 1. Introduction

**Dylib injection** permet d'injecter du code dans un processus cible en forçant le chargement d'une bibliothèque dynamique (.dylib).

## 2. Méthodes d'Injection

### Méthode 1 : DYLD_INSERT_LIBRARIES

```bash
# Forcer le chargement d'une dylib
DYLD_INSERT_LIBRARIES=/path/to/inject.dylib /path/to/target

# Désactivé par SIP pour binaires signés
```

### Méthode 2 : Modifier Mach-O

Ajouter un `LC_LOAD_DYLIB` au binaire.

```bash
# Avec insert_dylib (outil tiers)
insert_dylib --inplace /path/to/inject.dylib target_binary
```

### Méthode 3 : task_for_pid + Injection Mémoire

Plus avancé, nécessite privilèges.

## 3. Créer une Dylib Injectable

```c
// inject.c
#include <stdio.h>

__attribute__((constructor))
void on_load() {
    printf("[+] Dylib injected!\n");
    // Code malveillant ici
}

__attribute__((destructor))
void on_unload() {
    printf("[-] Dylib unloaded\n");
}
```

**Compilation** :
```bash
clang -dynamiclib -o inject.dylib inject.c
```

## 4. Interception de Fonctions (Hooking)

### Avec dlsym

```c
#include <dlfcn.h>

static int (*original_printf)(const char*, ...) = NULL;

int printf(const char *format, ...) {
    if (!original_printf) {
        original_printf = dlsym(RTLD_NEXT, "printf");
    }
    
    // Log avant appel original
    original_printf("[HOOK] ");
    
    va_list args;
    va_start(args, format);
    int ret = original_printf(format, args);
    va_end(args);
    
    return ret;
}
```

### Avec Fishook (Facebook)

```c
#include "fishhook.h"

static int (*original_open)(const char*, int, ...) = NULL;

int my_open(const char *path, int flags, ...) {
    printf("[HOOK] open(%s)\n", path);
    return original_open(path, flags);
}

__attribute__((constructor))
void init() {
    rebind_symbols((struct rebinding[1]){
        {"open", my_open, (void*)&original_open}
    }, 1);
}
```

## 5. Injection dans Processus en Cours

### task_for_pid

```c
#include <mach/mach.h>

task_t task;
kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);

if (kr != KERN_SUCCESS) {
    printf("task_for_pid failed\n");
    return;
}
```

### Allouer Mémoire Distante

```c
mach_vm_address_t remote_addr = 0;
mach_vm_allocate(task, &remote_addr, size, VM_FLAGS_ANYWHERE);
```

### Écrire Dylib Path

```c
const char *dylib_path = "/tmp/inject.dylib";
mach_vm_write(task, remote_addr, (vm_offset_t)dylib_path, strlen(dylib_path));
```

### Créer Thread avec dlopen

```c
#include <pthread.h>

// Trouver adresse de dlopen
void *dlopen_addr = dlsym(RTLD_DEFAULT, "dlopen");

// Créer thread dans processus cible
pthread_t thread;
thread_create_running(task, ARM_THREAD_STATE64, 
                      (thread_state_t)&state, 
                      ARM_THREAD_STATE64_COUNT, &thread);
```

## 6. Protection et Détection

### Hardened Runtime

Empêche DYLD_INSERT_LIBRARIES et restrict dylib loading.

```bash
codesign -s - --options=runtime binary
```

### Library Validation

Valide que les dylibs sont signées par le même développeur.

### Entitlements

```xml
<key>com.apple.security.cs.allow-dyld-environment-variables</key>
<false/>
<key>com.apple.security.cs.disable-library-validation</key>
<false/>
```

### Détection

```c
// Lister dylibs chargées
#include <mach-o/dyld.h>

for (uint32_t i = 0; i < _dyld_image_count(); i++) {
    const char *name = _dyld_get_image_name(i);
    printf("Loaded: %s\n", name);
}
```

## 7. Exemples Pratiques

### Logger toutes les allocations

```c
void* malloc(size_t size) {
    static void* (*real_malloc)(size_t) = NULL;
    if (!real_malloc) real_malloc = dlsym(RTLD_NEXT, "malloc");
    
    void *ptr = real_malloc(size);
    printf("[malloc] %zu bytes at %p\n", size, ptr);
    
    return ptr;
}
```

### Intercepter network calls

```c
ssize_t send(int socket, const void *buffer, size_t length, int flags) {
    static ssize_t (*real_send)(int, const void*, size_t, int) = NULL;
    if (!real_send) real_send = dlsym(RTLD_NEXT, "send");
    
    printf("[send] %zu bytes\n", length);
    // Log data...
    
    return real_send(socket, buffer, length, flags);
}
```

## 8. Outils

- **insert_dylib** : Modifier Mach-O
- **Fishook** : Function hooking
- **Frida** : Dynamic instrumentation framework
- **Substrate** : Mobile Substrate (jailbreak)

## 9. Sécurité

### ⚠️ SIP (System Integrity Protection)

Empêche injection dans processus système.

### ⚠️ Code Signing

Dylibs injectées doivent être signées (ou SIP désactivé).

### ⚠️ AMFI

Apple Mobile File Integrity vérifie signatures.

## Ressources

- [dyld Source Code](https://opensource.apple.com/source/dyld/)
- [Fishook](https://github.com/facebook/fishhook)
- [Frida](https://frida.re/)

