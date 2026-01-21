# SOLUTION : DYLIB INJECTION


---
1. DYLIB AVEC HOOK PRINTF

---

Voir example.c pour le code complet.


```bash
# Compilation
```
clang -dynamiclib -o inject.dylib example.c


```bash
# Programme test
```
cat > test.c << 'EOF'

```c
#include <stdio.h>
int main() {
```
    printf("Hello World\n");
    printf("Test 123\n");
    return 0;
}
EOF

clang -o test test.c


```bash
# Injection
```
DYLD_INSERT_LIBRARIES=./inject.dylib ./test


```bash
# Sortie :
# === DYLIB INJECTED ===
# [HOOKED] Hello World
# [HOOKED] Test 123
```


---
2. HOOK MALLOC

---


```c
// malloc_logger.c
#include <stdio.h>
#include <dlfcn.h>
```

static void* (*real_malloc)(size_t) = NULL;

void* malloc(size_t size) {
    if (!real_malloc) {
        real_malloc = dlsym(RTLD_NEXT, "malloc");
    }
    

```c
    void *ptr = real_malloc(size);
```
    fprintf(stderr, "[malloc] %zu bytes → %p\n", size, ptr);
    
    return ptr;
}

__attribute__((constructor))

```c
void init() {
```
    fprintf(stderr, "[+] Malloc logger active\n");
}


```bash
# Compilation
```
clang -dynamiclib -o malloc_log.dylib malloc_logger.c


```bash
# Test
```
DYLD_INSERT_LIBRARIES=./malloc_log.dylib ./any_program


---
3. DÉTECTER DYLIBS CHARGÉES

---


```c
// list_dylibs.c
#include <stdio.h>
#include <mach-o/dyld.h>
```


```c
int main() {
```
    printf("=== Loaded Dylibs ===\n\n");
    
    uint32_t count = _dyld_image_count();
    printf("Total: %u dylibs\n\n", count);
    
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        const struct mach_header *header = _dyld_get_image_header(i);
        
        printf("%3u. %s\n", i+1, name);
        printf("     Base: %p\n\n", header);
    }
    
    return 0;
}


```bash
# Compilation
```
clang -o list_dylibs list_dylibs.c
./list_dylibs


---
4. MODIFIER MACH-O

---


```bash
# Installer insert_dylib
```
git clone https://github.com/Tyilo/insert_dylib
cd insert_dylib
make


```bash
# Modifier binaire
```
./insert_dylib --inplace /path/to/inject.dylib target_binary


```bash
# Vérifier
```
otool -L target_binary


```bash
# Exécuter (dylib chargée automatiquement)
```
./target_binary


---
NOTES DE SÉCURITÉ

---

- DYLD_INSERT_LIBRARIES ne fonctionne PAS avec SIP actif
- Les binaires signés rejettent les dylibs non signées
- Hardened Runtime désactive les env vars DYLD
- Pour contourner : désactiver SIP (mode recovery)


---
FIN DE LA SOLUTION

---


