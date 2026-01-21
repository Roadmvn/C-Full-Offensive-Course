# MODULE L08 : MEMORY LINUX - SOLUTIONS

## Exercice 1 : mmap() basique
```c
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    void *addr = mmap(NULL, 8192, PROT_READ|PROT_WRITE,
                      MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    printf("Adresse: %p\n", addr);
    strcpy(addr, "Test");
    munmap(addr, 8192);
    return 0;
}
```

## Exercice 2 : Mémoire exécutable
```c
#include <sys/mman.h>
#include <string.h>

int main(void) {
    unsigned char code[] = { 0xc3 };
    void *mem = mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC,
                     MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    memcpy(mem, code, 1);
    ((void(*)(void))mem)();
    munmap(mem, 4096);
    return 0;
}
```

## Exercice 3 : W^X bypass
```c
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>

int main(void) {
    size_t sz = getpagesize();
    void *mem = mmap(NULL, sz, PROT_READ|PROT_WRITE,
                     MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

    unsigned char code[] = { 0xc3 };
    memcpy(mem, code, 1);

    mprotect(mem, sz, PROT_READ|PROT_EXEC);
    ((void(*)(void))mem)();

    munmap(mem, sz);
    return 0;
}
```

## Exercice 4 : Parser /proc/self/maps
```c
#include <stdio.h>

int main(void) {
    FILE *fp = fopen("/proc/self/maps", "r");
    char line[512];

    while (fgets(line, sizeof(line), fp)) {
        unsigned long start, end;
        char perms[5], path[256] = "";
        sscanf(line, "%lx-%lx %4s %*s %*s %*s %255[^\n]",
               &start, &end, perms, path);
        printf("%016lx-%016lx %s %s\n", start, end, perms, path);
    }

    fclose(fp);
    return 0;
}
```

## Exercice 5 : Détecter RWX
```c
#include <stdio.h>
#include <string.h>

int main(void) {
    FILE *fp = fopen("/proc/self/maps", "r");
    char line[512];

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "rwxp")) {
            printf("[ALERT] %s", line);
        }
    }
    fclose(fp);
    return 0;
}
```

## Exercice 6 : Trouver libc
```c
#include <stdio.h>
#include <string.h>

unsigned long find_libc_base(void) {
    FILE *fp = fopen("/proc/self/maps", "r");
    char line[512];
    unsigned long base = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "libc") && strstr(line, "r-xp")) {
            sscanf(line, "%lx", &base);
            break;
        }
    }
    fclose(fp);
    return base;
}
```
