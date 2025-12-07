# Cheatsheet Syntaxe C - Red Team Edition

## Types de données

```c
// Types basiques
char c = 'A';              // 1 byte
short s = 32767;           // 2 bytes
int i = 42;                // 4 bytes
long l = 1234567890L;      // 8 bytes (64-bit)
float f = 3.14f;           // 4 bytes
double d = 3.14159;        // 8 bytes

// Types unsigned (important pour shellcode)
unsigned char uc = 0xFF;   // 0-255
unsigned int ui = 0xDEADBEEF;
size_t size = 1024;        // Type pour tailles mémoire

// Pointeurs (essentiel pour exploitation)
int *ptr = NULL;
void *generic_ptr = NULL;
char **argv;               // Pointeur vers pointeur
```

## Opérateurs bit à bit (crucial pour shellcode/encoding)

```c
// AND, OR, XOR, NOT
x & y    // ET bit à bit
x | y    // OU bit à bit
x ^ y    // XOR bit à bit (encryption basique)
~x       // Complément à un

// Shifts (multiplication/division rapide)
x << 2   // Shift gauche (multiply par 4)
x >> 2   // Shift droite (divide par 4)

// Rotation (utile pour obfuscation)
#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
```

## Structures et unions

```c
// Structure (utile pour PE headers, syscalls)
struct ProcessInfo {
    int pid;
    char name[256];
    void *base_address;
};

// Union (utile pour type punning)
union Converter {
    unsigned int i;
    unsigned char bytes[4];
};

// Typedef pour simplicité
typedef struct {
    void *address;
    size_t size;
} MemRegion;

// Packed struct (pas de padding - important pour network/PE parsing)
struct __attribute__((packed)) PacketHeader {
    unsigned short magic;
    unsigned int length;
};
```

## Pointeurs de fonction (hooking, callbacks)

```c
// Déclaration
typedef int (*FuncPtr)(int, int);

// Utilisation
int add(int a, int b) { return a + b; }
FuncPtr func = &add;
int result = func(5, 3);  // Appel via pointeur

// Callback Windows API style
typedef BOOL (*WINAPI_FUNC)(HANDLE, LPVOID, SIZE_T);
WINAPI_FUNC WriteProcessMemory_ptr;
```

## Manipulation mémoire

```c
// Allocation dynamique
void *buffer = malloc(1024);
if (buffer == NULL) { /* Erreur */ }
free(buffer);

// Allocation alignée (important pour shellcode)
void *aligned = aligned_alloc(16, 1024);

// Copie mémoire
memcpy(dest, src, size);
memmove(dest, src, size);  // Safe pour overlap
memset(buffer, 0x90, size);  // Remplir avec NOP

// Comparaison
if (memcmp(buf1, buf2, size) == 0) { /* égal */ }
```

## Casting et conversions

```c
// Cast basique
int x = 42;
void *ptr = (void *)x;

// Cast pointeur de fonction
void *handle = dlopen("lib.so", RTLD_NOW);
void (*func)() = (void(*)())dlsym(handle, "symbol");

// Cast pour contourner warnings (dangereux mais parfois nécessaire)
unsigned char *shellcode = (unsigned char *)VirtualAlloc(...);
```

## Macros préprocesseur (obfuscation)

```c
// Macros basiques
#define BUF_SIZE 4096
#define MAX(a, b) ((a) > (b) ? (a) : (b))

// String obfuscation
#define DECRYPT(s) decrypt_string(s)
#define HIDE_STR(s) ((char[]){s[0]^0xAA, s[1]^0xAA, ...})

// Macros conditionnelles (multi-platform)
#ifdef _WIN32
    #define EXPORT __declspec(dllexport)
#else
    #define EXPORT __attribute__((visibility("default")))
#endif

// Suppression warnings
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
// Code ici
#pragma GCC diagnostic pop
```

## Inline Assembly (shellcode, syscalls)

```c
// x64 Linux syscall
static inline long my_syscall(long n, long a1, long a2, long a3) {
    long ret;
    asm volatile (
        "mov %1, %%rax\n"
        "mov %2, %%rdi\n"
        "mov %3, %%rsi\n"
        "mov %4, %%rdx\n"
        "syscall\n"
        "mov %%rax, %0"
        : "=r"(ret)
        : "r"(n), "r"(a1), "r"(a2), "r"(a3)
        : "rax", "rdi", "rsi", "rdx", "rcx", "r11", "memory"
    );
    return ret;
}

// Lecture de registres
unsigned long get_rsp() {
    unsigned long rsp;
    asm volatile("mov %%rsp, %0" : "=r"(rsp));
    return rsp;
}
```

## Attributs compilateur (stealth)

```c
// Section personnalisée
__attribute__((section(".mycode"))) void hidden_func() {}

// Constructor/Destructor (exécution auto)
__attribute__((constructor)) void before_main() {
    // S'exécute avant main()
}

// Optimisation désactivée (anti-debug)
__attribute__((optimize("O0"))) void sensitive_func() {}

// Packing de struct
__attribute__((packed)) struct NoAlign {};

// Toujours inline (performance critique)
__attribute__((always_inline)) inline void fast_func() {}
```

## Gestion fichiers

```c
// Lecture binaire
FILE *f = fopen("target.exe", "rb");
fseek(f, 0, SEEK_END);
long size = ftell(f);
fseek(f, 0, SEEK_SET);
unsigned char *buf = malloc(size);
fread(buf, 1, size, f);
fclose(f);

// Écriture
FILE *out = fopen("payload.bin", "wb");
fwrite(shellcode, 1, shellcode_size, out);
fclose(out);
```

## Chaînes de caractères

```c
// Déclaration
char str1[] = "Hello";           // Mutable
const char *str2 = "World";      // Immutable

// Manipulation
strlen(str);                      // Longueur
strcpy(dest, src);                // Copie (dangereux!)
strncpy(dest, src, n);            // Copie limitée
strcat(dest, src);                // Concaténation
strcmp(s1, s2);                   // Comparaison

// Conversion
int num = atoi("123");
char buf[32];
snprintf(buf, sizeof(buf), "PID: %d", pid);
```

## Gestion erreurs

```c
// errno (POSIX)
#include <errno.h>
if (result == -1) {
    perror("Error");
    fprintf(stderr, "Code: %d\n", errno);
}

// Windows
DWORD err = GetLastError();
```

## Volatilité (anti-optimisation)

```c
// Empêche le compilateur d'optimiser
volatile int anti_debug = 0;

// Important pour timing attacks
volatile unsigned long long start, end;
```

## Constantes utiles

```c
// NULL pointer
#define NULL ((void *)0)

// Tailles
#define KB(x) ((x) * 1024)
#define MB(x) ((x) * 1024 * 1024)

// Boolean (si pas <stdbool.h>)
#define TRUE  1
#define FALSE 0
typedef int BOOL;

// Codes retour
#define SUCCESS 0
#define ERROR   -1
```

## Tricks Red Team

```c
// XOR encoder inline
for (int i = 0; i < size; i++) {
    buffer[i] ^= 0xAA;
}

// Zeroing sécurisé (pas optimisé out)
void secure_zero(void *ptr, size_t len) {
    volatile unsigned char *p = ptr;
    while (len--) *p++ = 0;
}

// String obfuscation simple
char key[] = {0x48^0xFF, 0x65^0xFF, 0x6C^0xFF, 0x6C^0xFF, 0x6F^0xFF, 0};
for (int i = 0; key[i]; i++) key[i] ^= 0xFF;

// Indirect call (anti-analysis)
void (*fptr)() = target_function;
fptr();
```

## Format strings (dangerous mais utile)

```c
// Lecture stack
printf("%p %p %p %p\n");  // Leak stack addresses

// Écriture mémoire (exploitation)
printf("%n", &variable);  // Écrit nombre de bytes imprimés

// Padding
printf("%08x", value);    // Pad avec zeros
printf("%-10s", str);     // Pad avec espaces
```

## Opérateurs ternaires (code compact)

```c
// Condition inline
int max = (a > b) ? a : b;

// Nesting
int result = (x > 0) ? 1 : (x < 0) ? -1 : 0;
```

## Static et extern

```c
// Static: limité au fichier (stealth)
static void internal_func() {}
static int counter = 0;

// Extern: partagé entre fichiers
extern void shared_func();
extern int global_var;
```
