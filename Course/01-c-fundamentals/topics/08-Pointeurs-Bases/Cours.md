# Module 09 - Pointeurs : L'arme fatale du maldev

## Pourquoi tu dois maîtriser ça

```c
// Injection de shellcode
void* addr = VirtualAlloc(NULL, sc_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
memcpy(addr, shellcode, sc_len);      // ← pointeur pour copier
((void(*)())addr)();                  // ← pointeur de fonction pour exécuter

// Hook de fonction API
unsigned char* target = (unsigned char*)GetProcAddress(kernel32, "LoadLibraryA");
*target = 0xE9;                       // ← patch avec un JMP
*(int*)(target+1) = offset;           // ← écriture d'adresse via pointeur

// Lecture mémoire d'un autre process
ReadProcessMemory(hProcess, (LPCVOID)0x7FFE0000, buffer, 1024, NULL);
```

**Sans pointeurs, pas d'exploitation mémoire, pas d'injection, pas de hook.**

---

## L'essentiel en 30 secondes

```c
int x = 42;        // x = valeur
int *ptr = &x;     // ptr = adresse de x
*ptr = 1337;       // x vaut maintenant 1337
```

> **Pointeur** = variable qui contient une **adresse mémoire**, pas une valeur directe.

```
Variable x :
┌─────────────┐
│ valeur: 42  │ ← à l'adresse 0x7FFE0000
└─────────────┘
        ↑
        │
┌───────┴─────┐
│ ptr         │
│ = 0x7FFE0000│ ← stocke l'ADRESSE, pas 42
└─────────────┘
```

---

## Les deux opérateurs : & et *

| Opérateur | Nom | Fait quoi | Exemple |
|-----------|-----|-----------|---------|
| `&` | Adresse de | Retourne l'adresse | `&x` → `0x7FFE0000` |
| `*` | Déréférencement | Lit/écrit à l'adresse | `*ptr` → valeur à cette adresse |

```c
int x = 42;
int *ptr = &x;       // ptr pointe vers x

printf("%p\n", ptr);  // 0x7FFE0000 (adresse)
printf("%d\n", *ptr); // 42 (valeur à cette adresse)

*ptr = 99;           // Modifie x via ptr
printf("%d\n", x);   // 99
```

---

## Taille des pointeurs

```c
// Sur x64 : TOUS les pointeurs font 8 bytes
sizeof(int*)    // 8
sizeof(char*)   // 8
sizeof(void*)   // 8
```

| Architecture | Taille pointeur | Format `%p` |
|--------------|-----------------|-------------|
| 32-bit | 4 bytes | `0x12345678` |
| 64-bit | 8 bytes | `0x00007FFE12345678` |

> **Pourquoi c'est important ?** En exploitation, une adresse = 4 ou 8 bytes selon l'archi. Ton payload doit être adapté.

---

## Le type compte (casting)

Le type du pointeur détermine comment lire les données :

```c
int value = 0x41424344;    // En mémoire (little endian) : 44 43 42 41

int  *pi = &value;
char *pc = (char*)&value;  // Cast vers char*

printf("%X\n", *pi);       // 41424344 (lit 4 bytes)
printf("%c\n", *pc);       // D (lit 1 byte = 0x44 = 'D')
printf("%c\n", *(pc+1));   // C (byte suivant = 0x43 = 'C')
```

> **Cast** = conversion de type. `(char*)ptr` dit "traite cette adresse comme pointeur vers char".

### Application : Lire un buffer byte par byte

```c
unsigned char* dump_memory(void* addr, int size) {
    unsigned char* ptr = (unsigned char*)addr;
    for (int i = 0; i < size; i++) {
        printf("%02X ", ptr[i]);
    }
    printf("\n");
}

int x = 0xDEADBEEF;
dump_memory(&x, 4);  // EF BE AD DE (little endian)
```

---

## Arithmétique de pointeurs

L'incrément dépend du type :

```c
int arr[] = {10, 20, 30, 40};
int *p = arr;

printf("%d\n", *p);    // 10
p++;                   // Avance de sizeof(int) = 4 bytes
printf("%d\n", *p);    // 20
p += 2;                // Avance de 2*sizeof(int) = 8 bytes
printf("%d\n", *p);    // 40
```

> **`ptr++`** avance de `sizeof(*ptr)` bytes, pas de 1 byte !

### Pour avancer de 1 byte exactement :

```c
int x = 0x41424344;
unsigned char* bp = (unsigned char*)&x;

bp++;   // Avance de 1 byte (sizeof(char) = 1)
printf("%02X\n", *bp);  // 43 ('C')
```

---

## void* : Le pointeur générique

> **`void*`** = pointeur qui peut pointer vers n'importe quel type. Doit être casté pour être utilisé.

```c
void* ptr;

int x = 42;
ptr = &x;              // OK

float y = 3.14;
ptr = &y;              // OK

// Pour utiliser, on DOIT caster :
printf("%d\n", *(int*)ptr);  // Interprète comme int
```

### Utilisation : Fonctions génériques

```c
// memcpy, memset, VirtualAlloc... utilisent void*
void* memcpy(void* dest, const void* src, size_t n);

unsigned char shellcode[] = {0x90, 0x90, 0xCC};
void* exec_mem = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
memcpy(exec_mem, shellcode, sizeof(shellcode));
```

---

## Pointeurs et tableaux

En C, un tableau EST un pointeur vers son premier élément :

```c
int arr[] = {10, 20, 30};

printf("%p\n", arr);       // 0x7FFE1000
printf("%p\n", &arr[0]);   // 0x7FFE1000 (identique!)

// Ces notations sont équivalentes :
arr[i]  ←→  *(arr + i)
```

### Application : Parcours de shellcode

```c
unsigned char sc[] = {0x48, 0x31, 0xC0, 0xC3};  // xor rax,rax; ret

// Méthode 1 : index
for (int i = 0; i < sizeof(sc); i++) {
    printf("%02X ", sc[i]);
}

// Méthode 2 : pointeur (plus idiomatique en maldev)
for (unsigned char* p = sc; p < sc + sizeof(sc); p++) {
    printf("%02X ", *p);
}
```

---

## Passage par référence

Sans pointeur, la fonction reçoit une **copie** :

```c
void echec(int x) {
    x = 1337;  // Modifie la copie locale
}

int val = 42;
echec(val);
printf("%d\n", val);  // Toujours 42!
```

Avec pointeur, la fonction modifie **l'original** :

```c
void succes(int *x) {
    *x = 1337;  // Modifie via l'adresse
}

int val = 42;
succes(&val);
printf("%d\n", val);  // 1337!
```

### Application : Fonctions qui modifient des buffers

```c
void xor_decode(unsigned char* data, int len, unsigned char key) {
    for (int i = 0; i < len; i++) {
        data[i] ^= key;  // Modifie directement le buffer original
    }
}

unsigned char payload[] = {0x2A, 0x27, 0x3B};  // XOR 0x42
xor_decode(payload, 3, 0x42);
// payload est maintenant décodé sur place
```

---

## Pointeurs de fonction

> **Pointeur de fonction** = variable qui stocke l'adresse d'une fonction. Permet d'appeler dynamiquement.

```c
// Déclaration : retour (*nom)(paramètres)
void (*func_ptr)(void);

void ma_fonction(void) {
    printf("Exécuté!\n");
}

func_ptr = ma_fonction;  // Assigne l'adresse
func_ptr();              // Appelle via le pointeur
```

### Application : Exécution de shellcode

```c
unsigned char shellcode[] = {
    0x48, 0x31, 0xC0,  // xor rax, rax
    0xC3               // ret
};

// Cast en pointeur de fonction et exécute
void (*exec)(void) = (void (*)(void))shellcode;
exec();  // BOOM (nécessite mémoire exécutable)
```

### Application : Table de dispatch C2

```c
typedef void (*cmd_handler)(char* arg);

void cmd_shell(char* arg)    { system(arg); }
void cmd_download(char* arg) { /* ... */ }
void cmd_upload(char* arg)   { /* ... */ }

struct {
    char* name;
    cmd_handler handler;
} commands[] = {
    {"shell", cmd_shell},
    {"download", cmd_download},
    {"upload", cmd_upload},
    {NULL, NULL}
};

// Exécution dynamique
void execute_command(char* name, char* arg) {
    for (int i = 0; commands[i].name; i++) {
        if (strcmp(commands[i].name, name) == 0) {
            commands[i].handler(arg);  // Appel via pointeur
            return;
        }
    }
}
```

---

## Dangers et bonnes pratiques

### 1. Pointeur non initialisé

```c
int *ptr;        // ❌ Valeur aléatoire (garbage)
*ptr = 42;       // Crash ou corruption mémoire

int *ptr = NULL; // ✅ Initialisé
```

### 2. NULL dereference

```c
int *ptr = NULL;
*ptr = 42;       // ❌ Segmentation fault

// ✅ Toujours vérifier
if (ptr != NULL) {
    *ptr = 42;
}
```

> **Segfault** (Segmentation Fault) = accès mémoire interdit. Le kernel tue ton process.

### 3. Dangling pointer

> **Dangling pointer** = pointeur vers une zone mémoire qui n'existe plus.

```c
int* bad_function(void) {
    int x = 42;
    return &x;    // ❌ x n'existe plus après return!
}

int *ptr = bad_function();
printf("%d\n", *ptr);  // Comportement indéfini (garbage ou crash)
```

### 4. Buffer overflow via pointeur

```c
char buf[8];
char *ptr = buf;

// ❌ Écriture hors limites
for (int i = 0; i < 100; i++) {
    *ptr++ = 'A';  // Écrase tout ce qui suit buf
}
```

---

## Applications offensives

### Hexdump (analyse mémoire)

```c
void hexdump(void* addr, int len) {
    unsigned char* p = (unsigned char*)addr;
    for (int i = 0; i < len; i++) {
        if (i % 16 == 0) printf("%08lX: ", (unsigned long)(p + i));
        printf("%02X ", p[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (len % 16 != 0) printf("\n");
}
```

### XOR decoder avec pointeurs

```c
void xor_decode(unsigned char* data, int len, unsigned char key) {
    unsigned char* end = data + len;
    while (data < end) {
        *data++ ^= key;
    }
}
```

### Pattern search (pour hooking/patching)

```c
unsigned char* find_pattern(unsigned char* start, int size,
                            unsigned char* pattern, int pat_len) {
    unsigned char* end = start + size - pat_len;
    for (unsigned char* p = start; p <= end; p++) {
        int found = 1;
        for (int i = 0; i < pat_len && found; i++) {
            if (p[i] != pattern[i]) found = 0;
        }
        if (found) return p;
    }
    return NULL;
}

// Usage : trouver "JNE" (0x75 0x??)
unsigned char* jne = find_pattern(code, code_len, (unsigned char*)"\x75", 1);
if (jne) {
    *jne = 0xEB;  // Patch en JMP
}
```

### Memory patching

```c
// Patch une instruction
void patch_byte(void* addr, unsigned char value) {
    // En vrai : nécessite VirtualProtect/mprotect pour changer les permissions
    *(unsigned char*)addr = value;
}

// Patch un DWORD (ex: offset de jump)
void patch_dword(void* addr, unsigned int value) {
    *(unsigned int*)addr = value;
}
```

---

## Exercices pratiques

### Exo 1 : Hexdump (5 min)
Implémente `hexdump(void* addr, int len)` qui affiche les bytes en hex.

### Exo 2 : XOR avec pointeurs (5 min)
Implémente `xor_crypt(unsigned char* data, int len, unsigned char key)` **sans utiliser d'index** (seulement `*ptr++`).

### Exo 3 : Pattern finder (10 min)
Trouve toutes les occurrences de `0x90 0x90` (NOP NOP) dans un buffer.

### Exo 4 : Memory patch (10 min)
Dans un buffer simulant du code, trouve `0x75` (JNE) et remplace par `0xEB` (JMP).

---

## Checklist

```
□ Je sais déclarer et initialiser un pointeur
□ Je comprends & (adresse) et * (déréférencement)
□ Je sais caster void* vers le bon type
□ Je comprends l'arithmétique de pointeurs
□ Je sais parcourir un buffer avec un pointeur
□ Je comprends les pointeurs de fonction
□ J'initialise TOUJOURS mes pointeurs (NULL ou adresse valide)
□ Je vérifie NULL avant de déréférencer
```

---

## Glossaire express

| Terme | Définition |
|-------|------------|
| **Pointeur** | Variable contenant une adresse mémoire |
| **Déréférencement** | Accès à la valeur via `*ptr` |
| **Cast** | Conversion de type `(type*)ptr` |
| **void*** | Pointeur générique (doit être casté) |
| **Segfault** | Crash par accès mémoire invalide |
| **Dangling pointer** | Pointeur vers mémoire libérée/invalide |
| **Pointeur de fonction** | Variable stockant l'adresse d'une fonction |
| **Arithmétique de pointeur** | `ptr++` avance de `sizeof(*ptr)` bytes |

---

## Prochaine étape

**Module suivant →** [10 - Pointeurs Avancés (malloc, pointeurs de pointeurs)](../10_pointers_advanced/)

---

**Temps lecture :** 8 min | **Pratique :** 30 min
