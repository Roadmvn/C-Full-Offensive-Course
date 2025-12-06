SOLUTIONS - MODULE 29 : CODE OBFUSCATION

⚠️ AVERTISSEMENT : Techniques conceptuelles pour compréhension défensive.

SOLUTION 1 : STRING OBFUSCATION MACRO

C++ constexpr :
template<size_t N, char KEY>
struct ObfString {
    char data[N];
    constexpr ObfString(const char(&str)[N]) : data{} {
        for(size_t i=0; i<N; i++) data[i] = str[i] ^ KEY;
    }
};


```bash
#define OBFSTR(s) []{ \
```
    constexpr auto enc = ObfString<sizeof(s), __LINE__ & 0xFF>(s); \
    char dec[sizeof(s)]; \
    for(size_t i=0; i<sizeof(s); i++) dec[i] = enc.data[i] ^ (__LINE__ & 0xFF); \
    return dec; \
}()

Test : strings binary.exe | grep "password"  // Rien trouvé

SOLUTION 2 : CONTROL FLOW FLATTENING

Transformation :
Original: A(); B(); C();

Flattened:
int state = rand() % 3;  // Random start
int next[] = {1, 2, -1};  // State transitions obfusquées
while(state != -1) {
    switch((state * 7 + 3) % 4) {  // Opaque dispatcher
        case 0: A(); state = next[0]; break;
        case 1: B(); state = next[1]; break;
        case 2: C(); state = next[2]; break;
    }
}

CFG devient incompréhensible pour IDA Pro (spaghetti code)

SOLUTION 3 : OPAQUE PREDICATES

Toujours VRAI :
- (x * x) >= 0
- (x & 1) == 0 || (x & 1) == 1
- (&var == &var)
- getpid() > 0
- 7*x² + 7*y² - 5 != 0  // Aucune solution entière

Toujours FAUX :
- (x * (x+1)) % 2 == 1  // Produit consécutifs toujours pair
- (x % 2 == 0) && (x % 2 == 1)
- rand() < 0

Usage :
if (opaque_true) {
    real_payload();
} else {
    fake_decoy_code();
}

SOLUTION 4 : JUNK CODE GENERATOR

NOP variations :
xchg eax, eax
mov eax, eax
lea eax, [eax + 0]
sub eax, 0
add eax, 0

Push/pop pairs :
push eax; pop eax
push ebx; mov ebx, [esp]; pop ebx

Insertion :
real_instr_1();
JUNK(); JUNK();
real_instr_2();
JUNK();
real_instr_3();

Détection : Pattern matching junk, emulation

SOLUTION 5 : INSTRUCTION VIRTUALIZATION

Bytecode definition :
enum {VM_ADD, VM_SUB, VM_MOV, VM_JMP, VM_CALL, VM_RET};

Compiler :
int x = 5 + 3;  ->  [VM_MOV, reg0, 5], [VM_MOV, reg1, 3], [VM_ADD, reg0, reg1]

VM interpreter :

```c
void vm_execute(uint8_t* bytecode) {
    int regs[16], pc = 0;
```
    while(1) {
        switch(bytecode[pc++]) {
            case VM_ADD: regs[bytecode[pc]] = regs[bytecode[pc+1]] + regs[bytecode[pc+2]]; pc+=3; break;
            case VM_RET: return;
        }
    }
}

Avantage : Code original jamais visible en x86/x64

SOLUTION 6 : API HASHING

DJB2 Hash :
uint32_t djb2(const char* str) {
    uint32_t hash = 5381;
    while(*str) hash = ((hash << 5) + hash) + *str++;
    return hash;
}

Resolve API :
FARPROC get_proc_by_hash(uint32_t hash) {
    PEB* peb = __readgsqword(0x60);  // x64
    for (each module in peb->Ldr) {
        for (each export in module) {
            if (djb2(export_name) == hash)
                return export_address;
        }
    }
}

Usage :
auto CreateProcessA = (CREATEPROC)get_proc_by_hash(0xABCD1234);
CreateProcessA(...);

IAT vide, pas d'imports visibles

SOLUTION 7 : CALL INDIRECTION

Transformation :
direct_call();  ->  (*func_ptrs[opaque_index])();

Implementation :

```c
typedef void (*func_ptr)();
```
func_ptr funcs[] = {func_a, func_b, target_func, func_c};


```c
// Opaque index calculation
int idx = (getpid() ^ time(NULL)) % 4;  // Toujours 2 en réalité
```
funcs[idx]();  // Appel indirect

IDA Pro ne peut pas résoudre statiquement

SOLUTION 8 : METAMORPHIC CODE

Variations équivalentes de "x = x + 5" :
1. x = x + 5
2. x += 5
3. x = x - (-5)
4. x = x + 2 + 3
5. mov eax, [x]; add eax, 5; mov [x], eax
6. mov eax, [x]; lea eax, [eax + 5]; mov [x], eax

Register allocation :
Original : mov eax, 5
Variants : mov ebx, 5 | mov ecx, 5 | mov edx, 5

Reordering :
a=1; b=2; c=3;  ->  b=2; c=3; a=1; (si pas dépendances)

Chaque build génère signature différente

RÉFÉRENCES :
- Obfuscator-LLVM documentation
- Tigress C Obfuscator
- VMProtect whitepaper
- "Practical Malware Analysis" Chapter 15

