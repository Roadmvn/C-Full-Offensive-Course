/*
 * OBJECTIF  : Comprendre la gestion memoire Windows (VirtualAlloc, VirtualProtect)
 * PREREQUIS : Bases du C (pointeurs, allocation dynamique)
 * COMPILE   : cl example.c /Fe:example.exe
 *
 * Ce programme demontre les APIs memoire Windows essentielles pour le red teaming :
 * - VirtualAlloc / VirtualFree (allocation)
 * - VirtualProtect (changement de permissions)
 * - VirtualQuery (inspection de la memoire)
 * - HeapAlloc / HeapFree (heap management)
 */

#include <windows.h>
#include <stdio.h>

/* Decoder les flags de protection memoire */
const char* protection_name(DWORD protect) {
    switch (protect) {
        case PAGE_NOACCESS:          return "NO_ACCESS";
        case PAGE_READONLY:          return "READONLY";
        case PAGE_READWRITE:         return "READWRITE";
        case PAGE_EXECUTE:           return "EXECUTE";
        case PAGE_EXECUTE_READ:      return "EXECUTE_READ";
        case PAGE_EXECUTE_READWRITE: return "EXECUTE_READWRITE";
        case PAGE_WRITECOPY:         return "WRITECOPY";
        case PAGE_GUARD | PAGE_READWRITE: return "GUARD|READWRITE";
        default: return "AUTRE";
    }
}

/* Decoder le type de region memoire */
const char* state_name(DWORD state) {
    switch (state) {
        case MEM_COMMIT:  return "COMMIT";
        case MEM_RESERVE: return "RESERVE";
        case MEM_FREE:    return "FREE";
        default: return "?";
    }
}

/* Demo 1 : VirtualAlloc et VirtualFree */
void demo_virtual_alloc(void) {
    printf("[1] VirtualAlloc / VirtualFree\n\n");

    /* Etape 1 : Reserver sans commit (reserve l'espace d'adressage) */
    LPVOID reserved = VirtualAlloc(NULL, 0x10000, MEM_RESERVE, PAGE_READWRITE);
    printf("    [+] MEM_RESERVE   : %p (64KB reserves, pas de memoire physique)\n", reserved);

    /* Etape 2 : Commit partiel (allouer de la memoire physique) */
    LPVOID committed = VirtualAlloc(reserved, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    printf("    [+] MEM_COMMIT    : %p (4KB commites, memoire physique allouee)\n", committed);

    /* On peut maintenant ecrire dans la zone commitee */
    memcpy(committed, "Hello from VirtualAlloc!", 24);
    printf("    [+] Ecriture OK   : \"%s\"\n", (char*)committed);

    /* Liberer toute la region */
    VirtualFree(reserved, 0, MEM_RELEASE);
    printf("    [+] MEM_RELEASE   : memoire liberee\n\n");

    /* Allocation directe commit + reserve en un seul appel */
    LPVOID direct = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    printf("    [+] Alloc directe : %p (reserve + commit en un coup)\n", direct);
    VirtualFree(direct, 0, MEM_RELEASE);
    printf("\n");
}

/* Demo 2 : VirtualProtect (changement de permissions) */
void demo_virtual_protect(void) {
    printf("[2] VirtualProtect (changement de protection)\n\n");

    /* Allouer en RW (lecture/ecriture) */
    BYTE* mem = (BYTE*)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    printf("    [+] Alloue en PAGE_READWRITE : %p\n", mem);

    /* Ecrire du "code" (NOP sled + RET pour la demo) */
    mem[0] = 0x90; /* NOP */
    mem[1] = 0x90; /* NOP */
    mem[2] = 0xC3; /* RET */
    printf("    [+] Shellcode ecrit : 90 90 C3 (NOP NOP RET)\n");

    /*
     * Changer en RX (lecture/execution) - necessaire pour executer du code
     * C'est exactement ce que fait un loader de shellcode :
     * 1. Allouer en RW
     * 2. Ecrire le shellcode
     * 3. Changer en RX (ou RWX)
     * 4. Executer
     */
    DWORD old_protect;
    VirtualProtect(mem, 4096, PAGE_EXECUTE_READ, &old_protect);
    printf("    [+] Change en PAGE_EXECUTE_READ (ancienne: 0x%lX)\n", old_protect);

    /* Executer le code (NOP NOP RET - inoffensif) */
    typedef void (*func_t)(void);
    func_t f = (func_t)mem;
    f();
    printf("    [+] Code execute avec succes (NOP NOP RET)\n");

    /*
     * Technique RW -> RX est plus furtive que RWX direct
     * PAGE_EXECUTE_READWRITE (RWX) est un red flag pour les EDR
     */
    printf("    [!] Astuce : RW->RX est plus furtif que RWX direct\n");

    VirtualFree(mem, 0, MEM_RELEASE);
    printf("\n");
}

/* Demo 3 : VirtualQuery (inspection memoire) */
void demo_virtual_query(void) {
    printf("[3] VirtualQuery (inspection des regions memoire)\n\n");

    /* Inspecter les premieres regions de notre espace d'adressage */
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = NULL;
    int count = 0;

    printf("    %-18s  %-10s  %-10s  %-20s  %s\n",
           "Base", "Size", "State", "Protection", "Type");
    printf("    %-18s  %-10s  %-10s  %-20s  %s\n",
           "------------------", "----------", "----------", "--------------------", "----");

    while (count < 15 && VirtualQuery(addr, &mbi, sizeof(mbi))) {
        if (mbi.State != MEM_FREE) {
            const char* type = "";
            if (mbi.Type == MEM_IMAGE) type = "IMAGE";
            else if (mbi.Type == MEM_MAPPED) type = "MAPPED";
            else if (mbi.Type == MEM_PRIVATE) type = "PRIVATE";

            printf("    %p  0x%08lX  %-10s  %-20s  %s\n",
                   mbi.BaseAddress,
                   (DWORD)mbi.RegionSize,
                   state_name(mbi.State),
                   protection_name(mbi.Protect),
                   type);
            count++;
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
    }
    printf("\n    [*] MEM_IMAGE = DLL/EXE mappe, MEM_PRIVATE = VirtualAlloc\n\n");
}

/* Demo 4 : HeapAlloc (allocation sur le heap) */
void demo_heap(void) {
    printf("[4] Heap Management\n\n");

    /* Le heap par defaut du processus */
    HANDLE hHeap = GetProcessHeap();
    printf("    [+] Process Heap : %p\n", hHeap);

    /* Allocation sur le heap (equivalent de malloc) */
    char* buf = (char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 256);
    printf("    [+] HeapAlloc    : %p (256 octets)\n", buf);
    strcpy_s(buf, 256, "Donnees sur le heap");
    printf("    [+] Contenu      : \"%s\"\n", buf);
    HeapFree(hHeap, 0, buf);

    /* Creer un heap prive (utile pour isolation) */
    HANDLE hPrivate = HeapCreate(0, 0x10000, 0);
    printf("    [+] Heap prive   : %p\n", hPrivate);
    char* priv = (char*)HeapAlloc(hPrivate, 0, 128);
    printf("    [+] Alloc prive  : %p\n", priv);
    HeapFree(hPrivate, 0, priv);
    HeapDestroy(hPrivate);
    printf("    [+] Heap prive detruit\n\n");
}

int main(void) {
    printf("[*] Demo : Gestion memoire Windows\n");
    printf("[*] ==========================================\n\n");

    demo_virtual_alloc();
    demo_virtual_protect();
    demo_virtual_query();
    demo_heap();

    printf("[+] Exemple termine avec succes\n");
    return 0;
}
