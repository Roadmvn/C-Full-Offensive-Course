# Module : API Hashing et Résolution Dynamique

## Objectifs

- Comprendre la résolution d'API Windows sans imports
- Implémenter le hash de noms d'API
- Parcourir le PEB pour trouver les DLLs

---

## 1. Pourquoi le hashing ?

```
PROBLÈME : Shellcode ne peut pas importer de DLLs
SOLUTION : Résoudre les APIs dynamiquement via PEB

ÉTAPES :
1. Accéder au PEB (Process Environment Block)
2. Parcourir la liste des modules chargés
3. Trouver kernel32.dll
4. Parser son Export Table
5. Trouver les fonctions par hash
```

---

## 2. Accès au PEB (x64)

```nasm
; x64 : PEB accessible via GS segment
mov rax, gs:[0x60]      ; RAX = PEB

; Structure PEB :
; +0x018 : Ldr (PEB_LDR_DATA*)
;   +0x020 : InMemoryOrderModuleList
```

---

## 3. Algorithme de hash ROR13

```c
uint32_t hash_api(const char *name) {
    uint32_t hash = 0;
    while (*name) {
        hash = (hash >> 13) | (hash << 19);  // ROR 13
        hash += *name++;
    }
    return hash;
}

// Exemples :
// "LoadLibraryA" → 0xEC0E4E8E
// "GetProcAddress" → 0x7C0DFCAA
```

---

## 4. Code complet

```nasm
find_function:
    mov rbx, gs:[0x60]      ; PEB
    mov rbx, [rbx + 0x18]   ; Ldr
    mov rbx, [rbx + 0x20]   ; InMemoryOrderList
    mov rbx, [rbx]          ; Premier module (ntdll)
    mov rbx, [rbx]          ; Deuxième (kernel32)
    mov rbx, [rbx + 0x20]   ; DllBase
    ; ... parser Export Table
```

---

## Résumé

| Hash | API |
|------|-----|
| 0xEC0E4E8E | LoadLibraryA |
| 0x7C0DFCAA | GetProcAddress |
| 0x56A2B5F0 | ExitProcess |
