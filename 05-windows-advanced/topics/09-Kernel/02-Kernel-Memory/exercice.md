# Exercices - Kernel Memory

## Objectifs des exercices

Ces exercices vous permettront de pratiquer la gestion memoire en mode kernel.
Progressez du plus simple au plus complexe.

---

## Exercice 1 : Pool Allocation Basique (Tres facile)

**Objectif** : Allouer et liberer de la memoire dans le NonPaged Pool

**Instructions** :
1. Creer un driver qui alloue 1024 bytes dans le NonPaged Pool
2. Utiliser le tag 'tseT' (Test)
3. Initialiser le buffer avec des zeros
4. Afficher l'adresse allouee avec DbgPrint
5. Liberer la memoire proprement

**Code de base** :
```c
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    PVOID buffer = NULL;

    // TODO: Allouer 1024 bytes avec le tag 'tseT'

    // TODO: Verifier si allocation a reussi

    // TODO: Initialiser a zero

    // TODO: Afficher l'adresse

    // TODO: Liberer la memoire

    DriverObject->DriverUnload = DriverUnload;
    return STATUS_SUCCESS;
}
```

**Resultat attendu** :
```
[+] Allocated 1024 bytes at 0xFFFFF80012345678
[+] Memory freed at 0xFFFFF80012345678
```

**Indice** : Utilisez ExAllocatePoolWithTag() et ExFreePoolWithTag()

---

## Exercice 2 : Structures avec Pool Tags (Facile)

**Objectif** : Gerer plusieurs allocations avec des tags differents

**Instructions** :
1. Definir une structure PROCESS_INFO :
   ```c
   typedef struct _PROCESS_INFO {
       ULONG ProcessId;
       WCHAR ProcessName[256];
       LARGE_INTEGER Timestamp;
   } PROCESS_INFO, *PPROCESS_INFO;
   ```
2. Allouer cette structure dans le Paged Pool avec le tag 'ofnI'
3. Remplir les champs avec des donnees de test
4. Afficher le contenu
5. Liberer proprement

**Criteres de reussite** :
- [ ] Structure allouee dans Paged Pool
- [ ] Tag 'ofnI' utilise
- [ ] Tous les champs initialises
- [ ] Memoire liberee sans fuite

---

## Exercice 3 : Creation de MDL (Moyen)

**Objectif** : Mapper un buffer user-mode vers kernel-mode

**Instructions** :
1. Creer un handler IOCTL qui reçoit un buffer user-mode
2. Allouer un MDL pour ce buffer
3. Locker les pages avec MmProbeAndLockPages
4. Obtenir l'adresse kernel avec MmGetSystemAddressForMdlSafe
5. Lire les premiers bytes et les afficher
6. Cleanup complet (unlock, free MDL)

**Code de base** :
```c
NTSTATUS HandleIoctl(PVOID InputBuffer, ULONG InputLength) {
    PMDL mdl = NULL;
    PVOID kernelVa = NULL;

    __try {
        // TODO: Creer MDL

        // TODO: Prober et locker pages

        // TODO: Obtenir adresse kernel

        // TODO: Lire donnees

    } __except(EXCEPTION_EXECUTE_HANDLER) {
        // TODO: Gerer exception
    }

    // TODO: Cleanup

    return STATUS_SUCCESS;
}
```

**Criteres de reussite** :
- [ ] MDL cree et libere sans fuite
- [ ] Pages lockees et unlockees
- [ ] Exceptions gerees correctement
- [ ] Donnees lues depuis user-mode

---

## Exercice 4 : Lecture Memoire Processus (Moyen-Difficile)

**Objectif** : Lire la memoire d'un autre processus

**Instructions** :
1. Implementer une fonction ReadProcessMemory kernel
2. Utiliser PsLookupProcessByProcessId pour obtenir EPROCESS
3. Attacher au processus avec KeStackAttachProcess
4. Lire 256 bytes depuis l'adresse 0x400000 (base executable)
5. Detacher proprement
6. Dereferencer l'objet process

**Prototype** :
```c
NTSTATUS ReadProcessMemory(
    ULONG ProcessId,
    PVOID Address,
    PVOID Buffer,
    SIZE_T Size
);
```

**Test** :
- Lire la memoire de notepad.exe (PID a passer en parametre)
- Afficher les 16 premiers bytes (MZ header attendu)

**Criteres de reussite** :
- [ ] EPROCESS obtenu et derefere
- [ ] Attach/Detach correct
- [ ] Gestion d'erreurs (PID invalide, adresse invalide)
- [ ] Memoire lue correctement

---

## Exercice 5 : Pool Monitor (Difficile)

**Objectif** : Creer un outil de monitoring des allocations

**Instructions** :
1. Creer une structure pour tracker les allocations :
   ```c
   typedef struct _ALLOC_ENTRY {
       LIST_ENTRY ListEntry;
       PVOID Address;
       SIZE_T Size;
       ULONG Tag;
       LARGE_INTEGER Timestamp;
   } ALLOC_ENTRY, *PALLOC_ENTRY;
   ```
2. Implementer un wrapper autour de ExAllocatePoolWithTag
3. Stocker chaque allocation dans une liste chainee
4. Implementer un wrapper de liberation
5. Creer un IOCTL pour lister toutes les allocations actives
6. Detecter les fuites memoire au unload

**Fonctionnalites attendues** :
- TrackedAllocate() - alloue et enregistre
- TrackedFree() - libere et supprime de la liste
- GetAllocationStats() - retourne stats (count, total size)
- DumpLeaks() - affiche allocations non liberees

**Bonus** :
- Ajouter le nom du fichier et la ligne d'appel (macro __FILE__, __LINE__)
- Implementer une limite de memoire (quota)
- Generer un rapport detaille des fuites

---

## Exercice 6 : Memory Injector (Challenge Red Team)

**Objectif** : Injecter du code dans un processus distant

**Contexte** :
Vous devez creer un driver capable d'injecter du shellcode
dans un processus cible et l'executer.

**Instructions** :
1. Implementer InjectShellcode(ProcessId, Shellcode, Size)
2. Attacher au processus cible
3. Allouer memoire executable avec ZwAllocateVirtualMemory
4. Copier le shellcode
5. Creer un thread avec PsCreateSystemThread (recherche necessaire)
6. Detacher

**Shellcode de test** (MessageBox) :
```c
unsigned char shellcode[] = {
    0x48, 0x83, 0xEC, 0x28,  // sub rsp, 0x28
    0x48, 0x31, 0xC9,        // xor rcx, rcx
    0x48, 0x31, 0xD2,        // xor rdx, rdx
    // ... (MessageBox shellcode)
};
```

**Criteres de reussite** :
- [ ] Memoire allouee dans le processus cible
- [ ] Shellcode copie correctement
- [ ] Thread cree et execute
- [ ] Pas de crash du processus cible
- [ ] Cleanup complet

**Considerations OPSEC** :
- Quelle protection memoire utiliser ?
- Comment eviter la detection EDR ?
- Quels logs sont generes ?

---

## Auto-evaluation

Avant de passer au module suivant, verifiez que vous pouvez :
- [ ] Expliquer la difference entre Paged et NonPaged Pool
- [ ] Allouer/liberer memoire sans fuites
- [ ] Creer et utiliser des MDL
- [ ] Acceder a la memoire d'autres processus
- [ ] Gerer les erreurs et exceptions
- [ ] Debugger avec PoolMon et WinDbg
- [ ] Identifier les applications offensives
- [ ] Comprendre les risques BSOD

## Solutions

Les solutions detaillees sont disponibles dans [solution.md](solution.md)
