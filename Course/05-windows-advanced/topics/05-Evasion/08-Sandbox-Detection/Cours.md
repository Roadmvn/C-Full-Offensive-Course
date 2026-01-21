# Cours : Anti-VM - Détecter les Machines Virtuelles

## 1. Introduction

Les malwares détectent les **VMs** et **sandboxes** pour éviter l'analyse.

## 2. Techniques de Détection

### 2.1 CPUID

```c
void cpuid(int info[4], int function) {
    __asm__ __volatile__(
        "cpuid"
        : "=a"(info[0]), "=b"(info[1]), "=c"(info[2]), "=d"(info[3])
        : "a"(function)
    );
}

// Vérifier hypervisor
int is_vm() {
    int info[4];
    cpuid(info, 1);
    return (info[2] >> 31) & 1;  // Bit hypervisor
}
```

### 2.2 Artifacts de VM

```ascii
VMWARE :
- Fichiers : C:\Program Files\VMware\
- Processus : vmtoolsd.exe
- MAC address : 00:0C:29:* ou 00:50:56:*

VIRTUALBOX :
- Fichiers : C:\Program Files\Oracle\VirtualBox\
- Drivers : VBoxGuest.sys
- Processus : VBoxService.exe

HYPER-V :
- Registre : HKLM\SOFTWARE\Microsoft\Virtual Machine
```

### 2.3 Timing

```ascii
VM = Plus lent que hardware réel

Mesurer temps d'exécution :
- Instructions CPU (RDTSC)
- Sleep() accuracy
- Opérations I/O

Si anormalement lent → VM/Sandbox
```

## Ressources

- [VM Detection](https://evasions.checkpoint.com/)

