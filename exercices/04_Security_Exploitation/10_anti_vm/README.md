# Anti-VM & Anti-Sandbox - Détection Environnements d'Analyse

CPUID checks, MAC address OUI, VM artifacts, sandbox behavior - techniques pour détecter VMware/VirtualBox/Cuckoo/Any.run et refuser exécution. Évite analyse automatisée par SOC/CERT.

⚠️ AVERTISSEMENT STRICT : Techniques de malware development avancées. Usage éducatif uniquement. Tests sur VM isolées. Usage malveillant = PRISON.

```c
// CPUID VM detection
void cpuid(int leaf, int* eax, int* ebx, int* ecx, int* edx) {
    __asm__ __volatile__("cpuid" : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx) : "a"(leaf));
}

// VMware hypercall
int detect_vmware() {
    unsigned int magic = 0x564D5868;  // 'VMXh'
    unsigned int port = 0x5658;       // 'VX'
    __asm__ __volatile__("in %%dx, %%eax" : : "a"(magic), "d"(port));
    // Si VM : pas d'exception, sinon : crash
}
```

## Compilation

```bash
gcc example.c -o anti_vm
```

## Concepts clés

- **CPUID Leaf 0x40000000** : Hypervisor vendor string
- **VM Artifacts** : Fichiers VMware Tools, VBox Guest Additions
- **MAC Address OUI** : 00:0C:29 (VMware), 08:00:27 (VBox)
- **Registry Keys** : HKLM\\SOFTWARE\\VMware, VirtualBox
- **Processes** : vmtoolsd.exe, vboxservice.exe
- **Sleep Acceleration** : Sandbox skip Sleep() pour vitesse
- **User Interaction** : Sandbox pas de clics souris/clavier

## Techniques utilisées par

- **Emotet** : CPUID, registry keys, process names checks
- **TrickBot** : Sleep acceleration, user interaction detection
- **Dridex** : CPUID, MAC OUI, VM file artifacts
- **APT malwares** : Multi-layer VM detection avant payload
- **Ransomware** : Éviter infection sandboxes (perte Bitcoin)

## Détection et Mitigation

**Indicateurs** :
- CPUID instructions répétées
- Registry/file checks VM paths
- MAC address queries
- Sleep() calls avec timing checks
- Mouse/keyboard input monitoring

**Bypass VM Detection** :
- Patch CPUID results
- Hide VM artifacts (files, registry)
- Spoof MAC address OUI
- Pafish tool pour tester détections
- Bare metal analysis (pas de VM)
