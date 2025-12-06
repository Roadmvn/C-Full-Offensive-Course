⚠️ AVERTISSEMENT STRICT
Techniques de malware development. Usage éducatif uniquement.


### EXERCICES - MODULE 31 : ANTI-VM & ANTI-SANDBOX

[ ] 1. CPUID COMPREHENSIVE CHECKS
Tous les leafs CPUID pertinents :
- Leaf 0x1 : Hypervisor bit (ECX bit 31)
- Leaf 0x40000000 : Hypervisor vendor ("VMwareVMware", "Microsoft Hv", "KVMKVMKVM")
- Leaf 0x40000001-0x40000010 : Hypervisor info
- Detect VMware, VirtualBox, Hyper-V, KVM, Xen

Référence : CPUID specification Intel/AMD

[ ] 2. MAC ADDRESS & NETWORK CHECKS
Détection réseau complète :
- MAC OUI: VMware (00:0C:29, 00:50:56), VBox (08:00:27), QEMU (52:54:00)
- Hostname patterns: "sandbox", "malware", "virus"
- IP address ranges: 10.x, 192.168.x (souvent sandboxes)
- DNS servers: Google DNS (sandbox standard)

Référence : Pafish anti-sandbox checks

[ ] 3. VM ARTIFACTS (FILES/REGISTRY/SERVICES)
Scanner tous artifacts :
- VMware: vmtools, vmhgfs, vmmouse drivers
- VirtualBox: VBoxGuest, VBoxService, VBoxTray
- QEMU: qemu-ga
- Registry keys multiples
- Services running
- Window classes (VMware, VBox)

Référence : Al-Khaser VM detection

[ ] 4. SANDBOX BEHAVIOR DETECTION
Comportements sandbox typiques :
- Sleep() acceleration (skip delays)
- Limited execution time (timeout kill)
- No user interaction (mouse/keyboard idle)
- High CPU count (sandbox parallélisation)
- Low disk space (minimal VMs)
- Fake file operations (hooks retournent fake)

Référence : Cuckoo Sandbox evasion

[ ] 5. WMI QUERIES ANTI-VM
Windows Management Instrumentation :
- SELECT * FROM Win32_ComputerSystem (Manufacturer, Model)
- SELECT * FROM Win32_BIOS (SerialNumber, Version)
- SELECT * FROM Win32_BaseBoard (Manufacturer, Product)
- Détecter "VMware", "VirtualBox", "QEMU", "Bochs"

Référence : WMI anti-VM queries

[ ] 6. TIMING & PERFORMANCE CHECKS
Détection via performance anormales :
- RDTSC timing (VM overhead)
- Disk I/O speed (VMs plus lents)
- Network latency (virtual adapters)
- CPU benchmarks (émulation lente)

Référence : Timing-based VM detection

[ ] 7. HUMAN INTERACTION DETECTION
Vérifier activité humaine :
- Mouse movements tracking (GetCursorPos loop)
- Keyboard input monitoring (GetAsyncKeyState)
- Window focus changes
- Idle time analysis
- Captcha-like challenges

Référence : User interaction checks

[ ] 8. MULTI-LAYER EVASION
Combiner 20+ techniques :
- CPUID + MAC + Files + Registry
- Timing + Sleep + User interaction
- WMI + Services + Processes
- Randomize check order
- Delayed checks (après 5min)

Référence : APT malware evasion (Dridex, Emotet)


### NOTES :
- VMs peuvent hide artifacts (stealthier configs)
- Bare metal analysis = ultimate bypass
- Tester avec Pafish tool (open source)
- Cuckoo/Any.run ont anti-evasion (detect checks)
- Combiner avec anti-debug pour maximum efficacité

