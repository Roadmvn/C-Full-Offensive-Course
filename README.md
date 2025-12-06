# C Full Offensive Course

> **Formation complète en C pour Red Teamers et Malware Developers**
> De "Hello World" au développement de C2 frameworks

## 🎯 Objectif

Ce cours t'apprend le C depuis zéro avec un objectif clair : devenir Red Teamer / Malware Developer.
Progression : bases → exploitation → évasion → post-exploitation.

## 📋 Prérequis

- **Aucune connaissance en C requise**
- Motivation pour l'offensive security
- Machine virtuelle recommandée pour les phases d'exploitation
- OS supportés : Linux, macOS, Windows

## 🚀 Installation rapide

```bash
# Clone le repo
git clone https://github.com/TON_USERNAME/C-Full-Offensive-Course.git
cd C-Full-Offensive-Course

# Lance le setup (détecte ton OS automatiquement)
chmod +x setup.sh
./setup.sh
```

## 📚 Structure du cours

### PHASE 1 : FONDAMENTAUX (Modules 01-10)
Bases du C : variables, conditions, boucles, tableaux, pointeurs de base.

- [01 - Hello World](PHASE_1_FONDAMENTAUX/01_hello_world/)
- [02 - Variables et Types](PHASE_1_FONDAMENTAUX/02_variables_types/)
- [03 - Printf et Scanf](PHASE_1_FONDAMENTAUX/03_printf_scanf/)
- [04 - Opérateurs](PHASE_1_FONDAMENTAUX/04_operateurs/)
- [05 - Bitwise Operations](PHASE_1_FONDAMENTAUX/05_bitwise/)
- [06 - Conditions](PHASE_1_FONDAMENTAUX/06_conditions/)
- [07 - Boucles](PHASE_1_FONDAMENTAUX/07_loops/)
- [08 - Tableaux](PHASE_1_FONDAMENTAUX/08_arrays/)
- [09 - Strings](PHASE_1_FONDAMENTAUX/09_strings/)
- [10 - Fonctions](PHASE_1_FONDAMENTAUX/10_functions/)

### PHASE 2 : CONCEPTS AVANCÉS (Modules 11-17)
Pointeurs avancés, mémoire, structures, compilation.

- [11 - Pointeurs Introduction](PHASE_2_CONCEPTS_AVANCES/11_pointeurs_intro/)
- [12 - Pointeurs Avancés](PHASE_2_CONCEPTS_AVANCES/12_pointeurs_avances/)
- [13 - Memory Management](PHASE_2_CONCEPTS_AVANCES/13_memory_management/)
- [14 - Structures et Unions](PHASE_2_CONCEPTS_AVANCES/14_structures_unions/)
- [15 - Fichiers I/O](PHASE_2_CONCEPTS_AVANCES/15_fichiers_io/)
- [16 - Préprocesseur et Macros](PHASE_2_CONCEPTS_AVANCES/16_preprocesseur_macros/)
- [17 - Compilation et Linking](PHASE_2_CONCEPTS_AVANCES/17_compilation_linking/)

### PHASE 3 : TOOLING (Modules 18-19)
Debugging avec GDB, LLDB, x64dbg, WinDbg.

- [18 - Debugging GDB/LLDB](PHASE_3_TOOLING/18_debugging_gdb_lldb/)
- [19 - Debugging Windows](PHASE_3_TOOLING/19_debugging_windows/)

### PHASE 4 : EXPLOITATION BINAIRE (Modules 20-31)
Buffer overflow, ROP, shellcode x64/ARM64.

- [20 - Integer Overflow](PHASE_4_EXPLOITATION_BINAIRE/20_integer_overflow/)
- [21 - Buffer Overflow Intro](PHASE_4_EXPLOITATION_BINAIRE/21_buffer_overflow_intro/)
- [22 - Stack Overflow x64](PHASE_4_EXPLOITATION_BINAIRE/22_stack_overflow_x64/)
- [23 - ROP Chains x64](PHASE_4_EXPLOITATION_BINAIRE/23_rop_chains_x64/)
- [24 - Shellcode x64](PHASE_4_EXPLOITATION_BINAIRE/24_shellcode_x64/)
- [25 - Format String](PHASE_4_EXPLOITATION_BINAIRE/25_format_string/)
- [26 - Heap Exploitation](PHASE_4_EXPLOITATION_BINAIRE/26_heap_exploitation/)
- [27 - Race Conditions](PHASE_4_EXPLOITATION_BINAIRE/27_race_conditions/)
- [28 - Reverse Shell](PHASE_4_EXPLOITATION_BINAIRE/28_reverse_shell/)
- [29 - ARM64 Architecture](PHASE_4_EXPLOITATION_BINAIRE/29_arm64_architecture/)
- [30 - Shellcode ARM64](PHASE_4_EXPLOITATION_BINAIRE/30_shellcode_arm64/)
- [31 - ROP Chains ARM64](PHASE_4_EXPLOITATION_BINAIRE/31_rop_chains_arm64/)

### PHASE 5 : WINDOWS INTERNALS (Modules 32-36)
Windows API, syscalls directs, EDR bypass.

- [32 - Process & Threads Windows](PHASE_5_WINDOWS_INTERNALS/32_process_threads_win/)
- [33 - Windows API](PHASE_5_WINDOWS_INTERNALS/33_windows_api/)
- [34 - Syscalls Directs](PHASE_5_WINDOWS_INTERNALS/34_syscalls_directs/)
- [35 - Token Manipulation](PHASE_5_WINDOWS_INTERNALS/35_token_manipulation/)
- [36 - Registry & Persistence](PHASE_5_WINDOWS_INTERNALS/36_registry_persistence/)

### PHASE 6 : LINUX INTERNALS (Modules 37-39)
Syscalls, ELF parsing, persistence.

- [37 - Linux Syscalls](PHASE_6_LINUX_INTERNALS/37_linux_syscalls/)
- [38 - ELF Parsing](PHASE_6_LINUX_INTERNALS/38_elf_parsing/)
- [39 - Persistence Linux](PHASE_6_LINUX_INTERNALS/39_persistence_linux/)

### PHASE 7 : MACOS INTERNALS (Modules 40-45)
Mach-O, SIP bypass, dylib injection.

- [40 - Mach-O Format](PHASE_7_MACOS_INTERNALS/40_macho_format/)
- [41 - macOS Security Model](PHASE_7_MACOS_INTERNALS/41_macos_security_model/)
- [42 - macOS Syscalls](PHASE_7_MACOS_INTERNALS/42_macos_syscalls/)
- [43 - Dylib Injection](PHASE_7_MACOS_INTERNALS/43_dylib_injection/)
- [44 - macOS Persistence](PHASE_7_MACOS_INTERNALS/44_macos_persistence/)
- [45 - macOS Evasion](PHASE_7_MACOS_INTERNALS/45_macos_evasion/)

### PHASE 8 : INJECTION & HOOKING (Modules 46-51)
Process injection, DLL injection, API hooking.

- [46 - Process Injection](PHASE_8_INJECTION_HOOKING/46_process_injection/)
- [47 - DLL Injection](PHASE_8_INJECTION_HOOKING/47_dll_injection/)
- [48 - Reflective Loading](PHASE_8_INJECTION_HOOKING/48_reflective_loading/)
- [49 - API Hooking](PHASE_8_INJECTION_HOOKING/49_api_hooking/)
- [50 - Code Caves](PHASE_8_INJECTION_HOOKING/50_code_caves/)
- [51 - Memory Mapping Advanced](PHASE_8_INJECTION_HOOKING/51_memory_mapping_advanced/)

### PHASE 9 : EVASION (Modules 52-58)
Cryptographie, obfuscation, anti-debugging, EDR bypass.

- [52 - Cryptographie XOR/AES](PHASE_9_EVASION/52_cryptographie_xor_aes/)
- [53 - String Obfuscation](PHASE_9_EVASION/53_string_obfuscation/)
- [54 - Anti-Debugging](PHASE_9_EVASION/54_anti_debugging/)
- [55 - Anti-VM/Sandbox](PHASE_9_EVASION/55_anti_vm_sandbox/)
- [56 - Packing/Unpacking](PHASE_9_EVASION/56_packing_unpacking/)
- [57 - ETW Patching](PHASE_9_EVASION/57_etw_patching/)
- [58 - AMSI Bypass](PHASE_9_EVASION/58_amsi_bypass/)

### PHASE 10 : POST-EXPLOITATION (Modules 59-61)
Credential dumping, lateral movement, C2 development.

- [59 - Credential Dumping](PHASE_10_POST_EXPLOITATION/59_credential_dumping/)
- [60 - Lateral Movement](PHASE_10_POST_EXPLOITATION/60_lateral_movement/)
- [61 - C2 Development](PHASE_10_POST_EXPLOITATION/61_c2_development/)

### RESSOURCES

- [Cheatsheets](RESSOURCES/cheatsheets/) - Références rapides
- [Templates](RESSOURCES/templates/) - Code réutilisable
- [Lab Setup](RESSOURCES/lab_setup/) - Configuration environnement

## 📖 Comment utiliser ce cours

1. **Lis le README.md** de chaque module
2. **Analyse l'example.c** (code commenté)
3. **Fais les exercices** dans exercice.txt (coche [ ] → [x] au fur et à mesure)
4. **Compare avec solution.txt** uniquement après avoir essayé

## ⚠️ Disclaimer

**Ce cours est à but éducatif uniquement.**
L'utilisation de ces techniques sur des systèmes sans autorisation explicite est **illégale**.
Utilise ces connaissances de manière éthique et responsable.

## 📜 Licence

MIT License - Voir [LICENCE](LICENCE)

## 🤝 Contribution

Les PR sont les bienvenues ! Ouvre une issue d'abord pour discuter des changements majeurs.

---

**Happy Hacking! 🔥**
