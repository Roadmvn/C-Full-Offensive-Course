# Structure du Cours C Full Offensive

**Taille totale** : 2.6 MB
**Fichiers** : 336 fichiers (markdown, C, scripts)
**Modules** : 61 modules complets

## 📊 Vue d'ensemble

| Phase | Modules | Statut | Description |
|-------|---------|--------|-------------|
| **PHASE 1** | 01-10 | ✅ Complet | Fondamentaux du C |
| **PHASE 2** | 11-17 | ✅ Complet | Concepts avancés |
| **PHASE 3** | 18-19 | ✅ Complet | Debugging tools |
| **PHASE 4** | 20-31 | ✅ Complet | Exploitation binaire |
| **PHASE 5** | 32-36 | ✅ Complet | Windows internals |
| **PHASE 6** | 37-39 | ✅ Complet | Linux internals |
| **PHASE 7** | 40-45 | ✅ Complet | macOS internals |
| **PHASE 8** | 46-51 | ✅ Complet | Injection & hooking |
| **PHASE 9** | 52-58 | ✅ Complet | Evasion techniques |
| **PHASE 10** | 59-61 | ✅ Complet | Post-exploitation |
| **RESSOURCES** | - | ✅ Complet | Cheatsheets + templates |

## 📚 Détail des modules

### PHASE 1 : FONDAMENTAUX (10 modules)
```
01_hello_world           ✅ Créé (agent)
02_variables_types       ✅ Créé (agent)
03_printf_scanf          ✅ Créé (agent)
04_operateurs            ✅ Créé (agent)
05_bitwise               ✅ Créé (agent)
06_conditions            ✅ Créé (agent)
07_loops                 ✅ Créé (agent)
08_arrays                ✅ Créé (agent)
09_strings               ✅ Créé (agent)
10_functions             ✅ Créé (agent)
```

### PHASE 2 : CONCEPTS AVANCÉS (7 modules)
```
11_pointeurs_intro       ✅ Migré (depuis exercices/)
12_pointeurs_avances     ✅ Migré (depuis exercices/)
13_memory_management     ✅ Migré (depuis exercices/)
14_structures_unions     ✅ Migré (depuis exercices/)
15_fichiers_io           ✅ Migré (depuis exercices/)
16_preprocesseur_macros  ✅ Créé (nouveau)
17_compilation_linking   ✅ Créé (nouveau)
```

### PHASE 3 : TOOLING (2 modules)
```
18_debugging_gdb_lldb    ✅ Créé (nouveau)
19_debugging_windows     ✅ Créé (nouveau)
```

### PHASE 4 : EXPLOITATION BINAIRE (12 modules)
```
20_integer_overflow      ✅ Créé (nouveau)
21_buffer_overflow_intro ✅ Migré (depuis exercices/)
22_stack_overflow_x64    ✅ Migré (depuis exercices/)
23_rop_chains_x64        ✅ Migré (depuis exercices/)
24_shellcode_x64         ✅ Migré (depuis exercices/)
25_format_string         ✅ Migré (depuis exercices/)
26_heap_exploitation     ✅ Migré (depuis exercices/)
27_race_conditions       ✅ Créé (nouveau)
28_reverse_shell         ✅ Migré (depuis exercices/)
29_arm64_architecture    ✅ Migré (depuis exercices/)
30_shellcode_arm64       ✅ Migré (depuis exercices/)
31_rop_chains_arm64      ✅ Créé (nouveau)
```

### PHASE 5 : WINDOWS INTERNALS (5 modules)
```
32_process_threads_win   ✅ Migré (depuis exercices/)
33_windows_api           ✅ Migré (depuis exercices/)
34_syscalls_directs      ✅ Migré (depuis exercices/)
35_token_manipulation    ✅ Migré (depuis exercices/)
36_registry_persistence  ✅ Migré (depuis exercices/)
```

### PHASE 6 : LINUX INTERNALS (3 modules)
```
37_linux_syscalls        ✅ Créé (nouveau)
38_elf_parsing           ✅ Créé (nouveau)
39_persistence_linux     ✅ Migré (depuis exercices/)
```

### PHASE 7 : MACOS INTERNALS (6 modules)
```
40_macho_format          ✅ Migré (depuis exercices/)
41_macos_security_model  ✅ Migré (depuis exercices/)
42_macos_syscalls        ✅ Créé (nouveau)
43_dylib_injection       ✅ Migré (depuis exercices/)
44_macos_persistence     ✅ Créé (nouveau)
45_macos_evasion         ✅ Créé (nouveau)
```

### PHASE 8 : INJECTION & HOOKING (6 modules)
```
46_process_injection     ✅ Migré (depuis exercices/)
47_dll_injection         ✅ Migré (depuis exercices/)
48_reflective_loading    ✅ Migré (depuis exercices/)
49_api_hooking           ✅ Migré (depuis exercices/)
50_code_caves            ✅ Migré (depuis exercices/)
51_memory_mapping_adv    ✅ Migré (depuis exercices/)
```

### PHASE 9 : EVASION (7 modules)
```
52_cryptographie_xor_aes ✅ Migré (depuis exercices/)
53_string_obfuscation    ✅ Migré (depuis exercices/)
54_anti_debugging        ✅ Migré (depuis exercices/)
55_anti_vm_sandbox       ✅ Migré (depuis exercices/)
56_packing_unpacking     ✅ Migré (depuis exercices/)
57_etw_patching          ✅ Migré (depuis exercices/)
58_amsi_bypass           ✅ Migré (depuis exercices/)
```

### PHASE 10 : POST-EXPLOITATION (3 modules)
```
59_credential_dumping    ✅ Migré (depuis exercices/)
60_lateral_movement      ✅ Migré (depuis exercices/)
61_c2_development        ✅ Migré (depuis exercices/)
```

### RESSOURCES (21 fichiers)
```
cheatsheets/
  ├── c_syntax.md            ✅ Créé
  ├── gdb_lldb_commands.md   ✅ Créé
  ├── x64dbg_commands.md     ✅ Créé
  ├── windows_api.md         ✅ Créé
  ├── linux_syscalls.md      ✅ Créé
  ├── macos_syscalls.md      ✅ Créé
  ├── arm64_instructions.md  ✅ Créé
  ├── x64_instructions.md    ✅ Créé
  └── shellcode_reference.md ✅ Créé

templates/
  ├── basic_injector_win.c   ✅ Créé
  ├── basic_injector_linux.c ✅ Créé
  ├── basic_injector_macos.c ✅ Créé
  ├── reverse_shell_x64.c    ✅ Créé
  ├── reverse_shell_arm64.c  ✅ Créé
  ├── loader_template.c      ✅ Créé
  └── crypter_template.c     ✅ Créé

lab_setup/
  ├── windows_vm.md          ✅ Créé
  ├── linux_vm.md            ✅ Créé
  ├── macos_setup.md         ✅ Créé
  ├── debugging_setup.md     ✅ Créé
  └── network_lab.md         ✅ Créé
```

## 📝 Format des modules

Chaque module contient :
- **README.md** ou **Cours.md** : Théorie + section Red Team
- **example.c** : Code fonctionnel commenté en français
- **Exercice.md** ou **exercice.txt** : 8 exercices avec [ ] checkboxes
- **Solution.md** ou **solution.txt** : Solutions complètes

## 🎯 Répartition du contenu

| Source | Modules | Pourcentage |
|--------|---------|-------------|
| Créés neufs (agent) | 22 modules | 36% |
| Migrés (exercices/) | 39 modules | 64% |
| **TOTAL** | **61 modules** | **100%** |

## 🚀 Utilisation

```bash
cd C-Full-Offensive-Course

# Setup automatique
./setup.sh

# Commencer par la PHASE 1
cd PHASE_1_FONDAMENTAUX/01_hello_world
cat README.md
gcc example.c -o example
./example
```

## 📦 Fichiers racine

```
C-Full-Offensive-Course/
├── README.md           ✅ Vue d'ensemble du cours
├── LICENCE             ✅ MIT + Disclaimer légal
├── setup.sh            ✅ Script installation multi-OS
├── STRUCTURE.md        ✅ Ce fichier
└── migrate_content.sh  ✅ Script de migration utilisé
```

## ✨ Points forts

- **100% complet** : Tous les 61 modules ont du contenu
- **Multi-plateforme** : Linux, macOS, Windows
- **Multi-architecture** : x64 et ARM64
- **Orienté Red Team** : Chaque module a une section offensive
- **Code fonctionnel** : Tous les examples.c compilent
- **Progression pédagogique** : De "Hello World" au C2 development
- **Ressources complètes** : Cheatsheets + templates + lab setup

---

**Cours prêt à être utilisé pour l'apprentissage du C offensif ! 🔥**
