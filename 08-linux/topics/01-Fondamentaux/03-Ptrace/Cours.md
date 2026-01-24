# Module 18 : Debugging avec GDB et LLDB

Bienvenue dans le monde du debugging offensif. Tu maitrises maintenant le C et la mémoire. Il est temps d'apprendre à regarder SOUS LE CAPOT des programmes en cours d'exécution.

## 1. C'est quoi un Debugger et Pourquoi tu en as Besoin ?

### 1.1 Le Problème

Imagine que tu as un programme binaire sans le code source :

```ascii
PROGRAMME MYSTÈRE :
┌─────────────────────┐
│  Binary Executable  │  Que fait-il ?
│  010101010101010...  │  Où sont les bugs ?
│  ????????????????    │  Comment l'exploiter ?
└─────────────────────┘
         ↓
    TU ES AVEUGLE

Sans debugger, tu ne peux que :
- Exécuter le programme
- Observer le résultat final
- Deviner ce qui se passe à l'intérieur
```

### 1.2 La Solution : Un Debugger

Un **debugger** est un outil qui te permet de :

```ascii
AVEC UN DEBUGGER :
┌────────────────────────────────────────┐
│  1. PAUSE LE PROGRAMME                 │
│     Arrêter à n'importe quel moment    │
├────────────────────────────────────────┤
│  2. VOIR L'INTÉRIEUR                   │
│     ├─ Registres (RAX, RBX, RIP...)   │
│     ├─ Mémoire (Stack, Heap)          │
│     └─ Variables                       │
├────────────────────────────────────────┤
│  3. MODIFIER EN DIRECT                 │
│     ├─ Changer valeurs registres      │
│     ├─ Modifier mémoire               │
│     └─ Patcher instructions            │
├────────────────────────────────────────┤
│  4. AVANCER PAS À PAS                  │
│     Exécuter ligne par ligne           │
└────────────────────────────────────────┘

Tu deviens CHIRURGIEN du programme
```

### 1.3 GDB vs LLDB

Deux debuggers principaux selon ton OS :

```ascii
┌─────────────────────────────────────────────┐
│  GDB (GNU Debugger)                         │
│  ├─ Plateforme : Linux, BSD, Windows (MinGW)│
│  ├─ Force : Mature, extensible, plugins    │
│  ├─ Syntaxe : break, run, continue          │
│  └─ Extensions : pwndbg, GEF, PEDA          │
├─────────────────────────────────────────────┤
│  LLDB (LLVM Debugger)                       │
│  ├─ Plateforme : macOS, iOS, Linux          │
│  ├─ Force : Moderne, Apple Silicon support │
│  ├─ Syntaxe : breakpoint set, process launch│
│  └─ Intégration : Xcode                     │
└─────────────────────────────────────────────┘

Les deux sont PUISSANTS et utilisés en Red Team
```

## 2. Installation et Setup

### 2.1 GDB (Linux/WSL)

```bash
# Installation
sudo apt update
sudo apt install gdb

# Vérifier version
gdb --version

# Installer pwndbg (extension Red Team essentielle)
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```

### 2.2 LLDB (macOS)

```bash
# Déjà installé avec Xcode Command Line Tools
xcode-select --install

# Vérifier
lldb --version

# Configuration (optionnel)
echo "settings set target.x86-disassembly-flavor intel" >> ~/.lldbinit
```

## 3. Breakpoints : Mettre le Programme sur PAUSE

### 3.1 C'est quoi un Breakpoint ?

Un **breakpoint** est un point d'arrêt que tu places dans le code :

```ascii
PROGRAMME EN EXÉCUTION :

main() {
    printf("Début\n");
    int x = 42;          ← BREAKPOINT ICI
    printf("x = %d\n", x);
    return 0;
}

FLOW NORMAL :          FLOW AVEC BREAKPOINT :
main()                 main()
  ↓                      ↓
printf("Début")        printf("Début")
  ↓                      ↓
x = 42                 x = 42 ■ PAUSE !
  ↓
printf("x = %d")       Programme s'arrête
  ↓                    Tu peux inspecter :
return                 - Valeur de x
                       - Registres
                       - Stack
                       Puis continuer (ou pas)
```

### 3.2 Breakpoints Software vs Hardware

```ascii
┌──────────────────────────────────────────────────┐
│  SOFTWARE BREAKPOINT                             │
├──────────────────────────────────────────────────┤
│  Fonctionnement :                                │
│  1. Debugger lit instruction à l'adresse         │
│  2. La remplace par INT3 (0xCC sur x86)         │
│  3. CPU exécute INT3 → génère exception         │
│  4. OS passe contrôle au debugger                │
│                                                  │
│  AVANT :              APRÈS :                    │
│  0x401000: mov rax,1  0x401000: int3 (0xCC)     │
│                                                  │
│  Limite : Illimité en nombre                     │
│  Détectable : Oui (code modifié)                 │
└──────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────┐
│  HARDWARE BREAKPOINT                             │
├──────────────────────────────────────────────────┤
│  Fonctionnement :                                │
│  1. Utilise registres DR0-DR7 du CPU             │
│  2. Pas de modification du code                  │
│  3. CPU génère exception automatiquement         │
│                                                  │
│  Limite : 4 breakpoints max (x86-64)            │
│  Détectable : Non (pas de modification code)    │
│  Usage : Anti-debugging bypass                   │
└──────────────────────────────────────────────────┘
```

### 3.3 GDB - Commandes Breakpoint

```bash
# Lancer GDB
gdb ./program

# Break sur fonction
(gdb) break main
Breakpoint 1 at 0x401156: file main.c, line 5.

# Break sur adresse spécifique
(gdb) break *0x401234
Breakpoint 2 at 0x401234

# Break sur fichier:ligne
(gdb) break main.c:42
Breakpoint 3 at 0x401200: file main.c, line 42.

# Break conditionnel
(gdb) break vulnerable_function if buffer_size > 100
Breakpoint 4 at 0x401300

# Lister tous les breakpoints
(gdb) info breakpoints
Num     Type           Disp Enb Address            What
1       breakpoint     keep y   0x0000000000401156 in main at main.c:5
2       breakpoint     keep y   0x0000000000401234
3       breakpoint     keep y   0x0000000000401200 in main at main.c:42

# Supprimer breakpoint
(gdb) delete 2

# Désactiver temporairement
(gdb) disable 1

# Réactiver
(gdb) enable 1
```

**Visualisation** :

```ascii
CODE SOURCE (main.c) :

    1  #include <stdio.h>
    2
    3  int main() {
    4      char buffer[64];
    5      printf("Enter input: ");    ← BREAKPOINT 1 ici
    6      gets(buffer);                ← BREAKPOINT 2 ici
    7      printf("You entered: %s\n", buffer);
    8      return 0;
    9  }

BREAKPOINTS PLACÉS :
BP1 : Juste avant lecture input
BP2 : Après lecture, buffer plein

STRATÉGIE RED TEAM :
├─ BP1 : Voir l'état AVANT exploitation
├─ BP2 : Voir si buffer overflow réussit
└─ Comparer registres et mémoire
```

### 3.4 LLDB - Commandes Breakpoint

```bash
# Lancer LLDB
lldb ./program

# Break sur fonction
(lldb) breakpoint set -n main
Breakpoint 1: where = program`main, address = 0x0000000100003f00

# Syntaxe courte (compatible GDB)
(lldb) b main

# Break sur adresse
(lldb) breakpoint set -a 0x100000
(lldb) b 0x100000

# Break sur fichier:ligne
(lldb) breakpoint set -f main.c -l 42
(lldb) b main.c:42

# Lister
(lldb) breakpoint list
Current breakpoints:
1: name = 'main', locations = 1

# Supprimer
(lldb) breakpoint delete 1

# Désactiver
(lldb) breakpoint disable 1
```

## 4. Commandes Essentielles d'Exécution

### 4.1 Les 5 Commandes Vitales

```ascii
┌──────────┬─────────────────────────────────────────┐
│ Commande │ Effet                                   │
├──────────┼─────────────────────────────────────────┤
│ RUN      │ Démarrer le programme                   │
│          │ S'arrête au premier breakpoint          │
├──────────┼─────────────────────────────────────────┤
│ CONTINUE │ Reprendre exécution                     │
│          │ Jusqu'au prochain breakpoint            │
├──────────┼─────────────────────────────────────────┤
│ STEP     │ Avancer d'UNE instruction              │
│          │ ENTRE dans les fonctions (step into)    │
├──────────┼─────────────────────────────────────────┤
│ NEXT     │ Avancer d'UNE ligne                    │
│          │ SAUTE par-dessus fonctions (step over) │
├──────────┼─────────────────────────────────────────┤
│ FINISH   │ Sortir de la fonction courante          │
│          │ (step out)                              │
└──────────┴─────────────────────────────────────────┘
```

**Différence STEP vs NEXT** :

```ascii
CODE :
10  void foo() {
11      printf("Inside foo\n");
12  }
13
14  int main() {
15      int x = 10;
16      foo();           ← Tu es ici
17      return 0;
18  }

STEP (s) :                 NEXT (n) :
main:16 → foo()            main:16 → foo()
  ↓                          ↓ (exécute foo)
foo:11 → printf            main:17 → return
  ↓
Entre dans foo             Saute par-dessus foo

Usage :                    Usage :
- Analyser fonction        - Ignorer fonctions connues
- Debugging profond        - Rester au niveau actuel
```

### 4.2 GDB - Exécution

```bash
# Démarrer programme
(gdb) run
Starting program: /home/user/vuln
[Breakpoint 1, main () at vuln.c:5]

# Avec arguments
(gdb) run arg1 arg2

# Avec stdin redirigé
(gdb) run < input.txt

# Continuer jusqu'au prochain breakpoint
(gdb) continue
Continuing.
[Breakpoint 2, vulnerable_function () at vuln.c:12]

# Step into (entre dans fonctions)
(gdb) step
(gdb) s

# Next (saute par-dessus fonctions)
(gdb) next
(gdb) n

# Finish (sortir de fonction courante)
(gdb) finish
Run till exit from #0  vulnerable_function () at vuln.c:12
0x00000000004011a0 in main () at vuln.c:20

# Continuer jusqu'à ligne spécifique
(gdb) until 25
```

### 4.3 LLDB - Exécution

```bash
# Démarrer
(lldb) run
(lldb) r

# Avec arguments
(lldb) run arg1 arg2
(lldb) process launch -- arg1 arg2

# Continuer
(lldb) continue
(lldb) c

# Step into
(lldb) step
(lldb) s
(lldb) thread step-in

# Step over
(lldb) next
(lldb) n
(lldb) thread step-over

# Step out
(lldb) finish
(lldb) thread step-out
```

## 5. Examen de la Mémoire : Voir l'Invisible

### 5.1 La Commande x/ (examine) dans GDB

**Syntaxe** : `x/[count][format][size] address`

```ascii
┌─────────────────────────────────────────────┐
│  FORMAT :                                   │
│  x = hexadécimal                            │
│  d = décimal                                │
│  t = binaire                                │
│  s = string                                 │
│  i = instruction (assembly)                 │
│  c = caractère                              │
├─────────────────────────────────────────────┤
│  SIZE :                                     │
│  b = byte (1 octet)                         │
│  h = halfword (2 octets)                    │
│  w = word (4 octets)                        │
│  g = giant (8 octets, 64-bit)              │
└─────────────────────────────────────────────┘
```

**Exemples pratiques** :

```bash
# Examiner 10 mots (8 bytes) en hexa depuis RSP
(gdb) x/10gx $rsp
0x7fffffffe400: 0x00007fffffffe4b0  0x0000000000401156
0x7fffffffe410: 0x4141414141414141  0x4141414141414141
0x7fffffffe420: 0x4141414141414141  0x0000000000000000

# Voir la stack (20 mots)
(gdb) x/20x $rsp

# Lire une string à une adresse
(gdb) x/s 0x401000
0x401000: "Enter password: "

# Désassembler 10 instructions depuis RIP
(gdb) x/10i $rip
=> 0x401156 <main+0>:    push   rbp
   0x401157 <main+1>:    mov    rbp,rsp
   0x40115a <main+4>:    sub    rsp,0x40
   0x40115e <main+8>:    lea    rdi,[rip+0xe9f]
   0x401165 <main+15>:   call   0x401030 <puts@plt>

# Examiner buffer en ASCII
(gdb) x/64c $rsp
0x7fffffffe3c0: 65 'A'  66 'B'  67 'C'  68 'D' ...
```

**Visualisation Stack** :

```ascii
MÉMOIRE APRÈS BUFFER OVERFLOW :

(gdb) x/20gx $rsp

0x7fffffffe3c0: 0x4141414141414141  ← "AAAAAAAA" (buffer début)
0x7fffffffe3c8: 0x4141414141414141  ← "AAAAAAAA"
0x7fffffffe3d0: 0x4141414141414141  ← "AAAAAAAA"
0x7fffffffe3d8: 0x4141414141414141  ← "AAAAAAAA"
0x7fffffffe3e0: 0x4141414141414141  ← "AAAAAAAA"
0x7fffffffe3e8: 0x4141414141414141  ← "AAAAAAAA"
0x7fffffffe3f0: 0x4141414141414141  ← "AAAAAAAA"
0x7fffffffe3f8: 0x4141414141414141  ← "AAAAAAAA"
0x7fffffffe400: 0x4141414141414141  ← Saved RBP ÉCRASÉ !
0x7fffffffe408: 0x4141414141414141  ← Return Address ÉCRASÉ !
                         ↑
                    EXPLOITATION RÉUSSIE
                    RIP va sauter vers 0x414141...
```

### 5.2 Registres : Le Tableau de Bord du CPU

```bash
# GDB - Voir tous les registres
(gdb) info registers
rax            0x0                 0
rbx            0x0                 0
rcx            0x7ffff7dd1718      140737351899928
rdx            0x7fffffffe4c8      140737488348360
rsi            0x7fffffffe4b8      140737488348344
rdi            0x1                 1
rbp            0x7fffffffe3b0      0x7fffffffe3b0
rsp            0x7fffffffe3b0      0x7fffffffe3b0
r8             0x0                 0
rip            0x401156            0x401156 <main>

# Voir registres spécifiques
(gdb) info registers rax rip
rax            0x4141414141414141  4702111234474983745
rip            0x401156            0x401156 <main>

# Afficher en différents formats
(gdb) print $rax
$1 = 4702111234474983745

(gdb) print/x $rax
$2 = 0x4141414141414141

(gdb) print/t $rax
$3 = 100000101000001010000010100000101000001010000010100000101000001
```

**LLDB - Registres** :

```bash
# Tous les registres
(lldb) register read
General Purpose Registers:
       rax = 0x0000000000000000
       rbx = 0x0000000000000000
       ...

# Registre spécifique
(lldb) register read rax
     rax = 0x0000000000000000

# Modifier registre
(lldb) register write rax 0x42
```

### 5.3 Modifier la Mémoire et Registres en RUNTIME

```bash
# GDB - Modifier registre
(gdb) set $rax = 0x1234
(gdb) set $rip = 0x401000

# Modifier mémoire (int à une adresse)
(gdb) set {int}0x7fffffffe400 = 0xDEADBEEF

# Modifier plusieurs bytes
(gdb) set {long}0x7fffffffe400 = 0x4141414141414141

# Écrire une string
(gdb) set {char[8]}0x7fffffffe400 = "HACKED!"

# LLDB - Modifier registre
(lldb) register write rax 0x1234

# Modifier mémoire
(lldb) memory write 0x7fffffffe400 0xDEADBEEF
```

**Usage Red Team** :

```ascii
SCÉNARIO : Bypass de check de mot de passe

CODE :
if (strcmp(input, "secret") == 0) {
    printf("Access granted!\n");
} else {
    printf("Access denied!\n");
}

DANS LE DEBUGGER :

1. Breakpoint APRÈS strcmp
   (gdb) break *0x401234

2. Run
   (gdb) run
   Enter password: wrong
   [Breakpoint 1, 0x401234]

3. Voir résultat strcmp (dans RAX)
   (gdb) print $rax
   $1 = 1  ← Différent de 0 (échec)

4. FORCER le résultat
   (gdb) set $rax = 0
       ↓
   strcmp retourne maintenant 0 (égal)

5. Continuer
   (gdb) continue
   Access granted!  ← BYPASS RÉUSSI !
```

## 6. Backtrace et Stack Frames

### 6.1 C'est quoi un Backtrace ?

```ascii
APPELS DE FONCTIONS EMPILÉS :

main() {
    function_a();
}

function_a() {
    function_b();
}

function_b() {
    function_c();
}

function_c() {
    <== TU ES ICI (breakpoint)
}

CALL STACK :
┌──────────────┐
│ function_c() │ ← Frame 0 (actuel)
├──────────────┤
│ function_b() │ ← Frame 1
├──────────────┤
│ function_a() │ ← Frame 2
├──────────────┤
│ main()       │ ← Frame 3
├──────────────┤
│ _start()     │ ← Frame 4 (début programme)
└──────────────┘

BACKTRACE = HISTORIQUE DES APPELS
```

### 6.2 GDB - Backtrace

```bash
# Voir la call stack complète
(gdb) backtrace
#0  function_c () at prog.c:15
#1  0x0000000000401234 in function_b () at prog.c:11
#2  0x0000000000401189 in function_a () at prog.c:7
#3  0x0000000000401156 in main () at prog.c:3

# Backtrace avec variables locales
(gdb) backtrace full
#0  function_c () at prog.c:15
        buffer = "AAAA\000\000..."
        size = 64
#1  0x0000000000401234 in function_b () at prog.c:11
        x = 42
#2  0x0000000000401189 in function_a () at prog.c:7
        y = 100

# Naviguer entre frames
(gdb) frame 2
#2  0x0000000000401189 in function_a () at prog.c:7

# Voir variables du frame actuel
(gdb) info locals
y = 100

# Voir arguments de la fonction
(gdb) info args
(no arguments)
```

### 6.3 LLDB - Backtrace

```bash
# Backtrace
(lldb) thread backtrace
(lldb) bt

* thread #1, queue = 'com.apple.main-thread'
  * frame #0: 0x0000000100003f40 program`function_c at prog.c:15
    frame #1: 0x0000000100003f20 program`function_b at prog.c:11
    frame #2: 0x0000000100003f00 program`function_a at prog.c:7
    frame #3: 0x0000000100003ee0 program`main at prog.c:3

# Sélectionner frame
(lldb) frame select 2
frame #2: 0x0000000100003f00 program`function_a at prog.c:7

# Variables locales
(lldb) frame variable
(int) y = 100
```

## 7. Red Team : Analyser un Binaire Inconnu

### 7.1 Workflow d'Analyse

```ascii
ÉTAPE 1 : RECONNAISSANCE
├─ Lancer le programme dans le debugger
├─ Break sur main ou entry point
└─ Observer le flow général

ÉTAPE 2 : CARTOGRAPHIE
├─ Identifier fonctions intéressantes
├─ Trouver checks (strcmp, if...)
└─ Repérer I/O (scanf, gets, read...)

ÉTAPE 3 : ANALYSE DYNAMIQUE
├─ Breakpoints sur fonctions critiques
├─ Examiner registres et mémoire
└─ Modifier valeurs pour tester

ÉTAPE 4 : EXPLOITATION
├─ Identifier vulnérabilité
├─ Calculer offsets
└─ Créer exploit
```

**Exemple Concret** :

```bash
# 1. Charger binaire mystère
$ gdb ./mystery_program
(gdb) info functions
All defined functions:
0x0000000000401000  _start
0x0000000000401156  main
0x0000000000401200  check_password
0x0000000000401300  vulnerable_function
0x0000000000401400  win

# 2. Désassembler fonction intéressante
(gdb) disassemble check_password
Dump of assembler code for function check_password:
   0x0000000000401200 <+0>:     push   rbp
   0x0000000000401201 <+1>:     mov    rbp,rsp
   0x0000000000401204 <+4>:     sub    rsp,0x10
   0x0000000000401208 <+8>:     mov    QWORD PTR [rbp-0x8],rdi
   0x000000000040120c <+12>:    mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000401210 <+16>:    lea    rsi,[rip+0xe91]        # 0x4020a8
   0x0000000000401217 <+23>:    mov    rdi,rax
   0x000000000040121a <+26>:    call   0x401030 <strcmp@plt>

# 3. Trouver la string de comparaison
(gdb) x/s 0x4020a8
0x4020a8: "sup3rs3cr3t"

# 4. PWNED ! On a le mot de passe sans reverse engineering complet
```

### 7.2 Patcher en Runtime

```bash
# Scenario : Bypass anti-debug check

CODE (hypothétique) :
if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
    printf("Debugger detected!\n");
    exit(1);
}

DANS GDB :

# 1. Breakpoint sur ptrace
(gdb) break ptrace
Breakpoint 1 at 0x401030

# 2. Run
(gdb) run
[Breakpoint 1, ptrace@plt]

# 3. Forcer le retour (succès)
(gdb) finish
Run till exit from ptrace@plt
0x0000000000401234 in main ()
Value returned is $1 = -1

(gdb) set $rax = 0
      ↑
Ptrace retourne maintenant 0 (pas de debugger)

# 4. Continue
(gdb) continue
Program continues normally!
```

### 7.3 Dumper la Mémoire

```bash
# GDB - Dumper une région mémoire
(gdb) dump binary memory output.bin 0x400000 0x401000
       ↓                  ↓           ↓        ↓
   Commande          Fichier     Début    Fin

# Dumper le heap
(gdb) info proc mappings
  Start Addr           End Addr       Size     Offset objfile
  0x555555554000  0x555555555000     0x1000        0x0 /path/program
  0x555555756000  0x555555777000    0x21000        0x0 [heap]

(gdb) dump binary memory heap.bin 0x555555756000 0x555555777000

# LLDB - Dumper mémoire
(lldb) memory read --outfile output.bin --binary 0x400000 0x401000
```

## 8. Extensions Red Team : pwndbg, GEF, PEDA

### 8.1 pwndbg (Recommandé)

```bash
# Installation
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh

# Features :
┌────────────────────────────────────────┐
│ - Vue automatique registres/stack      │
│ - Désassemblage coloré                 │
│ - Détection protections (ASLR, NX...)  │
│ - Commandes exploitation (cyclic...)   │
│ - Heap analysis                        │
└────────────────────────────────────────┘
```

**Interface pwndbg** :

```ascii
Quand tu break, tu vois AUTOMATIQUEMENT :

REGISTERS
RAX  0x4141414141414141 ('AAAAAAAA')
RBX  0x0
RIP  0x401234 (main+20)
RSP  0x7fffffffe400 ◂— 0x4141414141414141

DISASM
► 0x401234 <main+20>    ret
  0x401235 <main+21>    nop

STACK
00:0000│ rsp  0x7fffffffe400 ◂— 0x4141414141414141
01:0008│      0x7fffffffe408 ◂— 0x4141414141414141

BACKTRACE
► f 0     401234 main+20
  f 1 4141414141414141
  f 2 4141414141414141
```

**Commandes pwndbg utiles** :

```bash
# Créer pattern cyclique (trouver offsets)
pwndbg> cyclic 200
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaa...

pwndbg> cyclic -l 0x61616161
Finding cyclic pattern of 4 bytes: b'aaaa' (hex: 0x61616161)
Found at offset 0

# Chercher gadgets ROP
pwndbg> rop --grep "pop rdi"
0x0000000000401234 : pop rdi ; ret

# Voir protections
pwndbg> checksec
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX disabled
PIE:      No PIE

# Chercher en mémoire
pwndbg> search -s "/bin/sh"
[stack]         0x7fffffffe500 "/bin/sh"
```

## 9. Tableau Comparatif GDB vs LLDB

```ascii
┌─────────────────────┬────────────────────┬─────────────────────┐
│ Action              │ GDB                │ LLDB                │
├─────────────────────┼────────────────────┼─────────────────────┤
│ Break fonction      │ break main         │ b main              │
│ Break adresse       │ break *0x401000    │ b 0x401000          │
│ Run                 │ run / r            │ run / r             │
│ Continue            │ continue / c       │ continue / c        │
│ Step into           │ step / s           │ step / s            │
│ Step over           │ next / n           │ next / n            │
│ Registres           │ info registers     │ register read       │
│ Mémoire hexa        │ x/10x $rsp         │ x/10x $rsp          │
│ Backtrace           │ backtrace / bt     │ bt                  │
│ Désassembler        │ disassemble main   │ disassemble -n main │
│ Modifier registre   │ set $rax=0x42      │ register write rax  │
│ Quitter             │ quit / q           │ quit / q            │
└─────────────────────┴────────────────────┴─────────────────────┘
```

## 10. Cas d'Usage Red Team Réels

### Scénario 1 : Bypass Licence Check

```bash
# Programme vérifie licence
# Code : if (check_license() == 1) { run(); } else { exit(); }

(gdb) break check_license
(gdb) run
[Breakpoint hit]

(gdb) finish
Value returned is $1 = 0  ← Licence invalide

(gdb) set $rax = 1  ← Forcer succès
(gdb) continue
[Programme lance avec "licence valide"]
```

### Scénario 2 : Trouver Buffer Overflow Offset

```bash
# Créer pattern
pwndbg> cyclic 200

# Run avec pattern
pwndbg> run
Enter input: [Paste cyclic pattern]
[Program crashes]

# Voir RIP écrasé
pwndbg> info registers rip
rip = 0x6161616b

# Trouver offset
pwndbg> cyclic -l 0x6161616b
72

# Offset = 72 bytes avant d'écraser RIP
```

### Scénario 3 : Leak ASLR

```bash
# Programme avec ASLR
(gdb) break main
(gdb) run

# Voir adresse libc
(gdb) info proc mappings | grep libc
0x7ffff7a0d000  0x7ffff7bcd000 libc-2.31.so

# Calculer base libc
Base libc = 0x7ffff7a0d000

# Trouver offset system()
(gdb) print system
$1 = {<text variable, no debug info>} 0x7ffff7a52290 <system>

Offset system = 0x7ffff7a52290 - 0x7ffff7a0d000 = 0x45290

# Exploitation : base_libc + 0x45290 = system()
```

## Ressources

- GDB Documentation officielle : https://sourceware.org/gdb/documentation/
- LLDB Tutorial : https://lldb.llvm.org/use/tutorial.html
- pwndbg : https://github.com/pwndbg/pwndbg
- GDB Cheat Sheet : https://darkdust.net/files/GDB%20Cheat%20Sheet.pdf
- Exploitation avec GDB : https://www.exploit-db.com/docs/english/13519-debugging-with-gdb.pdf
