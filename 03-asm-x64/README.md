# Module 03 : Assembly x64

```
+-------------------------------------------------------------------+
|                                                                     |
|   "Si tu ne comprends pas l'assembleur, tu ne comprends pas        |
|    ce que ta machine execute reellement."                           |
|                                                                     |
|   Ce module t'apprend a lire et ecrire du x86-64.                  |
|   Indispensable pour le shellcoding et le reverse engineering.     |
|                                                                     |
+-------------------------------------------------------------------+
```

## Objectifs d'apprentissage

A la fin de ce module, tu sauras :

- Comprendre les registres x64 et leur role (RAX, RCX, RDX, R8-R15...)
- Lire et ecrire des instructions assembleur de base (mov, push, pop, call, ret)
- Maitriser les calling conventions Windows x64 (rcx, rdx, r8, r9 + shadow space)
- Manipuler la stack manuellement (prologue, epilogue, variables locales)
- Ecrire de l'inline ASM en C et utiliser MASM/NASM

## Prerequis

- Module 01 (C Fundamentals) valide
- Module 02 (Memory & Pointers) valide
- Comprendre la notion de stack et de memoire

## Contenu du module

### Lessons

| # | Dossier | Sujet | Fichiers |
|---|---------|-------|----------|
| 01 | `01-Registres-Instructions/` | Registres x64, instructions de base (mov, add, sub, cmp, jmp) | example.c |
| 02 | `02-Calling-Conventions/` | Convention d'appel Windows x64, passage de parametres | example.c, solution.c |
| 03 | `03-Stack-Operations/` | Manipulation de la stack, push/pop, prologue/epilogue | example.c |
| 04 | `04-Inline-ASM/` | Assembleur inline dans du code C, __asm blocks | example.c |
| 05 | `05-MASM-NASM/` | Ecrire des fichiers .asm avec MASM et NASM | example.c |

## Comment travailler

```
1. Ouvre le dossier de la lesson (ex: lessons/01-Registres-Instructions/)
2. Lis le fichier example.c - les commentaires expliquent tout
3. Compile : cl example.c
4. Execute et observe le resultat
5. Modifie le code pour experimenter
6. Passe a la lesson suivante
```

## Compilation

```batch
REM Compiler un exemple
cl example.c

REM Si tu utilises MASM
ml64 fichier.asm /link /entry:main
```

## Lien avec le maldev

| Concept | Usage offensif |
|---------|---------------|
| Registres | Comprendre les debuggers, lire le shellcode |
| Calling conventions | Appeler des API Windows depuis du shellcode |
| Stack operations | Construire des ROP chains, buffer overflow |
| Inline ASM | Syscalls directs, stubs d'evasion |
| MASM/NASM | Ecrire du shellcode position-independent |

## Checklist

- [ ] J'ai compris les registres x64 principaux
- [ ] Je sais lire une calling convention Windows x64
- [ ] Je comprends le mecanisme de la stack (push/pop/ret)
- [ ] J'ai ecrit du code inline ASM en C
- [ ] J'ai compile un fichier MASM ou NASM

---

Temps estime : **6-8 heures**

Prochain module : [04 - Windows Fundamentals](../04-windows-fundamentals/)
