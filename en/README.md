**English** · [Français](../fr/README.md)

# C Offensive Security Journey

A free, progressive path for learning systems-level C for authorized security research, from computing prerequisites to hands-on Windows, Linux, and macOS labs.

> Content status: 216 units are inventoried. Readiness is audited publicly; incomplete material stays available and is labeled `Draft`.

[Start here](start-here.md) · [Choose a path](paths.md) · [Lab safety](safety/lab-safety.md)

[Methodology](../docs/LEARNING_METHODOLOGY.md) · [Current French curriculum](../00-prerequisites/README.md) · [Français](../fr/README.md)

> Educational use only. Run security labs only on systems you own or are explicitly authorized to test, inside an isolated environment.

All C source and lab artifacts remain shared in the historical course directories; they are never copied into the language portals. Advanced material remains visible when it is `Draft`, with that status shown clearly.

## Four curriculum paths

1. **12-week beginner core:** progress from computing prerequisites to an integrated project through sections `00` to `07`, with assembly section `03` before Windows internals.
2. **Windows depth:** study sections `04` and `05`, followed by selected references from `10`.
3. **Linux or macOS specialization:** choose section `08` or `09` after memory and assembly in sections `02` and `03`.
4. **Advanced reference:** use section `10` as optional material outside the 12-week promise.

## Learning approach

The course starts with how a computer represents data and executes programs, then builds through C fundamentals, memory, x64 assembly, operating-system internals, networking, and integrated projects. Theory, shared examples, exercises, and solutions are kept together at different audited maturity levels.

## 12-week core roadmap

The following historical, aspirational roadmap preserves the original direction from `printf()` to a functional C2 beacon and professional-level offensive tooling over a proposed 12-week core. It is not a guaranteed outcome: units that have not passed readiness review remain visible as `Draft`, and their audited status describes current maturity.

| Phase | Week | Focus | Deliverable |
|-------|------|-------|-------------|
| 0 | Before week 1 | Binary, CPU, memory, operating systems | Machine-model foundations |
| 1 | 1 | C basics: variables, conditions, loops, functions | Calculator |
| 1 | 2 | Pointers, memory, `malloc` and `free` | XOR buffer |
| 1 | 3 | Structures and binary files | Binary parser |
| 1 | 4 | First WinAPI calls: `MessageBox`, handles | WinAPI introduction |
| 2 | 5 | Processes, threads, enumeration | Process lister |
| 2 | 6 | `VirtualAlloc`, `VirtualProtect`, RWX memory | Local shellcode runner |
| 2 | 7 | Dynamic libraries and API resolution | API resolver |
| 3 | 8 | Winsock and TCP client/server concepts | TCP reverse shell |
| 3 | 9 | WinHTTP, requests, and response parsing | HTTP callback |
| 4 | 10 | Architecture, sleep, check-in | Beacon skeleton |
| 4 | 11 | Commands: `whoami`, `ls`, `cat`, `cd` | Beacon with five commands |
| 4 | 12 | Obfuscation concepts, compilation, testing | Final beacon |

The Linux, macOS, and advanced-reference sections remain available after the core and are not included in the 12-week estimate.

## Quick start

### 1. Clone the repository

```bash
git clone https://github.com/Roadmvn/C-Full-Offensive-Course.git
cd C-Full-Offensive-Course
```

### 2. Install Visual Studio Build Tools

- Download [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022).
- Install the **Desktop development with C++** workload.

### 3. Read the prerequisites or go to C fundamentals

```bash
# Absolute beginners: reading and written exercises only
cd 00-prerequisites

# When you finish reading, return to the repository root
cd ..
```

If you already understand the computing basics, stay at the repository root and continue to step 4. The `00-prerequisites` directory contains no C source; compilation begins in `01-c-fundamentals`.

### 4. Compile the first shared lesson

Open a **Developer Command Prompt for Visual Studio**, then run these commands from the repository root:

```batch
cd 01-c-fundamentals
cl lessons\01-hello-world.c
01-hello-world.exe
```

Expected output:

```text
Hello, World!
```

## Repository map

```text
C-Full-Offensive-Course/
├── README.md                     Bilingual language chooser
├── fr/README.md                  French course home
├── en/README.md                  English course home
├── 00-prerequisites/             Binary, CPU, memory, operating systems
├── 01-c-fundamentals/            C variables, pointers, and functions
├── 02-memory-pointers/           Stack, heap, and memory behavior
├── 03-asm-x64/                   x64 assembly and calling conventions
├── 04-windows-fundamentals/      WinAPI, processes, threads, memory
├── 05-windows-advanced/          Advanced Windows security topics
├── 06-network/                   TCP, HTTP, Winsock, WinHTTP
├── 07-beacon-dev/                Beacon architecture, commands, final lab
├── 08-linux/                     Syscalls, ELF, eBPF, containers
├── 09-macos/                     Mach-O, TCC, dylibs, ARM64
├── 10-advanced/                  Hypervisors, firmware, hardware, AI security
├── content/curriculum.json       Audited 216-unit inventory
└── docs/LEARNING_METHODOLOGY.md  Full learning methodology
```

Each historical module can contain a README, checkpoints, lessons, exercises, solutions, and advanced topics. The language portals point to those same shared files.

## Methodology

See [LEARNING_METHODOLOGY.md](../docs/LEARNING_METHODOLOGY.md) for the learning cycle, practice rules, and skill-validation approach.

## Curriculum coverage

| Section | Scope |
|---------|-------|
| `00-prerequisites` | Binary, CPU, memory, operating systems |
| `01-c-fundamentals` | Variables, types, pointers, functions |
| `02-memory-pointers` | Stack, heap, allocation, memory errors |
| `03-asm-x64` | Registers, calling conventions, inline assembly |
| `04-windows-fundamentals` | WinAPI, processes, threads, memory, internals |
| `05-windows-advanced` | Advanced Windows security research topics |
| `06-network` | TCP, HTTP, Winsock, WinHTTP |
| `07-beacon-dev` | Beacon architecture, commands, obfuscation |
| `08-linux` | Syscalls, ELF, eBPF, containers |
| `09-macos` | Mach-O, TCC, SIP, dylibs, ARM64 |
| `10-advanced` | Hypervisors, firmware, hardware, AI security |

## Safety and authorization

This course is for education and authorized security research only. Use disposable, isolated lab systems; never run a security exercise against a system without the owner's explicit permission. Read the canonical [MIT license](../LICENSE) and the separate [legal and ethical warning](../DISCLAIMER.md).

## Contribute

[Contribution guide](../CONTRIBUTING.md) · [Report a course issue](https://github.com/Roadmvn/C-Full-Offensive-Course/issues/new/choose) · [Propose a change](https://github.com/Roadmvn/C-Full-Offensive-Course/pulls) · [Support](../SUPPORT.md) · [Security](../SECURITY.md)
