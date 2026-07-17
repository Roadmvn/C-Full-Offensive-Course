[Français](../../fr/setup/macos.md) · **English**

# macOS setup: Clang

Apple's Xcode Command Line Tools provide `clang`, `make`, and related developer utilities without requiring the full Xcode application.

Git is required to clone the course repository. The Command Line Tools installed below normally provide Git as well; if Git remains unavailable afterward, use the [official Git downloads](https://git-scm.com/downloads/).

## 1. Install Xcode Command Line Tools

Open Terminal and run:

```bash
xcode-select --install
```

Follow the macOS dialog and accept Apple's license terms. If macOS says the tools are already installed, continue to verification.

## 2. Verify the tools and architecture

```bash
git --version
xcode-select -p
clang --version
make --version
uname -m
```

`xcode-select -p` should print the active developer directory, and `clang --version` should print the compiler version. `uname -m` normally reports `arm64` on Apple Silicon or `x86_64` on an Intel Mac. Record this value because later assembly and platform material can be architecture-specific.

For Apple Silicon learners, the `03-asm-x64` assembly exercises require an `x86-64` VM. Rosetta alone does not guarantee that the module's compiler, assembler, debugger, and expected x86-64 environment are available; use a disposable x86-64 VM for those exercises.

## 3. Verify the first build

From the repository root, run:

```bash
cd 01-c-fundamentals
clang lessons/01-hello-world.c -o hello-world
./hello-world
```

The expected program output is `Hello, World!`. Return to the [first-session guide](../start-here.md) for the exercise and next steps.

## Cleanup or uninstall

Remove the generated program from `01-c-fundamentals`:

```bash
rm hello-world
```

The Command Line Tools are shared by many development tools. Keep them unless you have a specific reason to remove them; if removal is required, use the current Apple-supported developer-tools workflow rather than deleting developer directories without review.

[Course home](../README.md) · [Lab safety](../safety/lab-safety.md)
