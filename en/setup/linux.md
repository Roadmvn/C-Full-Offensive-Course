[Français](../../fr/setup/linux.md) · **English**

# Linux setup: GCC or Clang

Git is required to clone the course repository. Install Git, one C compiler, `make`, and `gdb`. The package commands below are grouped by distribution; run only the block that matches your system. The [official Git downloads](https://git-scm.com/downloads/) provide an alternative route if your distribution does not package Git.

## 1. Install the tools

**Ubuntu or Debian:**

```bash
sudo apt update
sudo apt install git build-essential clang gdb
```

**Fedora:**

```bash
sudo dnf install git gcc clang make gdb
```

**Arch Linux:**

```bash
sudo pacman -Syu --needed git base-devel clang gdb
```

These commands change system packages and may ask for your administrator password. Do not combine commands from different distributions.

## 2. Verify the tools

The examples above install both GCC and Clang so that you can compare them. You need only one of them to compile the first lesson.

```bash
git --version
gcc --version
clang --version
make --version
gdb --version
```

Each command should print its tool name and version. If one is missing, use your distribution's package manager to confirm that its package finished installing.

## 3. Verify the first build

From the repository root, compile with either GCC:

```bash
cd 01-c-fundamentals
gcc lessons/01-hello-world.c -o hello-world
./hello-world
```

or Clang:

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

If you later uninstall packages, use the same distribution package manager and remove only packages that you installed solely for this course. Development groups such as `build-essential` or `base-devel` may be shared by other projects, so review package-manager history and dependencies before removing them.

[Course home](../README.md) · [Lab safety](../safety/lab-safety.md)
