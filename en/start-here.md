[Français](../fr/start-here.md) · **English**

# Start here: verify your first C build

This guide is for a first course session. You will choose the right entry point, install one C toolchain, compile the shared first lesson, and clean up the generated file.

> Before any security lab, pass the [lab-safety gate](safety/lab-safety.md). The first C lesson below is a normal local programming exercise and does not require a security lab.

## 1. Choose your starting point

- **New to binary, CPU, memory, or operating-system concepts:** first read [`00-prerequisites`](../00-prerequisites/README.md) and complete its written exercises.
- **Already comfortable with those concepts:** start directly with the C fundamentals below.

`00-prerequisites` is reading-only: it contains reading and written exercises, not `01-hello-world.c`. Compilation starts in `01-c-fundamentals`.

## 2. Verify Git and clone the repository

Git is required to download and update the course. Check it before cloning:

```bash
git --version
```

If the command is not found, install Git for your operating system from the [official Git downloads](https://git-scm.com/downloads/), reopen the terminal, and run `git --version` again.

Then clone the repository:

```bash
git clone https://github.com/Roadmvn/C-Full-Offensive-Course.git
cd C-Full-Offensive-Course
```

If you already cloned the repository, open a terminal at its root instead.

## 3. Select one toolchain

Use the setup guide for your operating system:

- [Windows with MSVC](setup/windows.md)
- [Linux with GCC or Clang](setup/linux.md)
- [macOS with Clang](setup/macos.md)

You need only one compiler. Do not install every toolchain unless another project requires it.

## 4. Verify the compiler

Run the command for the toolchain you selected.

**MSVC, in a Developer Command Prompt for Visual Studio:**

```batch
cl
```

**GCC:**

```bash
gcc --version
```

**Clang:**

```bash
clang --version
```

You should see a compiler name and version. If the command is not found, return to the matching setup guide before continuing.

## 5. Enter the C fundamentals module

From the repository root, run exactly:

```bash
cd 01-c-fundamentals
```

The source remains in one shared location: [`../01-c-fundamentals/lessons/01-hello-world.c`](../01-c-fundamentals/lessons/01-hello-world.c). The English and French portals do not copy it.

## 6. Compile and run the lesson

Choose the commands for your compiler.

**MSVC:**

```batch
cl lessons\01-hello-world.c /Fe:hello-world.exe
hello-world.exe
```

**GCC:**

```bash
gcc lessons/01-hello-world.c -o hello-world
./hello-world
```

**Clang:**

```bash
clang lessons/01-hello-world.c -o hello-world
./hello-world
```

Expected output:

```text
Hello, World!
```

If compilation fails, read the first error line, confirm that your terminal is still in `01-c-fundamentals`, and verify your compiler again.

## 7. Do the first exercise

Open [`exercises/ex01-calculator.c`](../01-c-fundamentals/exercises/ex01-calculator.c), read its instructions, and work in that shared file or in your own local Git branch. Apply the same compile-and-run cycle you just verified. Do not create a copy under `en/` or `fr/`.

## 8. Clean up the generated build files

From `01-c-fundamentals`, use the command for the build you ran.

**MSVC:**

```batch
del hello-world.exe 01-hello-world.obj
```

**GCC or Clang:**

```bash
rm hello-world
```

This removes generated files only; it does not remove the lesson source.

## Next

[Choose one of the four learning paths](paths.md). Before opening any hands-on security material, review the [lab-safety gate](safety/lab-safety.md).
