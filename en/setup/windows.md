[Français](../../fr/setup/windows.md) · **English**

# Windows setup: MSVC

This guide installs the Microsoft C compiler used by the first lesson. Use a supported Windows 10 or Windows 11 system for course setup; use a disposable VM for later security labs.

## Git prerequisite

Git is required to clone the course repository. Install the Windows version from the [official Git downloads](https://git-scm.com/downloads/), reopen your terminal, and verify it:

```batch
git --version
```

The command should print a Git version before you continue.

## 1. Install Visual Studio Build Tools 2022

1. Download [Visual Studio Build Tools 2022](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022).
2. Start the installer and select the **Desktop development with C++** workload.
3. Keep the workload's recommended MSVC compiler and Windows SDK components selected.
4. Finish the installation and restart Windows only if the installer requests it.

Administrator approval may be required for installation. Daily compilation should not require an administrator terminal.

## 2. Open the configured terminal

From the Windows Start menu, open **Developer Command Prompt for VS 2022**. This shortcut configures the paths used by `cl`; a normal Command Prompt may not know where the compiler is.

Verify the location and compiler version:

```batch
where cl
cl
```

`where cl` should show a path inside the Visual Studio Build Tools installation. `cl` should print a Microsoft compiler version banner. If Windows reports that `cl` is unknown, confirm the selected workload and reopen the Developer Command Prompt.

## 3. Verify the first build

Open the repository root in the Developer Command Prompt, then run:

```batch
cd 01-c-fundamentals
cl lessons\01-hello-world.c /Fe:hello-world.exe
hello-world.exe
```

The expected program output is `Hello, World!`. Return to the [first-session guide](../start-here.md) for the exercise and next steps.

## Cleanup or uninstall

Remove only the generated build files:

```batch
del hello-world.exe 01-hello-world.obj
```

To remove the toolchain, open **Visual Studio Installer**, choose **Modify** to remove **Desktop development with C++**, or choose **More > Uninstall** for Build Tools 2022. Do this only if no other project uses those shared tools or SDKs.

[Course home](../README.md) · [Lab safety](../safety/lab-safety.md)
