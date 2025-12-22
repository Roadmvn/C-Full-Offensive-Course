@echo off
REM Build script for Week 6 - Memory Operations
REM Compiles all lessons, exercises, and solutions

echo ========================================
echo   Week 6: Memory Operations - Build
echo ========================================
echo.

REM Check if Visual Studio environment is set up
where cl >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Error: MSVC compiler not found
    echo [!] Please run this from Developer Command Prompt
    echo [!] Or run: "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    exit /b 1
)

echo [*] Compiler found: MSVC
echo.

REM Create output directories
if not exist "bin" mkdir bin
if not exist "bin\lessons" mkdir bin\lessons
if not exist "bin\exercises" mkdir bin\exercises
if not exist "bin\solutions" mkdir bin\solutions

echo ========================================
echo   Building Lessons
echo ========================================
echo.

echo [*] Building 01-virtualalloc.c...
cl /nologo /Fe:bin\lessons\01-virtualalloc.exe Lessons\01-virtualalloc.c /link /OUT:bin\lessons\01-virtualalloc.exe >nul 2>&1
if %errorlevel% equ 0 (
    echo [+] Success: bin\lessons\01-virtualalloc.exe
) else (
    echo [-] Failed to build 01-virtualalloc.c
)

echo [*] Building 02-virtualprotect.c...
cl /nologo /Fe:bin\lessons\02-virtualprotect.exe Lessons\02-virtualprotect.c /link /OUT:bin\lessons\02-virtualprotect.exe >nul 2>&1
if %errorlevel% equ 0 (
    echo [+] Success: bin\lessons\02-virtualprotect.exe
) else (
    echo [-] Failed to build 02-virtualprotect.c
)

echo [*] Building 03-memory-rw.c...
cl /nologo /Fe:bin\lessons\03-memory-rw.exe Lessons\03-memory-rw.c /link /OUT:bin\lessons\03-memory-rw.exe >nul 2>&1
if %errorlevel% equ 0 (
    echo [+] Success: bin\lessons\03-memory-rw.exe
) else (
    echo [-] Failed to build 03-memory-rw.c
)

echo [*] Building 04-shellcode-local.c...
cl /nologo /Fe:bin\lessons\04-shellcode-local.exe Lessons\04-shellcode-local.c /link /OUT:bin\lessons\04-shellcode-local.exe >nul 2>&1
if %errorlevel% equ 0 (
    echo [+] Success: bin\lessons\04-shellcode-local.exe
) else (
    echo [-] Failed to build 04-shellcode-local.c
)

echo.
echo ========================================
echo   Building Exercises
echo ========================================
echo.

echo [*] Building ex01-alloc-buffer.c...
cl /nologo /Fe:bin\exercises\ex01-alloc-buffer.exe Exercises\ex01-alloc-buffer.c /link /OUT:bin\exercises\ex01-alloc-buffer.exe >nul 2>&1
if %errorlevel% equ 0 (
    echo [+] Success: bin\exercises\ex01-alloc-buffer.exe
) else (
    echo [-] Failed to build ex01-alloc-buffer.c
)

echo [*] Building ex02-rwx-transition.c...
cl /nologo /Fe:bin\exercises\ex02-rwx-transition.exe Exercises\ex02-rwx-transition.c /link /OUT:bin\exercises\ex02-rwx-transition.exe >nul 2>&1
if %errorlevel% equ 0 (
    echo [+] Success: bin\exercises\ex02-rwx-transition.exe
) else (
    echo [-] Failed to build ex02-rwx-transition.c
)

echo [*] Building ex03-run-shellcode.c...
cl /nologo /Fe:bin\exercises\ex03-run-shellcode.exe Exercises\ex03-run-shellcode.c /link /OUT:bin\exercises\ex03-run-shellcode.exe >nul 2>&1
if %errorlevel% equ 0 (
    echo [+] Success: bin\exercises\ex03-run-shellcode.exe
) else (
    echo [-] Failed to build ex03-run-shellcode.c
)

echo.
echo ========================================
echo   Building Solutions
echo ========================================
echo.

echo [*] Building ex01-alloc-buffer-solution.c...
cl /nologo /Fe:bin\solutions\ex01-alloc-buffer-solution.exe Solutions\ex01-alloc-buffer-solution.c /link /OUT:bin\solutions\ex01-alloc-buffer-solution.exe >nul 2>&1
if %errorlevel% equ 0 (
    echo [+] Success: bin\solutions\ex01-alloc-buffer-solution.exe
) else (
    echo [-] Failed to build ex01-alloc-buffer-solution.c
)

echo [*] Building ex02-rwx-transition-solution.c...
cl /nologo /Fe:bin\solutions\ex02-rwx-transition-solution.exe Solutions\ex02-rwx-transition-solution.c /link /OUT:bin\solutions\ex02-rwx-transition-solution.exe >nul 2>&1
if %errorlevel% equ 0 (
    echo [+] Success: bin\solutions\ex02-rwx-transition-solution.exe
) else (
    echo [-] Failed to build ex02-rwx-transition-solution.c
)

echo [*] Building ex03-run-shellcode-solution.c...
cl /nologo /Fe:bin\solutions\ex03-run-shellcode-solution.exe Solutions\ex03-run-shellcode-solution.c /link /OUT:bin\solutions\ex03-run-shellcode-solution.exe >nul 2>&1
if %errorlevel% equ 0 (
    echo [+] Success: bin\solutions\ex03-run-shellcode-solution.exe
) else (
    echo [-] Failed to build ex03-run-shellcode-solution.c
)

REM Clean up build artifacts
echo.
echo [*] Cleaning up build artifacts...
del /Q *.obj >nul 2>&1

echo.
echo ========================================
echo   Build Complete!
echo ========================================
echo.
echo [*] Binaries location:
echo     Lessons:   bin\lessons\
echo     Exercises: bin\exercises\
echo     Solutions: bin\solutions\
echo.
echo [*] Run examples:
echo     bin\lessons\01-virtualalloc.exe
echo     bin\lessons\02-virtualprotect.exe
echo     bin\lessons\03-memory-rw.exe
echo     bin\lessons\04-shellcode-local.exe
echo.
echo [*] Run exercises:
echo     bin\exercises\ex01-alloc-buffer.exe
echo     bin\exercises\ex02-rwx-transition.exe
echo     bin\exercises\ex03-run-shellcode.exe
echo.

pause
