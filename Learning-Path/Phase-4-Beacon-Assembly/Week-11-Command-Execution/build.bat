@echo off
REM Build script for Week 11: Command Execution
REM Compiles all lessons, exercises, and solutions

echo ============================================
echo Week 11: Command Execution - Build Script
echo ============================================
echo.

REM Check for Visual Studio environment
where cl >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] MSVC compiler not found!
    echo Please run this from a Visual Studio Developer Command Prompt
    echo or run: "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    pause
    exit /b 1
)

echo [*] Compiler found: MSVC
echo.

REM Create output directories
if not exist "bin" mkdir bin
if not exist "bin\lessons" mkdir bin\lessons
if not exist "bin\exercises" mkdir bin\exercises
if not exist "bin\solutions" mkdir bin\solutions

echo [*] Building Lessons...
echo.

REM Lesson 01: cmd-whoami
echo [+] Compiling 01-cmd-whoami.c...
cl /nologo /W4 /O2 /Fe:bin\lessons\01-cmd-whoami.exe Lessons\01-cmd-whoami.c /link /SUBSYSTEM:CONSOLE >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo     [OK] bin\lessons\01-cmd-whoami.exe
) else (
    echo     [FAIL] Error compiling 01-cmd-whoami.c
)
del *.obj 2>nul

REM Lesson 02: cmd-filesystem
echo [+] Compiling 02-cmd-filesystem.c...
cl /nologo /W4 /O2 /Fe:bin\lessons\02-cmd-filesystem.exe Lessons\02-cmd-filesystem.c /link /SUBSYSTEM:CONSOLE >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo     [OK] bin\lessons\02-cmd-filesystem.exe
) else (
    echo     [FAIL] Error compiling 02-cmd-filesystem.c
)
del *.obj 2>nul

REM Lesson 03: cmd-cat
echo [+] Compiling 03-cmd-cat.c...
cl /nologo /W4 /O2 /Fe:bin\lessons\03-cmd-cat.exe Lessons\03-cmd-cat.c /link /SUBSYSTEM:CONSOLE >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo     [OK] bin\lessons\03-cmd-cat.exe
) else (
    echo     [FAIL] Error compiling 03-cmd-cat.c
)
del *.obj 2>nul

REM Lesson 04: dispatcher
echo [+] Compiling 04-dispatcher.c...
cl /nologo /W4 /O2 /Fe:bin\lessons\04-dispatcher.exe Lessons\04-dispatcher.c /link /SUBSYSTEM:CONSOLE >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo     [OK] bin\lessons\04-dispatcher.exe
) else (
    echo     [FAIL] Error compiling 04-dispatcher.c
)
del *.obj 2>nul

echo.
echo [*] Building Exercises...
echo.

REM Exercise 01: capture-output
echo [+] Compiling ex01-capture-output.c...
cl /nologo /W4 /O2 /Fe:bin\exercises\ex01-capture-output.exe Exercises\ex01-capture-output.c /link /SUBSYSTEM:CONSOLE >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo     [OK] bin\exercises\ex01-capture-output.exe
) else (
    echo     [FAIL] Error compiling ex01-capture-output.c
)
del *.obj 2>nul

REM Exercise 02: implement-ls
echo [+] Compiling ex02-implement-ls.c...
cl /nologo /W4 /O2 /Fe:bin\exercises\ex02-implement-ls.exe Exercises\ex02-implement-ls.c /link /SUBSYSTEM:CONSOLE >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo     [OK] bin\exercises\ex02-implement-ls.exe
) else (
    echo     [FAIL] Error compiling ex02-implement-ls.c
)
del *.obj 2>nul

REM Exercise 03: full-dispatcher
echo [+] Compiling ex03-full-dispatcher.c...
cl /nologo /W4 /O2 /Fe:bin\exercises\ex03-full-dispatcher.exe Exercises\ex03-full-dispatcher.c /link /SUBSYSTEM:CONSOLE >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo     [OK] bin\exercises\ex03-full-dispatcher.exe
) else (
    echo     [FAIL] Error compiling ex03-full-dispatcher.c
)
del *.obj 2>nul

echo.
echo [*] Building Solutions...
echo.

REM Solution 01: capture-output
echo [+] Compiling sol01-capture-output.c...
cl /nologo /W4 /O2 /Fe:bin\solutions\sol01-capture-output.exe Solutions\sol01-capture-output.c /link /SUBSYSTEM:CONSOLE >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo     [OK] bin\solutions\sol01-capture-output.exe
) else (
    echo     [FAIL] Error compiling sol01-capture-output.c
)
del *.obj 2>nul

REM Solution 02: implement-ls
echo [+] Compiling sol02-implement-ls.c...
cl /nologo /W4 /O2 /Fe:bin\solutions\sol02-implement-ls.exe Solutions\sol02-implement-ls.c /link /SUBSYSTEM:CONSOLE >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo     [OK] bin\solutions\sol02-implement-ls.exe
) else (
    echo     [FAIL] Error compiling sol02-implement-ls.c
)
del *.obj 2>nul

REM Solution 03: full-dispatcher
echo [+] Compiling sol03-full-dispatcher.c...
cl /nologo /W4 /O2 /Fe:bin\solutions\sol03-full-dispatcher.exe Solutions\sol03-full-dispatcher.c /link /SUBSYSTEM:CONSOLE >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo     [OK] bin\solutions\sol03-full-dispatcher.exe
) else (
    echo     [FAIL] Error compiling sol03-full-dispatcher.c
)
del *.obj 2>nul

REM Cleanup
del *.obj 2>nul

echo.
echo ============================================
echo Build Complete!
echo ============================================
echo.
echo Executables are in the bin\ directory:
echo   - bin\lessons\     (4 files)
echo   - bin\exercises\   (3 files)
echo   - bin\solutions\   (3 files)
echo.
echo To run a lesson:   bin\lessons\01-cmd-whoami.exe
echo To run exercise:   bin\exercises\ex01-capture-output.exe
echo To run solution:   bin\solutions\sol01-capture-output.exe
echo.

pause
