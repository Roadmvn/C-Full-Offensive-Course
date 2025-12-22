@echo off
REM Week 07 - DLLs & Modules Build Script
REM Requires Visual Studio Developer Command Prompt

echo ========================================
echo   Week 07 - DLLs ^& Modules
echo ========================================

if not exist "bin" mkdir bin

echo.
echo [*] Compiling Lessons...
for %%f in (Lessons\*.c) do (
    echo     Compiling %%~nf.c
    cl /nologo /W3 /Fe:bin\%%~nf.exe %%f /link /SUBSYSTEM:CONSOLE >nul 2>&1
    if errorlevel 1 (
        echo     [!] Error compiling %%~nf.c
    )
)

echo.
echo [*] Compiling Exercises...
for %%f in (Exercises\*.c) do (
    echo     Compiling %%~nf.c
    cl /nologo /W3 /Fe:bin\%%~nf.exe %%f /link /SUBSYSTEM:CONSOLE >nul 2>&1
    if errorlevel 1 (
        echo     [!] Error compiling %%~nf.c
    )
)

echo.
echo [*] Compiling Solutions...
for %%f in (Solutions\*.c) do (
    echo     Compiling %%~nf.c
    cl /nologo /W3 /Fe:bin\%%~nf.exe %%f /link /SUBSYSTEM:CONSOLE >nul 2>&1
    if errorlevel 1 (
        echo     [!] Error compiling %%~nf.c
    )
)

echo.
echo ========================================
echo   Build complete! Binaries in bin\
echo ========================================
echo.
pause
