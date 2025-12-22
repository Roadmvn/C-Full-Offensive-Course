@echo off
REM Build script for Final Beacon
REM Demonstrates different build configurations

echo ================================================
echo Final Beacon - Build Script
echo ================================================
echo.

REM Check for MSVC compiler
where cl >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] MSVC compiler not found!
    echo     Run this from Developer Command Prompt for VS
    echo     Or run: "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    exit /b 1
)

echo [*] Choose build type:
echo     1. Debug (with symbols, no optimization)
echo     2. Release (optimized, no symbols)
echo     3. Minimal (size optimized, no console)
echo     4. All lessons
echo     5. All exercises
echo.

set /p choice="Enter choice (1-5): "

if "%choice%"=="1" goto debug
if "%choice%"=="2" goto release
if "%choice%"=="3" goto minimal
if "%choice%"=="4" goto lessons
if "%choice%"=="5" goto exercises

echo [!] Invalid choice
exit /b 1

:debug
echo.
echo [*] Building DEBUG version...
echo     - Debug symbols: YES
echo     - Optimization: OFF
echo     - Output: final-beacon-debug.exe
echo.
cl /Zi /Od /W4 final-beacon.c /Fe:final-beacon-debug.exe
if %errorlevel% equ 0 (
    echo [+] Build successful!
    echo [*] Size:
    dir /b final-beacon-debug.exe | xargs -I {} stat -f "%%z bytes" {}
)
goto end

:release
echo.
echo [*] Building RELEASE version...
echo     - Optimization: Maximum speed (/O2)
echo     - Link-time code gen: YES
echo     - Debug symbols: NO
echo     - Output: final-beacon.exe
echo.
cl /O2 /GL /W4 /DNDEBUG final-beacon.c /link /LTCG /OPT:REF /OPT:ICF /Fe:final-beacon.exe
if %errorlevel% equ 0 (
    echo [+] Build successful!
    echo [*] Size:
    dir final-beacon.exe
)
goto end

:minimal
echo.
echo [*] Building MINIMAL version...
echo     - Optimization: Size (/O1 /Os)
echo     - No stack canary (/GS-)
echo     - No console window
echo     - Stripped symbols
echo     - Output: final-beacon-minimal.exe
echo.
cl /O1 /Os /GL /GS- /W4 /DNDEBUG final-beacon.c /link /LTCG /OPT:REF /OPT:ICF /SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup /Fe:final-beacon-minimal.exe

if %errorlevel% equ 0 (
    echo [+] Build successful!
    echo [*] Size before stripping:
    dir final-beacon-minimal.exe

    REM Strip if available
    where strip >nul 2>&1
    if %errorlevel% equ 0 (
        echo [*] Stripping symbols...
        strip -s final-beacon-minimal.exe
        echo [*] Size after stripping:
        dir final-beacon-minimal.exe
    )
)
goto end

:lessons
echo.
echo [*] Building all lessons...
echo.
for %%f in (Lessons\*.c) do (
    echo Building %%f...
    cl /O2 /W4 %%f /Fe:%%~nf.exe
    if %errorlevel% neq 0 (
        echo [!] Failed to build %%f
    ) else (
        echo [+] %%~nf.exe
    )
)
goto end

:exercises
echo.
echo [*] Building all exercises...
echo.
for %%f in (Exercises\*.c) do (
    echo Building %%f...
    cl /O2 /W4 %%f /Fe:%%~nf.exe
    if %errorlevel% neq 0 (
        echo [!] Failed to build %%f
    ) else (
        echo [+] %%~nf.exe
    )
)
goto end

:end
echo.
echo ================================================
echo Build complete!
echo ================================================
echo.
echo [*] Usage examples:
echo     Debug:   final-beacon-debug.exe
echo     Release: final-beacon.exe
echo     Minimal: final-beacon-minimal.exe (no console)
echo.
echo [*] Test with: python test-server.py
echo     (See TEST-GUIDE.md for details)
echo.
