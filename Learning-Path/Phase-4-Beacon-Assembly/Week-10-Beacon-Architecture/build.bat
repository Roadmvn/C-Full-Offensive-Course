@echo off
REM ========================================
REM Week 10: Beacon Architecture - Build Script
REM ========================================

echo.
echo ========================================
echo Week 10: Beacon Architecture
echo Build Script
echo ========================================
echo.

REM Check if cl.exe is available
where cl.exe >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [!] ERROR: cl.exe not found in PATH
    echo [!] Please run this from a Visual Studio Developer Command Prompt
    echo.
    pause
    exit /b 1
)

echo [*] Visual Studio compiler found
echo.

REM Create output directory
if not exist "bin" mkdir bin
echo [*] Output directory: bin\
echo.

REM ========================================
REM Build Lessons
REM ========================================

echo ========================================
echo Building Lessons
echo ========================================
echo.

echo [*] Building 01-beacon-concept.c...
cl.exe /nologo /W3 /O2 Lessons\01-beacon-concept.c /Fe:bin\01-beacon-concept.exe /link wininet.lib
if %ERRORLEVEL% EQU 0 (
    echo [+] SUCCESS: bin\01-beacon-concept.exe
) else (
    echo [-] FAILED: 01-beacon-concept.c
)
echo.

echo [*] Building 02-config-struct.c...
cl.exe /nologo /W3 /O2 Lessons\02-config-struct.c /Fe:bin\02-config-struct.exe
if %ERRORLEVEL% EQU 0 (
    echo [+] SUCCESS: bin\02-config-struct.exe
) else (
    echo [-] FAILED: 02-config-struct.c
)
echo.

echo [*] Building 03-sleep-loop.c...
cl.exe /nologo /W3 /O2 Lessons\03-sleep-loop.c /Fe:bin\03-sleep-loop.exe
if %ERRORLEVEL% EQU 0 (
    echo [+] SUCCESS: bin\03-sleep-loop.exe
) else (
    echo [-] FAILED: 03-sleep-loop.c
)
echo.

echo [*] Building 04-check-in.c...
cl.exe /nologo /W3 /O2 Lessons\04-check-in.c /Fe:bin\04-check-in.exe /link wininet.lib
if %ERRORLEVEL% EQU 0 (
    echo [+] SUCCESS: bin\04-check-in.exe
) else (
    echo [-] FAILED: 04-check-in.c
)
echo.

REM ========================================
REM Build Exercises
REM ========================================

echo ========================================
echo Building Exercises
echo ========================================
echo.

echo [*] Building ex01-config-init.c...
cl.exe /nologo /W3 /O2 Exercises\ex01-config-init.c /Fe:bin\ex01-config-init.exe
if %ERRORLEVEL% EQU 0 (
    echo [+] SUCCESS: bin\ex01-config-init.exe
) else (
    echo [-] FAILED: ex01-config-init.c
)
echo.

echo [*] Building ex02-jitter-sleep.c...
cl.exe /nologo /W3 /O2 Exercises\ex02-jitter-sleep.c /Fe:bin\ex02-jitter-sleep.exe
if %ERRORLEVEL% EQU 0 (
    echo [+] SUCCESS: bin\ex02-jitter-sleep.exe
) else (
    echo [-] FAILED: ex02-jitter-sleep.c
)
echo.

echo [*] Building ex03-beacon-skeleton.c...
cl.exe /nologo /W3 /O2 Exercises\ex03-beacon-skeleton.c /Fe:bin\ex03-beacon-skeleton.exe /link wininet.lib
if %ERRORLEVEL% EQU 0 (
    echo [+] SUCCESS: bin\ex03-beacon-skeleton.exe
) else (
    echo [-] FAILED: ex03-beacon-skeleton.c
)
echo.

REM ========================================
REM Build Solutions
REM ========================================

echo ========================================
echo Building Solutions
echo ========================================
echo.

echo [*] Building sol01-config-init.c...
cl.exe /nologo /W3 /O2 Solutions\sol01-config-init.c /Fe:bin\sol01-config-init.exe
if %ERRORLEVEL% EQU 0 (
    echo [+] SUCCESS: bin\sol01-config-init.exe
) else (
    echo [-] FAILED: sol01-config-init.c
)
echo.

echo [*] Building sol02-jitter-sleep.c...
cl.exe /nologo /W3 /O2 Solutions\sol02-jitter-sleep.c /Fe:bin\sol02-jitter-sleep.exe
if %ERRORLEVEL% EQU 0 (
    echo [+] SUCCESS: bin\sol02-jitter-sleep.exe
) else (
    echo [-] FAILED: sol02-jitter-sleep.c
)
echo.

echo [*] Building sol03-beacon-skeleton.c...
cl.exe /nologo /W3 /O2 Solutions\sol03-beacon-skeleton.c /Fe:bin\sol03-beacon-skeleton.exe /link wininet.lib
if %ERRORLEVEL% EQU 0 (
    echo [+] SUCCESS: bin\sol03-beacon-skeleton.exe
) else (
    echo [-] FAILED: sol03-beacon-skeleton.c
)
echo.

REM ========================================
REM Cleanup
REM ========================================

echo [*] Cleaning up temporary files...
del /Q *.obj 2>nul

echo.
echo ========================================
echo Build Complete
echo ========================================
echo.
echo All executables are in the bin\ directory
echo.
echo To run lessons:
echo   bin\01-beacon-concept.exe
echo   bin\02-config-struct.exe
echo   bin\03-sleep-loop.exe
echo   bin\04-check-in.exe
echo.
echo To run exercises:
echo   bin\ex01-config-init.exe
echo   bin\ex02-jitter-sleep.exe
echo   bin\ex03-beacon-skeleton.exe
echo.
echo To test beacon with C2 server:
echo   1. Run: python server.py (if you created it)
echo   2. Run: bin\ex03-beacon-skeleton.exe
echo.

pause
