@echo off
REM Build script for Week 09: HTTP/WinHTTP
REM Compiles all lesson files and solutions

echo ========================================
echo Week 09: HTTP/WinHTTP - Build Script
echo ========================================
echo.

REM Check if we're in the right directory
if not exist "Lessons" (
    echo [!] Error: Lessons directory not found
    echo [!] Please run this script from the Week-09-HTTP-WinHTTP directory
    pause
    exit /b 1
)

REM Create output directory for binaries
if not exist "bin" mkdir bin

echo [*] Building Lesson Files...
echo.

REM Build Lesson 01
echo [+] Building 01-winhttp-intro.c...
cl /nologo /W4 /O2 Lessons\01-winhttp-intro.c /Fe:bin\01-winhttp-intro.exe /link winhttp.lib >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo     [OK] 01-winhttp-intro.exe
) else (
    echo     [FAIL] Failed to compile 01-winhttp-intro.c
)

REM Build Lesson 02
echo [+] Building 02-http-get.c...
cl /nologo /W4 /O2 Lessons\02-http-get.c /Fe:bin\02-http-get.exe /link winhttp.lib >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo     [OK] 02-http-get.exe
) else (
    echo     [FAIL] Failed to compile 02-http-get.c
)

REM Build Lesson 03
echo [+] Building 03-http-post.c...
cl /nologo /W4 /O2 Lessons\03-http-post.c /Fe:bin\03-http-post.exe /link winhttp.lib >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo     [OK] 03-http-post.exe
) else (
    echo     [FAIL] Failed to compile 03-http-post.c
)

REM Build Lesson 04
echo [+] Building 04-http-callback.c...
cl /nologo /W4 /O2 Lessons\04-http-callback.c /Fe:bin\04-http-callback.exe /link winhttp.lib >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo     [OK] 04-http-callback.exe
) else (
    echo     [FAIL] Failed to compile 04-http-callback.c
)

echo.
echo [*] Building Solution Files...
echo.

REM Build Solution 01
echo [+] Building ex01-fetch-page-solution.c...
cl /nologo /W4 /O2 Solutions\ex01-fetch-page-solution.c /Fe:bin\ex01-solution.exe /link winhttp.lib >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo     [OK] ex01-solution.exe
) else (
    echo     [FAIL] Failed to compile ex01-fetch-page-solution.c
)

REM Build Solution 02
echo [+] Building ex02-post-data-solution.c...
cl /nologo /W4 /O2 Solutions\ex02-post-data-solution.c /Fe:bin\ex02-solution.exe /link winhttp.lib >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo     [OK] ex02-solution.exe
) else (
    echo     [FAIL] Failed to compile ex02-post-data-solution.c
)

REM Build Solution 03
echo [+] Building ex03-beacon-checkin-solution.c...
cl /nologo /W4 /O2 Solutions\ex03-beacon-checkin-solution.c /Fe:bin\ex03-solution.exe /link winhttp.lib >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo     [OK] ex03-solution.exe
) else (
    echo     [FAIL] Failed to compile ex03-beacon-checkin-solution.c
)

echo.
echo [*] Cleaning up temporary files...
del /q *.obj 2>nul

echo.
echo ========================================
echo Build Complete!
echo ========================================
echo.
echo Binaries are in the 'bin' directory
echo.
echo To run a program:
echo   bin\01-winhttp-intro.exe
echo   bin\02-http-get.exe
echo   bin\03-http-post.exe
echo   bin\04-http-callback.exe
echo   bin\ex01-solution.exe
echo   bin\ex02-solution.exe
echo   bin\ex03-solution.exe
echo.

REM Build individual exercise file if specified
if "%1"=="" goto :end

echo.
echo [*] Building custom file: %1
cl /W4 /O2 %1 /link winhttp.lib
if %ERRORLEVEL% EQU 0 (
    echo [+] Build successful!
) else (
    echo [!] Build failed
)

:end
pause
