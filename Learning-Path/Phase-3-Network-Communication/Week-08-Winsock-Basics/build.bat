@echo off
REM ============================================================================
REM Build Script for Week 08: Winsock Basics
REM
REM Usage:
REM   build.bat <source_file.c>
REM   build.bat <source_file.c> <output_name>
REM
REM Examples:
REM   build.bat 01-winsock-init.c
REM   build.bat 02-tcp-client.c my_client
REM
REM This script:
REM - Compiles C files with MSVC (cl.exe)
REM - Links against ws2_32.lib (Winsock library)
REM - Enables warnings (/W4)
REM - Outputs to current directory
REM ============================================================================

setlocal enabledelayedexpansion

REM Check if source file was provided
if "%~1"=="" (
    echo [!] Error: No source file specified
    echo.
    echo Usage: build.bat ^<source_file.c^> [output_name]
    echo.
    echo Examples:
    echo   build.bat Lessons\01-winsock-init.c
    echo   build.bat Exercises\ex01-connect-server.c
    echo   build.bat Solutions\ex01-solution.c my_solution
    echo.
    exit /b 1
)

REM Get source file
set SOURCE=%~1

REM Check if source file exists
if not exist "%SOURCE%" (
    echo [!] Error: Source file not found: %SOURCE%
    exit /b 1
)

REM Determine output name
if "%~2"=="" (
    REM Use source filename without extension
    set OUTPUT=%~n1.exe
) else (
    REM Use provided output name
    set OUTPUT=%~2.exe
)

echo ============================================================================
echo Week 08: Winsock Basics - Build Script
echo ============================================================================
echo [*] Source file: %SOURCE%
echo [*] Output file: %OUTPUT%
echo.

REM Check if cl.exe is available
where cl.exe >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [!] Error: cl.exe not found
    echo [!] Please run this from Visual Studio Developer Command Prompt
    echo.
    echo To open Developer Command Prompt:
    echo 1. Search for "Developer Command Prompt for VS" in Start Menu
    echo 2. Or run: "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
    echo.
    exit /b 1
)

REM Compile and link
echo [*] Compiling...
cl /nologo /W4 /Fe:%OUTPUT% %SOURCE% /link ws2_32.lib

REM Check compilation result
if %ERRORLEVEL% EQU 0 (
    echo.
    echo ============================================================================
    echo [+] Build successful!
    echo [+] Output: %OUTPUT%
    echo ============================================================================
    echo.
    echo To run:
    echo   %OUTPUT%
    echo.
) else (
    echo.
    echo ============================================================================
    echo [!] Build failed with error code: %ERRORLEVEL%
    echo ============================================================================
    echo.
    exit /b %ERRORLEVEL%
)

endlocal
