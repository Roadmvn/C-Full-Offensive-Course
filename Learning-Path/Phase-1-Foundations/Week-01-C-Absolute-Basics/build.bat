@echo off
REM ============================================================================
REM BUILD SCRIPT - Week 01 : C Absolute Basics
REM ============================================================================
REM
REM Ce script compile tous les fichiers .c de la semaine
REM Execute-le dans "Developer Command Prompt for VS"
REM
REM Usage : build.bat
REM
REM ============================================================================

echo.
echo ============================================
echo   COMPILATION - Week 01 : C Absolute Basics
echo ============================================
echo.

REM Creer le dossier bin s'il n'existe pas
if not exist "bin" mkdir bin

set ERRORS=0

REM Compiler les lessons
echo [LESSONS]
echo.

for %%f in (Lessons\*.c) do (
    echo   Compiling: %%~nxf
    cl /nologo /W4 /Fe:bin\%%~nf.exe %%f >nul 2>&1
    if errorlevel 1 (
        echo     [ERREUR] %%~nxf
        set /a ERRORS+=1
    ) else (
        echo     [OK]
    )
)

REM Compiler les exercices
echo.
echo [EXERCICES]
echo.

for %%f in (Exercises\*.c) do (
    echo   Compiling: %%~nxf
    cl /nologo /W4 /Fe:bin\%%~nf.exe %%f >nul 2>&1
    if errorlevel 1 (
        echo     [ERREUR] %%~nxf
        set /a ERRORS+=1
    ) else (
        echo     [OK]
    )
)

REM Compiler les solutions
echo.
echo [SOLUTIONS]
echo.

for %%f in (Solutions\*.c) do (
    echo   Compiling: %%~nxf
    cl /nologo /W4 /Fe:bin\sol_%%~nf.exe %%f >nul 2>&1
    if errorlevel 1 (
        echo     [ERREUR] %%~nxf
        set /a ERRORS+=1
    ) else (
        echo     [OK]
    )
)

REM Nettoyer les fichiers .obj
del /q *.obj >nul 2>&1

echo.
echo ============================================
if %ERRORS% EQU 0 (
    echo   SUCCES ! Tous les fichiers compiles.
    echo   Executables dans le dossier bin\
) else (
    echo   %ERRORS% erreur(s) de compilation.
    echo   Verifie les fichiers marques [ERREUR]
)
echo ============================================
echo.

REM Lister les executables
echo Executables disponibles :
echo.
dir /b bin\*.exe 2>nul
echo.
