@echo off
REM =============================================================================
REM SCRIPT DE COMPILATION - WEEK 3 : STRUCTS & FILES
REM =============================================================================
REM
REM Ce script compile tous les fichiers de la Week 3.
REM
REM USAGE :
REM   build.bat              - Compile tout
REM   build.bat lessons      - Compile seulement les lessons
REM   build.bat exercises    - Compile seulement les exercices
REM   build.bat solutions    - Compile seulement les solutions
REM   build.bat clean        - Supprime tous les executables
REM
REM =============================================================================

setlocal enabledelayedexpansion

echo ========================================
echo  WEEK 3 - STRUCTS ^& FILES - BUILD
echo ========================================
echo.

REM Vérifier que cl.exe est disponible
where cl.exe >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] cl.exe non trouve !
    echo.
    echo Ouvre "Developer Command Prompt for VS" ou execute :
    echo   "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
    echo.
    pause
    exit /b 1
)

REM Créer le dossier de sortie si nécessaire
if not exist "bin" mkdir bin

REM Parser les arguments
set BUILD_TARGET=%1
if "%BUILD_TARGET%"=="" set BUILD_TARGET=all

if /i "%BUILD_TARGET%"=="clean" goto :clean
if /i "%BUILD_TARGET%"=="lessons" goto :build_lessons
if /i "%BUILD_TARGET%"=="exercises" goto :build_exercises
if /i "%BUILD_TARGET%"=="solutions" goto :build_solutions
if /i "%BUILD_TARGET%"=="all" goto :build_all

echo [ERROR] Argument invalide : %BUILD_TARGET%
echo.
echo Usage : build.bat [lessons^|exercises^|solutions^|clean^|all]
echo.
pause
exit /b 1

REM =============================================================================
REM BUILD ALL
REM =============================================================================
:build_all
echo [INFO] Compilation de TOUS les fichiers...
echo.
call :build_lessons
call :build_exercises
call :build_solutions
goto :end

REM =============================================================================
REM BUILD LESSONS
REM =============================================================================
:build_lessons
echo ========================================
echo  COMPILATION DES LESSONS
echo ========================================
echo.

set LESSONS_DIR=Lessons
set OUTPUT_DIR=bin

for %%F in (%LESSONS_DIR%\*.c) do (
    echo [LESSON] Compilation de %%~nF.c...
    cl /nologo /W3 /O2 /Fe:%OUTPUT_DIR%\%%~nF.exe %%F >nul 2>&1
    if !ERRORLEVEL! equ 0 (
        echo          [OK] %%~nF.exe cree
    ) else (
        echo          [ERREUR] Echec de compilation
    )
    REM Supprimer les fichiers intermediaires
    if exist %%~nF.obj del %%~nF.obj >nul 2>&1
    echo.
)

goto :eof

REM =============================================================================
REM BUILD EXERCISES
REM =============================================================================
:build_exercises
echo ========================================
echo  COMPILATION DES EXERCICES
echo ========================================
echo.

set EXERCISES_DIR=Exercises
set OUTPUT_DIR=bin

for %%F in (%EXERCISES_DIR%\*.c) do (
    echo [EXERCISE] Compilation de %%~nF.c...
    cl /nologo /W3 /O2 /Fe:%OUTPUT_DIR%\%%~nF.exe %%F >nul 2>&1
    if !ERRORLEVEL! equ 0 (
        echo            [OK] %%~nF.exe cree
    ) else (
        echo            [ERREUR] Echec de compilation
    )
    REM Supprimer les fichiers intermediaires
    if exist %%~nF.obj del %%~nF.obj >nul 2>&1
    echo.
)

goto :eof

REM =============================================================================
REM BUILD SOLUTIONS
REM =============================================================================
:build_solutions
echo ========================================
echo  COMPILATION DES SOLUTIONS
echo ========================================
echo.

set SOLUTIONS_DIR=Solutions
set OUTPUT_DIR=bin

for %%F in (%SOLUTIONS_DIR%\*.c) do (
    echo [SOLUTION] Compilation de %%~nF.c...
    cl /nologo /W3 /O2 /Fe:%OUTPUT_DIR%\%%~nF.exe %%F >nul 2>&1
    if !ERRORLEVEL! equ 0 (
        echo            [OK] %%~nF.exe cree
    ) else (
        echo            [ERREUR] Echec de compilation
    )
    REM Supprimer les fichiers intermediaires
    if exist %%~nF.obj del %%~nF.obj >nul 2>&1
    echo.
)

goto :eof

REM =============================================================================
REM CLEAN
REM =============================================================================
:clean
echo ========================================
echo  NETTOYAGE
echo ========================================
echo.

echo [CLEAN] Suppression des executables...
if exist bin\*.exe (
    del /Q bin\*.exe
    echo        [OK] Executables supprimes
) else (
    echo        [INFO] Aucun executable a supprimer
)

echo.
echo [CLEAN] Suppression des fichiers intermediaires...
if exist *.obj (
    del /Q *.obj
    echo        [OK] Fichiers .obj supprimes
)
if exist *.pdb (
    del /Q *.pdb
    echo        [OK] Fichiers .pdb supprimes
)
if exist *.ilk (
    del /Q *.ilk
    echo        [OK] Fichiers .ilk supprimes
)

echo.
echo [CLEAN] Nettoyage termine !
echo.
goto :end

REM =============================================================================
REM END
REM =============================================================================
:end
echo ========================================
echo  BUILD TERMINE
echo ========================================
echo.
echo Les executables sont dans le dossier : bin\
echo.
echo Pour executer un exemple :
echo   bin\01-structures.exe
echo   bin\ex01-person-struct.exe
echo   etc.
echo.
pause
exit /b 0
