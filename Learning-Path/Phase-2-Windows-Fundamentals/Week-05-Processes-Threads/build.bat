@echo off
REM Build script for Week 05 - Processes & Threads
REM Compile tous les fichiers du module

echo ========================================
echo Week 05 - Processes ^& Threads - Build
echo ========================================
echo.

REM Verifier que cl.exe est disponible
where cl.exe >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERREUR] Compilateur MSVC non trouve!
    echo.
    echo Veuillez executer ce script depuis:
    echo   - Developer Command Prompt for VS
    echo   - Ou apres avoir execute vcvarsall.bat
    echo.
    pause
    exit /b 1
)

REM Creer le repertoire de sortie
if not exist "bin\" mkdir bin

echo [*] Compilation des Lessons...
echo.

REM Compiler les lessons
for %%f in (Lessons\*.c) do (
    echo Compilation: %%~nxf
    cl.exe /nologo /W4 /O2 /Fe:bin\%%~nf.exe %%f /link psapi.lib
    if %errorlevel% neq 0 (
        echo [ERREUR] Echec compilation de %%~nxf
        pause
        exit /b 1
    )
    echo.
)

echo [*] Compilation des Exercises...
echo.

REM Compiler les exercices
for %%f in (Exercises\*.c) do (
    echo Compilation: %%~nxf
    cl.exe /nologo /W4 /O2 /Fe:bin\%%~nf.exe %%f /link psapi.lib
    if %errorlevel% neq 0 (
        echo [ERREUR] Echec compilation de %%~nxf
        pause
        exit /b 1
    )
    echo.
)

echo [*] Compilation des Solutions...
echo.

REM Compiler les solutions
for %%f in (Solutions\*.c) do (
    echo Compilation: %%~nxf
    cl.exe /nologo /W4 /O2 /Fe:bin\sol-%%~nf.exe %%f /link psapi.lib
    if %errorlevel% neq 0 (
        echo [ERREUR] Echec compilation de %%~nxf
        pause
        exit /b 1
    )
    echo.
)

REM Nettoyer les fichiers temporaires
echo [*] Nettoyage des fichiers temporaires...
del /q *.obj 2>nul
del /q bin\*.obj 2>nul

echo.
echo ========================================
echo BUILD TERMINE AVEC SUCCES!
echo ========================================
echo.
echo Executables generes dans: bin\
echo.
dir /b bin\*.exe
echo.
echo Pour executer une lesson:
echo   bin\01-process-basics.exe
echo.
echo Pour executer un exercice:
echo   bin\ex01-run-notepad.exe
echo.
echo Pour voir la solution:
echo   bin\sol-ex01-run-notepad.exe
echo.
pause
