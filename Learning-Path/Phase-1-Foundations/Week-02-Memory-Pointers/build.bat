@echo off
echo.
echo === COMPILATION Week 02 : Memory and Pointers ===
echo.

if not exist "bin" mkdir bin

for %%f in (Lessons\*.c) do (
    echo Compiling: %%~nxf
    cl /nologo /W4 /Fe:bin\%%~nf.exe %%f >nul 2>&1
    if errorlevel 1 (echo   [ERREUR]) else (echo   [OK])
)

for %%f in (Exercises\*.c) do (
    echo Compiling: %%~nxf
    cl /nologo /W4 /Fe:bin\%%~nf.exe %%f >nul 2>&1
    if errorlevel 1 (echo   [ERREUR]) else (echo   [OK])
)

for %%f in (Solutions\*.c) do (
    echo Compiling: %%~nxf
    cl /nologo /W4 /Fe:bin\sol_%%~nf.exe %%f >nul 2>&1
    if errorlevel 1 (echo   [ERREUR]) else (echo   [OK])
)

del /q *.obj >nul 2>&1
echo.
echo Done. Executables in bin\
