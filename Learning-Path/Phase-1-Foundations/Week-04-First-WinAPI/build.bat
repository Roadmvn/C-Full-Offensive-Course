@echo off
REM ========================================
REM  Build script for Week 04 - First WinAPI
REM ========================================
REM
REM Usage:
REM   build.bat <file.c>              - Compile single file
REM   build.bat all                   - Compile all lessons
REM   build.bat exercises             - Compile all exercises
REM   build.bat solutions             - Compile all solutions
REM   build.bat clean                 - Clean all .exe and .obj files

setlocal enabledelayedexpansion

REM Compiler settings
set COMPILER=cl
set CFLAGS=/W4 /Zi /Od /D_CRT_SECURE_NO_WARNINGS
set LIBS=user32.lib kernel32.lib

REM Check if cl.exe is available
where cl.exe >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [!] cl.exe not found. Please run this from a Visual Studio Developer Command Prompt.
    echo [!] Or run: "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    exit /b 1
)

REM Single file compilation
if "%~1" NEQ "" (
    if "%~1" == "all" goto build_all
    if "%~1" == "exercises" goto build_exercises
    if "%~1" == "solutions" goto build_solutions
    if "%~1" == "clean" goto clean

    REM Compile single file
    if not exist "%~1" (
        echo [!] File not found: %~1
        exit /b 1
    )

    echo [*] Compiling %~1...
    %COMPILER% %CFLAGS% "%~1" /link %LIBS%

    if %ERRORLEVEL% EQU 0 (
        echo [+] Compilation successful!
        set OUTPUT=%~n1.exe
        echo [+] Output: !OUTPUT!
    ) else (
        echo [!] Compilation failed!
        exit /b 1
    )

    goto end
)

REM No argument provided
echo Usage:
echo   build.bat ^<file.c^>           - Compile single file
echo   build.bat all                 - Compile all lessons
echo   build.bat exercises           - Compile all exercises
echo   build.bat solutions           - Compile all solutions
echo   build.bat clean               - Clean all .exe and .obj files
echo.
echo Examples:
echo   build.bat Lessons\01-windows-types.c
echo   build.bat all
echo   build.bat clean
goto end

:build_all
echo [*] Compiling all lessons...
echo.

for %%f in (Lessons\*.c) do (
    echo [*] Compiling %%f...
    %COMPILER% %CFLAGS% "%%f" /link %LIBS%
    if !ERRORLEVEL! EQU 0 (
        echo [+] %%~nf.exe compiled successfully
    ) else (
        echo [!] Failed to compile %%f
    )
    echo.
)

echo [+] All lessons compiled!
goto end

:build_exercises
echo [*] Compiling all exercises...
echo.

for %%f in (Exercises\*.c) do (
    echo [*] Compiling %%f...
    %COMPILER% %CFLAGS% "%%f" /link %LIBS%
    if !ERRORLEVEL! EQU 0 (
        echo [+] %%~nf.exe compiled successfully
    ) else (
        echo [!] Failed to compile %%f
    )
    echo.
)

echo [+] All exercises compiled!
goto end

:build_solutions
echo [*] Compiling all solutions...
echo.

for %%f in (Solutions\*.c) do (
    echo [*] Compiling %%f...
    %COMPILER% %CFLAGS% "%%f" /link %LIBS%
    if !ERRORLEVEL! EQU 0 (
        echo [+] %%~nf.exe compiled successfully
    ) else (
        echo [!] Failed to compile %%f
    )
    echo.
)

echo [+] All solutions compiled!
goto end

:clean
echo [*] Cleaning build artifacts...

del /Q *.exe 2>nul
del /Q *.obj 2>nul
del /Q *.pdb 2>nul
del /Q *.ilk 2>nul
del /Q Lessons\*.exe 2>nul
del /Q Lessons\*.obj 2>nul
del /Q Lessons\*.pdb 2>nul
del /Q Lessons\*.ilk 2>nul
del /Q Exercises\*.exe 2>nul
del /Q Exercises\*.obj 2>nul
del /Q Exercises\*.pdb 2>nul
del /Q Exercises\*.ilk 2>nul
del /Q Solutions\*.exe 2>nul
del /Q Solutions\*.obj 2>nul
del /Q Solutions\*.pdb 2>nul
del /Q Solutions\*.ilk 2>nul

REM Clean test files created by exercises
del /Q test.txt 2>nul
del /Q test_handle.txt 2>nul
del /Q handle_demo.txt 2>nul
del /Q valid_handle.txt 2>nul
del /Q person.bin 2>nul

echo [+] Clean complete!
goto end

:end
endlocal
