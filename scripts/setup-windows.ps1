#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Setup environnement maldev Windows

.DESCRIPTION
    Installe Visual Studio Build Tools, Windows SDK, et configure l'environnement
    pour le cours C Maldev Journey.

.EXAMPLE
    .\setup-windows.ps1

.NOTES
    Necessite les droits administrateur
#>

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  C MALDEV JOURNEY - SETUP WINDOWS" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# =============================================================================
# 1. VERIFICATION VISUAL STUDIO
# =============================================================================

Write-Host "[1/4] Verification de Visual Studio..." -ForegroundColor Yellow

$vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vsInstalled = $false

if (Test-Path $vsWhere) {
    $vsPath = & $vsWhere -latest -property installationPath 2>$null
    if ($vsPath) {
        Write-Host "  [OK] Visual Studio trouve: $vsPath" -ForegroundColor Green
        $vsInstalled = $true
    }
}

if (-not $vsInstalled) {
    Write-Host "  [!] Visual Studio non trouve." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Pour compiler du C sur Windows, tu as besoin de Visual Studio Build Tools."
    Write-Host ""
    Write-Host "  OPTIONS :" -ForegroundColor Cyan
    Write-Host "  1. Telecharge Build Tools : https://aka.ms/vs/17/release/vs_BuildTools.exe"
    Write-Host "  2. Installe avec les composants :"
    Write-Host "     - Desktop development with C++"
    Write-Host "     - Windows 11 SDK"
    Write-Host ""

    $install = Read-Host "  Veux-tu que je telecharge l'installateur ? (O/N)"

    if ($install -eq "O" -or $install -eq "o") {
        Write-Host "  Telechargement en cours..." -ForegroundColor Yellow
        $installerUrl = "https://aka.ms/vs/17/release/vs_BuildTools.exe"
        $installerPath = "$env:TEMP\vs_BuildTools.exe"

        try {
            Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath -UseBasicParsing
            Write-Host "  [OK] Telecharge vers: $installerPath" -ForegroundColor Green
            Write-Host ""
            Write-Host "  Lance l'installateur et selectionne :" -ForegroundColor Cyan
            Write-Host "  - Desktop development with C++"
            Write-Host ""
            Start-Process $installerPath
            Write-Host "  Relance ce script apres l'installation." -ForegroundColor Yellow
            exit 0
        }
        catch {
            Write-Host "  [ERREUR] Echec du telechargement: $_" -ForegroundColor Red
            exit 1
        }
    }
    else {
        Write-Host "  Installation manuelle requise. Script termine." -ForegroundColor Yellow
        exit 0
    }
}

# =============================================================================
# 2. VERIFICATION COMPILATEUR
# =============================================================================

Write-Host ""
Write-Host "[2/4] Verification du compilateur cl.exe..." -ForegroundColor Yellow

# Chercher vcvars64.bat
$vcvarsLocations = @(
    "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat",
    "${env:ProgramFiles}\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat",
    "${env:ProgramFiles}\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat",
    "${env:ProgramFiles}\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat",
    "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat",
    "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat",
    "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
)

$vcvarsPath = $null
foreach ($path in $vcvarsLocations) {
    if (Test-Path $path) {
        $vcvarsPath = $path
        break
    }
}

if ($vcvarsPath) {
    Write-Host "  [OK] vcvars64.bat trouve: $vcvarsPath" -ForegroundColor Green
}
else {
    Write-Host "  [ERREUR] vcvars64.bat non trouve" -ForegroundColor Red
    Write-Host "  Assure-toi d'avoir installe 'Desktop development with C++'" -ForegroundColor Yellow
    exit 1
}

# =============================================================================
# 3. TEST DE COMPILATION
# =============================================================================

Write-Host ""
Write-Host "[3/4] Test de compilation..." -ForegroundColor Yellow

$testCode = @'
#include <stdio.h>
int main() {
    printf("Compilation OK!\n");
    return 0;
}
'@

$testFile = "$env:TEMP\test_maldev_setup.c"
$testExe = "$env:TEMP\test_maldev_setup.exe"

$testCode | Out-File -FilePath $testFile -Encoding ASCII

# Compiler via cmd avec vcvars
$compileCmd = "call `"$vcvarsPath`" >nul 2>&1 && cl /nologo /W4 `"$testFile`" /Fe:`"$testExe`" >nul 2>&1"
$result = cmd /c $compileCmd 2>&1

if (Test-Path $testExe) {
    $output = & $testExe
    Write-Host "  [OK] $output" -ForegroundColor Green
    Remove-Item "$env:TEMP\test_maldev_setup.*" -Force -ErrorAction SilentlyContinue
}
else {
    Write-Host "  [ERREUR] La compilation a echoue" -ForegroundColor Red
    Write-Host "  Verifie l'installation de Visual Studio" -ForegroundColor Yellow
    exit 1
}

# =============================================================================
# 4. CONFIGURATION PROFIL POWERSHELL
# =============================================================================

Write-Host ""
Write-Host "[4/4] Configuration du profil PowerShell..." -ForegroundColor Yellow

$profileContent = @"

# ============================================================================
# C MALDEV JOURNEY - Aliases et fonctions
# ============================================================================

# Chemin vers vcvars64.bat
`$script:VCVarsPath = "$vcvarsPath"

# Fonction pour initialiser l'environnement de compilation
function Init-DevEnv {
    Write-Host "Initialisation de l'environnement de developpement..." -ForegroundColor Cyan
    cmd /c "call `"`$script:VCVarsPath`" >nul 2>&1 && set" | ForEach-Object {
        if (`$_ -match "^([^=]+)=(.*)") {
            [System.Environment]::SetEnvironmentVariable(`$matches[1], `$matches[2], "Process")
        }
    }
    Write-Host "Environnement pret. Tu peux utiliser 'cl' directement." -ForegroundColor Green
}

# Alias de compilation rapide
function mcc {
    param([Parameter(ValueFromRemainingArguments=`$true)][string[]]`$args)
    cl /W4 @args
}

function mcc-debug {
    param([Parameter(ValueFromRemainingArguments=`$true)][string[]]`$args)
    cl /W4 /Zi @args
}

function mcc-release {
    param([Parameter(ValueFromRemainingArguments=`$true)][string[]]`$args)
    cl /O2 /W4 /MT @args
}

Write-Host "C Maldev Journey: Tape 'Init-DevEnv' pour activer le compilateur." -ForegroundColor DarkGray

# ============================================================================
"@

$profilePath = $PROFILE.CurrentUserAllHosts

# Verifier si deja configure
$marker = "C MALDEV JOURNEY"
$alreadyConfigured = $false

if (Test-Path $profilePath) {
    $existingContent = Get-Content $profilePath -Raw -ErrorAction SilentlyContinue
    if ($existingContent -and $existingContent.Contains($marker)) {
        $alreadyConfigured = $true
    }
}

if (-not $alreadyConfigured) {
    # Creer le fichier profile s'il n'existe pas
    if (-not (Test-Path $profilePath)) {
        New-Item -ItemType File -Path $profilePath -Force | Out-Null
    }

    Add-Content -Path $profilePath -Value $profileContent
    Write-Host "  [OK] Profil PowerShell configure" -ForegroundColor Green
    Write-Host "  Aliases ajoutes: mcc, mcc-debug, mcc-release" -ForegroundColor Gray
}
else {
    Write-Host "  [OK] Profil deja configure" -ForegroundColor Green
}

# =============================================================================
# RESUME
# =============================================================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  SETUP TERMINE !" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Pour compiler tes programmes :" -ForegroundColor Yellow
Write-Host ""
Write-Host "  OPTION 1 (Recommande) :" -ForegroundColor Cyan
Write-Host "    Ouvre 'Developer Command Prompt for VS' depuis le menu Demarrer"
Write-Host "    Puis: cl mon_fichier.c"
Write-Host ""
Write-Host "  OPTION 2 (PowerShell) :" -ForegroundColor Cyan
Write-Host "    Ferme et rouvre PowerShell"
Write-Host "    Tape: Init-DevEnv"
Write-Host "    Puis: mcc mon_fichier.c"
Write-Host ""
Write-Host "  PROCHAINE ETAPE :" -ForegroundColor Yellow
Write-Host "    cd Learning-Path/Phase-1-Foundations/Week-01-C-Absolute-Basics"
Write-Host "    Ouvre Lessons/01-hello-world.c et commence !"
Write-Host ""
