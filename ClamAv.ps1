<#
ClamAV 1.5.1 ZIP install -> Program Files
Creates Database folder
Converts *.conf.sample -> *.conf (removes Example line)
Runs freshclam
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run PowerShell as Administrator."
    }
}

function Ensure-Dir([string]$Path) {
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Remove-ExampleLineAndWrite([string]$Source, [string]$Dest, [string]$DbDir) {
    if (-not (Test-Path $Source)) { throw "Missing file: $Source" }

    $lines = Get-Content -Path $Source -ErrorAction Stop

    # Remove lines that are exactly "Example" or "# Example" (any whitespace allowed)
    $lines = $lines | Where-Object { $_ -notmatch '^\s*#?\s*Example\s*$' }

    # Ensure DatabaseDirectory points to our Database folder
    # Remove any existing DatabaseDirectory (commented or not), then add ours
    $lines = $lines | Where-Object { $_ -notmatch '^\s*#?\s*DatabaseDirectory\s+' }
    $lines += "DatabaseDirectory `"$DbDir`""

    Set-Content -Path $Dest -Value $lines -Encoding UTF8
}

# ---------------- MAIN ----------------
Assert-Admin

$zipUrl = "https://www.clamav.net/downloads/production/clamav-1.5.1.win.x64.zip"

$tempDir = Join-Path $env:TEMP "clamav_zip"
$zipPath = Join-Path $tempDir "clamav-1.5.1.win.x64.zip"

$programFiles = ${env:ProgramFiles}
$extractRoot  = $programFiles                       # unzip into Program Files
$expectedDir  = Join-Path $programFiles "clamav-1.5.1.win.x64"
$dbDir        = Join-Path $expectedDir "Database"
$confExamples = Join-Path $expectedDir "conf_examples"

Write-Host "[*] Using Program Files: $programFiles"
Ensure-Dir $tempDir

# Download ZIP
Write-Host "[*] Downloading ZIP..."
Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing

# Extract ZIP into Program Files
Write-Host "[*] Extracting ZIP into $extractRoot ..."
Expand-Archive -Path $zipPath -DestinationPath $extractRoot -Force

# Confirm extracted folder exists (ZIP contains clamav-1.5.1.win.x64)
if (-not (Test-Path $expectedDir)) {
    # Sometimes zip extracts into another nested folder, try to find it
    $found = Get-ChildItem -Path $extractRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "clamav-1.5.1.win.x64*" } |
        Select-Object -First 1

    if ($found) {
        $expectedDir  = $found.FullName
        $dbDir        = Join-Path $expectedDir "Database"
        $confExamples = Join-Path $expectedDir "conf_examples"
        Write-Host "[*] Found extracted folder at: $expectedDir"
    } else {
        throw "Could not find extracted folder 'clamav-1.5.1.win.x64' in Program Files after unzip."
    }
}

# Create Database folder inside clamav-1.5.1.win.x64
Write-Host "[*] Creating Database folder: $dbDir"
Ensure-Dir $dbDir

# Locate sample config files
$clamdSample = Join-Path $confExamples "clamd.conf.sample"
$freshSample = Join-Path $confExamples "freshclam.conf.sample"

if (-not (Test-Path $confExamples)) {
    throw "conf_examples folder not found: $confExamples"
}
if (-not (Test-Path $clamdSample)) { throw "Missing: $clamdSample" }
if (-not (Test-Path $freshSample)) { throw "Missing: $freshSample" }

# Create final config files inside Database (remove .sample and remove Example line)
$clamdConfOut = Join-Path $dbDir "clamd.conf"
$freshConfOut = Join-Path $dbDir "freshclam.conf"

Write-Host "[*] Writing cleaned configs to Database folder..."
Remove-ExampleLineAndWrite -Source $clamdSample -Dest $clamdConfOut -DbDir $dbDir
Remove-ExampleLineAndWrite -Source $freshSample -Dest $freshConfOut -DbDir $dbDir

Write-Host "[+] Created:"
Write-Host "    $clamdConfOut"
Write-Host "    $freshConfOut"

# Run freshclam using the config we just wrote
$freshclamExe = Join-Path $expectedDir "freshclam.exe"
if (-not (Test-Path $freshclamExe)) {
    throw "freshclam.exe not found at: $freshclamExe"
}

Write-Host "[*] Running freshclam..."
Start-Process -FilePath $freshclamExe -ArgumentList @("--config-file=$freshConfOut") -Wait

Write-Host "`n[✔] Done. ClamAV extracted, Database folder created, configs generated, freshclam ran."
