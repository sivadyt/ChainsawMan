# clamav-win-setup.ps1
# Installs ClamAV (MSI), ensures database dir exists, runs freshclam update,
# adds ClamAV to PATH (Machine), and prints final paths.

$ErrorActionPreference = "Stop"

$WIN_MSI_URL = "https://www.clamav.net/downloads/production/clamav-1.5.1.win.x64.msi"
$DEFAULT_INSTALL_DIR = "C:\Program Files\ClamAV"
$DEFAULT_DB_DIR      = "$DEFAULT_INSTALL_DIR\database"

function Is-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Download-File([string]$Url, [string]$OutFile) {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  New-Item -ItemType Directory -Force -Path (Split-Path $OutFile) | Out-Null
  Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing
}

function Find-Exe([string]$name, [string[]]$roots) {
  foreach ($r in $roots) {
    if (Test-Path $r) {
      $hit = Get-ChildItem $r -Recurse -Filter $name -ErrorAction SilentlyContinue | Select-Object -First 1
      if ($hit) { return $hit.FullName }
    }
  }
  return $null
}

function Add-ToMachinePath([string]$dir) {
  $machinePath = [Environment]::GetEnvironmentVariable("Path","Machine")
  if ($machinePath -notlike "*$dir*") {
    [Environment]::SetEnvironmentVariable("Path", ($machinePath.TrimEnd(';') + ";$dir"), "Machine")
  }
  # also for current session
  if ($env:Path -notlike "*$dir*") { $env:Path += ";$dir" }
}

if (-not (Is-Admin)) { throw "Run PowerShell as Administrator." }

# Temp workspace
$tmp = Join-Path $env:TEMP ("clamav_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

# Detect if already installed (by presence of clamscan.exe somewhere common)
$roots = @($DEFAULT_INSTALL_DIR, "C:\Program Files", "C:\Program Files (x86)")
$clamscan = Find-Exe "clamscan.exe" $roots

if (-not $clamscan) {
  $msi = Join-Path $tmp "clamav.msi"
  Write-Host "Downloading MSI..."
  Download-File $WIN_MSI_URL $msi

  Write-Host "Installing MSI..."
  $log = Join-Path $tmp "clamav-install.log"
  $args = "/i `"$msi`" /qn /norestart /l*v `"$log`""
  $p = Start-Process -FilePath "msiexec.exe" -ArgumentList $args -Wait -PassThru
  if ($p.ExitCode -ne 0) { throw "MSI install failed. ExitCode=$($p.ExitCode). Log: $log" }

  # Re-scan after install
  $clamscan = Find-Exe "clamscan.exe" $roots
  if (-not $clamscan) { throw "Installed, but clamscan.exe not found under Program Files." }
} else {
  Write-Host "ClamAV already present: $clamscan"
}

# Derive install dir from clamscan path
$installDir = Split-Path $clamscan -Parent

# Some builds put binaries in \bin
$freshclam = Join-Path $installDir "freshclam.exe"
if (-not (Test-Path $freshclam)) {
  $freshclam = Find-Exe "freshclam.exe" @($installDir, (Join-Path $installDir "bin"), $DEFAULT_INSTALL_DIR)
}
if (-not $freshclam) { throw "freshclam.exe not found. Can't update database." }

# Ensure database dir exists
$dbDir = $DEFAULT_DB_DIR
New-Item -ItemType Directory -Force -Path $dbDir | Out-Null

# Write minimal freshclam.conf (so it always knows where DB is)
$freshclamConf = Join-Path $DEFAULT_INSTALL_DIR "freshclam.conf"
@"
DatabaseDirectory $dbDir
DNSDatabaseInfo current.cvd.clamav.net
DatabaseMirror database.clamav.net
LogTime yes
"@ | Set-Content -Encoding ASCII $freshclamConf

Write-Host "Updating database with freshclam..."
& $freshclam --config-file="$freshclamConf"

# Add install dir (and bin if exists) to PATH
Add-ToMachinePath $installDir
$binDir = Join-Path $installDir "bin"
if (Test-Path $binDir) { Add-ToMachinePath $binDir }

# Show final info
Write-Host ""
Write-Host "=== ClamAV Paths ==="
Write-Host "Install dir : $installDir"
Write-Host "clamscan    : $clamscan"
Write-Host "freshclam   : $freshclam"
Write-Host "DB dir      : $dbDir"
Write-Host "Config      : $freshclamConf"
Write-Host ""

Write-Host "=== DB Files (top) ==="
Get-ChildItem $dbDir -ErrorAction SilentlyContinue | Sort-Object Length -Descending | Select-Object -First 10 Name,Length

Write-Host ""
Write-Host "=== Version Check ==="
& $clamscan --version