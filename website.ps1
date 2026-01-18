# install-iis-wwwroot-https.ps1
param(
  [string]$ZipUrl   = "https://github.com/4rji/dotfiles/blob/a4faf1daceb10c2d7f6f99b8facbd6b05150e0a1/wwwroot.zip",
  [string]$SiteName = "wwwroot",
  [string]$HostName = "",          # opcional: "mysite.local" (si no, usa localhost/*)
  [string]$WebRoot  = "C:\inetpub\wwwroot",
  [int]$HttpPort    = 80,
  [int]$HttpsPort   = 443
)

$ErrorActionPreference = "Stop"

function Ensure-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run PowerShell as Administrator"
  }
}

function AsRawUrl([string]$u) {
  if ($u -match "github\.com/.*/blob/") {
    if ($u -notmatch "\?raw=1") { return $u + "?raw=1" }
  }
  return $u
}

Ensure-Admin

$zipUrlRaw  = AsRawUrl $ZipUrl
$sitePath   = Join-Path $WebRoot $SiteName
$tmpZip     = Join-Path $env:TEMP "$SiteName.zip"
$redirName  = "redirect-80"
$redirPath  = "C:\inetpub\redirect-80"
$dnsName    = if ($HostName -and $HostName.Trim()) { $HostName } else { "localhost" }

Write-Host "[*] Installing IIS features..."
Import-Module ServerManager
Add-WindowsFeature `
  Web-Server,Web-WebServer,Web-Common-Http,Web-Static-Content,Web-Default-Doc,Web-Http-Errors, `
  Web-Http-Redirect,Web-Mgmt-Tools | Out-Null

Import-Module WebAdministration

Write-Host "[*] Stopping Default Web Site to avoid conflicts..."
if (Test-Path "IIS:\Sites\Default Web Site") {
  Stop-Website "Default Web Site" -ErrorAction SilentlyContinue
}

# --- Clean up old sites if exist ---
if (Test-Path "IIS:\Sites\$SiteName")   { Remove-Website $SiteName }
if (Test-Path "IIS:\Sites\$redirName")  { Remove-Website $redirName }

# --- AppPools ---
if (-not (Test-Path "IIS:\AppPools\$SiteName"))  { New-WebAppPool $SiteName  | Out-Null }
if (-not (Test-Path "IIS:\AppPools\$redirName")) { New-WebAppPool $redirName | Out-Null }
Set-ItemProperty "IIS:\AppPools\$SiteName"  -Name managedRuntimeVersion -Value ""
Set-ItemProperty "IIS:\AppPools\$redirName" -Name managedRuntimeVersion -Value ""

# --- Download & Extract ---
Write-Host "[*] Downloading ZIP..."
New-Item -ItemType Directory -Force -Path $sitePath | Out-Null
Invoke-WebRequest -Uri $zipUrlRaw -OutFile $tmpZip

Write-Host "[*] Extracting..."
Expand-Archive -Path $tmpZip -DestinationPath $sitePath -Force
Remove-Item -LiteralPath $tmpZip -Force

# Flatten single-folder ZIP
$items = Get-ChildItem -LiteralPath $sitePath -Force
if ($items.Count -eq 1 -and $items[0].PSIsContainer) {
  $inner = $items[0].FullName
  Get-ChildItem -LiteralPath $inner -Force | Move-Item -Destination $sitePath -Force
  Remove-Item -LiteralPath $inner -Recurse -Force
}

# --- Create MAIN site (HTTPS only) ---
Write-Host "[*] Creating main site HTTPS:$HttpsPort ..."
New-Website -Name $SiteName -PhysicalPath $sitePath -Port $HttpPort -ApplicationPool $SiteName | Out-Null
# Remove the auto http binding created by New-Website
Get-WebBinding -Name $SiteName -Protocol http -ErrorAction SilentlyContinue | Remove-WebBinding

# Add HTTPS binding
if ($HostName -and $HostName.Trim()) {
  New-WebBinding -Name $SiteName -Protocol https -Port $HttpsPort -HostHeader $HostName -SslFlags 1 | Out-Null
} else {
  New-WebBinding -Name $SiteName -Protocol https -Port $HttpsPort | Out-Null
}

# --- Cert + SslBinding ---
Write-Host "[*] Creating/using self-signed cert for CN=$dnsName ..."
$cert = Get-ChildItem Cert:\LocalMachine\My | ? { $_.Subject -eq "CN=$dnsName" } | sort NotAfter -desc | select -first 1
if (-not $cert) {
  $cert = New-SelfSignedCertificate -DnsName $dnsName -CertStoreLocation "Cert:\LocalMachine\My"
}

# Bind cert to IIS ssl bindings
if ($HostName -and $HostName.Trim()) {
  $sslPath = "IIS:\SslBindings\!$HttpsPort!$HostName"
  if (Test-Path $sslPath) { Remove-Item $sslPath -Force }
  New-Item $sslPath -Thumbprint $cert.Thumbprint -SSLFlags 1 | Out-Null
} else {
  $sslPath = "IIS:\SslBindings\0.0.0.0!$HttpsPort"
  if (Test-Path $sslPath) { Remove-Item $sslPath -Force }
  New-Item $sslPath -Thumbprint $cert.Thumbprint | Out-Null
}

# --- Redirector site on HTTP 80 ---
Write-Host "[*] Creating redirector on HTTP:$HttpPort -> HTTPS:$HttpsPort ..."
New-Item -ItemType Directory -Force -Path $redirPath | Out-Null
Set-Content -Path (Join-Path $redirPath "index.html") -Value "redirecting..." -Encoding ascii

New-Website -Name $redirName -PhysicalPath $redirPath -Port $HttpPort -ApplicationPool $redirName | Out-Null

# Configure redirect placeholders (IIS style)
Set-WebConfigurationProperty -PSPath "IIS:\Sites\$redirName" `
  -Filter "system.webServer/httpRedirect" -Name "enabled" -Value "True"

$dest = if ($HttpsPort -eq 443) { "https://{HTTP_HOST}{PATH_INFO}" } else { "https://{HTTP_HOST}:$HttpsPort{PATH_INFO}" }

Set-WebConfigurationProperty -PSPath "IIS:\Sites\$redirName" `
  -Filter "system.webServer/httpRedirect" -Name "destination" -Value $dest

Set-WebConfigurationProperty -PSPath "IIS:\Sites\$redirName" `
  -Filter "system.webServer/httpRedirect" -Name "appendQueryString" -Value "True"

Set-WebConfigurationProperty -PSPath "IIS:\Sites\$redirName" `
  -Filter "system.webServer/httpRedirect" -Name "httpResponseStatus" -Value "Permanent"

# --- Firewall ---
Write-Host "[*] Opening firewall ports $HttpPort/$HttpsPort ..."
$rule80  = "IIS-$SiteName-HTTP-$HttpPort"
$rule443 = "IIS-$SiteName-HTTPS-$HttpsPort"

Get-NetFirewallRule -DisplayName $rule80  -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
Get-NetFirewallRule -DisplayName $rule443 -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

New-NetFirewallRule -DisplayName $rule80  -Direction Inbound -Action Allow -Protocol TCP -LocalPort $HttpPort  | Out-Null
New-NetFirewallRule -DisplayName $rule443 -Direction Inbound -Action Allow -Protocol TCP -LocalPort $HttpsPort | Out-Null

# Start sites
Start-Website $SiteName
Start-Website $redirName

iisreset | Out-Null

Write-Host ""
Write-Host "[+] Done."
Write-Host "    MAIN (HTTPS): https://$dnsName`:$HttpsPort"
Write-Host "    Redirect (HTTP): http://$dnsName`:$HttpPort  ->  HTTPS"
Write-Host ""
Write-Host "[*] Check listeners:"
Write-Host "    netstat -ano | findstr `":$HttpsPort`""
