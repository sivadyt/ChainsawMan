# setup-iis-https-only.ps1
# MAIN site: HTTPS only on 443 (serves C:\inetpub\wwwroot\wwwroot)
# Redirector site: HTTP 80 -> redirects to https://... (does NOT serve content)
# Stops Default Web Site, opens firewall 80/443

$ErrorActionPreference = "Stop"

$MainSite  = "wwwroot"
$MainPath  = "C:\inetpub\wwwroot\wwwroot"
$DnsName   = "localhost"   # cert CN
$HttpsPort = 443
$HttpPort  = 80

$RedirSite = "redirect-80"
$RedirPath = "C:\inetpub\redirect-80"

Import-Module ServerManager
Add-WindowsFeature `
  Web-Server,Web-WebServer,Web-Common-Http,Web-Static-Content,Web-Default-Doc,Web-Http-Errors, `
  Web-Http-Redirect,Web-Mgmt-Tools | Out-Null
Import-Module WebAdministration

if (-not (Test-Path "$MainPath\index.html")) { throw "Missing $MainPath\index.html" }

# avoid conflicts
Stop-Website "Default Web Site" -ErrorAction SilentlyContinue

# remove existing
if (Test-Path "IIS:\Sites\$MainSite")  { Remove-Website $MainSite }
if (Test-Path "IIS:\Sites\$RedirSite") { Remove-Website $RedirSite }

# app pools
if (-not (Test-Path "IIS:\AppPools\$MainSite"))  { New-WebAppPool $MainSite  | Out-Null }
if (-not (Test-Path "IIS:\AppPools\$RedirSite")) { New-WebAppPool $RedirSite | Out-Null }
Set-ItemProperty "IIS:\AppPools\$MainSite"  -Name managedRuntimeVersion -Value ""
Set-ItemProperty "IIS:\AppPools\$RedirSite" -Name managedRuntimeVersion -Value ""

# MAIN HTTPS site (no HTTP binding)
New-Website -Name $MainSite -PhysicalPath $MainPath -Port 12345 -ApplicationPool $MainSite | Out-Null
Get-WebBinding -Name $MainSite -Protocol http -ErrorAction SilentlyContinue | Remove-WebBinding
New-WebBinding -Name $MainSite -Protocol https -Port $HttpsPort | Out-Null

# cert + ssl bind
$cert = Get-ChildItem Cert:\LocalMachine\My | ? {$_.Subject -eq "CN=$DnsName"} | sort NotAfter -desc | select -first 1
if (-not $cert) { $cert = New-SelfSignedCertificate -DnsName $DnsName -CertStoreLocation "Cert:\LocalMachine\My" }
if (Test-Path "IIS:\SslBindings\0.0.0.0!$HttpsPort") { Remove-Item "IIS:\SslBindings\0.0.0.0!$HttpsPort" -Force }
New-Item "IIS:\SslBindings\0.0.0.0!$HttpsPort" -Thumbprint $cert.Thumbprint | Out-Null

# Redirector on 80
New-Item -ItemType Directory -Force -Path $RedirPath | Out-Null
Set-Content -Path (Join-Path $RedirPath "index.html") -Value "redirecting..." -Encoding ascii
New-Website -Name $RedirSite -PhysicalPath $RedirPath -Port $HttpPort -ApplicationPool $RedirSite | Out-Null

Set-WebConfigurationProperty -PSPath "IIS:\Sites\$RedirSite" `
  -Filter "system.webServer/httpRedirect" -Name "enabled" -Value "True"
Set-WebConfigurationProperty -PSPath "IIS:\Sites\$RedirSite" `
  -Filter "system.webServer/httpRedirect" -Name "destination" -Value "https://{HTTP_HOST}{PATH_INFO}"
Set-WebConfigurationProperty -PSPath "IIS:\Sites\$RedirSite" `
  -Filter "system.webServer/httpRedirect" -Name "appendQueryString" -Value "True"
Set-WebConfigurationProperty -PSPath "IIS:\Sites\$RedirSite" `
  -Filter "system.webServer/httpRedirect" -Name "httpResponseStatus" -Value "Permanent"

# firewall
$rule80  = "IIS-$MainSite-REDIRECT-80"
$rule443 = "IIS-$MainSite-HTTPS-443"
Get-NetFirewallRule -DisplayName $rule80  -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
Get-NetFirewallRule -DisplayName $rule443 -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName $rule80  -Direction Inbound -Action Allow -Protocol TCP -LocalPort $HttpPort  | Out-Null
New-NetFirewallRule -DisplayName $rule443 -Direction Inbound -Action Allow -Protocol TCP -LocalPort $HttpsPort | Out-Null

iisreset | Out-Null
Start-Website $MainSite
Start-Website $RedirSite

Write-Host "[+] Done."
Get-Website | ft name,state,bindings,physicalPath -Auto
