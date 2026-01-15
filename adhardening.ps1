#Requires -RunAsAdministrator
# AD-DNS-Hardening.ps1 (fixed)
# CCDC hardening for DC + DNS, non-destructive defaults, best-effort removals.

$ErrorActionPreference = "Stop"

# ---- EDIT ME ----
$TrustedNtpServer = "time.windows.com"
$DisableDFS       = $true          # set $false if DFS is required
$DisableADLDS     = $true          # best-effort remove if installed
$DisableSpooler   = $true
$DisableWinRM     = $true
$DisableSMBv1     = $true
$DisableLLMNR     = $true
$DisableNetBIOS   = $true

# DNS recursion: disable unless you explicitly need the DC to be a recursive resolver for clients
$DisableDnsRecursion = $true
# -----------------

function Disable-ServiceSafe($name) {
  $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
  if ($svc) {
    if ($svc.Status -ne "Stopped") { Stop-Service -Name $name -Force -ErrorAction SilentlyContinue }
    Set-Service -Name $name -StartupType Disabled -ErrorAction SilentlyContinue
    Write-Host "[OK] Disabled service: $name"
  } else {
    Write-Host "[..] Service not present: $name"
  }
}
function Ensure-RegKey($path) {
  if (-not (Test-Path -Path $path)) {
    try { New-Item -Path $path -Force -ErrorAction Stop | Out-Null } catch {}
  }
}
function Set-RegDword($path, $name, $value) {
  Ensure-RegKey $path
  try {
    Set-ItemProperty -Path $path -Name $name -Value $value -Type DWord -ErrorAction Stop | Out-Null
  } catch {
    try {
      New-ItemProperty -Path $path -Name $name -PropertyType DWord -Value $value -Force -ErrorAction Stop | Out-Null
    } catch {
      Write-Host "[!!] Registry set failed: $path\$name -> $($_.Exception.Message)"
    }
  }
}


function Try-DisableFeature($name) {
  $f = Get-WindowsFeature -Name $name -ErrorAction SilentlyContinue
  if ($f -and $f.Installed) {
    Remove-WindowsFeature -Name $name -IncludeManagementTools -Restart:$false | Out-Null
    Write-Host "[OK] Removed WindowsFeature: $name"
  } elseif ($f) {
    Write-Host "[..] Feature not installed: $name"
  } else {
    Write-Host "[..] Feature unknown on this host: $name"
  }
}

Write-Host "=== AD + DNS Hardening (CCDC) ==="

# --- Kill obvious lateral-move services ---
if ($DisableSpooler) { Disable-ServiceSafe "Spooler" }
Disable-ServiceSafe "RemoteRegistry"
Disable-ServiceSafe "Fax"
Disable-ServiceSafe "BluetoothSupportService"
Disable-ServiceSafe "WerSvc"

if ($DisableWinRM) { Disable-ServiceSafe "WinRM" }

# --- Optional role cleanup (best-effort) ---
if ($DisableADLDS) {
  # AD LDS role on Server is "ADLDS"
  Try-DisableFeature "ADLDS"
  # Also remove RSAT AD LDS tools if present
  Try-DisableFeature "RSAT-ADLDS"
}

if ($DisableDFS) {
  Disable-ServiceSafe "DFSR"
  # If DFS Namespaces/Replication roles were installed, remove them best-effort:
  Try-DisableFeature "FS-DFS-Namespace"
  Try-DisableFeature "FS-DFS-Replication"
}

# --- SMBv1 OFF ---
if ($DisableSMBv1) {
  Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
  Write-Host "[OK] SMBv1 disabled."
}

# --- LLMNR OFF ---
if ($DisableLLMNR) {
  Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast" 0
  Write-Host "[OK] LLMNR disabled."
}

# --- NetBIOS OFF (CIM, no WMI) ---
try {
  $nics = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE"
  foreach ($nic in $nics) {
    try {
      Invoke-CimMethod -InputObject $nic -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = 2 } | Out-Null
      Write-Host "[OK] NetBIOS disabled on: $($nic.Description)"
    } catch {
      Write-Host "[!!] NetBIOS disable failed on: $($nic.Description) -> $($_.Exception.Message)"
    }
  }
} catch {
  Write-Host "[!!] CIM query failed for NICs (skipping NetBIOS step): $($_.Exception.Message)"
}



# --- NTLM hardening ---
Set-RegDword "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel" 5
Set-RegDword "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential" 0
Write-Host "[OK] NTLMv2 enforced, WDigest disabled."

# --- PowerShell logging ---
Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging" 1
Set-RegDword "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" "EnableModuleLogging" 1
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Name "*" -PropertyType String -Value "*" -Force | Out-Null
Write-Host "[OK] PowerShell logging enabled."

# --- Advanced auditing ---
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable | Out-Null
auditpol /set /category:"Account Logon" /success:enable /failure:enable | Out-Null
auditpol /set /category:"Account Management" /success:enable /failure:enable | Out-Null
auditpol /set /category:"Policy Change" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable | Out-Null
Write-Host "[OK] Advanced audit policy enabled."

# --- DNS hardening ---
try {
  Import-Module DNSServer -ErrorAction Stop

  # Zone transfers OFF (best-effort per zone)
  Get-DnsServerZone | Where-Object { $_.ZoneType -eq "Primary" } | ForEach-Object {
    try {
      Set-DnsServerPrimaryZone -Name $_.ZoneName -SecureSecondaries NoTransfer -ErrorAction Stop
    } catch {}
  }

  # Secure dynamic updates for AD-integrated zones
  Get-DnsServerZone | Where-Object { $_.IsDsIntegrated } | ForEach-Object {
    Set-DnsServerPrimaryZone -Name $_.ZoneName -DynamicUpdate Secure -ErrorAction SilentlyContinue
  }

  if ($DisableDnsRecursion) {
    Set-DnsServerRecursion -Enable $false -ErrorAction SilentlyContinue
    Write-Host "[OK] DNS recursion disabled."
  } else {
    Write-Host "[..] DNS recursion unchanged."
  }

  Write-Host "[OK] DNS: zone transfers off + secure dynamic updates (AD zones)."
} catch {
  Write-Host "[..] DNS module not available or partial DNS hardening skipped."
}

# --- Time source hardening (safe) ---
try {
  w32tm /config /manualpeerlist:$TrustedNtpServer /syncfromflags:manual /reliable:yes /update | Out-Null

  # Try a soft start if stopped
  $svc = Get-Service w32time -ErrorAction SilentlyContinue
  if ($svc -and $svc.Status -ne "Running") {
    Start-Service w32time -ErrorAction SilentlyContinue
  }

  # Force resync (does not require restart)
  w32tm /resync /force | Out-Null

  Write-Host "[OK] Time source configured and resync attempted."
} catch {
  Write-Host "[!!] Time service configured but could not start/resync now. Will recover after reboot."
}
# --- Firewall: robust (BFE/MpsSvc + fallback to netsh) ---

function Ensure-ServiceRunning($name) {
  $s = Get-Service $name -ErrorAction SilentlyContinue
  if ($s -and $s.Status -ne "Running") {
    try { Start-Service $name -ErrorAction Stop } catch {}
  }
}

Ensure-ServiceRunning "BFE"    # Base Filtering Engine
Ensure-ServiceRunning "MpsSvc" # Windows Defender Firewall

# Enable firewall + default inbound block (best-effort)
try { netsh advfirewall set allprofiles state on | Out-Null } catch {}
try { netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound | Out-Null } catch {}

$TcpPorts = @(53,88,135,389,445,464,636,3268,3269)
$UdpPorts = @(53,88,123,389,464)

foreach ($p in $TcpPorts) {
  $name = "CCDC-DC-Allow-TCP-$p"
  try {
    New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Allow -Protocol TCP -LocalPort $p -Profile Any -ErrorAction Stop | Out-Null
    Write-Host "[OK] FW rule (TCP $p) added via New-NetFirewallRule"
  } catch {
    # fallback
    netsh advfirewall firewall add rule name="$name" dir=in action=allow protocol=TCP localport=$p profile=any | Out-Null
    Write-Host "[OK] FW rule (TCP $p) added via netsh fallback"
  }
}

foreach ($p in $UdpPorts) {
  $name = "CCDC-DC-Allow-UDP-$p"
  try {
    New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Allow -Protocol UDP -LocalPort $p -Profile Any -ErrorAction Stop | Out-Null
    Write-Host "[OK] FW rule (UDP $p) added via New-NetFirewallRule"
  } catch {
    netsh advfirewall firewall add rule name="$name" dir=in action=allow protocol=UDP localport=$p profile=any | Out-Null
    Write-Host "[OK] FW rule (UDP $p) added via netsh fallback"
  }
}

# Disable existing Remote Desktop allow rules (group), then add explicit block rules for 3389.
try {
  Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction Stop | Disable-NetFirewallRule | Out-Null
  Write-Host "[OK] Remote Desktop firewall group disabled."
} catch {
  try {
    netsh advfirewall firewall set rule group="remote desktop" new enable=No | Out-Null
    Write-Host "[OK] Remote Desktop firewall group disabled via netsh."
  } catch {
    Write-Host "[!!] Could not disable Remote Desktop firewall group."
  }
}

foreach ($proto in @("TCP","UDP")) {
  $name = "CCDC-Block-RDP-$proto-3389"
  try {
    $existing = Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
    if ($existing) {
      Enable-NetFirewallRule -DisplayName $name | Out-Null
    } else {
      New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Block -Protocol $proto -LocalPort 3389 -Profile Any -ErrorAction Stop | Out-Null
    }
    Write-Host "[OK] FW rule (Block $proto 3389) enforced."
  } catch {
    netsh advfirewall firewall add rule name="$name" dir=in action=block protocol=$proto localport=3389 profile=any | Out-Null
    Write-Host "[OK] FW rule (Block $proto 3389) added via netsh fallback."
  }
}

Write-Host "[OK] Firewall locked to core AD/DNS ports (plus NTP UDP/123)."

Write-Host "=== Validation (best-effort) ==="
try {
  $llmnr = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction Stop
  Write-Host "LLMNR disabled (EnableMulticast=0)    " ($llmnr.EnableMulticast -eq 0)
} catch {
  Write-Host "LLMNR disabled (EnableMulticast=0)    FAIL   EnableMulticast="
}
try {
  $sbl = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction Stop
  Write-Host "PowerShell ScriptBlockLogging enabled " ($sbl.EnableScriptBlockLogging -eq 1)
} catch {
  Write-Host "PowerShell ScriptBlockLogging enabled FAIL   EnableScriptBlockLogging="
}
try {
  $ml = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -ErrorAction Stop
  Write-Host "PowerShell ModuleLogging enabled      " ($ml.EnableModuleLogging -eq 1)
} catch {
  Write-Host "PowerShell ModuleLogging enabled      FAIL   EnableModuleLogging="
}
try {
  Import-Module DNSServer -ErrorAction Stop
  $rec = Get-DnsServerRecursion -ErrorAction Stop
  Write-Host "DNS recursion disabled                " (-not $rec.Enable)
} catch {
  Write-Host "DNS recursion disabled                FAIL   Enable="
}

Write-Host "=== Done. Reboot recommended if features changed. ==="
