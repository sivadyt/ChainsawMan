<#
CCDC Blue Team Lockdown (Domain-Joined Windows Server 2019 / Windows)

- HARD LOCKDOWN: inbound blocked by default, outbound blocked by default.
- Prompts for inbound ports to allow (TCP/UDP), DC IP, new local admin username + password.
- Disables: Print Spooler, RemoteRegistry, SMBv1, RDP
- Refuses to run on a Domain Controller.

RUN FROM CONSOLE. If you lock yourself out, you’ll need VM/console access to recover.
#>

#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# -------------------------
# GUARD: refuse to run on a Domain Controller
# -------------------------
try {
    $cs = Get-CimInstance Win32_ComputerSystem
    if ($cs.DomainRole -ge 4) {
        throw "This machine appears to be a Domain Controller (DomainRole=$($cs.DomainRole)). Refusing to run."
    }
} catch {
    Write-Error $_
    exit 1
}

# -------------------------
# PROMPTS
# -------------------------
function Read-NonEmpty([string]$Prompt) {
    while ($true) {
        $v = Read-Host $Prompt
        if (-not [string]::IsNullOrWhiteSpace($v)) { return $v.Trim() }
        Write-Host "Value cannot be empty." -ForegroundColor Yellow
    }
}

function Read-Ports([string]$Prompt) {
    # Accept: "80,443,9997" or "80 443 9997" or "80"
    while ($true) {
        $raw = Read-Host $Prompt
        if ([string]::IsNullOrWhiteSpace($raw)) {
            Write-Host "Enter at least one port." -ForegroundColor Yellow
            continue
        }

        $parts = ($raw -split '[,\s]+' | Where-Object { $_ -and $_.Trim() -ne "" })
        $ports = @()

        $ok = $true
        foreach ($p in $parts) {
            if ($p -notmatch '^\d+$') { $ok = $false; break }
            $n = [int]$p
            if ($n -lt 1 -or $n -gt 65535) { $ok = $false; break }
            $ports += $n
        }

        if (-not $ok) {
            Write-Host "Invalid ports. Example: 80,443,9997" -ForegroundColor Yellow
            continue
        }

        $ports = $ports | Sort-Object -Unique
        return ($ports -join ",")
    }
}

$DomainControllerIP = Read-NonEmpty "Enter Domain Controller IP (DC/DNS) (example: 172.20.240.102)"
$NewAdminUser       = Read-NonEmpty "Enter NEW local admin username to create/ensure (example: CCDCBlueTeam)"
$SecurePassword     = Read-Host "Enter password for $NewAdminUser" -AsSecureString

$InboundTcpPorts = Read-Ports "Enter INBOUND TCP ports to ALLOW (comma/space-separated) (example: 80,443)"
$InboundUdpPorts = Read-Ports "Enter INBOUND UDP ports to ALLOW (comma/space-separated) (example: 53,123)"

# Policies
$MinPwLen               = 14
$MaxPwAgeDays           = 90
$LockoutThreshold       = 5
$LockoutDurationMinutes = 15
$LockoutWindowMinutes   = 15

# Who is running the script (avoid disabling this account mid-run)
$CurrentUserName = ($env:USERNAME)

# -------------------------
# Helpers
# -------------------------
function Ensure-LocalAdminUser {
    param(
        [Parameter(Mandatory)] [string]$Username,
        [Parameter(Mandatory)] [securestring]$Password
    )

    $existing = Get-LocalUser -Name $Username -ErrorAction SilentlyContinue

    if (-not $existing) {
        New-LocalUser -Name $Username -Password $Password -FullName $Username `
            -Description "CCDC Blue Team Local Admin" -PasswordNeverExpires:$false | Out-Null
    } else {
        $existing | Set-LocalUser -Password $Password
        if ($existing.Enabled -eq $false) { Enable-LocalUser -Name $Username }
    }

    # Add to local Administrators
    $isMember = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match "\\$Username$" -or $_.Name -ieq $Username }

    if (-not $isMember) {
        Add-LocalGroupMember -Group "Administrators" -Member $Username
    }
}

function Disable-AllOtherLocalAccounts {
    param(
        [Parameter(Mandatory)] [string]$KeepUser,
        [Parameter(Mandatory)] [string]$AlsoKeepUser
    )

    foreach ($u in Get-LocalUser) {
        if ($u.Name -ieq $KeepUser) { continue }
        if ($u.Name -ieq $AlsoKeepUser) { continue } # don't disable the account currently running the script
        if ($u.Enabled) {
            try { Disable-LocalUser -Name $u.Name } catch {}
        }
    }
}

function Set-LocalAccountPolicies {
    param(
        [int]$MinLength,
        [int]$MaxAgeDays,
        [int]$LockThreshold,
        [int]$LockDurationMinutes,
        [int]$LockWindowMinutes
    )

    & net accounts /minpwlen:$MinLength | Out-Null
    & net accounts /maxpwage:$MaxAgeDays | Out-Null
    & net accounts /lockoutthreshold:$LockThreshold | Out-Null
    & net accounts /lockoutduration:$LockDurationMinutes | Out-Null
    & net accounts /lockoutwindow:$LockWindowMinutes | Out-Null

    # Enforce complexity via local security policy (secedit)
    $tmp = Join-Path $env:TEMP "ccdc_secpol.inf"
    $db  = Join-Path $env:TEMP "ccdc_secpol.sdb"

    & secedit /export /cfg $tmp | Out-Null
    $content = Get-Content $tmp -Raw

    if ($content -notmatch "\[System Access\]") {
        $content += "`r`n[System Access]`r`n"
    }

    if ($content -match "PasswordComplexity\s*=") {
        $content = [regex]::Replace($content, "PasswordComplexity\s*=\s*\d+", "PasswordComplexity = 1")
    } else {
        $content = $content -replace "(\[System Access\]\s*)", "`$1`r`nPasswordComplexity = 1`r`n"
    }

    Set-Content -Path $tmp -Value $content -Encoding Unicode
    & secedit /configure /db $db /cfg $tmp /areas SECURITYPOLICY | Out-Null
    & gpupdate /force | Out-Null
}

function Set-CCDCFirewallLockdown {
    param(
        [Parameter(Mandatory)] [string]$DCIP,
        [Parameter(Mandatory)] [string]$AllowInboundTcpPorts,
        [Parameter(Mandatory)] [string]$AllowInboundUdpPorts
    )

    # Disable all existing inbound rules
    Get-NetFirewallRule -Direction Inbound -ErrorAction SilentlyContinue |
        Disable-NetFirewallRule -ErrorAction SilentlyContinue

    # Default: block inbound + outbound on all profiles
    Set-NetFirewallProfile -Profile Domain,Public,Private `
        -Enabled True `
        -DefaultInboundAction Block `
        -DefaultOutboundAction Block

    # -----------------------------
    # INBOUND allow-list (ONLY what user entered)
    # -----------------------------
    New-NetFirewallRule -DisplayName "CCDC ALLOW IN TCP ($AllowInboundTcpPorts)" `
        -Direction Inbound -Action Allow -Protocol TCP -LocalPort $AllowInboundTcpPorts -Profile Any | Out-Null

    New-NetFirewallRule -DisplayName "CCDC ALLOW IN UDP ($AllowInboundUdpPorts)" `
        -Direction Inbound -Action Allow -Protocol UDP -LocalPort $AllowInboundUdpPorts -Profile Any | Out-Null

    # -----------------------------
    # OUTBOUND baseline allow-list
    # -----------------------------
    New-NetFirewallRule -DisplayName "CCDC ALLOW OUT DNS UDP 53" `
        -Direction Outbound -Action Allow -Protocol UDP -RemotePort 53 -Profile Any | Out-Null
    New-NetFirewallRule -DisplayName "CCDC ALLOW OUT DNS TCP 53" `
        -Direction Outbound -Action Allow -Protocol TCP -RemotePort 53 -Profile Any | Out-Null

    New-NetFirewallRule -DisplayName "CCDC ALLOW OUT HTTP/HTTPS" `
        -Direction Outbound -Action Allow -Protocol TCP -RemotePort 80,443 -Profile Any | Out-Null

    # -----------------------------
    # OUTBOUND Domain/DC required (scoped to DC IP)
    # -----------------------------
    New-NetFirewallRule -DisplayName "CCDC ALLOW OUT Kerberos TCP 88 to DC" `
        -Direction Outbound -Action Allow -Protocol TCP -RemoteAddress $DCIP -RemotePort 88 -Profile Any | Out-Null
    New-NetFirewallRule -DisplayName "CCDC ALLOW OUT Kerberos UDP 88 to DC" `
        -Direction Outbound -Action Allow -Protocol UDP -RemoteAddress $DCIP -RemotePort 88 -Profile Any | Out-Null

    New-NetFirewallRule -DisplayName "CCDC ALLOW OUT Kerberos TCP 464 to DC" `
        -Direction Outbound -Action Allow -Protocol TCP -RemoteAddress $DCIP -RemotePort 464 -Profile Any | Out-Null
    New-NetFirewallRule -DisplayName "CCDC ALLOW OUT Kerberos UDP 464 to DC" `
        -Direction Outbound -Action Allow -Protocol UDP -RemoteAddress $DCIP -RemotePort 464 -Profile Any | Out-Null

    New-NetFirewallRule -DisplayName "CCDC ALLOW OUT LDAP TCP 389 to DC" `
        -Direction Outbound -Action Allow -Protocol TCP -RemoteAddress $DCIP -RemotePort 389 -Profile Any | Out-Null
    New-NetFirewallRule -DisplayName "CCDC ALLOW OUT LDAP UDP 389 to DC" `
        -Direction Outbound -Action Allow -Protocol UDP -RemoteAddress $DCIP -RemotePort 389 -Profile Any | Out-Null
    New-NetFirewallRule -DisplayName "CCDC ALLOW OUT LDAPS TCP 636 to DC" `
        -Direction Outbound -Action Allow -Protocol TCP -RemoteAddress $DCIP -RemotePort 636 -Profile Any | Out-Null

    New-NetFirewallRule -DisplayName "CCDC ALLOW OUT GC TCP 3268 to DC" `
        -Direction Outbound -Action Allow -Protocol TCP -RemoteAddress $DCIP -RemotePort 3268 -Profile Any | Out-Null
    New-NetFirewallRule -DisplayName "CCDC ALLOW OUT GC SSL TCP 3269 to DC" `
        -Direction Outbound -Action Allow -Protocol TCP -RemoteAddress $DCIP -RemotePort 3269 -Profile Any | Out-Null

    New-NetFirewallRule -DisplayName "CCDC ALLOW OUT SMB TCP 445 to DC" `
        -Direction Outbound -Action Allow -Protocol TCP -RemoteAddress $DCIP -RemotePort 445 -Profile Any | Out-Null

    New-NetFirewallRule -DisplayName "CCDC ALLOW OUT RPC TCP 135 to DC" `
        -Direction Outbound -Action Allow -Protocol TCP -RemoteAddress $DCIP -RemotePort 135 -Profile Any | Out-Null
    New-NetFirewallRule -DisplayName "CCDC ALLOW OUT RPC Dynamic TCP 49152-65535 to DC" `
        -Direction Outbound -Action Allow -Protocol TCP -RemoteAddress $DCIP -RemotePort 49152-65535 -Profile Any | Out-Null

    New-NetFirewallRule -DisplayName "CCDC ALLOW OUT NTP UDP 123 to DC" `
        -Direction Outbound -Action Allow -Protocol UDP -RemoteAddress $DCIP -RemotePort 123 -Profile Any | Out-Null

    New-NetFirewallRule -DisplayName "CCDC ALLOW OUT ICMPv4" `
        -Direction Outbound -Action Allow -Protocol ICMPv4 -Profile Any | Out-Null
}

function Disable-Services-And-Features {
    # Print Spooler
    try {
        Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue
        Set-Service -Name Spooler -StartupType Disabled
    } catch {}

    # RemoteRegistry
    try {
        Stop-Service -Name RemoteRegistry -Force -ErrorAction SilentlyContinue
        Set-Service -Name RemoteRegistry -StartupType Disabled
    } catch {}

    # SMBv1
    try { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force | Out-Null } catch {}
    try { Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null } catch {}

    # Disable RDP
    try {
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
    } catch {}
    try {
        Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue |
            Disable-NetFirewallRule -ErrorAction SilentlyContinue
    } catch {}
}

function Enable-DefenderProtections {
    try {
        Set-Service -Name WinDefend -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name WinDefend -ErrorAction SilentlyContinue
    } catch {}

    try { Set-MpPreference -DisableRealtimeMonitoring $false } catch {}
    try { Set-MpPreference -MAPSReporting 2 } catch {}
    try { Set-MpPreference -SubmitSamplesConsent 1 } catch {}
    try { Set-MpPreference -DisableBehaviorMonitoring $false } catch {}
}

# -------------------------
# EXECUTE
# -------------------------
Write-Host "[1/7] Creating/ensuring local admin user: $NewAdminUser"
Ensure-LocalAdminUser -Username $NewAdminUser -Password $SecurePassword

Write-Host "[2/7] Disabling ALL other local accounts (keeping: $NewAdminUser, and current user: $CurrentUserName)"
Disable-AllOtherLocalAccounts -KeepUser $NewAdminUser -AlsoKeepUser $CurrentUserName

Write-Host "[3/7] Setting password + lockout policies"
Set-LocalAccountPolicies -MinLength $MinPwLen -MaxAgeDays $MaxPwAgeDays `
    -LockThreshold $LockoutThreshold -LockDurationMinutes $LockoutDurationMinutes -LockWindowMinutes $LockoutWindowMinutes

Write-Host "[4/7] Applying firewall lockdown (ONLY inbound ports you entered; outbound scoped to DC for AD traffic)"
Set-CCDCFirewallLockdown -DCIP $DomainControllerIP -AllowInboundTcpPorts $InboundTcpPorts -AllowInboundUdpPorts $InboundUdpPorts

Write-Host "[5/7] Disabling Spooler, RemoteRegistry, SMBv1, and RDP"
Disable-Services-And-Features

Write-Host "[6/7] Enabling Windows Defender + real-time + cloud-delivered protection"
Enable-DefenderProtections

Write-Host "[7/7] Quick status checks"
Write-Host "  - Local users enabled:"; Get-LocalUser | Select-Object Name,Enabled | Format-Table -AutoSize
Write-Host "  - Firewall profiles:"; Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | Format-Table -AutoSize
Write-Host "  - Inbound allow rules created:"; Get-NetFirewallRule -DisplayName "CCDC ALLOW IN *" | Select-Object DisplayName,Enabled,Direction,Action | Format-Table -AutoSize
Write-Host "  - Defender status:"; try { Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,IsTamperProtected,MAPSReporting | Format-List } catch { Write-Host "    (Get-MpComputerStatus not available)" }

Write-Host "`nDONE. Reboot recommended (especially for SMB feature changes)."
