#Requires -RunAsAdministrator
<# =====================================================================
   borgar  (192.168.220.10)  -  Windows Server 2022  -  Food Ordering Service
   UPDATE + HARDENING SCRIPT

   HOW TO RUN: open PowerShell AS ADMINISTRATOR, then:
       Set-ExecutionPolicy -Scope Process Bypass -Force
       .\borgar.ps1
   (A full log is saved to C:\HardeningBackup-<date>\hardening-log.txt)

   WHAT IT DOES, IN ORDER:
       1. Installs Windows Updates and updates Defender
       2. Lists local user accounts and admins          (report only)
       3. Hardens SMB, NTLM, LLMNR, RDP, WDigest, auditing
       4. Lists open ports, scheduled tasks, startup programs (report only)
       5. Hardens IIS (the food ordering website) if it is installed
       6. Turns on Windows Firewall and allows the ports below

   SAFE BY DESIGN: it never deletes users or stops the website, and it
   backs up the firewall, LSA registry key and security policy first.
   ===================================================================== #>

# ---------------------------------------------------------------------
#  SETTINGS - CHECK THESE BEFORE YOU RUN
# ---------------------------------------------------------------------
$InstallUpdates   = $true          # $false = skip Windows Update (it can take a long time)
$AllowedTcpPorts  = @(80, 443, 3389)  # 80/443 = food ordering site, 3389 = RDP. Add the app's port if it is different!
$DisableOldTls    = $false         # $true = turn off TLS 1.0/1.1 for the website (reboot needed).
                                   #         Leave $false if an old app or SQL Server needs them.
$DisableGuest     = $true          # $true = disable the built-in Guest account

# =====================================================================
#  HELPER FUNCTIONS  (you do not need to edit anything below this line)
# =====================================================================
$Stamp     = Get-Date -Format 'yyyyMMdd-HHmmss'
$BackupDir = "C:\HardeningBackup-$Stamp"          # backups + the log go here
New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
Start-Transcript -Path "$BackupDir\hardening-log.txt" | Out-Null

function Say  ($Text) { Write-Host "`n==== $Text ====" -ForegroundColor Cyan }
function Note ($Text) { Write-Host "  [*] $Text" }
function Warn ($Text) { Write-Host "  [!] $Text" -ForegroundColor Yellow }

# Set-Reg PATH NAME VALUE -> create the key if needed and set a DWORD value
function Set-Reg ($Path, $Name, $Value) {
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord
    Note "Set $Path\$Name = $Value"
}

# Back up the settings we are about to change, so they can be restored.
Say "BACKUP"
netsh advfirewall export "$BackupDir\firewall-before.wfw" | Out-Null
reg export "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "$BackupDir\lsa-before.reg" /y | Out-Null
secedit /export /cfg "$BackupDir\security-policy-before.inf" | Out-Null
Note "Backups saved in $BackupDir"
Note "To restore the firewall:  netsh advfirewall import `"$BackupDir\firewall-before.wfw`""

# =====================================================================
#  STEP 1: Windows Updates + Defender
#  Uses the built-in Windows Update API, so no extra modules are needed.
# =====================================================================
Say "STEP 1: Windows Updates and Defender"
Note "OS: $((Get-CimInstance Win32_OperatingSystem).Caption)  build $([Environment]::OSVersion.Version)"

if ($InstallUpdates) {
    $Session  = New-Object -ComObject Microsoft.Update.Session
    $Searcher = $Session.CreateUpdateSearcher()
    Note "Searching for updates (this can take several minutes)..."
    $Found = $Searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0").Updates

    if ($Found.Count -eq 0) {
        Note "Windows is up to date."
    } else {
        $ToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
        foreach ($Update in $Found) {
            if (-not $Update.EulaAccepted) { $Update.AcceptEula() }
            Note "Will install: $($Update.Title)"
            [void]$ToInstall.Add($Update)
        }
        Note "Downloading..."
        $Downloader = $Session.CreateUpdateDownloader()
        $Downloader.Updates = $ToInstall
        [void]$Downloader.Download()

        Note "Installing..."
        $Installer = $Session.CreateUpdateInstaller()
        $Installer.Updates = $ToInstall
        $Result = $Installer.Install()
        Note "Result code: $($Result.ResultCode)   (2 = succeeded, 3 = succeeded with errors, 4 = failed)"
        if ($Result.RebootRequired) {
            Warn "A REBOOT is needed to finish updates. Reboot when it is safe for scoring."
        }
    }
} else {
    Note "InstallUpdates is `$false - skipping Windows Update."
}

# Microsoft Defender: newest signatures, real-time protection on.
try {
    Update-MpSignature -ErrorAction Stop
    Set-MpPreference -DisableRealtimeMonitoring $false
    Note "Defender signatures updated, real-time protection is ON."
    $Exclusions = (Get-MpPreference).ExclusionPath
    if ($Exclusions) { Warn "Defender has EXCLUDED folders (attackers like to add these): $($Exclusions -join ', ')" }
} catch {
    Warn "Could not update Defender: $($_.Exception.Message)"
}

# =====================================================================
#  STEP 2: Review local accounts (REPORT ONLY, except Guest)
# =====================================================================
Say "STEP 2: Local accounts"
Note "Members of the local Administrators group (should be only people you know):"
Get-LocalGroupMember -Group 'Administrators' | ForEach-Object { Write-Host "      $($_.Name)  ($($_.ObjectClass))" }

Note "Enabled local accounts:"
Get-LocalUser | Where-Object Enabled | ForEach-Object {
    Write-Host ("      {0,-20} last logon: {1,-22} password last set: {2}" -f $_.Name, $_.LastLogon, $_.PasswordLastSet)
}
Get-LocalUser | Where-Object { $_.Enabled -and -not $_.PasswordRequired } |
    ForEach-Object { Warn "$($_.Name) does NOT require a password!" }

if ($DisableGuest) {
    Disable-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
    Note "Guest account disabled."
}
Note "To change a password:   Set-LocalUser -Name <user> -Password (Read-Host -AsSecureString)"
Note "To disable an account:  Disable-LocalUser -Name <user>"

# =====================================================================
#  STEP 3: Protocol hardening (SMB, NTLM, LLMNR, RDP, WDigest)
#  These are standard Microsoft-recommended settings and do not stop
#  normal Windows file sharing, RDP or domain logons.
# =====================================================================
Say "STEP 3: Protocol hardening"

# --- SMB: turn off SMBv1 (EternalBlue/WannaCry) and require signing
Set-SmbServerConfiguration -EnableSMB1Protocol $false -RequireSecuritySignature $true -Force
Note "SMBv1 is OFF, SMB signing is REQUIRED."

# --- NTLM: refuse LM and NTLMv1 (easily cracked); don't store LM hashes
$Lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
Set-Reg $Lsa 'LmCompatibilityLevel' 5
Set-Reg $Lsa 'NoLMHash' 1
# --- Anonymous users can't list accounts and shares
Set-Reg $Lsa 'RestrictAnonymous' 1
Set-Reg $Lsa 'RestrictAnonymousSAM' 1

# --- WDigest: don't keep plain-text passwords in memory (stops Mimikatz from reading them)
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0

# --- LLMNR off (Responder-style password capture)
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0

# --- RDP: require Network Level Authentication (log in before a session is created)
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication' 1

# --- AutoRun off for all drives
Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' 255

# --- Log every PowerShell script that runs (helps you spot attackers)
Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 1

# --- Audit logons and account changes (shows up in Event Viewer > Security)
foreach ($Category in 'Logon/Logoff', 'Account Logon', 'Account Management') {
    auditpol /set /category:"$Category" /success:enable /failure:enable | Out-Null
}
Note "Auditing ON for logons and account changes."

# --- Risky protocols from the Common Protocols list (report only)
$Risky = @{ 'TlntSvr' = 'Telnet server'; 'FTPSVC' = 'IIS FTP server'; 'SNMP' = 'SNMP';
            'tvnserver' = 'TightVNC'; 'uvnc_service' = 'UltraVNC'; 'vncserver' = 'RealVNC';
            'OpenVPNService' = 'OpenVPN'; 'SMTPSVC' = 'IIS SMTP' }
foreach ($Name in $Risky.Keys) {
    $Svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($Svc) { Warn "$($Risky[$Name]) service ($Name) is installed, state: $($Svc.Status). Disable it if it is not scored." }
}
$Communities = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities' -ErrorAction SilentlyContinue
if ($Communities -and ($Communities.PSObject.Properties.Name -match '^(public|private)$')) {
    Warn "SNMP uses a DEFAULT community string (public/private) - change it."
}

# =====================================================================
#  STEP 4: Look for things an attacker may have left (REPORT ONLY)
# =====================================================================
Say "STEP 4: Open ports, scheduled tasks, startup programs (report only)"

Note "Ports listening on the network, and the program behind each one:"
Get-NetTCPConnection -State Listen |
    Where-Object { $_.LocalAddress -notin '127.0.0.1', '::1' } |
    Sort-Object LocalPort -Unique |
    ForEach-Object {
        $Proc = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
        Write-Host ("      TCP {0,-6} {1}" -f $_.LocalPort, $Proc)
    }

Note "Scheduled tasks that are NOT from Microsoft (check each one):"
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } |
    ForEach-Object { Write-Host "      $($_.TaskPath)$($_.TaskName)  ->  $($_.Actions.Execute) $($_.Actions.Arguments)" }

Note "Programs that start automatically (Run keys):"
foreach ($Key in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run') {
    $Values = Get-ItemProperty $Key -ErrorAction SilentlyContinue
    if ($Values) {
        $Values.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } |
            ForEach-Object { Write-Host "      $($_.Name) = $($_.Value)" }
    }
}

# =====================================================================
#  STEP 5: Harden IIS (the food ordering website)
# =====================================================================
Say "STEP 5: Harden IIS"
if (-not (Get-Service -Name 'W3SVC' -ErrorAction SilentlyContinue)) {
    Warn "IIS (W3SVC) is not installed. Find the food ordering app's port in STEP 4 and add it to `$AllowedTcpPorts."
} else {
    Import-Module WebAdministration
    # IIS's own backup of its whole config (restore with: appcmd restore backup "<name>")
    & "$env:windir\system32\inetsrv\appcmd.exe" add backup "Hardening-$Stamp" | Out-Null
    Note "IIS config backed up as 'Hardening-$Stamp'"

    Note "Websites on this server:"
    Get-Website | ForEach-Object {
        Write-Host "      $($_.Name)  [$($_.State)]  $($_.PhysicalPath)  bindings: $(($_.Bindings.Collection | ForEach-Object { "$($_.protocol) $($_.bindingInformation)" }) -join ', ')"
    }

    $Root = 'MACHINE/WEBROOT/APPHOST'
    # 1. No directory listings (stops people browsing your files)
    Set-WebConfigurationProperty -PSPath $Root -Filter 'system.webServer/directoryBrowse' -Name 'enabled' -Value $false
    Note "Directory browsing OFF"
    # 2. Hide the "Server: Microsoft-IIS/10.0" header
    Set-WebConfigurationProperty -PSPath $Root -Filter 'system.webServer/security/requestFiltering' -Name 'removeServerHeader' -Value $true
    Note "Server header removed"
    # 3. Hide the "X-Powered-By: ASP.NET" header
    Remove-WebConfigurationProperty -PSPath $Root -Filter 'system.webServer/httpProtocol/customHeaders' -Name '.' -AtElement @{ name = 'X-Powered-By' } -ErrorAction SilentlyContinue
    Note "X-Powered-By header removed"
    # 4. Block the HTTP TRACE method
    Add-WebConfigurationProperty -PSPath $Root -Filter 'system.webServer/security/requestFiltering/verbs' -Name '.' -Value @{ verb = 'TRACE'; allowed = 'false' } -ErrorAction SilentlyContinue
    Note "HTTP TRACE blocked"

    # 5. App pools should NOT run as LocalSystem (report only)
    Get-ChildItem IIS:\AppPools | ForEach-Object {
        $Identity = $_.processModel.identityType
        Write-Host "      App pool $($_.Name): runs as $Identity"
        if ($Identity -eq 'LocalSystem') { Warn "App pool $($_.Name) runs as LocalSystem - use ApplicationPoolIdentity instead." }
    }
    # 6. WebDAV lets people upload files - warn if it is installed
    if (Get-WindowsFeature Web-DAV-Publishing | Where-Object Installed) { Warn "WebDAV is installed. Remove it if the site doesn't need it." }
}

# --- SQL Server (common for ordering apps) - report only
Get-Service | Where-Object { $_.Name -like 'MSSQL*' } | ForEach-Object {
    Warn "SQL Server found ($($_.Name)). Make sure 'sa' has a strong password, and only open 1433 if another machine needs it."
}

# --- TLS: let .NET apps use TLS 1.2, optionally turn off TLS 1.0/1.1 for the server
Set-Reg 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' 'SchUseStrongCrypto' 1
Set-Reg 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' 'SchUseStrongCrypto' 1
if ($DisableOldTls) {
    foreach ($Protocol in 'SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1') {
        $Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Server"
        Set-Reg $Key 'Enabled' 0
        Set-Reg $Key 'DisabledByDefault' 1
    }
    Warn "Old TLS versions turned off - REBOOT for this to take effect."
}

# =====================================================================
#  STEP 6: Windows Firewall
#  Turns the firewall ON for all profiles. Inbound is blocked unless a
#  rule allows it. Windows' own built-in rules stay as they are, and
#  we add an allow rule for each port in $AllowedTcpPorts.
# =====================================================================
Say "STEP 6: Windows Firewall"
foreach ($Port in $AllowedTcpPorts) {
    $RuleName = "Hardening - allow TCP $Port"
    Remove-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue   # no duplicates on re-run
    New-NetFirewallRule -DisplayName $RuleName -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow | Out-Null
    Note "Allowed inbound TCP $Port"
}
Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True `
    -DefaultInboundAction Block -DefaultOutboundAction Allow `
    -LogBlocked True -LogFileName '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'
Note "Firewall ON for Domain, Private and Public profiles (blocked traffic is logged)."

# Anything listening that has no rule? (report only)
$Listening = Get-NetTCPConnection -State Listen | Where-Object { $_.LocalAddress -notin '127.0.0.1', '::1' -and $_.LocalPort -lt 49152 } |
    Select-Object -ExpandProperty LocalPort -Unique
foreach ($Port in $Listening) {
    if ($Port -notin $AllowedTcpPorts -and $Port -notin 135, 139, 445, 5985, 47001) {
        Warn "TCP $Port is listening but is not in `$AllowedTcpPorts. If it is scored, add it and run again."
    }
}

# =====================================================================
#  DONE
# =====================================================================
Say "FINISHED"
Note "Log and backups: $BackupDir"
Note "Things to do BY HAND now (see README.md for the how-to links):"
Note "  1. Change every weak/default password you saw in the account review."
Note "  2. Read every [!] line above and decide if it needs fixing."
Note "  3. Check the scored service still works from another machine."
Note "  4. Reboot if STEP 1 said so (at a safe time)."
Stop-Transcript | Out-Null
