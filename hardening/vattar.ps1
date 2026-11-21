#Requires -RunAsAdministrator
<# =====================================================================
   vattar  (192.168.220.79)  -  Windows Server 2019  -  Active Directory (Domain Controller)
   UPDATE + HARDENING SCRIPT

   HOW TO RUN: open PowerShell AS ADMINISTRATOR on the DC, then:
       Set-ExecutionPolicy -Scope Process Bypass -Force
       .\vattar.ps1
   (A full log is saved to C:\HardeningBackup-<date>\hardening-log.txt)

   WHAT IT DOES, IN ORDER:
       1. Installs Windows Updates and updates Defender
       2. Reviews AD accounts and fixes the two safest problems
          (no Kerberos pre-auth, no password required)
       3. Hardens SMB, NTLM, LLMNR, RDP, WDigest, auditing
       4. Lists open ports, scheduled tasks, startup programs (report only)
       5. Domain Controller extras: Print Spooler, DNS, LDAP signing check
       6. Turns on Windows Firewall with the built-in AD rules enabled

   SAFE BY DESIGN: it never deletes users or changes passwords, and it
   backs up the firewall, LSA registry key and security policy first.
   Every other Flókið machine depends on this DC, so test logons after!
   ===================================================================== #>

# ---------------------------------------------------------------------
#  SETTINGS - CHECK THESE BEFORE YOU RUN
# ---------------------------------------------------------------------
$InstallUpdates      = $true    # $false = skip Windows Update (it can take a long time)
$FixRiskyAccounts    = $true    # $true = require Kerberos pre-auth + a password on every account
$DisablePrintSpooler = $true    # $true = stop Print Spooler (PrintNightmare). Microsoft recommends this on DCs.
$SecureDnsUpdates    = $true    # $true = only domain members may update DNS records
$RequireLdapSigning  = $false   # $true = refuse unsigned LDAP binds. CAN BREAK apps that log in
                                #         to AD over plain LDAP (e.g. Gitea/Wabbit LDAP login). Test first!

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
#  STEP 2: Review Active Directory accounts
# =====================================================================
Say "STEP 2: Active Directory accounts"
Import-Module ActiveDirectory

Note "Members of the powerful groups (should be only people you know):"
foreach ($Group in 'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators') {
    $Members = (Get-ADGroupMember -Identity $Group -Recursive -ErrorAction SilentlyContinue).SamAccountName -join ', '
    Write-Host ("      {0,-18} {1}" -f $Group, $Members)
}

Note "Enabled accounts, newest first (new ones you didn't make are suspicious):"
Get-ADUser -Filter 'Enabled -eq $true' -Properties whenCreated, LastLogonDate |
    Sort-Object whenCreated -Descending |
    ForEach-Object { Write-Host ("      {0,-22} created {1}  last logon {2}" -f $_.SamAccountName, $_.whenCreated, $_.LastLogonDate) }

# Accounts that can be attacked offline (AS-REP roasting): no Kerberos pre-auth
$NoPreAuth = Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true'
# Accounts that may have an EMPTY password
$NoPassword = Get-ADUser -Filter 'PasswordNotRequired -eq $true -and Enabled -eq $true'
foreach ($User in $NoPreAuth) {
    Warn "$($User.SamAccountName) does not require Kerberos pre-auth (AS-REP roastable)."
    if ($FixRiskyAccounts) { Set-ADAccountControl -Identity $User -DoesNotRequirePreAuth $false; Note "  fixed" }
}
foreach ($User in $NoPassword) {
    Warn "$($User.SamAccountName) is allowed to have NO password."
    if ($FixRiskyAccounts) { Set-ADUser -Identity $User -PasswordNotRequired $false; Note "  fixed (set a real password for it!)" }
}

Note "Accounts with a service name (SPN) - their passwords can be cracked offline (Kerberoasting), so make them LONG:"
Get-ADUser -Filter 'ServicePrincipalName -like "*"' -Properties ServicePrincipalName |
    Where-Object SamAccountName -ne 'krbtgt' |
    ForEach-Object { Write-Host "      $($_.SamAccountName)" }

Note "Domain password policy:"
Get-ADDefaultDomainPasswordPolicy | Format-List MinPasswordLength, ComplexityEnabled, LockoutThreshold, MaxPasswordAge | Out-String | Write-Host
Note "To strengthen it:  Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain) -MinPasswordLength 12 -ComplexityEnabled `$true"

Disable-ADAccount -Identity 'Guest' -ErrorAction SilentlyContinue
Note "Guest account disabled."
Note "To reset a password:  Set-ADAccountPassword -Identity <user> -Reset -NewPassword (Read-Host -AsSecureString)"
Note "To disable an account: Disable-ADAccount -Identity <user>"

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
#  STEP 5: Domain Controller extras
# =====================================================================
Say "STEP 5: Domain Controller extras"

# --- Print Spooler: not needed on a DC and a well-known attack path (PrintNightmare)
if ($DisablePrintSpooler) {
    Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue
    Set-Service  -Name Spooler -StartupType Disabled
    Note "Print Spooler stopped and disabled."
}

# --- DNS (the DC is almost always the DNS server)
if (Get-Command Get-DnsServerZone -ErrorAction SilentlyContinue) {
    foreach ($Zone in Get-DnsServerZone | Where-Object { $_.ZoneType -eq 'Primary' -and -not $_.IsAutoCreated -and $_.ZoneName -ne 'TrustAnchors' }) {
        Write-Host "      DNS zone $($Zone.ZoneName): dynamic updates = $($Zone.DynamicUpdate), AD-integrated = $($Zone.IsDsIntegrated)"
        if ($SecureDnsUpdates -and $Zone.IsDsIntegrated -and $Zone.DynamicUpdate -eq 'NonsecureAndSecure') {
            Set-DnsServerPrimaryZone -Name $Zone.ZoneName -DynamicUpdate Secure
            Note "  -> now only allows SECURE dynamic updates"
        }
        if ($Zone.SecureSecondaries -eq 'TransferAnyServer') {
            Set-DnsServerPrimaryZone -Name $Zone.ZoneName -SecureSecondaries TransferToZoneNameServer
            Note "  -> zone transfers now only go to the zone's own name servers"
        }
    }
}

# --- LDAP signing (report, and optionally enforce)
$NtdsKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
$Current = (Get-ItemProperty $NtdsKey -ErrorAction SilentlyContinue).LDAPServerIntegrity
Note "LDAP signing level now: $Current  (1 = optional, 2 = required)"
if ($RequireLdapSigning) {
    Set-Reg $NtdsKey 'LDAPServerIntegrity' 2
    Warn "LDAP signing is now REQUIRED. Test every app that logs in to AD (Gitea, Wabbit, POS...)."
}
Note "krbtgt password reset and other deep AD steps: see the AD links in README.md (do them by hand)."

# =====================================================================
#  STEP 6: Windows Firewall (Domain Controller)
#  A DC needs MANY ports (DNS, Kerberos, LDAP, RPC, SMB...). Windows
#  ships ready-made rules for them, so we switch those rule groups on
#  instead of typing ports by hand, then turn the firewall on.
# =====================================================================
Say "STEP 6: Windows Firewall"
$RuleGroups = 'Active Directory Domain Services', 'DNS Service', 'Kerberos Key Distribution Center',
              'Remote Desktop', 'Netlogon Service', 'File and Printer Sharing', 'Windows Remote Management',
              'DFS Replication', 'Windows Time'
foreach ($Group in $RuleGroups) {
    try {
        Enable-NetFirewallRule -DisplayGroup $Group -ErrorAction Stop
        Note "Enabled built-in rules: $Group"
    } catch {
        Note "No built-in rules called '$Group' on this server (that's OK)."
    }
}
Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True `
    -DefaultInboundAction Block -DefaultOutboundAction Allow `
    -LogBlocked True -LogFileName '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'
Note "Firewall ON for Domain, Private and Public profiles (blocked traffic is logged)."
Note "Test now from another machine: domain logon, DNS lookup (nslookup), and RDP."

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
