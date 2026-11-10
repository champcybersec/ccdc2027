# Detects MITRE T1547.001 (Registry Run Keys / Startup Folder persistence).
# First run saves a baseline; every later run warns on anything new or changed.
# Run as admin so every loaded user hive and startup folder is readable.
#   .\reg_check.ps1            check against baseline (creates it if missing)
#   .\reg_check.ps1 -Update    accept the current state as the new baseline
#   .\reg_check.ps1 -Remove    also delete every NEW entry (CHANGED ones are left for manual review)

function Find-RunKeyPersistence {
    param(
        [string]$Baseline = "$env:ProgramData\runkey_baseline.json",
        [switch]$Update,
        [switch]$Remove
    )

    # Keys where every value (and subkey value) is an autostart entry
    $paths = 'Run', 'RunOnce', 'RunOnceEx', 'RunServices', 'RunServicesOnce', 'Policies\Explorer\Run' |
        ForEach-Object { "Software\Microsoft\Windows\CurrentVersion\$_" }
    # Keys where only the listed values matter
    $named = @{
        'Software\Microsoft\Windows NT\CurrentVersion\Winlogon'                 = 'Userinit', 'Shell'
        'Software\Microsoft\Windows NT\CurrentVersion\Windows'                  = 'Load', 'Run'
        'Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'      = 'Startup', 'Common Startup'
        'Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' = 'Startup', 'Common Startup'
        'System\CurrentControlSet\Control\Session Manager'                      = 'BootExecute'
    }
    $paths += $named.Keys
    $paths += $paths -like 'Software\*' -replace '^Software', 'Software\Wow6432Node'
    $roots = @('HKEY_LOCAL_MACHINE') +
        (Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue | Where-Object Name -notlike '*_Classes').Name

    # Snapshot: "location|name" -> value
    $current = @{}
    foreach ($root in $roots) {
        foreach ($path in $paths) {
            $want = $named[$path -replace '\\Wow6432Node']
            $keys = @(Get-Item -LiteralPath "Registry::$root\$path" -ErrorAction SilentlyContinue)
            if (-not $want) { $keys += Get-ChildItem -LiteralPath "Registry::$root\$path" -Recurse -ErrorAction SilentlyContinue }
            foreach ($key in $keys) {
                foreach ($name in $key.GetValueNames()) {
                    if ($want -and $name -notin $want) { continue }
                    $current["$($key.Name)|$name"] = @($key.GetValue($name, $null, 'DoNotExpandEnvironmentNames')) -join ';'
                }
            }
        }
    }
    $startup = "$env:SystemDrive\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
               "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
    Get-Item $startup -Force -ErrorAction SilentlyContinue | Get-ChildItem -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $current["$($_.DirectoryName)|$($_.Name)"] = (Get-FileHash -LiteralPath $_.FullName).Hash
    }

    if ($Update -or -not (Test-Path $Baseline)) {
        $current | ConvertTo-Json | Set-Content $Baseline -Encoding UTF8
        Write-Host "[T1547.001] Baseline of $($current.Count) entries saved to $Baseline - review them:"
        return $current.GetEnumerator() | Sort-Object Key |
            ForEach-Object { [pscustomobject]@{ Status = 'BASELINE'; Location = $_.Key; Value = $_.Value } }
    }

    $old = @{}
    (Get-Content $Baseline -Raw | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $old[$_.Name] = $_.Value }
    foreach ($entry in $current.GetEnumerator() | Sort-Object Key) {
        if ($old.ContainsKey($entry.Key) -and $old[$entry.Key] -eq $entry.Value) { continue }
        $status = if ($old.ContainsKey($entry.Key)) { 'CHANGED' } else { 'NEW' }
        Write-Warning "[T1547.001] $status autostart: $($entry.Key) = $($entry.Value)"
        if ($Remove -and $status -eq 'NEW') {
            $location, $name = $entry.Key -split '\|', 2
            try {
                if ($location -like 'HKEY_*') {
                    (Get-Item -LiteralPath "Registry::$location").OpenSubKey('', $true).DeleteValue($name)
                } else {
                    Remove-Item -LiteralPath (Join-Path $location $name) -Force -ErrorAction Stop
                }
                $status = 'REMOVED'
            } catch { Write-Warning "[T1547.001] could not remove $($entry.Key): $_" }
        }
        [pscustomobject]@{ Status = $status; Location = $entry.Key; Value = $entry.Value }
    }
}

# Runs the check when executed directly; does nothing when dot-sourced into another script
if ($MyInvocation.InvocationName -ne '.') { Find-RunKeyPersistence @args }
