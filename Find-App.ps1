<#
.SYNOPSIS
Scans for applications by name in registry, processes, and files.

.DESCRIPTION
Performs Lite, Fast, or Deep scans for a given application name.
Supports options to save reports, delete found items, and run silently.
Outputs detailed results to the console, optionally color-coded.

.PARAMETER AppName
Name of the application to scan for. Mandatory.

.PARAMETER LiteScan
Runs in Lite mode with MaxDepth = 1.

.PARAMETER DeepScan
Runs in Deep mode with MaxDepth = 3.

.PARAMETER Silent
Suppresses detailed output; shows only summary counts.

.PARAMETER SaveReport
Saves the scan results to a report file.

.PARAMETER DeleteFound
Prompts the user to delete all found entries.
#>

[CmdletBinding(DefaultParameterSetName = "Scan")]
param (
    [Parameter(Mandatory = $true, ParameterSetName = "Scan")]
    [string]$AppName,

    [Parameter(ParameterSetName = "Scan")]
    [switch]$LiteScan,

    [Parameter(ParameterSetName = "Scan")]
    [switch]$DeepScan,

    [Parameter(ParameterSetName = "Scan")]
    [switch]$Silent,

    [Parameter(ParameterSetName = "Scan")]
    [switch]$SaveReport,

    [Parameter(ParameterSetName = "Scan")]
    [switch]$DeleteFound,

    [Parameter(Mandatory = $true, ParameterSetName = "Examples")]
    [switch]$Examples
)

# ---------------- EXAMPLES ----------------
if ($Examples) {
    $sampleApps = @("Discord", "Zoom", "Spotify", "Slack", "Notion", "Telegram", "OBS Studio", "WeChat", "Steam", "VLC")
    $chosen = $sampleApps | Get-Random -Count 10

    Write-Host "`n=== Find-App.ps1 Examples ===`n" -ForegroundColor Cyan

    Write-Host ".\Find-App.ps1" -ForegroundColor Yellow -NoNewline
    Write-Host " -AppName " -ForegroundColor DarkGray -NoNewline
    Write-Host ('"{0}"' -f $chosen[0]) -ForegroundColor DarkCyan
    Write-Host "   Runs a FAST scan (MaxDepth=2) for $($chosen[0]) and shows detailed results." -ForegroundColor Gray
    Write-Host ""

    Write-Host ".\Find-App.ps1" -ForegroundColor Yellow -NoNewline
    Write-Host " -AppName " -ForegroundColor DarkGray -NoNewline
    Write-Host ('"{0}"' -f $chosen[1]) -ForegroundColor DarkCyan -NoNewline
    Write-Host " -LiteScan" -ForegroundColor DarkGray
    Write-Host "   Runs a Lite scan (MaxDepth=1) for $($chosen[1]) for quicker results." -ForegroundColor Gray
    Write-Host ""

    Write-Host ".\Find-App.ps1" -ForegroundColor Yellow -NoNewline
    Write-Host " -AppName " -ForegroundColor DarkGray -NoNewline
    Write-Host ('"{0}"' -f $chosen[2]) -ForegroundColor DarkCyan -NoNewline
    Write-Host " -DeepScan -SaveReport" -ForegroundColor DarkGray
    Write-Host "   Runs a Deep scan (MaxDepth=3) for $($chosen[2]) and saves results to a report." -ForegroundColor Gray
    Write-Host ""

    Write-Host ".\Find-App.ps1" -ForegroundColor Yellow -NoNewline
    Write-Host " -AppName " -ForegroundColor DarkGray -NoNewline
    Write-Host ('"{0}"' -f $chosen[3]) -ForegroundColor DarkCyan -NoNewline
    Write-Host " -Silent" -ForegroundColor DarkGray
    Write-Host "   Runs a FAST scan silently and shows only summary counts." -ForegroundColor Gray
    Write-Host ""

    Write-Host ".\Find-App.ps1" -ForegroundColor Yellow -NoNewline
    Write-Host " -AppName " -ForegroundColor DarkGray -NoNewline
    Write-Host ('"{0}"' -f $chosen[4]) -ForegroundColor DarkCyan -NoNewline
    Write-Host " -DeleteFound" -ForegroundColor DarkGray
    Write-Host "   Runs a FAST scan (MaxDepth=2) for $($chosen[0]) and deletes all found entries (prompts before deleting)." -ForegroundColor Gray

    Write-Host ""
    exit
}

# ---------------- CONFIG ----------------
$ErrorActionPreference = "SilentlyContinue"

# Sanitize AppName for filename
$sanitizedAppName = ($AppName -replace '[\\/:*?"<>|]', '_').Trim()
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$ReportFile = Join-Path $PSScriptRoot "$($sanitizedAppName)_Search_Report_$timestamp.txt"

# Escape regex + allow spaces/dash/underscore
$escapedAppName = [regex]::Escape($AppName) -replace '\\ ', '[-_\s]*'

# Determine mode, depth, and roots
if ($LiteScan) {
    $MaxDepth = 1
    $ModeName = "LITE"
    $fileRoots = @(
        "$env:USERPROFILE\AppData\Local",
        "$env:USERPROFILE\AppData\Roaming"
    )
    $regTargets = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    $regRoots = @()

} elseif ($DeepScan) {
    $MaxDepth = 3
    $ModeName = "DEEP"
    $fileRoots = @("C:\")
    $regTargets = @()
    $regRoots = @(
        "HKLM:\", 
        "HKCU:\"
    )

} else {
    $MaxDepth = 2
    $ModeName = "FAST"
    $fileRoots = @(
        "$env:ProgramFiles",
        "$env:ProgramFiles(x86)",
        "$env:LOCALAPPDATA",
        "$env:APPDATA",
        "$env:ProgramData"
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Desktop"
    )
    $regTargets = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    $regRoots = @(
        "HKLM:\SOFTWARE", 
        "HKLM:\SOFTWARE\WOW6432Node", 
        "HKCU:\SOFTWARE"
    )
}

# Normalize roots to eliminate trailing \
$fileRoots  = $fileRoots  | ForEach-Object { ($_ -replace '\\+$','') }
$regTargets = $regTargets | ForEach-Object { ($_ -replace '\\+$','') }
$regRoots   = $regRoots   | ForEach-Object { ($_ -replace '\\+$','') }

Write-Host "Starting search for '$AppName' in $ModeName mode..." -ForegroundColor Cyan
Write-Host "MaxDepth: $MaxDepth" -ForegroundColor DarkGray

# ---------------- HELPERS ----------------

# Limited recursive filesystem enumerator (depth limited)
function Get-ChildItems-Limited {
    param(
        [Parameter(Mandatory=$true)][string]$Root,
        [int]$MaxDepth = 2
    )
    $results = New-Object System.Collections.Generic.List[System.Object]

    function RecursePath {
        param($Path, $Depth)
        if ($Depth -gt $MaxDepth) { return }

        try {
            $items = Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        } catch {
            return
        }

        foreach ($it in $items) {
            $results.Add($it)
            if ($it.PSIsContainer -and $Depth -lt $MaxDepth) {
                RecursePath -Path $it.FullName -Depth ($Depth + 1)
            }
        }
    }

    RecursePath -Path $Root -Depth 0
    return $results
}

# Limited recursive registry enumerator (depth limited)
function Get-RegistryKeys-Limited {
    param(
        [Parameter(Mandatory=$true)][string]$RootKey,
        [int]$MaxDepth = 2
    )

    $results = New-Object System.Collections.Generic.List[Object]
    $skipKeys = @("HARDWARE","SECURITY","SAM")

    function RecurseReg {
        param($KeyPath, $Depth)
        if ($Depth -gt $MaxDepth) { return }

        try {
            $children = Get-ChildItem -Path $KeyPath -ErrorAction SilentlyContinue
        } catch {
            return
        }

        foreach ($ch in $children) {
            if ($null -eq $ch) { continue }
            if ($skipKeys -contains $ch.PSChildName.ToUpper()) { continue }
            $results.Add($ch)
            if ($Depth -lt $MaxDepth) {
                RecurseReg -KeyPath $ch.PSPath -Depth ($Depth + 1)
            }
        }
    }

    RecurseReg -KeyPath $RootKey -Depth 0
    return $results
}

# Progress logging helper (prints short progress messages)
function Write-Progress {
    param([string]$Message)
    Write-Host $Message -ForegroundColor DarkGray
}

# ---------------- STORAGE ----------------
$foundPrograms = New-Object System.Collections.Generic.List[Object]
$foundProcesses = New-Object System.Collections.Generic.List[Object]
$foundFiles = New-Object System.Collections.Generic.List[Object]
$foundRegistry = New-Object System.Collections.Generic.List[string]

# ---------------- INSTALLED PROGRAMS ----------------
Write-Progress "Scanning installed programs..."

$uninstallPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

foreach ($p in $uninstallPaths) {
    $items = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue
    foreach ($it in $items) {
        if ($it.DisplayName -imatch $escapedAppName) {
            $exists = $foundPrograms | Where-Object {
                ($it.PSPath -and $_.PSPath -eq $it.PSPath) -or ($_.DisplayName -eq $it.DisplayName)
            }
            if (-not $exists) { $foundPrograms.Add($it) | Out-Null }
        }
    }
}

# ---------------- RUNNING PROCESSES ----------------
Write-Progress "Scanning running processes..."

try {
    $procs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -imatch $escapedAppName }
    foreach ($pr in $procs) {
        # avoid duplicates by Id
        if (-not ($foundProcesses | Where-Object { $_.Id -eq $pr.Id })) {
            $foundProcesses.Add($pr) | Out-Null
        }
    }
} catch { }

# ---------------- FILE LOCATIONS ----------------
Write-Progress "Scanning files & folders..."

# skip some heavy/system paths
$skipRoots = @(
    "$env:SystemRoot",
    "$env:ProgramFiles\WindowsApps"
) | ForEach-Object { ($_ -replace '\\+$','') }

foreach ($root in $fileRoots) {
    if (-not (Test-Path $root)) { continue }
    if ($skipRoots -contains $root) { continue }
    try {
        $items = Get-ChildItems-Limited -Root $root -MaxDepth $MaxDepth
        foreach ($it in $items) {
            if ($null -ne $it.Name -and ($it.Name -imatch $escapedAppName)) {
                # prevent duplicates by FullName
                if (-not ($foundFiles | Where-Object { $_.FullName -eq $it.FullName })) {
                    $foundFiles.Add($it) | Out-Null
                }
            }   
        }
    } catch { }
}

# ---------------- REGISTRY ENTRIES ----------------
Write-Progress "Scanning registry entries..."

$registryScanList = @()
$registryScanList += $regTargets | ForEach-Object { [PSCustomObject]@{ Path = $_; Recursive = $false } }
$registryScanList += $regRoots   | ForEach-Object { [PSCustomObject]@{ Path = $_; Recursive = $true  } }

foreach ($entry in $registryScanList) {
    # Determine how to get keys based on mode
    if ($entry.Recursive) {
        try {
            $keys = Get-RegistryKeys-Limited -RootKey $entry.Path -MaxDepth $MaxDepth
        } catch {
            $keys = @()
        }
    }
    else {
        try {
            $keys = Get-ChildItem -Path $entry.Path -ErrorAction SilentlyContinue
        } catch {
            $keys = @()
        }
    }

    foreach ($k in $keys) {
        if (-not $k) { continue }
        try {
            $props = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
            foreach ($prop in $props.PSObject.Properties) {
                if ($prop.Value -is [string] -and ($prop.Value -imatch $escapedAppName)) {
                    if (-not ($foundRegistry -contains $k.PSPath)) {
                        $foundRegistry.Add($k.PSPath) | Out-Null
                    }
                    break
                }
            }
        } catch { }
    }
}

# ----------- SUMMARY OUTPUT -----------
Write-Host ""
Write-Host "==== Scan Summary for '$AppName' ====" -ForegroundColor Cyan
Write-Host ("Scan Mode: {0} (MaxDepth={1})" -f $ModeName, $MaxDepth) -ForegroundColor Cyan
Write-Host ""

# Build summary data
$summary = @(
    @{ Label = "Programs Found:";      Count = $foundPrograms.Count }
    @{ Label = "Processes Found:";     Count = $foundProcesses.Count }
    @{ Label = "Files/Folders Found:"; Count = $foundFiles.Count }
    @{ Label = "Registry Entries Found:"; Count = $foundRegistry.Count }
)

# Calculate max label length for alignment
# $maxLabelLen = ($summary.Label | Measure-Object -Maximum Length).Maximum

# Print aligned counts
foreach ($item in $summary) {
    Write-Host ("{0,-1} {1}" -f $item.Label, $item.Count) -ForegroundColor Yellow

    if (-not $Silent) {
        # Print logs for each category
        switch ($item.Label) {
            "Programs Found:" {
                foreach ($p in $foundPrograms) {
                    if ($p.DisplayName) {
                        Write-Host ("{0,-20}" -f $p.DisplayName) -ForegroundColor White
                    }
                }
                if ($foundPrograms -or $foundProcesses) { Write-Host "" }
            }
            "Processes Found:" {
                foreach ($proc in $foundProcesses) {
                    Write-Host ("{0,-20} (Id: " -f $proc.ProcessName) -ForegroundColor White -NoNewline
                    Write-Host ("{0}" -f $proc.ID) -ForegroundColor DarkCyan -NoNewline
                    Write-Host ")" -ForegroundColor White
                }
                if ($foundProcesses -or $foundFiles) { Write-Host "" }
            }
            "Files/Folders Found:" {
                foreach ($file in $foundFiles) {
                    Write-Host $file.FullName -ForegroundColor White
                }
                if ($foundFiles -or $foundRegistry) { Write-Host "" }
            }
            "Registry Entries Found:" {
                foreach ($reg in $foundRegistry) {
                    $cleanReg = $reg -replace '^Microsoft\.PowerShell\.Core\\Registry::', ''
                    $root, $rest = $cleanReg -split "\\", 2
                    Write-Host $root -ForegroundColor Yellow -NoNewline
                    if ($rest) {
                        Write-Host "\" -NoNewline -ForegroundColor White
                        Write-Host $rest -ForegroundColor White
                    } else {
                        Write-Host ""
                    }
                }
            }
        }
    }
}

Write-Host ""
Write-Host "Scan completed." -ForegroundColor Cyan

# ---------------- SAVE REPORT ----------------
if ($SaveReport) {
    function Add-ReportLine {
        param(
            [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [string[]]$Line
        )
        process {
            foreach ($l in $Line) {
                if (-not [string]::IsNullOrWhiteSpace($l)) {
                    $l | Out-File -FilePath $ReportFile -Encoding UTF8 -Append
                } else {
                    "" | Out-File -FilePath $ReportFile -Encoding UTF8 -Append
                }
            }
        }
    }

    # Clear the file first
    "" | Out-File -FilePath $ReportFile -Encoding UTF8

    # Start writing report
    @(
        "==== Scan Summary for '$AppName' ====",
        ("Scan Mode: {0} (MaxDepth={1})" -f $ModeName, $MaxDepth),
        ""
    ) | Add-ReportLine

    # Programs
    ("Programs Found: $($foundPrograms.Count)") | Add-ReportLine
    $foundPrograms | ForEach-Object {
        if ($_.DisplayName) { "  $($_.DisplayName)" } else { "  $($_ | Out-String).Trim()" }
    } | Add-ReportLine
    "" | Add-ReportLine

    # Processes
    ("Processes Found: $($foundProcesses.Count)") | Add-ReportLine
    $foundProcesses | ForEach-Object { "  $($_.ProcessName) (Id: $($_.Id))" } | Add-ReportLine
    "" | Add-ReportLine

    # Files/Folders
    ("Files/Folders Found: $($foundFiles.Count)") | Add-ReportLine
    $foundFiles | ForEach-Object { "  $($_.FullName)" } | Add-ReportLine
    "" | Add-ReportLine

    # Registry
    ("Registry Entries Found: $($foundRegistry.Count)") | Add-ReportLine
    $foundRegistry | ForEach-Object { "  $_" } | Add-ReportLine

    Write-Host "Report saved to: $ReportFile" -ForegroundColor Cyan
}


# ---------------- DELETE FOUND (prompt) ----------------
if ($DeleteFound) {
    if (($foundFiles.Count -eq 0) -and ($foundRegistry.Count -eq 0) -and ($foundPrograms.Count -eq 0) -and ($foundProcesses.Count -eq 0)) {
        Write-Host "No found items to delete." -ForegroundColor Yellow
    } else {
        $confirm = Read-Host "Delete all found files/folders, processes and registry entries? (Y/N)"
        if ($confirm -match "^[Yy]$") {
            # stop processes that match (best-effort)
            foreach ($proc in $foundProcesses) {
                try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch {}
            }

            foreach ($f in $foundFiles) {
                try {
                    if (Test-Path $f.FullName) {
                        Remove-Item -LiteralPath $f.FullName -Recurse -Force -ErrorAction SilentlyContinue
                    }
                } catch {}
            }

            foreach ($r in $foundRegistry) {
                try { Remove-Item -LiteralPath $r -Recurse -Force -ErrorAction SilentlyContinue } catch {}
            }

            # Attempt removing uninstall registry entries we found
            foreach ($p in $foundPrograms) {
                try {
                    if ($p.PSPath) {
                        Remove-Item -LiteralPath $p.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                    }
                } catch {}
            }

            Write-Host "Deletion completed." -ForegroundColor Red
        } else {
            Write-Host "Deletion cancelled." -ForegroundColor Cyan
        }
    }
}
# End of script
