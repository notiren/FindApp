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

# sanitize AppName for filename
$sanitizedAppName = ($AppName -replace '[\\/:*?"<>|]', '_').Trim()
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$ReportFile = Join-Path $PSScriptRoot "$($sanitizedAppName)_Search_Report_$timestamp.txt"

# Determine mode and depth
if ($LiteScan) {
    $MaxDepth = 1
    $ModeName = "LITE"
} elseif ($DeepScan) {
    $MaxDepth = 3
    $ModeName = "DEEP"
} else {
    $MaxDepth = 2
    $ModeName = "FAST"
}

Write-Host "Starting search for '$AppName' in $ModeName mode..." -ForegroundColor Cyan
Write-Host "MaxDepth: $MaxDepth" -ForegroundColor DarkGray

# ---------------- Helpers ----------------

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
function Progress-Message {
    param([string]$Message)
    Write-Host $Message -ForegroundColor DarkGray
}

# Append content into a buffer for saving report (we build final report at end)
$reportLines = New-Object System.Collections.Generic.List[string]

function Report-AddLine {
    param([string]$Line)
    $reportLines.Add($Line) | Out-Null
}

# ---------------- Storage ----------------
$foundPrograms = New-Object System.Collections.Generic.List[Object]
$foundProcesses = New-Object System.Collections.Generic.List[Object]
$foundFiles = New-Object System.Collections.Generic.List[Object]
$foundRegistry = New-Object System.Collections.Generic.List[string]

# ---------------- INSTALLED PROGRAMS ----------------
Progress-Message "Scanning installed programs..."
Report-AddLine("=== Installed Programs ===")
$uninstallPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

foreach ($p in $uninstallPaths) {
    try {
        $items = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue
        foreach ($it in $items) {
            if ($null -ne $it.DisplayName -and ($it.DisplayName -imatch [regex]::Escape($AppName))) {
                # add unique by PSPath if present, fallback to DisplayName
                $exists = $false
                if ($it.PSPath) {
                    foreach ($x in $foundPrograms) { if ($x.PSPath -and $x.PSPath -eq $it.PSPath) { $exists = $true; break } }
                } else {
                    foreach ($x in $foundPrograms) { if ($x.DisplayName -and $x.DisplayName -eq $it.DisplayName) { $exists = $true; break } }
                }
                if (-not $exists) {
                    $foundPrograms.Add($it) | Out-Null
                    Report-AddLine(("DisplayName: {0}" -f $it.DisplayName))
                    if ($it.PSPath) { Report-AddLine(("PSPath: {0}" -f $it.PSPath)) }
                }
            }
        }
    } catch { }
}

# ---------------- RUNNING PROCESSES ----------------
Progress-Message "Scanning running processes..."
Report-AddLine("`n=== Running Processes ===")
try {
    $procs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -imatch [regex]::Escape($AppName) }
    foreach ($pr in $procs) {
        # avoid duplicates by Id
        if (-not ($foundProcesses | Where-Object { $_.Id -eq $pr.Id })) {
            $foundProcesses.Add($pr) | Out-Null
            Report-AddLine(("{0} (Id: {1})" -f $pr.ProcessName, $pr.Id))
        }
    }
} catch { }

# ---------------- FILE LOCATIONS ----------------
Progress-Message "Scanning files & folders..."
Report-AddLine("`n=== File Locations ===")

if ($LiteScan) {
    $fileRoots = @(
        "$env:USERPROFILE\AppData\Local",
        "$env:USERPROFILE\AppData\Roaming"
    )
} elseif ($DeepScan) {
    $fileRoots = @("C:\")
} else {
    $fileRoots = @(
        "$env:ProgramFiles",
        "$env:ProgramFiles(x86)",
        "$env:LOCALAPPDATA",
        "$env:APPDATA",
        "$env:ProgramData"
    )
}

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
            if ($null -ne $it.Name -and ($it.Name -imatch [regex]::Escape($AppName))) {
                # prevent duplicates by FullName
                if (-not ($foundFiles | Where-Object { $_.FullName -eq $it.FullName })) {
                    $foundFiles.Add($it) | Out-Null
                    Report-AddLine($it.FullName)
                }
            }
        }
    } catch { }
}

# ---------------- REGISTRY ENTRIES ----------------
Progress-Message "Scanning registry entries..."
Report-AddLine("`n=== Registry Entries ===")

if ($LiteScan) {
    $regTargets = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    foreach ($key in $regTargets) {
        try {
            $items = Get-ChildItem -Path $key -ErrorAction SilentlyContinue
            foreach ($k in $items) {
                try {
                    $props = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
                    foreach ($prop in $props.PSObject.Properties) {
                        if ($prop.Value -is [string] -and ($prop.Value -imatch [regex]::Escape($AppName))) {
                            if (-not ($foundRegistry -contains $k.PSPath)) {
                                $foundRegistry.Add($k.PSPath) | Out-Null
                                Report-AddLine($k.PSPath)
                            }
                            break
                        }
                    }
                } catch { }
            }
        } catch { }
    }
}
elseif ($DeepScan) {
    $roots = @("HKLM:\", "HKCU:\")
    foreach ($r in $roots) {
        $keys = Get-RegistryKeys-Limited -RootKey $r -MaxDepth $MaxDepth
        foreach ($k in $keys) {
            try {
                $props = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
                foreach ($prop in $props.PSObject.Properties) {
                    if ($prop.Value -is [string] -and ($prop.Value -imatch [regex]::Escape($AppName))) {
                        if (-not ($foundRegistry -contains $k.PSPath)) {
                            $foundRegistry.Add($k.PSPath) | Out-Null
                            Report-AddLine($k.PSPath)
                        }
                        break
                    }
                }
            } catch { }
        }
    }
}
else {
    # Fast mode: uninstall keys + lightweight SOFTWARE subtree
    $regTargets = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    foreach ($key in $regTargets) {
        try {
            $items = Get-ChildItem -Path $key -ErrorAction SilentlyContinue
            foreach ($k in $items) {
                try {
                    $props = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
                    foreach ($prop in $props.PSObject.Properties) {
                        if ($prop.Value -is [string] -and ($prop.Value -imatch [regex]::Escape($AppName))) {
                            if (-not ($foundRegistry -contains $k.PSPath)) {
                                $foundRegistry.Add($k.PSPath) | Out-Null
                                Report-AddLine($k.PSPath)
                            }
                            break
                        }
                    }
                } catch { }
            }
        } catch { }
    }

    $softRoots = @("HKLM:\SOFTWARE", "HKLM:\SOFTWARE\WOW6432Node", "HKCU:\SOFTWARE")
    foreach ($sr in $softRoots) {
        $keys = Get-RegistryKeys-Limited -RootKey $sr -MaxDepth 2
        foreach ($k in $keys) {
            try {
                $props = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
                foreach ($prop in $props.PSObject.Properties) {
                    if ($prop.Value -is [string] -and ($prop.Value -imatch [regex]::Escape($AppName))) {
                        if (-not ($foundRegistry -contains $k.PSPath)) {
                            $foundRegistry.Add($k.PSPath) | Out-Null
                            Report-AddLine($k.PSPath)
                        }
                        break
                    }
                }
            } catch { }
        }
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
$maxLabelLen = ($summary.Label | Measure-Object -Maximum Length).Maximum

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
                if ($foundProcesses.Count -gt 0) { Write-Host "" }
            }
            "Processes Found:" {
                foreach ($proc in $foundProcesses) {
                    Write-Host ("{0,-20} (Id: " -f $proc.ProcessName) -ForegroundColor White -NoNewline
                    Write-Host ("{0}" -f $proc.ID) -ForegroundColor DarkCyan -NoNewline
                    Write-Host ")" -ForegroundColor White
                }
                if ($foundFiles.Count -gt 0) { Write-Host "" }
            }
            "Files/Folders Found:" {
                foreach ($file in $foundFiles) {
                    Write-Host $file.FullName -ForegroundColor White
                }
                if ($foundRegistry.Count -gt 0) { Write-Host "" }
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
    $sb = New-Object System.Text.StringBuilder
    $sb.AppendLine("==== Scan Summary for '$AppName' ====") | Out-Null
    $sb.AppendLine(("Scan Mode: {0} (MaxDepth={1})" -f $ModeName, $MaxDepth)) | Out-Null
    $sb.AppendLine("") | Out-Null

    $sb.AppendLine("Programs Found: $($foundPrograms.Count)") | Out-Null
    foreach ($p in $foundPrograms) {
        if ($p.DisplayName) {
            $sb.AppendLine("  " + $p.DisplayName) | Out-Null
        } else {
            $sb.AppendLine(("  {0}" -f ($p | Out-String).Trim())) | Out-Null
        }
    }

    $sb.AppendLine("") | Out-Null
    $sb.AppendLine("Processes Found: $($foundProcesses.Count)") | Out-Null
    foreach ($pr in $foundProcesses) {
        $sb.AppendLine(("  {0} (Id: {1})" -f $pr.ProcessName, $pr.Id)) | Out-Null
    }

    $sb.AppendLine("") | Out-Null
    $sb.AppendLine("Files/Folders Found: $($foundFiles.Count)") | Out-Null
    foreach ($f in $foundFiles) { $sb.AppendLine("  " + $f.FullName) | Out-Null }

    $sb.AppendLine("") | Out-Null
    $sb.AppendLine("Registry Entries Found: $($foundRegistry.Count)") | Out-Null
    foreach ($r in $foundRegistry) { $sb.AppendLine("  " + $r) | Out-Null }

    [IO.File]::WriteAllText($ReportFile, $sb.ToString(), [System.Text.Encoding]::UTF8)
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
