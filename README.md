# Find-App.ps1

**Find-App.ps1** is a PowerShell script designed to scan for applications on a Windows system. It searches across the registry, running processes, and files. The script supports quick, deep, or lite scans, can save reports, and optionally delete found applications.

---

## Features

- Scan for applications by name in the registry, processes, and files.
- Choose between **Lite**, **Fast**, or **Deep** scans.
- Run silently with minimal output.
- Save scan results to a report.
- Delete found applications automatically.
- Built-in examples for guidance.

---

## Requirements

- PowerShell 5.1 or higher
- Windows OS

---

## Usage

```powershell
.\Find-App.ps1 -AppName "<ApplicationName>" [Switches]
```

### Switches

```	ext
-LiteScan      : Perform a quick scan (minimal registry depth).
-DeepScan      : Perform a thorough scan (full registry depth).
-Silent        : Run the scan silently, showing only summary counts.
-SaveReport    : Save the scan results to a report file.
-DeleteFound   : Automatically delete found applications.
-Examples      : Show usage examples.
```

---

## Examples

```powershell
# Example 1: Fast scan for Discord
.\Find-App.ps1 -AppName "Discord"

# Example 2: Lite scan for Zoom
.\Find-App.ps1 -AppName "Zoom" -LiteScan

# Example 3: Deep scan for Spotify and save report
.\Find-App.ps1 -AppName "Spotify" -DeepScan -SaveReport

# Example 4: Run a silent scan for Slack
.\Find-App.ps1 -AppName "Slack" -Silent

# Example 5: Delete found application Chrome
.\Find-App.ps1 -AppName "Chrome" -DeleteFound
```

---

## Notes

- `-AppName` is required for all scan operations.
- `-Examples` switch is a separate parameter set and will **not** prompt for an app name.
- Colors in the output help highlight important information (process IDs, registry keys, etc.).

---

## Author

Neriton Paçarizi

