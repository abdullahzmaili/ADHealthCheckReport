# Quick Start — AD HealthCheck

Get an Active Directory health report in a few minutes.

---

## Before you begin

- You're on a **domain-joined Windows** machine with **PowerShell 5.1**.
- You can open PowerShell **as Administrator**.
- Your account has **administrative (read) rights** in the forest.
- *(Recommended)* RSAT Active Directory tools are installed:

  ```powershell
  Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
  ```

---

## 3 steps to a report

### 1. Open an elevated PowerShell and go to the script folder

```powershell
Set-Location C:\path\to\ADHealthCheck
```

If the script was downloaded, unblock it once:

```powershell
Unblock-File -Path .\ADHealthCheck.ps1
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### 2. Run the script

```powershell
.\ADHealthCheck.ps1
```

Answer the prompts:

- **Output folder** — press **Enter** for the default.
- **Start Winmgmt?** *(only if it's stopped)* — press **Y** for best coverage.
- **Menu** — type **`1`** and press **Enter** to run a full assessment.

> **Prefer one command?** Skip the prompts with parameters:
>
> ```powershell
> .\ADHealthCheck.ps1 -OutputPath 'D:\Reports' -MenuOption 1
> ```
>
> `-MenuOption` accepts `1` (full) or `2`–`13` (a single category).

### 3. Open your report

When it finishes, open the HTML file from the new output folder:

```powershell
# Opens the most recent report
$latest = Get-ChildItem -Recurse -Filter ADHealthCheckReport.html |
          Sort-Object LastWriteTime -Descending | Select-Object -First 1
Invoke-Item $latest.FullName
```

---

## What you get

In a folder named `ADHealthCheck-<COMPUTERNAME>-<timestamp>`:

| File | What it is |
|------|------------|
| `ADHealthCheckReport.html` | Interactive report — **start here** |
| `ADHealthCheckResults.csv` | All findings as a table |
| `ADHealthCheckScores.json` | Scores per category |
| `ForestTopology.json` | Discovered topology |
| `ADHealthCheck.log` | Run log |

---

## Reading the report in 30 seconds

1. **Top of page** — overall **health score**, **grade (A–F)**, and **risk rating**.
2. **Category Scorecards** — see which areas are strong or weak.
3. **Detailed Findings** — filter and click **View Details** for evidence and remediation.
4. **Overrides** — mark items as *Mitigated / False Positive / Accept Risk*, then **Regenerate Report**.

---

## Want a focused run?

Instead of `1` (full assessment), pick a single category at the menu:

| Type | Runs |
|:----:|------|
| `6` | Security & Hardening |
| `4` | Replication Health |
| `5` | DNS Health |
| `3` | Domain Controller Health |

(See the full menu list in [INSTRUCTIONS.md](INSTRUCTIONS.md).)

---

## Stuck?

- Lots of **Skipped** findings → install RSAT and run as an admin account.
- Missing **CPU/Memory/Disk** results → allow the tool to start **Winmgmt**.
- Script won't run → `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`.

For detailed help, see **[INSTRUCTIONS.md](INSTRUCTIONS.md)**.
