# Instructions — AD HealthCheck

This document covers everything needed to install prerequisites, run AD HealthCheck, interpret its output, and troubleshoot common issues.

---

## 1. Overview

`ADHealthCheck.ps1` is a single, self-contained PowerShell script that:

1. Prompts for an output folder.
2. Optionally starts the local WMI (`Winmgmt`) service if it is stopped.
3. Presents a menu so you can run a full assessment or a single category.
4. Discovers your forest/domain/DC topology.
5. Runs the selected checks (in parallel where possible).
6. Exports CSV + JSON results and renders an interactive HTML report.

The tool is **read-only** against Active Directory and the domain controllers it queries.

---

## 2. Prerequisites

### 2.1 Operating system & shell

- **Windows** with **Windows PowerShell 5.1**.
- Run from an **elevated** session (Run as Administrator).

Confirm your PowerShell version:

```powershell
$PSVersionTable.PSVersion   # Major should be 5, Minor 1
```

### 2.2 Run location

Run the tool from a **domain-joined** machine — ideally a management/admin workstation or a domain controller — that has network line-of-sight to the domain controllers you want to assess.

### 2.3 Required / recommended modules (RSAT)

The script uses the following modules when present and degrades gracefully when they are not:

| Module | Used for | Required? |
|--------|----------|-----------|
| `ActiveDirectory` | Forest/domain discovery, most checks | Strongly recommended |
| `GroupPolicy` | Group Policy Health checks | Recommended |
| `DnsServer` | DNS Health checks | Recommended |

Install RSAT on **Windows 10/11**:

```powershell
# Active Directory tools
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
# Group Policy management tools
Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0
# DNS server tools
Add-WindowsCapability -Online -Name Rsat.Dns.Tools~~~~0.0.1.0
```

Install RSAT on **Windows Server**:

```powershell
Install-WindowsFeature RSAT-AD-PowerShell, GPMC, RSAT-DNS-Server
```

> If the `ActiveDirectory` module is missing, discovery falls back to .NET `System.DirectoryServices`, and module-dependent checks are reported as **Skipped** with guidance to install RSAT.

### 2.4 Permissions

For complete coverage, run as an account with:

- **Domain Admin / Enterprise Admin** (or equivalent delegated read permissions across the forest).
- Rights to **read remote registry** on domain controllers (used by security hardening checks).
- Rights to query **WMI/CIM** on domain controllers (used by DC resource and NTDS.dit checks).

Lower-privileged accounts will still run the assessment, but more checks may be marked *Skipped* or *Error*.

### 2.5 Connectivity

Ensure the following to/from the assessing host and the DCs:

- DNS resolution of DC hostnames.
- LDAP/LDAPS, RPC, SMB, Remote Registry, and WMI/DCOM (or WinRM) as applicable through any host firewalls.

### 2.6 Execution policy

If scripts are blocked, allow the current process to run it:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

If the file was downloaded from the internet, unblock it first:

```powershell
Unblock-File -Path .\ADHealthCheck.ps1
```

---

## 3. Running the Tool

1. Open **Windows PowerShell as Administrator**.
2. Change to the folder containing the script:

   ```powershell
   Set-Location C:\path\to\ADHealthCheck
   ```

3. Launch it:

   ```powershell
   .\ADHealthCheck.ps1
   ```

4. **Output folder prompt** — enter a path or press **Enter** to accept the default (`Reports` subfolder next to the script).

5. **Winmgmt prompt (conditional)** — if the local WMI service is stopped, you'll be asked whether to start it. Choosing **Y** improves coverage of CPU/memory/disk/NTDS.dit checks. Choosing **N** continues with a warning, and the HTML report notes that those results may be incomplete.

6. **Menu selection** — choose one option:

   | Option | Action |
   |:------:|--------|
   | `1` | Run full assessment (all categories) |
   | `2`–`13` | Run a single category |
   | `Q` | Quit |

7. The tool discovers topology, runs the selected checks, writes results, and generates the HTML report. Progress is logged to the console and to `ADHealthCheck.log`.

### 3.1 Parameters (unattended runs)

The script accepts two optional parameters that let you bypass the interactive prompts — useful for scheduled tasks or automation:

| Parameter | Type | Description |
|-----------|------|-------------|
| `-OutputPath` | string | Folder where reports are written. When supplied, the output-folder prompt is skipped. Defaults to a `Reports` subfolder next to the script. |
| `-MenuOption` | string | The assessment to run, validated to `1`–`13` (`1` = Full Assessment, `2`–`13` = individual categories). When supplied, the interactive menu is skipped. |

```powershell
# Full assessment, unattended, to a specific folder
.\ADHealthCheck.ps1 -OutputPath 'D:\Reports' -MenuOption 1

# Single category (e.g. DNS Health = option 5)
.\ADHealthCheck.ps1 -MenuOption 5
```

> The Winmgmt prompt may still appear if the local WMI service is stopped. Start the service beforehand for fully unattended runs.

---

## 4. Understanding the Output

A new folder `ADHealthCheck-<COMPUTERNAME>-<timestamp>` is created under your chosen output path:

| File | Purpose |
|------|---------|
| `ADHealthCheckReport.html` | Primary deliverable — open in any modern browser |
| `ADHealthCheckResults.csv` | All findings (Check ID, category, status, finding, recommendation, reference, etc.) |
| `ADHealthCheckScores.json` | Overall score, rating, and per-category scores |
| `ForestTopology.json` | Discovered forest, domains, DCs, sites, and trusts |
| `ADHealthCheck.log` | Timestamped run log |

### 4.1 Reading the HTML report

- **Executive Summary** — overall health score (0–100), letter grade (A–F), risk rating, and counts of Passed / Failed / Warning / Info / Critical checks.
- **Category Scorecards** — a per-category score ring with pass/fail/warn breakdown.
- **Detailed Findings** — filterable tables (per category and combined). Click **View Details** on any row to see evidence, reference, and the underlying query.
- **User Overrides** — mark a non-passing finding as *Mitigated*, *False Positive*, or *Accept Risk*, then click **Regenerate Report** to produce an updated, recalculated copy entirely in the browser.
- **Understanding Your Score** — an in-report explanation of the scoring methodology and category weights.

### 4.2 Finding statuses

| Status | Meaning | Base score |
|--------|---------|:----------:|
| Pass | Check satisfied | 100 |
| Info | Informational context, no penalty | 100 |
| Skipped | Could not run (e.g. module/host unavailable) | 85 |
| Partial | Partially satisfied | 70 |
| Warning | Sub-optimal, should be reviewed | 50 |
| Fail | Not satisfied — remediation required | 0 |

---

## 5. Tips for Large Environments

- The full assessment runs check phases in **parallel** (throttle limit 6) when more than two phases are selected. Single/dual category runs execute sequentially.
- Run from a host **close to the PDC Emulator** / well-connected site to reduce latency.
- If you only need a focused look (e.g. after a change), run an individual category from the menu instead of the full assessment.

---

## 6. Troubleshooting

| Symptom | Likely cause | Resolution |
|---------|--------------|------------|
| "ActiveDirectory module unavailable" in findings | RSAT AD tools not installed | Install RSAT (see §2.3) and re-run |
| Many checks marked **Skipped** or **Error** | Insufficient permissions or blocked connectivity | Run as Domain/Enterprise Admin; verify firewall/DNS/RPC/WMI access |
| CPU/Memory/Disk/NTDS.dit results missing | Local `Winmgmt` service stopped, or remote WMI blocked | Allow the tool to start Winmgmt; ensure remote WMI/CIM is reachable |
| Script blocked from running | Execution policy | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` |
| "running scripts is disabled" after download | File marked from internet | `Unblock-File .\ADHealthCheck.ps1` |
| Empty/partial HTML report | No results generated (all skipped) | Check `ADHealthCheck.log` and permissions/connectivity |
| Security hardening checks all fail/skip | Remote Registry access denied | Ensure the account can read remote registry on DCs |

Always inspect `ADHealthCheck.log` in the output folder first — it records each phase, timing, and any errors encountered.

---

## 7. Safety Notes

- The tool **does not modify** Active Directory, DC registry, or DC settings. It only reads state.
- The only optional local change is starting the **Winmgmt** service when you approve it.
- Run with proper authorization and in line with your organization's change/security policies.
- Test in a lab or non-production forest before first use in production.
