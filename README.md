# AD HealthCheck

A comprehensive, menu-driven **Active Directory health and security assessment** tool written in PowerShell. It discovers your forest and domain topology, runs a broad battery of operational and security checks against every reachable domain controller, scores the results, and produces a polished, interactive HTML report alongside machine-readable CSV/JSON output.

> **Author:** Abdullah Zmaili · **Version:** 2.0 · **Platform:** Windows PowerShell 5.1

---

## Highlights

- **12 assessment categories** spanning configuration, replication, DNS, security hardening, hygiene, GPOs, SYSVOL, sites, FSMO, time, and backup.
- **Single self-contained script** — no external modules to install beyond standard RSAT tooling.
- **Interactive HTML report** with an executive summary, per-category scorecards, an overall health score with letter grade and risk rating, filterable findings tables, evidence drill-downs, and per-finding user overrides ("Mitigated", "False Positive", "Accept Risk") that can regenerate the report in-browser.
- **Two-level weighted scoring** that prioritizes the categories that matter most to AD security (Security & Hardening carries the highest weight).
- **Parallel execution** of check phases via PowerShell runspaces for faster runs on large forests.
- **Graceful degradation** — when the ActiveDirectory module or a remote host is unavailable, affected checks are marked *Skipped* with remediation guidance rather than failing the run.
- **Actionable output** — every failed or warning finding includes a recommendation, severity, reference (CIS / Microsoft / MITRE ATT&CK), and supporting evidence.

---

## What It Checks

The tool groups checks into the following categories (menu order):

| # | Category | Focus |
|---|----------|-------|
| 1 | **Run Full Assessment** | Executes all categories below |
| 2 | Forest & Domain Configuration | Forest/domain functional levels, schema version, naming contexts, RODCs, Recycle Bin, SCPs |
| 3 | Domain Controller Health | DC reachability, services, CPU/memory/disk, NTDS.dit |
| 4 | Replication Health | Inbound/outbound replication, failures, lingering objects |
| 5 | DNS Health | Zones, forwarders, scavenging, DC resolution |
| 6 | Security & Hardening | Pass-the-Hash mitigations, LSASS protection, NTLM, LAPS, KRBTGT, Kerberoasting, AS-REP roasting, DCSync rights, anonymous access |
| 7 | User & Computer Hygiene | Stale accounts, password policy, privileged group membership |
| 8 | Group Policy Health | Unlinked/orphaned GPOs, Default Domain Policy, SYSVOL/AD consistency |
| 9 | SYSVOL & File Replication | DFSR/FRS state, SYSVOL replication consistency |
| 10 | Sites & Topology | Site/subnet mapping, site links, connection objects |
| 11 | FSMO Roles | Role placement and holder reachability |
| 12 | Time Synchronization | w32time configuration, PDC hierarchy |
| 13 | Backup & Recovery | AD backup recency, Recycle Bin, trust health |

Each check is identified by a stable ID (e.g. `SEC-061`, `RP-001`, `DNS-002`) and mapped, where relevant, to CIS Benchmarks, Microsoft guidance, and MITRE ATT&CK techniques.

---

## Requirements

- **Windows PowerShell 5.1** (run as Administrator).
- A domain-joined host with **network connectivity** to the target domain controllers.
- **RSAT — Active Directory** (`ActiveDirectory` PowerShell module) recommended. Without it, the script falls back to .NET directory services for discovery and skips checks that strictly require the module.
- For full coverage, also install the RSAT **GroupPolicy** and **DnsServer** modules.
- Appropriate **administrative rights** in the forest (Domain Admin / Enterprise Admin or equivalent delegated permissions) for complete data collection.
- **Remote Registry** and **WMI/CIM (Winmgmt)** access to domain controllers for hardening and resource checks.

See [INSTRUCTIONS.md](INSTRUCTIONS.md) for detailed prerequisite setup.

---

## Quick Start

```powershell
# From an elevated PowerShell prompt on a domain-joined host:
Set-Location C:\path\to\ADHealthCheck
.\ADHealthCheck.ps1
```

You'll be prompted for an output folder, then presented with the assessment menu. Choose **[1]** for a full assessment. See [QUICKSTART.md](QUICKSTART.md) for a step-by-step walkthrough.

### Parameters (optional)

Run unattended by supplying parameters to skip the prompts:

| Parameter | Description |
|-----------|-------------|
| `-OutputPath` | Folder where reports are written. Skips the output-folder prompt. Defaults to a `Reports` subfolder next to the script. |
| `-MenuOption` | Assessment to run, matching the menu numbers (`1` = Full Assessment, `2`–`13` = individual categories). Skips the interactive menu. |

```powershell
# Unattended full assessment to a specific folder
.\ADHealthCheck.ps1 -OutputPath 'D:\Reports' -MenuOption 1

# Run only the Security & Hardening category
.\ADHealthCheck.ps1 -MenuOption 6
```

---

## Output

Each run creates a timestamped folder named `ADHealthCheck-<COMPUTERNAME>-<yyyyMMdd-HHmmss>` under your chosen output path, containing:

| File | Description |
|------|-------------|
| `ADHealthCheckReport.html` | Interactive, self-contained HTML report (open in any browser) |
| `ADHealthCheckResults.csv` | All findings in tabular form |
| `ADHealthCheckScores.json` | Overall and per-category scores |
| `ForestTopology.json` | Discovered forest/domain/DC/site/trust topology |
| `ADHealthCheck.log` | Full run log |

---

## Scoring Model

The overall health score is a **two-level weighted average**:

1. **Per-check score** — each check earns a base score by status (`Pass`/`Info` = 100, `Skipped` = 85, `Partial` = 70, `Warning` = 50, `Fail` = 0), adjusted by an optional `ScoreImpact` penalty and multiplied by the check's `Weight`.
2. **Category weighting** — categories are combined by importance:

| Category | Weight |
|----------|:------:|
| Security & Hardening | 25% |
| Domain Controller Health | 15% |
| Replication Health | 15% |
| DNS Health | 10% |
| Forest & Domain Configuration | 10% |
| User & Computer Hygiene | 10% |
| Group Policy Health | 10% |
| SYSVOL & File Replication | 5% |
| Sites & Topology | 5% |
| Backup & Recovery | 4% |
| FSMO Roles | 3% |
| Time Synchronization | 3% |

The resulting score maps to a grade (A–F) and risk rating (Low → Critical), both shown at the top of the HTML report.

---

## Safety & Scope

This tool is **read-only**: it queries configuration and state. It does not modify Active Directory, registry values, or any domain controller settings. The only write the optional prompt performs is offering to start the local **Winmgmt** service if it is stopped. All output is written to the folder you specify.

> Always run assessment tooling with authorization and in accordance with your organization's change and security policies. Findings reflect configuration state at collection time and should be reviewed alongside operational context and compensating controls before acting.

---

## Documentation

- **[INSTRUCTIONS.md](INSTRUCTIONS.md)** — full prerequisites, configuration, usage details, and troubleshooting.
- **[QUICKSTART.md](QUICKSTART.md)** — get a report in under five minutes.


---

## Disclaimer

This project is provided "as is", without warranty of any kind. Test in a non-production or lab environment first. The author is not responsible for any impact resulting from its use.
