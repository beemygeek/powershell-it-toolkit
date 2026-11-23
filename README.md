# PowerShell IT Toolkit

![PowerShell lint](https://github.com/beemygeek/powershell-it-toolkit/actions/workflows/lint.yml/badge.svg)

Practical PowerShell for **help desk, desktop support, and Windows/Active Directory administration** — the repetitive tickets and audits that eat a technician's day, scripted so they're done the same safe way every time.

The scripts include comment-based help (`Get-Help .\Script.ps1 -Full`). Account changes and help desk fixes support `-WhatIf` previews. Output varies by script: provisioning exports CSV results, offboarding writes a JSON audit, quick fixes write a log, and reporting scripts return objects or formatted console output.

GitHub Actions parses the scripts and runs PSScriptAnalyzer on pushes and pull requests. These checks inspect syntax and static rules. Validate Windows, Active Directory, and remote execution behavior in a test environment before using a script for operational work.

## Choose a starting point

| Task | Start here | What to review |
| --- | --- | --- |
| Investigate an endpoint | [Endpoint health check](Endpoint/Get-EndpointHealth.ps1) | CIM session handling, health checks, and the returned Issues field. |
| Investigate failed sign-ins | [Failed-logon report](Security/Get-FailedLogonReport.ps1) | Event XML parsing, failure reason decoding, and grouping by source and account. |
| Review account provisioning | [User onboarding](ActiveDirectory/New-ADUserOnboarding.ps1) | CSV inputs, naming rules, group mapping, and the preview option. |

For detection rules and the response workflow that follow an investigation, see the [SOC Security Lab](https://github.com/beemygeek/soc-security-lab).

## What's inside

| Script | Category | What it solves |
|---|---|---|
| [`New-ADUserOnboarding.ps1`](ActiveDirectory/New-ADUserOnboarding.ps1) | Active Directory | Bulk new-hire accounts from a CSV: unique usernames, correct OU, strong temp password (must change at logon), department groups, results CSV |
| [`Invoke-ADUserOffboarding.ps1`](ActiveDirectory/Invoke-ADUserOffboarding.ps1) | Active Directory | Standardized offboarding: records groups for audit, disables + scrambles password, strips groups, hides from GAL, moves to Disabled OU, writes JSON audit |
| [`Get-StaleADAccounts.ps1`](ActiveDirectory/Get-StaleADAccounts.ps1) | Active Directory / Security | Enabled users and computers that haven't logged on in N days — a common audit finding and attacker foothold |
| [`Get-PasswordExpiryReport.ps1`](ActiveDirectory/Get-PasswordExpiryReport.ps1) | Help desk | Users whose passwords expire soon, so you can reach out *before* the "I can't log in" ticket (honors fine-grained password policies) |
| [`Get-EndpointHealth.ps1`](Endpoint/Get-EndpointHealth.ps1) | Endpoint | One object per PC: disk, memory, uptime, pending reboot, Defender status & signature age, last patch, BitLocker — with a plain-English `Issues` column |
| [`Invoke-HelpdeskQuickFix.ps1`](Endpoint/Invoke-HelpdeskQuickFix.ps1) | Endpoint | Tier 1 fixes as switches: network reset, GP refresh, Teams cache, print spooler, temp files — logged for the ticket |
| [`Get-FailedLogonReport.ps1`](Security/Get-FailedLogonReport.ps1) | Security | Decodes 4625/4740 events and flags **password spraying** (one source, many accounts) vs. **brute force** (one account, many failures) — MITRE T1110 |

## Quick start

```powershell
# Clone and unblock
git clone https://github.com/beemygeek/powershell-it-toolkit.git
cd powershell-it-toolkit
Get-ChildItem -Recurse *.ps1 | Unblock-File

# Always dry-run first
.\ActiveDirectory\New-ADUserOnboarding.ps1 -CsvPath .\examples\new-hires.csv `
    -UpnSuffix contoso.com -GroupMapPath .\examples\department-groups.json -WhatIf

# Check the local computer first
.\Endpoint\Get-EndpointHealth.ps1 | Format-List

# Check several computers using your own hostnames
'PC01', 'PC02' | .\Endpoint\Get-EndpointHealth.ps1 |
    Where-Object Issues | Format-Table ComputerName, Issues -Wrap

# Morning help desk report
.\ActiveDirectory\Get-PasswordExpiryReport.ps1 -WithinDays 7 | Format-Table
```

The onboarding example requires the sample OU, manager, department groups, and UPN suffix to match your test directory. A preview still reads Active Directory and writes a results CSV.

For endpoint checks, inspect the `Reachable` and `Issues` fields. Missing permissions or unavailable Windows components can affect the collected results.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- **Active Directory scripts:** RSAT `ActiveDirectory` module and appropriate delegated rights
- **Remote endpoint checks:** WinRM enabled on targets
- **Security log queries:** membership in *Event Log Readers* or local admin

## Design notes

- **Permissions follow the operation.** Active Directory changes require delegated rights. Endpoint checks and Security log access require the permissions listed above. Onboarding, offboarding, and quick fixes support previews.
- **No secrets in files.** Temporary passwords come from a cryptographic RNG and are shown only on the technician's console — never written to the results CSV.
- **Reviewable output.** Check per-account results and logs after each run. Provisioning depends on current directory state and generates a fresh temporary password for each created account.

## License

MIT
