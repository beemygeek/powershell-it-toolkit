# PowerShell IT Toolkit

![PowerShell lint](https://github.com/beemygeek/powershell-it-toolkit/actions/workflows/lint.yml/badge.svg)

Practical PowerShell for **help desk, desktop support, and Windows/Active Directory administration** — the repetitive tickets and audits that eat a technician's day, scripted so they're done the same safe way every time.

Every script:

- has full comment-based help (`Get-Help .\Script.ps1 -Full`)
- supports **`-WhatIf`** wherever it changes anything
- leaves an **audit trail** (CSV / JSON / log) suitable for attaching to a ticket
- is parse-checked and linted with PSScriptAnalyzer on every push

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

# Health check every machine in a list, show only the ones with problems
Get-Content .\computers.txt | .\Endpoint\Get-EndpointHealth.ps1 |
    Where-Object Issues | Format-Table ComputerName, Issues -Wrap

# Morning help desk report
.\ActiveDirectory\Get-PasswordExpiryReport.ps1 -WithinDays 7 | Format-Table
```

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- **Active Directory scripts:** RSAT `ActiveDirectory` module and appropriate delegated rights
- **Remote endpoint checks:** WinRM enabled on targets
- **Security log queries:** membership in *Event Log Readers* or local admin

## Design notes

- **Least privilege.** Read-only reports never require more than read rights; only onboarding/offboarding change AD, and both are `-WhatIf`-able (offboarding asks for confirmation by default).
- **No secrets in files.** Temporary passwords come from a cryptographic RNG and are shown only on the technician's console — never written to the results CSV.
- **Repeatable.** The same inputs produce the same result, which is what you want when an auditor asks "how do you offboard users?"

## License

MIT
