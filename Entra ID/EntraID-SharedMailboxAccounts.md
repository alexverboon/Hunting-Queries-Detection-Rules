---
title: "Entra ID - Shared Mailbox Account Sign-in Block Audit"

description: |
  Audits whether the Microsoft Entra ID accounts associated with selected Exchange Online shared mailboxes are blocked from direct sign-in, as Microsoft recommends. The query checks a manually configured list of user principal names (UPNs) and reports the observed account state alongside sign-in activity from the past 30 days.

# Options: Draft | InProgress | Stable | Deprecated
status: "Stable"

# Options: Detection | ThreatHunting | ThreatIntelligence | Audit | ExposureManagement | Vulnerability
queryType: "Audit"

risk: |
  If a shared mailbox account remains enabled and its credentials are compromised, an attacker could sign in as that account instead of using delegated access, potentially reading or sending mail. An enabled account is a configuration finding, not proof of compromise, and no recorded sign-ins do not prove the account is blocked.

author:
  name: "Alex Verboon"
  link: "https://github.com/alexverboon"

references:
  - "https://learn.microsoft.com/en-us/microsoft-365/admin/email/about-shared-mailboxes?view=o365-worldwide#access-and-permissions"
  - "https://learn.microsoft.com/en-us/microsoft-365/admin/email/create-a-shared-mailbox?view=o365-worldwide#create-a-shared-mailbox-and-add-members"
  - "https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-exomailbox?view=exchange-ps"

mitre:
  - id: "T1078.004"
    name: "Valid Accounts: Cloud Accounts"
    url: "https://attack.mitre.org/techniques/T1078/004/"

dataSources:
  - table: "IdentityAccountInfo"
    solution: "Microsoft Defender XDR"
  - table: "IdentityInfo"
    solution: "Microsoft Sentinel UEBA / Microsoft Defender XDR"
  - table: "SigninLogs"
    solution: "Microsoft Sentinel / Microsoft Entra ID"

version: "1.0"
created: "2026-11-18"
lastModified: "2026-11-19"
---

<!-- STATUS: uncomment the badge matching the status above -->
<!-- ![Status: Draft](https://img.shields.io/badge/status-draft-9ca3af.svg) -->
<!-- ![Status: In Progress](https://img.shields.io/badge/status-in%20progress-eab308.svg) -->
![Status: Stable](https://img.shields.io/badge/status-stable-22c55e.svg)
<!-- ![Status: Deprecated](https://img.shields.io/badge/status-deprecated-ef4444.svg) -->

<!-- QUERY TYPE: uncomment the badge matching the queryType above -->
<!-- ![Type: Detection](https://img.shields.io/badge/type-detection-ef4444.svg) -->
<!-- ![Type: Threat Hunting](https://img.shields.io/badge/type-threat%20hunting-f97316.svg) -->
<!-- ![Type: Threat Intelligence](https://img.shields.io/badge/type-threat%20intelligence-a855f7.svg) -->
![Type: Audit](https://img.shields.io/badge/type-audit-3b82f6.svg)
<!-- ![Type: Exposure Management](https://img.shields.io/badge/type-exposure%20management-8b5cf6.svg) -->
<!-- ![Type: Vulnerability](https://img.shields.io/badge/type-vulnerability-eab308.svg) -->

![Language: KQL](https://img.shields.io/badge/language-KQL-blue.svg)

---

# Entra ID - Shared Mailbox Account Sign-in Block Audit

## Query Information

### Description

Audits whether the Microsoft Entra ID accounts associated with selected Exchange Online shared mailboxes are blocked from direct sign-in, as Microsoft recommends. Users should access shared mailboxes through delegated permissions on their own accounts. `IdentityAccountInfo` and `IdentityInfo` do not identify which accounts back shared mailboxes, so the query relies on a manually supplied list of UPNs.

Use `AccountStatus` and `IsAccountEnabled` to review the account state reported by identity records within the lookback window (30 days by default). The query also reports successful and failed sign-in counts, the latest timestamps, and sign-in details from that period. `Not Found` means the query did not match an account record in that window, not that the account is blocked or does not exist.

### Before Running the Query

1. Get the shared mailbox accounts' UPNs from Exchange Online PowerShell or a management portal export. If the export only includes email addresses, look up the corresponding UPNs in Microsoft Entra ID rather than assuming they match.

   ```powershell
   Connect-ExchangeOnline
   Get-EXOMailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited -Properties UserPrincipalName |
       Select-Object -ExpandProperty UserPrincipalName
   ```

2. Replace the sample entries in `TargetUPNs` with the verified UPNs from your tenant.
3. If your data sources retain logs for longer than 30 days, consider increasing `Lookback` (for example, to `90d` if available). This setting applies to both identity records and sign-in logs. Then run the query.

### Risk

If a shared mailbox account remains enabled and its credentials are compromised, an attacker could sign in as that account instead of using delegated access, potentially reading or sending mail. An enabled account is a configuration finding, not proof of compromise. A successful sign-in merits investigation, but does not by itself prove mailbox access. No recorded sign-ins do not prove the account is blocked.

### Author

- **Name:** Alex Verboon
- **Link:** https://github.com/alexverboon

### References

- [Microsoft guidance: Keep direct sign-in blocked for shared mailbox accounts](https://learn.microsoft.com/en-us/microsoft-365/admin/email/about-shared-mailboxes?view=o365-worldwide#access-and-permissions)
- [Create a shared mailbox and review the default sign-in block](https://learn.microsoft.com/en-us/microsoft-365/admin/email/create-a-shared-mailbox?view=o365-worldwide#create-a-shared-mailbox-and-add-members)
- [Get-EXOMailbox: List shared mailbox accounts with Exchange Online PowerShell](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-exomailbox?view=exchange-ps)

### MITRE ATT&CK Technique(s)

| Technique ID | Title | Link |
| --- | --- | --- |
| T1078.004 | Valid Accounts: Cloud Accounts | [https://attack.mitre.org/techniques/T1078/004/](https://attack.mitre.org/techniques/T1078/004/) |

This audit is relevant to Initial Access: an enabled shared mailbox account can provide a direct sign-in path if its credentials are compromised. Neither an enabled account nor a successful sign-in alone establishes adversary use.

### Data Sources

| Table | Solution |
| --- | --- |
| `IdentityAccountInfo` | Microsoft Defender XDR |
| `IdentityInfo` | Microsoft Sentinel UEBA / Microsoft Defender XDR |
| `SigninLogs` | Microsoft Sentinel / Microsoft Entra ID |

### Investigation Guidance (Optional)

1. Verify the current sign-in setting in Microsoft Entra ID for accounts reported as enabled and for rows with missing or conflicting status. If a confirmed shared mailbox account is enabled, block direct sign-in and keep access delegated.
2. Investigate successful sign-ins, including when they occurred relative to any account changes. Review the application, IP address, location, and Conditional Access outcome, and check Exchange audit logs if you need to establish mailbox activity.

---

## KQL Query

```kql
let Lookback = 30d;
let TargetUPNs = datatable (TargetUPN:string)
[
    "securitytesting@avmtplab.onmicrosoft.com",
    "sharedmailbox001@avmtplab.onmicrosoft.com",
    "sharedmailbox002@avmtplab.onmicrosoft.com",
    "sharedmailbox003@avmtplab.onmicrosoft.com"
];
let AccountInfo =
    IdentityAccountInfo
    | where TimeGenerated >= ago(Lookback)
    | summarize arg_max(TimeGenerated, *) by IdentityId
    | extend JoinUPN = tolower(AccountUpn);
let IdentityDetails =
    IdentityInfo
    | where Timestamp >= ago(Lookback)
    | summarize arg_max(Timestamp, *) by IdentityId;
let SignInActivity =
    SigninLogs
    | where TimeGenerated >= ago(Lookback)
    | extend JoinUPN = tolower(UserPrincipalName)
    | extend SignInSuccessful = tostring(ResultType) == "0"
    | summarize
        SignInAttempts = count(),
        SuccessfulSignIns = countif(SignInSuccessful),
        FailedSignIns = countif(not(SignInSuccessful)),
        LastSignIn = max(TimeGenerated),
        LastSuccessfulSignIn = maxif(TimeGenerated, SignInSuccessful),
        LastFailedSignIn = maxif(TimeGenerated, not(SignInSuccessful)),
        SignInDetails = make_set(
            bag_pack(
                "TimeGenerated", TimeGenerated,
                "Successful", SignInSuccessful,
                "Application", AppDisplayName,
                "IPAddress", IPAddress,
                "ResultType", ResultType,
                "ResultDescription", ResultDescription,
                "Location", Location,
                "ConditionalAccessStatus", ConditionalAccessStatus
            ),
            1000
        )
        by JoinUPN;
TargetUPNs
| extend JoinUPN = tolower(TargetUPN)
| join kind=leftouter (
    AccountInfo
) on JoinUPN
| join kind=leftouter (
    IdentityDetails
) on IdentityId
| join kind=leftouter (
    SignInActivity
) on JoinUPN
| extend
    Status = iff(isempty(AccountUpn), "Not Found", "Found"),
    SignInAttempts = coalesce(SignInAttempts, 0),
    SuccessfulSignIns = coalesce(SuccessfulSignIns, 0),
    FailedSignIns = coalesce(FailedSignIns, 0),
    SignInDetails = coalesce(SignInDetails, dynamic([]))
| extend
    HasSignInAttempts = SignInAttempts > 0,
    HasSuccessfulSignIn = SuccessfulSignIns > 0
| project
    TargetUPN,
    Status,
    AccountUpn,
    DisplayName,
    IsAccountEnabled,
    AccountStatus,
    HasSignInAttempts,
    HasSuccessfulSignIn,
    SignInAttempts,
    SuccessfulSignIns,
    FailedSignIns,
    LastSignIn,
    LastSuccessfulSignIn,
    LastFailedSignIn,
    SignInDetails
| order by Status asc, TargetUPN asc
```
