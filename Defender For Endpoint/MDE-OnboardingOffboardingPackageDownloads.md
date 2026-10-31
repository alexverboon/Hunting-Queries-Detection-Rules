---
title: "Microsoft Defender for Endpoint - Onboarding and Offboarding Package Downloads"

description: |
  Audits Microsoft Defender for Endpoint onboarding and offboarding package download events recorded in CloudAppEvents. The query searches the last 30 days and returns the inferred operation, account, IP address, deployment method, operating-system family, and raw event data.

# Options: Draft | InProgress | Stable | Deprecated
status: "Stable"

# Options: Detection | ThreatHunting | ThreatIntelligence | Audit | ExposureManagement | Vulnerability
queryType: "Audit"

risk: |
  An unexpected offboarding package download may warrant investigation because running an offboarding package can stop a device from sending new detection, vulnerability, and security data to Defender for Endpoint. This query detects download events only; it does not establish that a package was run or that a device was offboarded.

author:
  name: "Alex Verboon"
  link: "https://github.com/alexverboon"

references:
  - "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table"
  - "https://learn.microsoft.com/en-us/defender-endpoint/configure-endpoints-script"
  - "https://learn.microsoft.com/en-us/defender-endpoint/offboard-machines"

mitre: []

dataSources:
  - table: "CloudAppEvents"
    solution: "Microsoft Defender XDR"

version: "1.0"
created: "2026-10-31"
lastModified: "2026-10-31"
---

![Status: Stable](https://img.shields.io/badge/status-stable-22c55e.svg)
![Type: Audit](https://img.shields.io/badge/type-audit-3b82f6.svg)
![Language: KQL](https://img.shields.io/badge/language-KQL-blue.svg)

---

# Microsoft Defender for Endpoint - Onboarding and Offboarding Package Downloads

## Query Information

### Description

Audits Defender for Endpoint onboarding and offboarding package download events recorded in `CloudAppEvents`. It searches the last 30 days, identifies the operation from `ActionType` or `RawEventData`, and returns account, IP address, deployment method, operating-system family, and raw event details.

### Risk

An unexpected offboarding package download may warrant investigation because running an offboarding package can stop a device from sending new detection, vulnerability, and security data to Defender for Endpoint. This query detects download events only; it does not establish that a package was run or that a device was offboarded.

### Author

- **Name:** Alex Verboon
- **Link:** <https://github.com/alexverboon>

### References

- [CloudAppEvents table in the advanced hunting schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table)
- [Onboard Windows devices to Microsoft Defender for Endpoint with a local script](https://learn.microsoft.com/en-us/defender-endpoint/configure-endpoints-script)
- [Offboard devices from Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/defender-endpoint/offboard-machines)

### MITRE ATT&CK Technique(s)

No direct mapping assigned. This query identifies package downloads, not package execution or confirmed offboarding.

### Data Sources

| Table | Solution |
| --- | --- |
| `CloudAppEvents` | Microsoft Defender XDR |

### False Positives and Tuning (Optional)

Authorized administrators may download these packages during planned device onboarding, offboarding, or deployment work. Validate the activity against the relevant change request and the account's role.

### Investigation Guidance (Optional)

Review the account, IP address, operation, deployment method, and operating-system family. For offboarding events, correlate with endpoint telemetry and approved change activity to determine whether the package was subsequently used. A download event alone does not confirm execution.

---

## KQL Query

```kql
let Lookback = 30d;
let PackageOperations = dynamic([
    "DownloadOnboardingPkg",
    "DownloadOffboardingPkg"
]);
CloudAppEvents
| where Timestamp > ago(Lookback)
| where ActionType in (PackageOperations)
    or RawEventData has_any (PackageOperations)
| extend Info = parse_json(RawEventData)
| extend
    Operation = case(
        ActionType == "DownloadOnboardingPkg", "Onboarding",
        ActionType == "DownloadOffboardingPkg", "Offboarding",
        tostring(RawEventData) contains "DownloadOnboardingPkg", "Onboarding",
        tostring(RawEventData) contains "DownloadOffboardingPkg", "Offboarding",
        "Unknown"
    ),
    DeploymentMethod = tostring(Info.DeploymentMethod),
    OsFamily = tostring(Info.OsFamily)
| project
    Timestamp,
    Operation,
    AccountDisplayName,
    AccountObjectId,
    IPAddress,
    DeploymentMethod,
    OsFamily,
    ActionType,
    RawEventData
| order by Timestamp desc
```
