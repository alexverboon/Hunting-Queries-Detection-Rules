---
title: "Windows LAPS Password Recovery and Administrator Logon Auditing"
description: |
    This Microsoft Defender XDR Advanced Hunting collection supports an end-to-end investigation of Windows LAPS recovery and subsequent local administrator activity. Start by identifying successful password retrievals and requesters, enrich those events with device inventory, and discover candidate LAPS-managed local accounts from observed administrator logons. Then correlate logons to preceding recoveries, find local administrator logons without an observed recent recovery, and review recovery and password-update timelines. These results are investigative leads: hostname and time correlations do not prove credential use, and observed account names do not confirm LAPS management.
status: "Draft"
queryType: "Audit"
risk: |
    Retrieving a Windows LAPS password provides access to a privileged credential. Unexpected or excessive recoveries, retrievals by unusual identities, and nearby local administrator logons should be investigated. None of these queries alone proves misuse or establishes which local account is managed by LAPS.
author:
  name: "Alex Verboon"
  link: "https://github.com/alexverboon"
references: ["https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview", "https://learn.microsoft.com/en-us/entra/identity/devices/howto-manage-local-admin-passwords", "https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-audit-logs", "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table", "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table", "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-management-event-log"]
mitre: [{ id: "T1078.003", name: "Valid Accounts: Local Accounts", url: "https://attack.mitre.org/techniques/T1078/003/" }]
mitreAtlas: []
dataSources: [{ table: "AuditLogs", solution: "Microsoft Entra ID" }, { table: "DeviceLogonEvents", solution: "Microsoft Defender XDR" }, { table: "DeviceInfo", solution: "Microsoft Defender XDR" }]
version: "3.0"
created: "2026-10-31"
lastModified: "2026-10-31"
---

![Status: Draft](https://img.shields.io/badge/status-draft-9ca3af.svg)
![Type: Audit](https://img.shields.io/badge/type-audit-3b82f6.svg)
![Language: KQL](https://img.shields.io/badge/language-KQL-blue.svg)

# Windows LAPS Password Recovery and Administrator Logon Auditing

## Query Information

### Description

This Microsoft Defender XDR Advanced Hunting collection supports an end-to-end investigation of Windows LAPS recovery and subsequent local administrator activity. Start by identifying successful password retrievals and requesters, enrich those events with device inventory, and discover candidate LAPS-managed local accounts from observed administrator logons. Then correlate logons to preceding recoveries, find local administrator logons without an observed recent recovery, and review recovery and password-update timelines. These results are investigative leads: hostname and time correlations do not prove credential use, and observed account names do not confirm LAPS management.

### Risk

Retrieving a Windows LAPS password provides access to a privileged credential. Unexpected or excessive recoveries, retrievals by unusual identities, and nearby local administrator logons should be investigated. None of these queries alone proves misuse or establishes which local account is managed by LAPS.

### Author

- **Name:** Alex Verboon
- **Link:** https://github.com/alexverboon

### References

- [Windows LAPS overview](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- [Manage Windows LAPS in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/devices/howto-manage-local-admin-passwords)
- [Microsoft Entra audit logs](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-audit-logs)
- [DeviceLogonEvents table in Defender XDR](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table)
- [DeviceInfo table in Defender XDR](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table)
- [Windows LAPS event logs](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-management-event-log)

### MITRE ATT&CK Technique(s)

| Technique ID | Title | Link |
| --- | --- | --- |
| T1078.003 | Valid Accounts: Local Accounts | <https://attack.mitre.org/techniques/T1078/003/> |

This mapping applies to local-administrator logon hunting in Queries 2 and 4–6. LAPS recovery events provide context but do not by themselves prove adversary access.

### Data Sources

| Table | Solution |
| --- | --- |
| `AuditLogs` | Microsoft Entra ID |
| `DeviceLogonEvents` | Microsoft Defender XDR |
| `DeviceInfo` | Microsoft Defender XDR |

### False Positives and Tuning (Optional)

Authorized helpdesk work, break-glass access, automation, and routine local administration may produce expected results. Validate the requester's role, change or incident ticket, the device's configured Windows LAPS account, and any approved password retrieval mechanism. Adjust correlation windows and known administrator names based on environment baselines.

### Investigation Guidance (Optional)

Start with Queries 1 and 7 to identify recovery patterns and requesters. Use Query 3 for device context, Query 4 to discover *observed candidate* local administrator names, and Query 5 for temporal recovery-to-logon correlation. Use Query 6 to find local admin logons with no *observed* recent Entra recovery. Query 8 provides recovery and password-update event context. Confirm the effective managed account through Windows LAPS policy/metadata or endpoint configuration rather than inference from the logon name.

| Step | Query | Investigation question |
| --- | --- | --- |
| 1 | Query 1 | Which devices have had their LAPS passwords recovered? |
| 2 | Query 7 | Who recovered passwords, and across how many devices? |
| 3 | Query 3 | What Defender device context is available for those hosts? |
| 4 | Query 2 | What local account names and administrator logons are observed? |
| 5 | Query 4 | Which candidate local administrator accounts appear on recovered hosts? |
| 6 | Query 5 | Did local administrator logons occur soon after recovery? |
| 7 | Query 6 | Which local admin logons have no observed recent Entra recovery? |
| 8 | Query 8 | Are password update events visible around recovery activity? |

---

## KQL Query

### Query 1 — LAPS password recovery requests by device

**Purpose:** Identify frequently recovered devices, unique requesters, and first/last observed recovery times. `TotalRecoveries` counts events, not users.

```kql
let Lookback = 90d;
AuditLogs
| where TimeGenerated > ago(Lookback)
| where OperationName == "Recover device local administrator password"
| where Result =~ "success"
| extend
    RequestedBy = coalesce(
        tostring(InitiatedBy.user.userPrincipalName),
        tostring(InitiatedBy.app.displayName)
    ),
    Device = tostring(TargetResources[0].displayName)
| where isnotempty(Device)
| summarize
    TotalRecoveries = count(),
    UniqueRequesters = dcount(RequestedBy),
    Requesters = make_set(RequestedBy, 100),
    FirstRecovery = min(TimeGenerated),
    LastRecovery = max(TimeGenerated)
    by Device
| order by TotalRecoveries desc
```

### Query 2 — Discover candidate local administrator account names

**Purpose:** Replace the fragile `AccountName startswith "admin"` filter with local-account and built-in Administrator indicators. Include observed logon types, source IPs, and administrator status.

```kql
let Lookback = 30d;
DeviceLogonEvents
| where TimeGenerated > ago(Lookback)
| where ActionType == "LogonSuccess"
| extend
    HostName = tolower(tostring(split(DeviceName, ".")[0])),
    AccountDomainName = tolower(AccountDomain),
    IsBuiltInAdmin = AccountSid matches regex @"^S-1-5-21-(\d+-){3}500$"
| where AccountDomainName == HostName or IsBuiltInAdmin
| summarize
    TotalLogons = count(),
    FirstLogon = min(TimeGenerated),
    LastLogon = max(TimeGenerated),
    LogonTypes = make_set(LogonType, 20),
    SourceIPs = make_set(RemoteIP, 50),
    AdminLogons = countif(IsLocalAdmin == true)
    by DeviceName, AccountName, AccountDomain, AccountSid, IsBuiltInAdmin
| order by TotalLogons desc
```

**Interpretation:** A local logon account name is only a *candidate*. For custom LAPS accounts, neither the name nor RID 500 reliably identifies the managed account. If the intent is exclusively administrator logons, add `| where IsLocalAdmin == true` before `summarize`.

### Query 3 — Successful recovery enriched with Defender device information

**Purpose:** Enrich each successful recovery with the latest available MDE device information. `DeviceLastSeen` describes the most recent `DeviceInfo` observation, not the recovery time.

```kql
let Lookback = 90d;
let DeviceInventory =
    DeviceInfo
    | summarize arg_max(TimeGenerated, *) by DeviceId
    | extend DeviceKey = tolower(tostring(split(DeviceName, ".")[0]))
    | project
        DeviceKey,
        MDEDeviceName = DeviceName,
        DeviceId,
        AadDeviceId,
        MachineGroup,
        OSPlatform,
        OnboardingStatus,
        SensorHealthState,
        LoggedOnUsers,
        DeviceLastSeen = TimeGenerated;
AuditLogs
| where TimeGenerated > ago(Lookback)
| where OperationName == "Recover device local administrator password"
| where Result =~ "success"
| mv-expand Target = TargetResources
| extend
    RecoveryTime = TimeGenerated,
    RequestedBy = tostring(InitiatedBy.user.userPrincipalName),
    Device = tostring(Target.displayName),
    EntraTargetId = tostring(Target.id)
| where isnotempty(Device)
| extend DeviceKey = tolower(tostring(split(Device, ".")[0]))
| join kind=leftouter DeviceInventory on DeviceKey
| project
    RecoveryTime,
    RequestedBy,
    Device,
    EntraTargetId,
    MDEDeviceName,
    DeviceId,
    AadDeviceId,
    MachineGroup,
    OSPlatform,
    OnboardingStatus,
    SensorHealthState,
    DeviceLastSeen,
    LoggedOnUsers
| order by RecoveryTime desc
```

**Tuning:** `TargetResources` may include more than one resource; verify its type before treating every element as a device. A hostname can map to multiple `DeviceId` values. If the Entra target ID and `AadDeviceId` are confirmed to represent the same identifier in your logs, join on that ID instead.

### Query 4 — Candidate LAPS account names on devices with password recovery

**Purpose:** Identify local administrator names observed on hosts for which an Entra LAPS password recovery occurred. This is a shortlist of **effective account-name candidates**, not proof of the configured LAPS account.

```kql
let Lookback = 90d;
let RecoveredDevices =
    AuditLogs
    | where TimeGenerated > ago(Lookback)
    | where OperationName == "Recover device local administrator password"
    | where Result =~ "success"
    | extend Device = tostring(TargetResources[0].displayName)
    | where isnotempty(Device)
    | extend DeviceKey = tolower(tostring(split(Device, ".")[0]))
    | summarize
        Recoveries = count(),
        LastRecovery = max(TimeGenerated)
        by DeviceKey;
DeviceLogonEvents
| where TimeGenerated > ago(Lookback)
| where ActionType == "LogonSuccess"
| where IsLocalAdmin == true
| extend
    DeviceKey = tolower(tostring(split(DeviceName, ".")[0])),
    AccountDomainKey = tolower(AccountDomain),
    IsBuiltInAdmin = AccountSid matches regex @"^S-1-5-21-(\d+-){3}500$"
| where AccountDomainKey == DeviceKey or IsBuiltInAdmin
| join kind=inner RecoveredDevices on DeviceKey
| summarize
    Logons = count(),
    FirstLogon = min(TimeGenerated),
    LastLogon = max(TimeGenerated),
    LogonTypes = make_set(LogonType, 20),
    SourceIPs = make_set(RemoteIP, 50)
    by DeviceName, AccountName, AccountSid,
       IsBuiltInAdmin, Recoveries, LastRecovery
| order by LastRecovery desc, Logons desc
```

### Query 5 — Correlate LAPS recovery with subsequent local administrator logon

**Purpose:** Find observed local administrator logons on the same hostname within four hours **after** a successful recovery. The requester and logon user are not necessarily the same person.

```kql
let Lookback = 30d;
let CorrelationWindow = 4h;
let Recovery =
    AuditLogs
    | where TimeGenerated between (ago(Lookback) .. ago(CorrelationWindow))
    | where OperationName == "Recover device local administrator password"
    | where Result =~ "success"
    | extend
        RecoveryTime = TimeGenerated,
        RequestedBy = tostring(InitiatedBy.user.userPrincipalName),
        Device = tostring(TargetResources[0].displayName)
    | where isnotempty(Device)
    | extend DeviceKey = tolower(tostring(split(Device, ".")[0]))
    | project RecoveryTime, RequestedBy, Device, DeviceKey;
let LocalAdminLogons =
    DeviceLogonEvents
    | where TimeGenerated > ago(Lookback)
    | where ActionType == "LogonSuccess"
    | where IsLocalAdmin == true
    | extend
        DeviceKey = tolower(tostring(split(DeviceName, ".")[0])),
        AccountDomainKey = tolower(AccountDomain),
        IsBuiltInAdmin = AccountSid matches regex @"^S-1-5-21-(\d+-){3}500$"
    | where AccountDomainKey == DeviceKey or IsBuiltInAdmin
    | project
        DeviceKey,
        LogonTime = TimeGenerated,
        DeviceName,
        AccountName,
        AccountSid,
        LogonType,
        RemoteIP,
        RemoteDeviceName;
Recovery
| join kind=inner LocalAdminLogons on DeviceKey
| where LogonTime between (RecoveryTime .. RecoveryTime + CorrelationWindow)
| extend MinutesAfterRecovery = datetime_diff("minute", LogonTime, RecoveryTime)
| project
    RecoveryTime,
    LogonTime,
    MinutesAfterRecovery,
    DeviceName,
    RequestedBy,
    AccountName,
    AccountSid,
    LogonType,
    RemoteIP,
    RemoteDeviceName
| order by RecoveryTime desc, LogonTime asc
```

**Interpretation:** This is a time-based correlation, not a proof of credential use. An event near the edge of the lookback window may be excluded to ensure the full correlation window has elapsed.

### Query 6 — Local administrator logons without an observed preceding recovery

**Purpose:** Find local administrator logons without a matching Entra LAPS recovery in the preceding 24 hours. Absence of an Entra recovery does **not** mean unauthorized access.

```kql
let Lookback = 30d;
let RecoveryWindow = 24h;
let Recoveries =
    AuditLogs
    | where TimeGenerated > ago(Lookback + RecoveryWindow)
    | where OperationName == "Recover device local administrator password"
    | where Result =~ "success"
    | extend Device = tostring(TargetResources[0].displayName)
    | where isnotempty(Device)
    | extend DeviceKey = tolower(tostring(split(Device, ".")[0]))
    | project DeviceKey, RecoveryTime = TimeGenerated;
let LocalLogons =
    DeviceLogonEvents
    | where TimeGenerated > ago(Lookback)
    | where ActionType == "LogonSuccess"
    | where IsLocalAdmin == true
    | extend
        DeviceKey = tolower(tostring(split(DeviceName, ".")[0])),
        AccountDomainKey = tolower(AccountDomain),
        IsBuiltInAdmin = AccountSid matches regex @"^S-1-5-21-(\d+-){3}500$"
    | where AccountDomainKey == DeviceKey or IsBuiltInAdmin
    | project
        DeviceKey,
        LogonTime = TimeGenerated,
        DeviceName,
        AccountName,
        AccountSid,
        LogonType,
        RemoteIP;
LocalLogons
| join kind=leftouter Recoveries on DeviceKey
| summarize
    PriorRecoveries = countif(
        RecoveryTime between (LogonTime - RecoveryWindow .. LogonTime)
    )
    by DeviceKey, LogonTime, DeviceName, AccountName,
       AccountSid, LogonType, RemoteIP
| where PriorRecoveries == 0
| project-away DeviceKey
| order by LogonTime desc
```

**Interpretation:** Possible explanations include previously cached knowledge of a credential, approved vault-based access, AD-backed LAPS recovery, missing audit ingestion, or an unrelated local administrator account.

### Query 7 — Requesters retrieving LAPS passwords across many devices

**Purpose:** Identify users or apps with high-volume or broad recovery activity. Establish a baseline before setting alert thresholds.

```kql
let Lookback = 30d;
AuditLogs
| where TimeGenerated > ago(Lookback)
| where OperationName == "Recover device local administrator password"
| where Result =~ "success"
| extend
    RequestedBy = coalesce(
        tostring(InitiatedBy.user.userPrincipalName),
        tostring(InitiatedBy.app.displayName)
    ),
    Device = tostring(TargetResources[0].displayName)
| where isnotempty(RequestedBy) and isnotempty(Device)
| summarize
    TotalRecoveries = count(),
    UniqueDevices = dcount(Device),
    Devices = make_set(Device, 100),
    FirstRecovery = min(TimeGenerated),
    LastRecovery = max(TimeGenerated)
    by RequestedBy
| order by UniqueDevices desc, TotalRecoveries desc
```

### Query 8 — LAPS password recovery and update timeline

**Purpose:** Review recoveries alongside recorded password updates. Verify the exact password-update operation name emitted by your tenant before using this query as a rotation control.

```kql
let Lookback = 90d;
AuditLogs
| where TimeGenerated > ago(Lookback)
| where OperationName in (
    "Recover device local administrator password",
    "Update device local administrator password"
)
| extend
    Device = tostring(TargetResources[0].displayName),
    Initiator = coalesce(
        tostring(InitiatedBy.user.userPrincipalName),
        tostring(InitiatedBy.app.displayName)
    ),
    EventType = case(
        OperationName startswith "Recover", "Password recovery",
        OperationName startswith "Update", "Password update",
        "Other"
    )
| project
    TimeGenerated,
    Device,
    EventType,
    OperationName,
    Initiator,
    Result,
    CorrelationId
| order by TimeGenerated desc
```

---

