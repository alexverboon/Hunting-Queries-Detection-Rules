---
title: "Defender for Endpoint - Data Collection Scripts"

description: |
  Retrieves process events for PowerShell scripts started by Defender for Endpoint's Data Collection component and enriches known script names with descriptions and purposes. Microsoft updates these scripts, which can result in new GUIDs; unidentified .ps1 scripts are reported as "Other/unknown script" with the purpose "Other / Unknown".

# Options: Draft | InProgress | Stable | Deprecated
status: "Stable"

# Options: Detection | ThreatHunting | ThreatIntelligence | Audit | ExposureManagement | Vulnerability
queryType: "Audit"

risk: "Not applicable"

author:
  name: "Alex Verboon"
  link: "https://github.com/alexverboon"

references:
  - "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table"

dataSources:
  - table: "DeviceProcessEvents"
    solution: "Microsoft Defender XDR"

version: "2.0"
created: "2026-11-16"
lastModified: "2026-11-16"
---

![Status: Stable](https://img.shields.io/badge/status-stable-22c55e.svg)
![Type: Audit](https://img.shields.io/badge/type-audit-3b82f6.svg)
![Language: KQL](https://img.shields.io/badge/language-KQL-blue.svg)

---

# Defender for Endpoint - Data Collection Scripts

## Query Information

### Description

Retrieves process events for PowerShell scripts started by Defender for Endpoint's Data Collection component and enriches known script names with descriptions and purposes. Microsoft updates these scripts periodically, which can result in new GUIDs; unidentified .ps1 scripts are reported as "Other/unknown script" with the purpose "Other / Unknown".

### Risk

Not applicable

### Author

- **Name:** Alex Verboon
- **Link:** https://github.com/alexverboon

### References

- [DeviceProcessEvents table in the advanced hunting schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)

### Data Sources

| Table | Solution |
| --- | --- |
| `DeviceProcessEvents` | Microsoft Defender XDR |

---

## KQL Query

```kql

let ScriptMap = datatable (
    ScriptName:string,
    ScriptDescription:string,
    ScriptPurpose:string
)
[
    "05f2c576-9ed5-41eb-9b1e-1b653eebfdff.ps1", "Updates Windows DataCollection LastUpdate registry value with a generated GUID", "System Configuration",
    "0e371fa0-b3cb-4d76-93ad-467add004280.ps1", "UsersInfoCollector: Collects users, group memberships, logon rights and privileges", "Identity & Access",
    "0e3d6d2d-06cc-486d-9465-9ef3bee75444.ps1", "DdcExeRunner: Loads and executes the OpenHandleCollector helper", "Collector Execution",
    "100c7519-406d-49cb-b7eb-41ce85513276.ps1", "Collects SCCM/MECM client agent service and site configuration", "Infrastructure Discovery",
    "149ae17f-1c51-47e8-90b8-8175a782d62b.ps1", "Collects Hyper-V virtual machine guest integration and host information", "Infrastructure Discovery",
    "163d0383-0c1c-4e5b-ba35-7eb12c62ec1f.ps1", "Discovers SCCM infrastructure, server configuration and service status", "Infrastructure Discovery",
    "1648ba23-91bf-4822-bd45-661d10a1ea81.ps1", "Collects Windows updates requiring a pending reboot", "Patch Management",
    "211ef051-ecf9-4b99-9eed-76e45a831a19.ps1", "Checks vulnerability mitigations including Exchange rules and Apache Tomcat", "Security Assessment",
    "2748432c-4054-4f7e-820d-0de9e5ec3093.ps1", "Collects Azure, AWS, GCP and Azure Arc instance metadata", "Infrastructure Discovery",
    "2d76cc84-8291-481d-845d-62f59f16e445.ps1", "Collects Microsoft Defender Antivirus configuration and protection settings", "Security Assessment",
    "36dc1ba5-2d7a-4cc0-8b07-8b26d1899492.ps1", "Log4jLocalScanner: Scans for Log4Shell vulnerability CVE-2021-44228", "Security Assessment",
    "3fa4876e-3ae5-4c59-9a4d-08a7400268a5.ps1", "Collects executable, .NET assembly, JAR and manifest software metadata", "Software Inventory",
    "53159fd8-6386-48c2-91e8-cf4860599c43.ps1", "ServicesCollector: Collects Windows services including RDP, SMB and WMI", "Device Inventory",
    "663510cf-f4cb-4268-bac1-a0c575b1bcd3.ps1", "Discovers Microsoft Exchange servers and related Active Directory information", "Infrastructure Discovery",
    "67689440-6f56-4fdc-a2a4-55cbb0c3f345.ps1", "Collects Microsoft Entra Connect synchronization services and configuration", "Infrastructure Discovery",
    "71e89914-243c-42d2-8567-6e52454f6954.ps1", "Collects AD FS farm configuration and authentication-related event logs", "Identity & Access",
    "83f59707-e052-422f-9d92-2490db0686e6.ps1", "Contains embedded binary data associated with OpenHandleCollector", "Collector Execution",
    "8e0b85ee-da90-46d9-b939-75081a1ceb3a.ps1", "Inventories Windows services, executable paths, permissions and security weaknesses", "Security Assessment",
    "93514365-7ff3-4f5e-9dfd-7eb9f6b779a7.ps1", "Collects Windows password policy configuration", "Identity & Access",
    "969023c4-546f-45ea-8f49-ca6d45ba75f4.ps1", "Collects Active Directory domain controllers, trusts and directory object statistics", "Infrastructure Discovery",
    "9bde6f2a-afcb-4c11-b890-d6a1f78e5c4b.ps1", "Discovers locally stored AWS, Azure and GCP CLI authentication configurations", "Identity & Access",
    "9e137068-a631-45e6-81aa-4adda242796e.ps1", "Inventories certificates and collects certificate properties", "Security Assessment",
    "9f2a6e93-4b3c-4a21-9d6a-879ebba4d64d.ps1", "Restores registry read permissions for a Microsoft Defender capability SID", "System Configuration",
    "a391f42c-7e1a-4611-8494-1817d2420e09.ps1", "Evaluates Windows security baseline settings and local configuration", "Security Assessment",
    "a7c4be84-977f-411f-a21d-6ecb62b76152.ps1", "Discovers Microsoft Entra Connect installations through Active Directory", "Infrastructure Discovery",
    "acd1e8f4-3c26-49a7-bec8-9d7a15e1a6d2.ps1", "Identifies AWS and Azure accounts from local browser authentication data", "Identity & Access",
    "aceb19ff-8484-4db4-b8f6-f5a8d03a8c4a.ps1", "Enumerates Windows SMB shares, share properties and access permissions", "Security Assessment",
    "b4b3befa-8ef5-48fb-ba4d-87c79987ebde.ps1", "Discovers Active Directory Certificate Services infrastructure", "Infrastructure Discovery",
    "c778e7b5-b450-40a5-b25a-64d3aa98e8ac.ps1", "Discovers Veritas Backup Exec jobs, catalogs and backup storage paths", "Infrastructure Discovery",
    "cb7aec68-dfca-4632-88ad-5b019cb0957d.ps1", "Collects Windows account lockout policy settings", "Identity & Access",
    "cfa5b5b7-e717-474f-ad6a-a99ebd513b5c.ps1", "Collects Windows Firewall outbound blocking rules and application paths", "Security Assessment",
    "e42f96b8-39ab-482c-86c3-db42380f8e06.ps1", "Discovers Hyper-V virtual machines, network adapters and virtual switches", "Infrastructure Discovery",
    "efc69106-6fc1-423a-94ef-221e65a28f09.ps1", "Collects device manufacturer, hardware model and network adapter details", "Device Inventory",
    "fc19515e-4fbb-46d1-b1f4-a28b394632fe.ps1", "Inventories Chromium and Firefox browser extensions across user profiles", "Software Inventory",
    "ff329403-23a5-41b7-a39d-aa72989ddc28.ps1", "Collects detailed Azure AD Connect synchronization and infrastructure configuration", "Infrastructure Discovery"
];
DeviceProcessEvents
| where InitiatingProcessFileName =~ "senseir.exe"
| where ProcessCommandLine contains @"\Microsoft\Windows Defender Advanced Threat Protection\DataCollection\"
| extend DataCollectionScript = tolower(
    coalesce(
        extract(@"(?i)([0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\.ps1)", 1, ProcessCommandLine),
        extract(@"(?i)(?:\\|/)([^\\/'""\s]+\.ps1)", 1, ProcessCommandLine)
    )
)
| where isnotempty(DataCollectionScript)
| lookup kind=leftouter ScriptMap on $left.DataCollectionScript == $right.ScriptName
| extend
    ScriptDescription = coalesce(ScriptDescription, "Other/unknown script"),
    ScriptPurpose = coalesce(ScriptPurpose, "Other / Unknown")
| project
    Timestamp,
    DeviceName,
    DeviceId,
    DataCollectionScript,
    ScriptDescription,
    ScriptPurpose,
    InitiatingProcessFileName,
    ProcessCommandLine
| order by Timestamp desc
```

### Optional follow-on aggregation

Apply this aggregation to the main query's result set to summarize executions by script purpose and name.

```
| summarize
    ExecutionCount = count(),
    DistinctDevices = dcount(DeviceId),
    LastExecution = max(Timestamp)
    by ScriptPurpose, DataCollectionScript, ScriptDescription
| order by ExecutionCount desc
```