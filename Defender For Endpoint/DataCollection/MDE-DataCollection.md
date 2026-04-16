# Defender for Endpoint - Data Collection Scripts

![KQL](https://img.shields.io/badge/language-KQL-blue.svg)
![Status: In Progress](https://img.shields.io/badge/status-in--progress-yellow.svg)

## Query Information

### Description

The below query retrieves information about the Data Collection scripts that are initiated by Defender for Endpoint.

#### References

### Author

- **Alex Verboon**

## Defender XDR

```kql
let ScriptMap = datatable (ScriptName:string, ScriptDescription:string)
[
  "9e137068-a631-45e6-81aa-4adda242796e.ps1", "Certificate inventory script",
  "211ef051-ecf9-4b99-9eed-76e45a831a19.ps1", "TVM InfoGathering inventory script",
  "7b060674-6027-411f-86aa-13a75308bdb2.ps1", "ImmuneComTelemetryEvent inventory script",
  "53159fd8-6386-48c2-91e8-cf4860599c43.ps1", "Services - RDP inventory script",
  "0e3d6d2d-06cc-486d-9465-9ef3bee75444.ps1", "OpenHandleCollector script",
  "05f2c576-9ed5-41eb-9b1e-1b653eebfdff.ps1", "HKLM:\\Software\\Policies\\Microsoft\\Windows\\DataCollection\\LastUpdate Inventory script",
  "a391f42c-7e1a-4611-8494-1817d2420e09.ps1", "TVM Baselines inventory script",
  "2d76cc84-8291-481d-845d-62f59f16e445.ps1", "TVM Defender AV Settings inventory script",
  "acd1e8f4-3c26-49a7-bec8-9d7a15e1a6d2.ps1", "LoggedOnAWS-Azure-Users inventory script",
  "fc19515e-4fbb-46d1-b1f4-a28b394632fe.ps1", "TVM Browser extensions inventory script",
  "cb7aec68-dfca-4632-88ad-5b019cb0957d.ps1", "AccountLockout Policy inventory script",
  "36dc1ba5-2d7a-4cc0-8b07-8b26d1899492.ps1", "Log4j vulnerability inventory script",
  "149ae17f-1c51-47e8-90b8-8175a782d62b.ps1", "Virtual Machine Info inventory script",
  "3fa4876e-3ae5-4c59-9a4d-08a7400268a5.ps1", "Software - dotnet Info inventory script",
  "9bde6f2a-afcb-4c11-b890-d6a1f78e5c4b.ps1", "Cloud Users inventory script",
  "cfa5b5b7-e717-474f-ad6a-a99ebd513b5c.ps1", "OutboundBlockFirewallRules inventory script",
  "aceb19ff-8484-4db4-b8f6-f5a8d03a8c4a.ps1", "Network Shares inventory script",
  "046a3caf-d9ec-4da6-a32a-fb148992596b.ps1", "NetworkInfo inventory script",
  "8e0b85ee-da90-46d9-b939-75081a1ceb3a.ps1", "TVM - Service Vulnenrabilities inventory script",
  "efc69106-6fc1-423a-94ef-221e65a28f09.ps1", "TVM Computer Info Inventory script",
  "9f2a6e93-4b3c-4a21-9d6a-879ebba4d64d.ps1", "Restore Capability SID permissions",
  "0e371fa0-b3cb-4d76-93ad-467add004280.ps1", "UsersInfoCollector inventory script",
  "47cc89c0-9f6d-434d-aa08-86e36c1dac92.ps1", "ImmuneComTelemetryEvent inventory script",
  "1648ba23-91bf-4822-bd45-661d10a1ea81.ps1", "Pending Reboot Updates inventory script",
  "100c7519-406d-49cb-b7eb-41ce85513276.ps1", "SCCM Agent related inventory script",
  "b3c7fc48-8e45-4cc3-9693-8acbc15a2307.ps1", "TVM Shared Shares Partial inventory script",
  "93514365-7ff3-4f5e-9dfd-7eb9f6b779a7.ps1", "PasswordPolicy inventory script",
  "cb99f1a7-ed1b-4385-a407-7f6229cd6a3b.ps1", "TVM Driver collector inventory script"
];
DeviceProcessEvents
| where InitiatingProcessFileName == @"senseir.exe"
| where ProcessCommandLine has @"C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\DataCollection\"
| extend ExecutedPs1 =
    coalesce(
      extract(@"(?i)(?:-file|/file)\s+['""]([^'""]+\.ps1)['""]", 1, ProcessCommandLine),
      extract(@"'([^']+\.ps1)'", 1, ProcessCommandLine),
      extract(@"""([^""]+\.ps1)""", 1, ProcessCommandLine),
      extract(@"(?i)([A-Za-z]:\\[^\s""']+\.ps1)", 1, ProcessCommandLine)
    )
| extend DataCollectionScript = tolower(tostring(split(ExecutedPs1, "\\")[-1]))
| lookup kind=leftouter ScriptMap on $left.DataCollectionScript == $right.ScriptName
| extend ScriptDescription = coalesce(ScriptDescription, "Other/unknown script")
| project
    TimeGenerated,
    DeviceName,
    DataCollectionScript,
    ScriptDescription,
    InitiatingProcessFileName
| order by TimeGenerated desc
```
