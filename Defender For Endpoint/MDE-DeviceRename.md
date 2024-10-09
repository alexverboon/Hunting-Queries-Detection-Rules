# MDE - Device Rename

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1078 | Initial Access: Valid Accounts | https://attack.mitre.org/techniques/T1078/ |

### Description

Use the below queries to identify Windows devices that have been renamed

#### References

- [Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [Windows Netlogon Elevation of Privilege Vulnerability - CVE-2024-38124](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38124)

### Microsoft Defender XDR

Detect device rename using Defender for Endpoint logs

```kql
let DeviceMultipleNames = (
DeviceInfo
| where isnotempty( HardwareUuid)
| summarize arg_max(Timestamp,*), ComputerNames = make_set(DeviceName), DeviceNameCount = dcount(DeviceName) by HardwareUuid
| where DeviceNameCount > 1
| project Timestamp,  ComputerNames, HardwareUuid);
DeviceMultipleNames
```

Detect device rename when device is AD joined (Requires Defender for Identity)

```kql
IdentityDirectoryEvents
| where ActionType == @"Account Name changed"
| extend FROM_Account_Name = tostring(AdditionalFields.["FROM Account Name"])
| extend TO_Account_Name = tostring(AdditionalFields.["TO Account Name"])
| project TimeGenerated, FROM_Account_Name, TO_Account_Name, ActionType, TargetDeviceName 
```
