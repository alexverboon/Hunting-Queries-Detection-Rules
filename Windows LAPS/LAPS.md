# TITLE

![KQL](https://img.shields.io/badge/language-KQL-blue.svg)

![Status: Work in Progress](https://img.shields.io/badge/status-work--in--progress-yellow.svg)
![Status: In Progress](https://img.shields.io/badge/status-in--progress-yellow.svg)
![Status: Complete](https://img.shields.io/badge/status-complete-brightgreen.svg)
![Status: Done](https://img.shields.io/badge/status-done-green.svg)
![Status: Draft](https://img.shields.io/badge/status-draft-lightgrey.svg)
![Status: Planned](https://img.shields.io/badge/status-planned-blue.svg)
![Status: Pending](https://img.shields.io/badge/status-pending-orange.svg)
![Status: Pending Review](https://img.shields.io/badge/status-pending--review-blue.svg)
![Status: Under Review](https://img.shields.io/badge/status-under--review-blue.svg)
![Status: On Hold](https://img.shields.io/badge/status-on--hold-yellow.svg)
![Status: Blocked](https://img.shields.io/badge/status-blocked-red.svg)
![Status: Deprecated](https://img.shields.io/badge/status-deprecated-critical.svg)
![Status: Archived](https://img.shields.io/badge/status-archived-lightgrey.svg)
![Status: Maintenance](https://img.shields.io/badge/status-maintenance-orange.svg)
![Status: Alpha](https://img.shields.io/badge/status-alpha-yellow.svg)
![Status: Beta](https://img.shields.io/badge/status-beta-blue.svg)
![Status: Preview](https://img.shields.io/badge/status-preview-blueviolet.svg)
![Status: Stable](https://img.shields.io/badge/status-stable-brightgreen.svg)
![Status: Experimental](https://img.shields.io/badge/status-experimental-red.svg)
![Status: Testing](https://img.shields.io/badge/status-testing-blue.svg)




## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1110.003 | Credential Access: Brute Force: Password Spraying | https://attack.mitre.org/techniques/T1110/003/ |

### Description

DESCRIPTION

#### References

### Author

- **Alex Verboon**

## Defender XDR

```kql
```

## Sentinel

```kql
```



AuditLogs
| where OperationName == @"Recover device local administrator password"
| extend InitiatedByUser = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend Device = tostring(TargetResources[0].displayName)
| summarize Initiators = make_set(InitiatedByUser), Total =  dcount(InitiatedByUser) by Device
| project Device, Total, Initiators
| sort by Total



DeviceLogonEvents
| where tolower(AccountName) startswith  "admin"
| project TimeGenerated, DeviceName, AccountDomain, ActionType, FailureReason, LogonType
| where ActionType == @"LogonSuccess"
| summarize Total=count() by DeviceName
| sort by Total



AuditLogs
| where OperationName in ('Recover device local administrator password')
| where Result == "success"
| extend User = (parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| mv-expand TargetResources
| extend Device = tolower(parse_json(TargetResources).displayName)
| project TimeGenerated,User, Device, OperationName
| join kind=leftouter (DeviceInfo
| summarize arg_max(TimeGenerated,*) by DeviceId
| extend MDEDeviceName = tolower(split(DeviceName,".")[0]))
on $left. Device == $right. MDEDeviceName
| project TimeGenerated, User, Device, OperationName,LoggedOnUsers, MachineGroup, OSPlatform