# Microsoft Defender for Endpoint - Device Groups

![KQL](https://img.shields.io/badge/language-KQL-blue.svg)
![Status: Complete](https://img.shields.io/badge/status-complete-brightgreen.svg)

## Query Information

### Description

This query identifies Windows 10 and Windows 11 devices across different device groups in Microsoft Defender for Endpoint, with a focus on discovering devices that end up in the "UnassignedGroup". It provides a pivot table view of device counts organized by OS platform and Device group, helping administrators quickly spot devices that haven't been properly assigned to a Device Group.

#### References

- [Create and manage device groups](https://learn.microsoft.com/en-us/defender-endpoint/machine-groups)

### Author

- **Alex Verboon**

## Defender XDR

Total Devices by OS per Device Group

```kql
let OS = dynamic(["Windows10","Windows11"]);
DeviceInfo
| where TimeGenerated > ago(30d)
| where OSPlatform has_any (OS)
| where OnboardingStatus == 'Onboarded'
| summarize arg_max(TimeGenerated,*) by DeviceId
| summarize DeviceCount = count() by OSPlatform, MachineGroup
| evaluate pivot(MachineGroup, sum(DeviceCount))
| order by OSPlatform asc
```

Detailed list of devices and device groups.

```kql
let OS = dynamic(["Windows10","Windows11"]);
DeviceInfo
| where TimeGenerated > ago(30d)
| where OSPlatform has_any (OS)
| where OnboardingStatus == 'Onboarded'
| summarize arg_max(TimeGenerated,*) by DeviceId
| project MachineGroup, OSPlatform, DeviceName, DeviceId, LoggedOnUsers
| order by MachineGroup asc, OSPlatform asc, DeviceName asc
```