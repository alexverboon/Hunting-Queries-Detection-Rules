# Defender for Endpoint - Active - Inactive Devices

![KQL](https://img.shields.io/badge/language-KQL-blue.svg)
![Status: Complete](https://img.shields.io/badge/status-complete-brightgreen.svg)

## Query Information

### Description

This query allows to identify active and non-active devices.

#### References

### Author

- **Alex Verboon**

## Defender XDR

```kql
let ActiveThresholdDays = 30;
let OS = dynamic(["Windows10","Windows11"]);
DeviceInfo
| where TimeGenerated > ago(30d)
| where OSPlatform has_any (OS)
| where OnboardingStatus == 'Onboarded'
| summarize arg_max(TimeGenerated,*) by DeviceId
| extend LastSeen = Timestamp
| extend DaysSinceLastSeen = datetime_diff("day", now(), LastSeen)
| extend DynamicTagsArray = iif(isnull(DeviceDynamicTags), 
    dynamic([]), todynamic(DeviceDynamicTags))
| project TimeGenerated,LastSeen, DaysSinceLastSeen,DeviceName, OSPlatform, MachineGroup, DynamicTagsArray 
// Show all active devices
//| where DaysSinceLastSeen <= ActiveThresholdDays
// Show all inactive devices
| where DaysSinceLastSeen >=  ActiveThresholdDays
```

With state column

```kql
let ActiveThresholdDays = 30;
let OS = dynamic(["Windows10","Windows11"]);
DeviceInfo
| where TimeGenerated > ago(30d)
| where OSPlatform has_any (OS)
| where OnboardingStatus == 'Onboarded'
| summarize arg_max(TimeGenerated,*) by DeviceId
| extend LastSeen = Timestamp
| extend DaysSinceLastSeen = datetime_diff("day", now(), LastSeen)
| extend DynamicTagsArray = iif(isnull(DeviceDynamicTags), 
    dynamic([]), todynamic(DeviceDynamicTags))
| extend State = iif(DaysSinceLastSeen <= ActiveThresholdDays, "🟢 Active", "⚪ Inactive")
| project TimeGenerated, LastSeen, DaysSinceLastSeen, State,
          DeviceName, OSPlatform, MachineGroup, DynamicTagsArray
```