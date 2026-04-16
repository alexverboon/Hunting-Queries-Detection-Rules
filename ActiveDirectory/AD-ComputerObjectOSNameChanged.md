# Active Directory - Computer Object - Operating System Name changes

![KQL](https://img.shields.io/badge/language-KQL-blue.svg)
![Status: Stable](https://img.shields.io/badge/status-stable-brightgreen.svg)

## Query Information

### Description

Use the below query to identify Active Directory Computer Object Operating System name changes

#### References

### Microsoft Defender XDR

```kql
IdentityDirectoryEvents
| where ActionType == @"Device Operating System changed"
| extend FROMDeviceOperatingSystem = parse_json(AdditionalFields)["FROM Device Operating System"]
| extend TODeviceOperatingSystem = parse_json(AdditionalFields)["TO Device Operating System"]
| project
    TimeGenerated,
    TargetDeviceName,
    FROMDeviceOperatingSystem,
    TODeviceOperatingSystem
| summarize arg_max(TimeGenerated, *) by TargetDeviceName
```
