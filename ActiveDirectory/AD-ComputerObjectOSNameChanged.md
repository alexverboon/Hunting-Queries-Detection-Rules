# Active Directory - Computer Object - Operating System Name changes

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
