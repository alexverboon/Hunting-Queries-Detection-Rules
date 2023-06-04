# Defender for Endpoint - Device Inventory - Windows LTSC devices

## Query Information

### Description

Use the below queries to identify Windows 10 LTSC devices within your MDE inventory

#### References

- [DeviceTvmInfoGathering](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicetvminfogathering-table?view=o365-worldwide)

- [Windows 10 Enterprise LTSC](https://learn.microsoft.com/en-us/windows/whats-new/ltsc/)

### Defender 365

We now have information within the DeviceTvmInfoGathering table about ltsc

```kql
DeviceTvmInfoGathering
| extend AF = parse_json(AdditionalFields)
| evaluate bag_unpack(AF)
| where IsWindowsLtscVersionRunning == @"true"
```

All Windows 10 devices running ltsc and sac, filter on IsLtsc true/false when you just want to see the ltsc/sac devices. 

```kql
let ltscdevices = DeviceTvmInfoGathering
    | summarize arg_max(Timestamp, *) by DeviceId
    | extend LtscDeviceId = DeviceId
    | extend LtscDeviceName = DeviceName
    | extend AF = parse_json(AdditionalFields)
    | evaluate bag_unpack(AF)
    | where IsWindowsLtscVersionRunning == "true"
    | project LtscDeviceId, LtscDeviceName, IsWindowsLtscVersionRunning;
DeviceInfo
| where isnotempty(OSArchitecture)
| summarize arg_max(Timestamp, *) by DeviceId
| where OnboardingStatus == 'Onboarded'
| where OSPlatform == @"Windows10"
| join kind=leftouter (ltscdevices)
    on $left.DeviceId == $right.LtscDeviceId
| extend IsLtsc = iff(IsWindowsLtscVersionRunning == "true", "true", "false")
| project Timestamp, DeviceId, DeviceName, IsLtsc, OSArchitecture, OSPlatform, OSBuild, OSVersionInfo, OSVersion,
    JoinType, MachineGroup
//| summarize count() by IsLtsc
//| render piechart 
```
