# MDE Device Discovery

## Query Information

### Description

Use the below queries to retreieve details about Device Discovery


#### References

- [Device Deiscovery overview](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/device-discovery?view=o365-worldwide)
- [SeenBy function](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-seenby-function?view=o365-worldwide)


### Microsoft 365 Defender


```Kusto
// Device Discovery - what onboarded device discovered the not onboarded Endpoint Device
let AllOnboardedDevices = DeviceInfo
| where Timestamp > ago (30d)
| where OnboardingStatus == 'Onboarded'
| where isnotempty( OSDistribution)
| extend DiscoveryDeviceId = DeviceId
| extend DiscoveryDeviceName = DeviceName
| extend DiscoveryOSDistribution = OSDistribution
| summarize arg_max(Timestamp,DiscoveryDeviceId, DiscoveryDeviceName, DiscoveryOSDistribution) by DiscoveryDeviceId
| project-away Timestamp, DiscoveryDeviceId1;
DeviceInfo
| where Timestamp > ago (30d)
| where OnboardingStatus <> 'Onboarded'
| where DeviceCategory == @"Endpoint"
| where isempty(MergedToDeviceId) 
| summarize arg_max(Timestamp,*) by DeviceId
| invoke SeenBy() 
| mv-expand parse_json(SeenBy)
| extend SeenDeviceId = tostring(parse_json(SeenBy.DeviceId))
| extend LastEncountered = todatetime(tostring(parse_json(SeenBy.LastEncountered)))
| project Timestamp, DeviceId, DeviceName, DeviceCategory, DeviceType, DeviceSubtype, Model, Vendor, OSDistribution, SeenDeviceId, LastEncountered, SeenBy
| summarize arg_max(LastEncountered,*) by DeviceId
| join kind=leftouter  AllOnboardedDevices
on $left.SeenDeviceId == $right.DiscoveryDeviceId 
| project-away SeenDeviceId
```


```Kusto
// Device Discovery - what onboarded device discovered the IoT and Network devices
let AllOnboardedDevices = DeviceInfo
| where Timestamp > ago (30d)
| where OnboardingStatus == 'Onboarded'
| where isnotempty( OSDistribution)
| extend DiscoveryDeviceId = DeviceId
| extend DiscoveryDeviceName = DeviceName
| extend DiscoveryOSDistribution = OSDistribution
| summarize arg_max(Timestamp,DiscoveryDeviceId, DiscoveryDeviceName, DiscoveryOSDistribution) by DiscoveryDeviceId
| project-away Timestamp, DiscoveryDeviceId1;
DeviceInfo
| where Timestamp > ago (30d)
| where DeviceCategory == @"IoT" or DeviceCategory contains  @"NetworkDevice"
| where isempty(MergedToDeviceId) 
| summarize arg_max(Timestamp,*) by DeviceId
| invoke SeenBy() 
| mv-expand parse_json(SeenBy)
| extend SeenDeviceId = tostring(parse_json(SeenBy.DeviceId))
| extend LastEncountered = todatetime(tostring(parse_json(SeenBy.LastEncountered)))
| project Timestamp, DeviceId, DeviceName, DeviceCategory, DeviceType, DeviceSubtype, Model, Vendor, OSDistribution, SeenDeviceId, LastEncountered
| summarize arg_max(LastEncountered,*) by DeviceId
| join kind=leftouter  AllOnboardedDevices
on $left.SeenDeviceId == $right.DiscoveryDeviceId 
| project-away SeenDeviceId
```

