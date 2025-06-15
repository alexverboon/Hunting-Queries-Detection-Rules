# Windows Server & Client Missing Updates

## Query Information

### Description

#### References

### Microsoft 365 Defender

```kql
DeviceTvmSoftwareVulnerabilities
| where SoftwareVendor == 'microsoft'
| where SoftwareName has_any ('windows_11','windows_10','Windows_Server')
| where isnotempty(RecommendedSecurityUpdate)
| distinct DeviceId, RecommendedSecurityUpdate, RecommendedSecurityUpdateId, SoftwareName
| join kind=leftouter (
    DeviceInfo
    | where isnotempty(OSPlatform)
    | where OnboardingStatus == 'Onboarded'
    | where isnotempty(OSVersionInfo)
    | summarize arg_max(Timestamp, *) by DeviceId)
    on $left.DeviceId == $right.DeviceId
| summarize MissingDevices = make_set(DeviceName) by SoftwareName
| extend TotalMissingKBDevice = array_length(MissingDevices)
| project  ['Total Exposed devices'] = TotalMissingKBDevice,  SoftwareName
```
