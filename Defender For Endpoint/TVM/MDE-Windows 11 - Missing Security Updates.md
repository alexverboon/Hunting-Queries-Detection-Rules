# Windows 10 - Missing Security Updates - Windows 11

## Query Information

### Description

The below query provides an overview of missing security updates for Windows 11 devices

#### References

### Microsoft 365 Defender

Overview Missing KBs Windows 11

```kql
DeviceTvmSoftwareVulnerabilities
| where SoftwareVendor == 'microsoft'
| where SoftwareName == 'windows_11'
| where isnotempty(RecommendedSecurityUpdate)
| distinct DeviceId, RecommendedSecurityUpdate, RecommendedSecurityUpdateId, SoftwareName
| join kind=leftouter (
    DeviceInfo
    | where isnotempty(OSPlatform)
    | where OnboardingStatus == 'Onboarded'
    | where isnotempty(OSVersionInfo)
    | summarize arg_max(Timestamp, *) by DeviceId)
    on $left.DeviceId == $right.DeviceId
| summarize MissingDevices = make_set(DeviceName) by SoftwareName, RecommendedSecurityUpdate, RecommendedSecurityUpdateId, OSVersionInfo
| extend TotalMissingKBDevice = array_length(MissingDevices)
| project ['Bulletin'] = RecommendedSecurityUpdate, ['ID'] = RecommendedSecurityUpdateId, ['Total Exposed devices'] = TotalMissingKBDevice, ['Exposed devices'] = MissingDevices, OSVersionInfo
---

Details missing KBs Windows 11

---kql
DeviceTvmSoftwareVulnerabilities
| where SoftwareVendor == 'microsoft'
| where SoftwareName == 'windows_11'
| where isnotempty(RecommendedSecurityUpdate)
| distinct DeviceId, RecommendedSecurityUpdate, RecommendedSecurityUpdateId, SoftwareName
| join kind=leftouter (
    DeviceInfo
    | where isnotempty(OSPlatform)
    | where OnboardingStatus == 'Onboarded'
    | where isnotempty(OSVersionInfo)
    | summarize arg_max(Timestamp, *) by DeviceId)
    on $left.DeviceId == $right.DeviceId
| summarize MissingKBs = make_set(RecommendedSecurityUpdate) by DeviceName
| extend TotalMissingKB = array_length(MissingKBs)

```
