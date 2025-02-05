# MDE - Windows 11 - Issues might occur with media which installs the October or November update

## Query Information

### Description

When using media to install Windows 11, version 24H2, the device might remain in a state where it cannot accept further Windows security updates. This occurs only when the media is created to include the October 2024, or November 2024, security updates as part of the installation (these updates were released between October 8, 2024 and November 12, 2024).

Use the below query to identify devices that are potentially affected.

Windows 11 Clients with OS Build 26100.2033

#### References

- [Issues might occur with media which installs the October or November update](https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-24h2#issues-might-occur-with-media-which-installs-the-october-or-november-update)

### Microsoft 365 Defender

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
        | summarize arg_max(Timestamp,*) by DeviceId
        | where OSPlatform == @"Windows11"
        | where OSVersionInfo == @"24H2"
        | where OSBuild == "26100"
        | where OsBuildRevision == @"2033")
           on $left.DeviceId == $right.DeviceId
| summarize MissingKBs = make_set(RecommendedSecurityUpdate) by DeviceName
| extend TotalMissingKB = array_length(MissingKBs)
```
