# MDE - Windows 11 - Issues might occur with media which installs the October or November update

## Query Information

### Description

When using media to install Windows 11, version 24H2, the device might remain in a state where it cannot accept further Windows security updates. This occurs only when the media is created to include the October 2024, or November 2024, security updates as part of the installation (these updates were released between October 8, 2024 and November 12, 2024).

Use the below query to identify devices that are potentially affected.

Windows 11 Clients with OS Build 26100 and Revisions 2033,2161,2314,2454,863,1742

#### References

- [Issues might occur with media which installs the October or November update](https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-24h2#issues-might-occur-with-media-which-installs-the-october-or-november-update)

### Credits

[Janic Verboon](https://bsky.app/profile/janicv.bsky.social) Intune Queries

### Microsoft Defender XDR

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
        | where OsBuildRevision in ("2033","2161","2314","2454","863","1742")
           on $left.DeviceId == $right.DeviceId
| summarize MissingKBs = make_set(RecommendedSecurityUpdate) by DeviceName
| extend TotalMissingKB = array_length(MissingKBs)
```

### Log Analytics (where you store your Intune Logs)

Find all possible affected devices

```kql
IntuneDevices 
| where OS == "Windows"
| where OSVersion in ("10.0.26100.2033","10.0.26100.2161","10.0.26100.2314","10.0.26100.2454","10.0.26100.863","10.0.26100.1742")
```

Windows Update for Business Report

```kql
UCClient 
| where OSVersion contains "Windows 11"
| where OSRevisionNumber in ("2033","2161","2314","2454","863","1742")
| project AzureADDeviceId,DeviceName,OSVersion,OSBuild,OSRevisionNumber
```
