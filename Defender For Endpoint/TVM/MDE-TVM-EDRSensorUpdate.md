# Defender for Endpoint - TVM - EDR Sensor Update

## Query Information

### Description

When you install the Defender unified Agent on Windows Server 2012-R2 and Windows Server 2016, the EDR Sensor is kept up to date by including KB5005292 in your update process.

- Windows Update
- A patch management solution such as WSUS
- Downloading and applying the package from the Microsoft [Update Catalog](https://www.catalog.update.microsoft.com/Search.aspx?q=KB5005292)

This update services the EDR sensor included in the new Microsoft Defender for Endpoint unified solution package released in 2021. This update gets released periodically, and with the same KB number (5005292).

Microsoft Defender Threat and Vulnerability Management includes a recommendation "Update Microsoft Defender for Endpoint core components".

The below query will list all devices where the update is missing and provides additional information of the currently installed version and when it was released.

The ***InitiatingProcessVersionInfoProductVersion*** shows he version, the ***GlobalFirstSeen*** gives you an idea of when the time when that sensor version was released, so you get an idea for how long the Sensor wasn't updated. 

Example: The most current version is now: 10.8760 (September 2024)an outdated system might have the version 10.8048 that was released in 2022.

The query will also check whether the server has any missing KBs, that would be an indicator for general Windows Update problems. Check the TotalMissingKB and MissingKBs columns for details. 

#### References

- [Microsoft Defender for Endpoint update for EDR Sensor](https://support.microsoft.com/en-gb/topic/microsoft-defender-for-endpoint-update-for-edr-sensor-f8f69773-f17f-420f-91f4-a8e5167284ac)
- [Onboard Windows servers to the Microsoft Defender for Endpoint service](https://learn.microsoft.com/en-us/defender-endpoint/configure-server-endpoints)

### Microsoft 365 Defender

Identify Windows Servers with missing EDR Sensor updates.

```kql
let missingKB = DeviceTvmSoftwareVulnerabilities
| where SoftwareVendor == 'microsoft'
| where SoftwareName startswith 'windows_server'
| where isnotempty(RecommendedSecurityUpdate)
| project-rename KBDeviceId = DeviceId
| distinct KBDeviceId, RecommendedSecurityUpdate, RecommendedSecurityUpdateId, SoftwareName
| summarize MissingKBs = make_set(RecommendedSecurityUpdate) by KBDeviceId
| extend TotalMissingKB = array_length(MissingKBs);
let configreq = (
DeviceTvmSecureConfigurationAssessment
| where ConfigurationId == 'scid-2030'
| where IsApplicable == "1"
| where IsCompliant == "0"
| project-rename configDeviceId = DeviceId
| project Timestamp, DeviceName, configDeviceId, OSPlatform
);
configreq
| join kind=leftouter  (DeviceTvmInfoGathering
| extend xAVMode = parse_json(AdditionalFields.AvMode)
| where isnotempty(xAVMode)
| extend AF = parse_json(AdditionalFields)
| evaluate bag_unpack(AF, columnsConflict='keep_source'): (
    Timestamp: datetime, 
    DeviceName: string, 
    DeviceId: string,
    OSPlatform: string, 
    AsrConfigurationStates: dynamic, 
    AvEnginePublishTime: datetime, 
    AvEngineRing: string, 
    AvEngineUpdateTime: datetime,
    AvEngineVersion: string,
    AvIsEngineUptodate: string ,
    AvIsPlatformUptodate: string,
    AvIsSignatureUptoDate: string,
    AvMode: string,
    AvPlatformPublishTime: datetime,
    AvPlatformRing: string,
    AvPlatformUpdateTime: datetime,
    AvPlatformVersion: string,
    AvScanResults: string,
    AvSignatureDataRefreshTime: datetime, 
    AvSignaturePublishTime: datetime,
    AvSignatureRing: string,
    AvSignatureUpdateTime: datetime, 
    AvSignatureVersion: string,
    CloudProtectionState: string,
    AdditionalFields: dynamic)
)
on $left. configDeviceId == $right.DeviceId
| join kind=leftouter (DeviceProcessEvents
| where FolderPath contains "defender"
| where InitiatingProcessFileName == @"MsSense.exe"
| summarize arg_max(Timestamp,*) by DeviceName, DeviceId
| extend xSHA256 = InitiatingProcessSHA256 
| project Timestamp,DeviceId, DeviceName,InitiatingProcessVersionInfoProductVersion, InitiatingProcessVersionInfoFileDescription, xSHA256,InitiatingProcessFileName)
on $left.DeviceId == $right.DeviceId
| invoke FileProfile(xSHA256) 
| project Timestamp, DeviceName,DeviceId,InitiatingProcessVersionInfoProductVersion, InitiatingProcessVersionInfoFileDescription, InitiatingProcessFileName, GlobalFirstSeen, AvEngineVersion, AvPlatformVersion, AvSignatureVersion
| join kind=leftouter (missingKB)
on $left. DeviceId == $right. KBDeviceId

```
