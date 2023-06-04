# Microsoft Defender - Engine , Platform states

## Query Information

### Description

Use the below queries to retrieve information about Microsoft Defender Antivirus Engine, Platform and Singnature status 

#### References

- [Device health reports in Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/device-health-reports?view=o365-worldwide)
- [Microsoft Defender Antivirus security intelligence and product updates](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/microsoft-defender-antivirus-updates?view=o365-worldwide)
- [Manage the gradual rollout process for Microsoft Defender updates](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/manage-gradual-rollout?view=o365-worldwide)

### Microsoft 365 Defender

// Detailed list of Defender Antivirus Engine, Platform and Signature updates

```kql
DeviceTvmInfoGathering
| extend xAVMode = parse_json(AdditionalFields.AvMode)
| where isnotempty(xAVMode)
| extend AF = parse_json(AdditionalFields)
| evaluate bag_unpack(AF, columnsConflict='keep_source'): (
    Timestamp: datetime, 
    DeviceName: string, 
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
    AdditionalFields: dynamic)
```

Append the below lines to the above query to get Engine, Platform and Signature specific details or summaries

```kql
// AV Engine Version summary
| project DeviceName, OSPlatform,AvIsEngineUptodate, AvEnginePublishTime,AvEngineUpdateTime,AvEngineVersion,AvEngineRing
| summarize count() by AvEngineVersion
```

```kql
// AV Platformversion
| project Timestamp, DeviceName, OSPlatform, AvIsPlatformUptodate,AvPlatformPublishTime,AvPlatformUpdateTime,AvPlatformVersion,AvPlatformRing
| summarize count() by AvPlatformVersion
```

```kql
// AVSignatureVersion
| project Timestamp, DeviceName, OSPlatform, AvIsSignatureUptoDate,AvSignatureUpdateTime,AvSignaturePublishTime,AvSignatureDataRefreshTime,AvSignatureVersion,AvSignatureRing
| summarize count() by AvSignatureVersion
```

```kql
// Update Rings
| project Timestamp, DeviceName, AvEngineRing, AvPlatformRing, AvSignatureRing
```
