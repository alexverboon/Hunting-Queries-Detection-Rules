# Safe Documents

## Query Information

### Description

Use the below queries to retreive Safe Docs Events from Microsoft 365 Defender


#### References



### Microsoft 365 Defender


All SafeDocs Events

```kql
DeviceEvents
| where ActionType == "SafeDocFileScan"
| extend xRawEventData = parse_json(AdditionalFields)
| extend VerificationResult =  tostring(parse_json(xRawEventData).VerificationResult)
| extend ContainerReason = tostring(parse_json(xRawEventData).ContainerReason)
| project Timestamp, DeviceName, ActionType,VerificationResult,FileName, FolderPath, SHA1, ReportId, ContainerReason
```

MalWare Detections

```kql
DeviceEvents
| where ActionType == "SafeDocFileScan"
| extend xRawEventData = parse_json(AdditionalFields)
| extend VerificationResult =  tostring(parse_json(xRawEventData).VerificationResult)
| extend ContainerReason = tostring(parse_json(xRawEventData).ContainerReason)
| project Timestamp, DeviceName, ActionType,VerificationResult,FileName, FolderPath, SHA1, ReportId, ContainerReason
| where VerificationResult == 'malware'
```

More filtering if you like

```
DeviceEvents
| where ActionType == "SafeDocFileScan"
| extend xRawEventData = parse_json(AdditionalFields)
| extend VerificationResult =  tostring(parse_json(xRawEventData).VerificationResult)
| extend ContainerReason = tostring(parse_json(xRawEventData).ContainerReason)
// | distinct ContainerReason
// | where ContainerReason == "IsFileBlock"
// | where ContainerReason == "IsEmailAttachment"
// | where ContainerReason == "IsInternetMarker"
// | where ContainerReason == "IsGateKeeperFail"
// | distinct VerificationResult
// | where VerificationResult == "clean"
// | where VerificationResult == "unknown"
// | where VerificationResult == "failed"
// | where VerificationResult == "no_result"
// | distinct DeviceName
```



