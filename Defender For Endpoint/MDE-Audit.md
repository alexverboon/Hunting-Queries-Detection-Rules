# Defender for Endpoint - Audit Logs

## Query Information

### Description

Work in progress.....

#### References

- [Audit Defender XDR Activities](https://kqlquery.com/posts/audit-defender-xdr/)

### Microsoft 365 Defender

Collect Support logs

```kql
CloudAppEvents
| extend WorkLoad = tostring(parse_json(RawEventData).Workload)
| where WorkLoad == "MicrosoftDefenderForEndpoint"
| where ActionType == "LogsCollection"
| extend ActionComment = tostring(RawEventData.ActionComment)
| extend DeviceName = tostring(RawEventData.DeviceName)
| extend UserId = tostring(RawEventData.UserId)
| extend ClientIP = tostring(RawEventData.ClientIP)
| project TimeGenerated, ActionType, UserId, AccountDisplayName, DeviceName, ClientIP, IPAddress,ActionComment
```

Collect investiatigation Package

```kql
CloudAppEvents
| extend WorkLoad = tostring(parse_json(RawEventData).Workload)
| where WorkLoad == "MicrosoftDefenderForEndpoint"
| where ActionType == "CollectInvestigationPackage"
| extend ActionComment = tostring(RawEventData.ActionComment)
| extend DeviceName = tostring(RawEventData.DeviceName)
| extend UserId = tostring(RawEventData.UserId)
| extend ClientIP = tostring(RawEventData.ClientIP)
| project TimeGenerated, ActionType, UserId, AccountDisplayName, DeviceName, ClientIP, IPAddress, ActionComment
```

Restrict App Execution - Remove App Execution

```kql
CloudAppEvents
| extend WorkLoad = tostring(parse_json(RawEventData).Workload)
| where WorkLoad == "MicrosoftDefenderForEndpoint"
| where ActionType == "RestrictAppExecution" or ActionType == "RemoveAppRestrictions"
| extend ActionComment = tostring(RawEventData.ActionComment)
| extend DeviceName = tostring(RawEventData.DeviceName)
| extend UserId = tostring(RawEventData.UserId)
| extend ClientIP = tostring(RawEventData.ClientIP)
| project TimeGenerated, ActionType, UserId, AccountDisplayName, DeviceName, ClientIP, IPAddress, ActionComment
```

Run Antivirus Scan

```kql
CloudAppEvents
| extend WorkLoad = tostring(parse_json(RawEventData).Workload)
| where WorkLoad == "MicrosoftDefenderForEndpoint"
| where ActionType == "RunAntiVirusScan"
| extend ActionComment = tostring(RawEventData.ActionComment)
| extend DeviceName = tostring(RawEventData.DeviceName)
| extend UserId = tostring(RawEventData.UserId)
| extend ClientIP = tostring(RawEventData.ClientIP)
| project TimeGenerated, ActionType, UserId, AccountDisplayName, DeviceName, ClientIP, IPAddress, ActionComment

```

Isolate Device - Release from Isolation

```kql
CloudAppEvents
| extend WorkLoad = tostring(parse_json(RawEventData).Workload)
| where WorkLoad == "MicrosoftDefenderForEndpoint"
| where ActionType == "IsolateDevice" or ActionType == "ReleaseFromIsolation"
| extend ActionComment = tostring(RawEventData.ActionComment)
| extend DeviceName = tostring(RawEventData.DeviceName)
| extend UserId = tostring(RawEventData.UserId)
| extend ClientIP = tostring(RawEventData.ClientIP)
| project TimeGenerated, ActionType, UserId, AccountDisplayName, DeviceName, ClientIP, IPAddress, ActionComment

```

Download File

```kql
CloudAppEvents
| extend WorkLoad = tostring(parse_json(RawEventData).Workload)
| where ActionType == "DownloadFile"
| extend ActionComment = tostring(RawEventData.ActionComment)
| extend DeviceName = tostring(RawEventData.DeviceName)
| extend UserId = tostring(RawEventData.UserId)
| extend ClientIP = tostring(RawEventData.ClientIP)
| extend FileName = tostring(RawEventData.FileName)
| extend FileSHA256 = tostring(RawEventData.FileSHA256)
| project TimeGenerated, ActionType, UserId, AccountDisplayName, DeviceName, ClientIP, ActionComment, FileName, FileSHA256

```

```kql
CloudAppEvents
| extend WorkLoad = tostring(parse_json(RawEventData).Workload)
| where WorkLoad == "MicrosoftDefenderForEndpoint"
| where ActionType == "LiveResponseGetFile"
```

```kql
CloudAppEvents
| extend WorkLoad = tostring(parse_json(RawEventData).Workload)
| where WorkLoad == "MicrosoftDefenderForEndpoint"
| where ActionType == "DownloadOnboardingPkg" or ActionType == "DownloadOffboardingPkg"
```

```kql
CloudAppEvents
| extend WorkLoad = tostring(parse_json(RawEventData).Workload)
| where ActionType == "AddIndicator" or ActionType == "DeleteIndicator"
```

```kql
CloudAppEvents
| extend WorkLoad = tostring(parse_json(RawEventData).Workload)
| where ActionType == "EditIndicator"
```

```kql
CloudAppEvents
| extend WorkLoad = tostring(parse_json(RawEventData).Workload)
| where ActionType == "SetAdvancedFeatures"
```

```kql
CloudAppEvents
| extend WorkLoad = tostring(parse_json(RawEventData).Workload)
| where ActionType == "StopAndQuarantineFile"
```

```kql
CloudAppEvents
| extend WorkLoad = tostring(parse_json(RawEventData).Workload)
| where ActionType == "DeleteCustomDetection"
```

```kql
CloudAppEvents
| extend WorkLoad = tostring(parse_json(RawEventData).Workload)
| where ActionType == "MonitoringAlertUpdated"
```

```kql
CloudAppEvents
| extend WorkLoad = tostring(parse_json(RawEventData).Workload)
```

```kql
CloudAppEvents
| where TimeGenerated > ago(90d)
| extend WorkLoad = tostring(parse_json(RawEventData).Workload)
| where WorkLoad contains "Defender"
| distinct ActionType
```
