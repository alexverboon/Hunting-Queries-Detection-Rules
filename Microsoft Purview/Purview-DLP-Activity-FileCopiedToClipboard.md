# Microsoft Purview - DLP - File copied to clipboard

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title                      | Link                                              |
|--------------|----------------------------|---------------------------------------------------|
| T1115        | Collection: Clipboard Data | https://attack.mitre.org/techniques/T1115/        |

### Description

Use the below query to see Microsoft Purview DLP ***File copied to clipboard*** activities

#### References

- [Learn about data loss prevention](https://learn.microsoft.com/en-us/purview/dlp-learn-about-dlp)
- [Get started with activity explorer](https://learn.microsoft.com/en-us/purview/data-classification-activity-explorer)
- [Learn about Endpoint data loss prevention](https://learn.microsoft.com/en-us/purview/endpoint-dlp-learn-about)

### Microsoft Defender XDR

```kql
CloudAppEvents
| where ActionType == @"FileCopiedToClipboard"
| extend ObjectId = parse_json(RawEventData)["ObjectId"]
| extend Sha = parse_json(RawEventData)["Sha256"]
| extend DeviceName = parse_json(RawEventData)["DeviceName"]
| extend Application = parse_json(RawEventData)["Application"]
| extend PolicyName = parse_json(RawEventData)["PolicyMatchInfo"]["PolicyName"]
| extend TargetFilePath = parse_json(RawEventData)["TargetFilePath"]
| extend Justification = parse_json(RawEventData)["Justification"]
| project
    Timestamp,
    AccountId,
    AccountDisplayName,
    IPAddress,
    DeviceName,
    ObjectId,
    Sha,
    Application,
    PolicyName,
    TargetFilePath,
    Justification,
    RawEventData
| extend JustificationTextStr = tostring(Justification)
| extend
    justification_id = extract(@"^([^_]+)", 1, JustificationTextStr),
    justification_description = extract(@"^[^_]+_(.*):", 1, JustificationTextStr),
    justification_comment = extract(@":(.*)$", 1, JustificationTextStr)
| project-away JustificationTextStr
| sort by Timestamp desc  
```
