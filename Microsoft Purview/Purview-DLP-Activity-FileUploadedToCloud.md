# Microsoft Purview - DLP - File copied to Cloud

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title                                  | Link                                                   |
|--------------|----------------------------------------|--------------------------------------------------------|
| T1537        | Exfiltration: Transfer Data to Cloud Account | https://attack.mitre.org/techniques/T1537/       |

### Description

Use the below query to see Microsoft Purview DLP ***File copied to Cloud*** activities

#### References

- [Learn about data loss prevention](https://learn.microsoft.com/en-us/purview/dlp-learn-about-dlp)
- [Get started with activity explorer](https://learn.microsoft.com/en-us/purview/data-classification-activity-explorer)
- [Learn about Endpoint data loss prevention](https://learn.microsoft.com/en-us/purview/endpoint-dlp-learn-about)

### Microsoft Defender XDR

```kql
 CloudAppEvents
| where ActionType == @"FileUploadedToCloud"
| extend ObjectId = parse_json(RawEventData)["ObjectId"]
| extend Sha = parse_json(RawEventData)["Sha256"]
| extend DeviceName = parse_json(RawEventData)["DeviceName"]
| extend Application = parse_json(RawEventData)["Application"]
| extend PolicyName = parse_json(RawEventData)["PolicyMatchInfo"]["PolicyName"]
| extend TargetUrl = parse_json(RawEventData)["TargetUrl"]
| extend TargetDomain = parse_json(RawEventData)["TargetDomain"]
| extend OriginatingDomain = parse_json(RawEventData)["OriginatingDomain"]
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
    TargetUrl,
    TargetDomain,
    OriginatingDomain,
    Justification,
    RawEventData
//| where isnotempty( Justification)
| extend JustificationTextStr = tostring(Justification)
| extend
    justification_id = extract(@"^([^_]+)", 1, JustificationTextStr),
    justification_description = extract(@"^[^_]+_(.*):", 1, JustificationTextStr),
    justification_comment = extract(@":(.*)$", 1, JustificationTextStr)
| project-away JustificationTextStr
| sort by Timestamp desc  
```
