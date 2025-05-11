# Microsoft Purview - DLP - File printed

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title                  | Link                                         |
|--------------|------------------------|----------------------------------------------|
| T1005        | Collection: Data from Local System | https://attack.mitre.org/techniques/T1005/   |

### Description

Use the below query to see Microsoft Purview DLP ***File Printed*** activities

#### References

- [Learn about data loss prevention](https://learn.microsoft.com/en-us/purview/dlp-learn-about-dlp)
- [Get started with activity explorer](https://learn.microsoft.com/en-us/purview/data-classification-activity-explorer)
- [Learn about Endpoint data loss prevention](https://learn.microsoft.com/en-us/purview/endpoint-dlp-learn-about)

### Microsoft Defender XDR

```kql
 CloudAppEvents
| where ActionType == @"FilePrinted"
| extend ObjectId = parse_json(RawEventData)["ObjectId"]
| extend Sha = parse_json(RawEventData)["Sha256"]
| extend DeviceName = parse_json(RawEventData)["DeviceName"]
| extend Application = parse_json(RawEventData)["Application"]
| extend PolicyName = parse_json(RawEventData)["PolicyMatchInfo"]["PolicyName"]
| extend TargetPrinterName = parse_json(RawEventData)["TargetPrinterName"]
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
    TargetPrinterName,
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
