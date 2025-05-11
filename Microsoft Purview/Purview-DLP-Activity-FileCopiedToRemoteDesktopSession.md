# Microsoft Purview - DLP - File copied to remote desktop session

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title                               | Link                                               |
|--------------|-------------------------------------|----------------------------------------------------|
| T1021.001    | Lateral Movement: Remote Desktop Protocol | https://attack.mitre.org/techniques/T1021/001/ |

### Description

Use the below query to see Microsoft Purview DLP ***File copied to remote desktop session*** activities

#### References

- [Learn about data loss prevention](https://learn.microsoft.com/en-us/purview/dlp-learn-about-dlp)
- [Get started with activity explorer](https://learn.microsoft.com/en-us/purview/data-classification-activity-explorer)
- [Learn about Endpoint data loss prevention](https://learn.microsoft.com/en-us/purview/endpoint-dlp-learn-about)

### Microsoft Defender XDR

```kql
CloudAppEvents
| where ActionType == @"FileCopiedToRemoteDesktopSession"
| extend ObjectId = parse_json(RawEventData)["ObjectId"]
| extend Sha = parse_json(RawEventData)["Sha256"]
| extend DeviceName = parse_json(RawEventData)["DeviceName"]
| extend Application = parse_json(RawEventData)["Application"]
| extend PolicyName = parse_json(RawEventData)["PolicyMatchInfo"]["PolicyName"]
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

Find details about the potential Remote Desktop connection that was made during the time frame of the DLP activity (5 minutes)

```kql
let DlpEvents = CloudAppEvents
| extend dlptimestamp = Timestamp
| where ActionType == @"FileCopiedToRemoteDesktopSession"
| extend ObjectId = parse_json(RawEventData)["ObjectId"]
| extend Sha = parse_json(RawEventData)["Sha256"]
| extend DeviceName = tostring(parse_json(RawEventData)["DeviceName"])
| extend Application = parse_json(RawEventData)["Application"]
| extend PolicyName = parse_json(RawEventData)["PolicyMatchInfo"]["PolicyName"]
| extend Justification = parse_json(RawEventData)["Justification"]
| project
    dlptimestamp,
    AccountId,
    AccountDisplayName,
    IPAddress,
    DeviceName,
    ObjectId,
    Sha,
    Application,
    PolicyName,
    Justification,
    RawEventData
| extend JustificationTextStr = tostring(Justification)
| extend
    justification_id = extract(@"^([^_]+)", 1, JustificationTextStr),
    justification_description = extract(@"^[^_]+_(.*):", 1, JustificationTextStr),
    justification_comment = extract(@":(.*)$", 1, JustificationTextStr)
| project-away JustificationTextStr
| sort by dlptimestamp desc;  
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName has "mstsc"
| join kind=inner (DlpEvents
) on $left.DeviceName == $right. DeviceName
| where abs(datetime_diff("minute", Timestamp, dlptimestamp)) <= 5
| project 
    dlptimestamp,
    Timestamp,
    DeviceName,
    RemoteIP = RemoteIP,
    RemotePort = RemotePort,
    AccountId,
    AccountDisplayName,
    ObjectId,
    Sha,
    Application,
    PolicyName,
    justification_id,
    justification_description,
    justification_comment,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| sort by dlptimestamp desc
```
