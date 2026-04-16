# Defender for Cloud Apps - FileCopiedToNetworkShare

![KQL](https://img.shields.io/badge/language-KQL-blue.svg)
![Status: In Progress](https://img.shields.io/badge/status-in--progress-yellow.svg)

## Query Information

### Description

File copied to Network Share events

#### References

### Author

- **Alex Verboon**

## Defender XDR

```kql
CloudAppEvents
| where ActionType == @"FileCopiedToNetworkShare"
| extend ObjectId = parse_json(RawEventData)["ObjectId"]
| extend TargetFilePath = parse_json(RawEventData)["TargetFilePath"]
| extend PreviousFileName = parse_json(RawEventData)["PreviousFileName"]
| extend FileType = parse_json(RawEventData)["FileType"]
| project ObjectId, TargetFilePath, PreviousFileName, FileType
```

