# Defender for Endpoint - TvmAxonTelemetryEvent

![KQL](https://img.shields.io/badge/language-KQL-blue.svg)

![Status: Experimental](https://img.shields.io/badge/status-experimental-red.svg)

## Query Information

### Description

The below query extracts information form the DeviceEvents Table where the ActionType is ***TvmAxonTelemetryEvent***

#### References

### Author

- **Alex Verboon**

## Defender XDR

```kql
DeviceEvents
| where ActionType == "TvmAxonTelemetryEvent"
| extend AF = parse_json(AdditionalFields)
| extend InfoArray = parse_json(tostring(AF.InfoAsJson)),
         BuildId    = tostring(AF.BuildId)
| mv-expand InfoEntry = InfoArray
| extend InfoTimestamp = todouble(InfoEntry.timestamp),
         Level         = tostring(InfoEntry.level),
         file          = tostring(InfoEntry.file),
         line          = tostring(InfoEntry.line),
         Source        = tostring(InfoEntry.source),
         Message       = tostring(InfoEntry.message)
//
// 5) Select what you care about
//
| project DeviceId, TimeGenerated, DeviceName, BuildId, file, Level, Source, Message
| order by TimeGenerated desc

```
