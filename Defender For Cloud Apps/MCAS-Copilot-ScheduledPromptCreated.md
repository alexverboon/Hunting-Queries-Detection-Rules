# Microsoft 365 - Copilot

![KQL](https://img.shields.io/badge/language-KQL-blue.svg)
![Status: Work in Progress](https://img.shields.io/badge/status-work--in--progress-yellow.svg)

## Query Information

### Description

ScheduledPromptCreated

#### References

### Author

- **Alex Verboon**

## Defender XDR

```kql
CloudAppEvents
| where ActionType == @"ScheduledPromptCreated"
| extend PromptText = parse_json(RawEventData)["PromptText"]
| extend ScenarioType = parse_json(RawEventData)["ScenarioType"]
| extend TriggerMode = parse_json(RawEventData)["TriggerMode"]
| project ScenarioType, PromptText, TriggerMode
```


