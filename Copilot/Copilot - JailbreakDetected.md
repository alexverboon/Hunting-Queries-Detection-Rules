# Copilot - Jailbreak Detection

![KQL](https://img.shields.io/badge/language-KQL-blue.svg)
![Status: Testing](https://img.shields.io/badge/status-testing-blue.svg)


## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T0054 | LLM Jailbreak | https://atlas.mitre.org/techniques/AML.T0054 |

### Description

This query retrieves events about Copilot jailbreak attempts.

#### References

- [LLM Jailbreak](https://atlas.mitre.org/techniques/AML.T0054)
- [Queries for the CopilotActivity table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/queries/copilotactivity)
- [The Microsoft Copilot Data Connector for Microsoft Sentinel is Now in Public Preview](https://techcommunity.microsoft.com/blog/microsoftsentinelblog/the-microsoft-copilot-data-connector-for-microsoft-sentinel-is-now-in-public-pre/4491986)


### Author

- **Alex Verboon**

## Defender XDR

```kql
CopilotActivity
| where RecordType == "CopilotInteraction"
| extend LLMData = parse_json(LLMEventData)
| mv-expand Message = LLMData.Messages
| extend JailbreakDetected = tobool(Message.JailbreakDetected)
| where JailbreakDetected == true
//| project TimeGenerated, ActorName, AppHost, AIModelName, MessageId = tostring(Message.Id), IsPrompt = tobool(Message.isPrompt)
| order by TimeGenerated desc
```

I have also come across another log entry.

```kql
CopilotActivity
| extend Parsed = parse_json(LLMEventData)
| mv-expand Resource = Parsed.AccessedResources
| extend Action = tostring(parse_json(Resource.Action))
| extend Id = tostring(parse_json(Resource.id))
| extend Name = tostring(parse_json(Resource.Name))
| extend Type = tostring(parse_json(Resource.Type))
| project TimeGenerated, Action, Id, Name, Type, SrcIpAddr, Workload, AppHost, AppIdentity
| where Name == @"JailBreak"
```





