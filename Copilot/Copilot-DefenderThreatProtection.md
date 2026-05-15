# Copilot - Microsoft Defender - AI agent threats

![KQL](https://img.shields.io/badge/language-KQL-blue.svg)
![Status: Stable](https://img.shields.io/badge/status-stable-brightgreen.svg)

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title                                | Link                                                                                         |
| ------------ | ------------------------------------ | -------------------------------------------------------------------------------------------- |
| AML.T0051    | Prompt Injection                     | [https://atlas.mitre.org/techniques/AML.T0051](https://atlas.mitre.org/techniques/AML.T0051) |
| AML.T0015    | Data Extraction / Model Data Leakage | [https://atlas.mitre.org/techniques/AML.T0015](https://atlas.mitre.org/techniques/AML.T0015) |
| AML.T0054    | Tool Manipulation                    | [https://atlas.mitre.org/techniques/AML.T0054](https://atlas.mitre.org/techniques/AML.T0054) |
| AML.T0007    | AI System Reconnaissance             | [https://atlas.mitre.org/techniques/AML.T0007](https://atlas.mitre.org/techniques/AML.T0007) |

### Description

This query retrieves Microsoft Defender for AI agent protection events related to blocked or suspicious AI agent activity, including detections such as secret leakage, suspicious knowledge access, unsafe tool invocation, prompt injection attempts, and other runtime protection actions triggered during AI agent execution.

#### References

- [Detect, block, and investigate threats to AI agents using Microsoft Defender (Preview)](https://learn.microsoft.com/en-us/defender-xdr/security-for-ai/ai-agent-detection-protection)
- [Real-time protection during agent runtime](https://derkvanderwoude.medium.com/real-time-protection-for-ai-agents-a335274b640c)

### Author

- **Alex Verboon**

## Defender XDR

```kql
CopilotActivity
| extend Parsed = parse_json(LLMEventData)
| mv-expand Resource = Parsed.AccessedResources
| extend Action = tostring(Resource.Action)
| extend Id = tostring(Resource.id)
| extend Name = tostring(Resource.Name)
| extend Type = tostring(Resource.Type)
| where Name == "Block"
| extend DetectionName = extract(@"blocked by ['""]([^'""]+)['""] detection", 1, Action)
| project TimeGenerated, DetectionName, Action, Id, Name, Type, SrcIpAddr, Workload, AppHost, AppIdentity, LLMEventData
| sort by TimeGenerated
```


