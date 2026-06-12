# MDE - Local AI Agents Inventory

![KQL](https://img.shields.io/badge/language-KQL-blue.svg)
![Status: Testing](https://img.shields.io/badge/status-testing-blue.svg)

## Query Information

### Description

These KQL queries inventory local AI agents detected by Microsoft Defender for Endpoint using the `AgentsInfo` table. The queries surface which devices have local AI agents installed and, conversely, which AI agents are present across how many devices, helping identify the spread and distribution of local AI agent deployments in your environment.

#### References

### Author

- **Alex Verboon**

## KQL Query

Devices with Local AI Agents

```kql
AgentsInfo
| where Platform == @"LocalAgents"
| extend AgentInfo = parse_json(RawAgentInfo).localAgentMetadata
| where isnotempty( AgentInfo)
| extend DeviceName = tostring(AgentInfo.deviceName)
| summarize Agents = make_set(Name), TotalAgents = dcount(Name,4) by DeviceName
| project DeviceName, TotalAgents, Agents
```

AI Agents and total devices

```kql
AgentsInfo
| where Platform == @"LocalAgents"
| extend AgentInfo = parse_json(RawAgentInfo).localAgentMetadata
| where isnotempty( AgentInfo)
| extend DeviceName = tostring(AgentInfo.deviceName)
| summarize Devices = make_set(DeviceName), TotalDevices = dcount(DeviceName,4) by Name
| project Agent=Name, TotalDevices, Devices
```
