# MDE - Local AI Agents Inventory

![KQL](https://img.shields.io/badge/language-KQL-blue.svg)
![Status: Testing](https://img.shields.io/badge/status-testing-blue.svg)

## Query Information

### Description

These KQL queries inventory local AI agents detected by Microsoft Defender for Endpoint using the `AgentsInfo` table. The queries surface which devices have local AI agents installed and, conversely, which AI agents are present across how many devices, helping identify the spread and distribution of local AI agent deployments in your environment.

***Preview** The ****AgentsInfo*** table in advanced hunting is now available in preview. The AIAgentsInfo table is transitioning to this new table, which provides a unified schema that supports agent inventory and governance for all agent types, including Copilot Studio, Microsoft Foundry, Microsoft 365 Copilot, third-party, and endpoint-discovered agents.

#### References

- [What's new in Microsoft Defender XDR](https://learn.microsoft.com/en-us/defender-xdr/whats-new)
- [Discover local AI agents with Microsoft Defender for Endpoint (Preview)](https://learn.microsoft.com/en-us/defender-endpoint/discover-local-ai-agents)

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
