# Microsoft Copilot Agents

![KQL](https://img.shields.io/badge/language-KQL-blue.svg)

![Status: Work in Progress](https://img.shields.io/badge/status-work--in--progress-yellow.svg)

## Query Information

### Description

#### References

- [Audit Copilot Studio activities in Microsoft Purview](https://learn.microsoft.com/en-us/microsoft-copilot-studio/admin-logging-copilot-studio)

https://learn.microsoft.com/en-us/purview/audit-log-activities#microsoft-365-copilot-admin-activities

### Author

- **Alex Verboon**

## Defender XDR

Create Agent

```kql
CloudAppEvents
| where ActionType == 'BotCreate'
```

```kql
CloudAppEvents
| where ActionType startswith "BotComponentCreate"
```

Publish Agent

```kql
CloudAppEvents
| where ActionType == "BotUpdateOperation-BotPublish"
```

Agent Name Update

```kql
CloudAppEvents
| where ActionType == "BotUpdateOperation-BotNameUpdate"
```

Agents with MCP Tools

```kql
AIAgentsInfo
            | summarize arg_max(Timestamp, *) by AIAgentId
            | where AgentStatus != "Deleted"
            | mvexpand Action = AgentToolsDetails
            | where  Action.action.operationDetails["$kind"] == "ModelContextProtocolMetadata"
            | extend MCPName = tostring(Action.modelDisplayName)
            | summarize MCPTools = make_set(MCPName) by AIAgentName, AIAgentId, EnvironmentId, CreatorAccountUpn
```


CloudAppEvents
| where ActionType == "AppPublishedToCatalog"

CloudAppEvents
| where ActionType == "BotUpdateOperation-BotShare"

CloudAppEvents
| where ActionType == "CopilotInteraction"


| where ActionType == "PutConnectionPermission"
| where ActionType == "TeamsAdminAction"
| where ActionType == "Add service principal."
