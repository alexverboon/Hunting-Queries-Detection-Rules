# Copilot - Agent Approval

![KQL](https://img.shields.io/badge/language-KQL-blue.svg)
![Status: Stable](https://img.shields.io/badge/status-stable-brightgreen.svg)

## Query Information

### Description

Companies can use Copilot Studio to create more advanced agents. These agents can be published to different channels within your organization, such as Microsoft 365 Copilot and Microsoft Teams. When an agent is published from Copilot Studio, the agent will be displayed in the Requests tab in the All agents list in the Microsoft 365 admin center.

The below query show the events when admin approves such a request.

#### References

- [Manage requested Copilot Studio agents](https://learn.microsoft.com/en-us/microsoft-365/copilot/agent-essentials/agent-lifecycle/agent-copilot-studio-requested)

### Author

- **Alex Verboon**

## Defender XDR

```kql
OfficeActivity
| where OfficeWorkload == "MicrosoftTeams"
| where Operation == "TeamsAdminAction"
| extend ApprovedAppID = tostring(ExtraProperties[0].Value)
| where NewValue == @"Approved"
| project TimeGenerated, ApprovedAppID,UserId
```

```kql
CloudAppEvents
| where ActionType == @"TeamsAdminAction"
| extend Info = parse_json(RawEventData)
| where parse_json(Info)["NewValue"] == 'Approved'
| extend ApprovedAppID = tostring(parse_json(Info.ExtraProperties[0].Value))
| project TimeGenerated, ApprovedAppID, AccountDisplayName
```