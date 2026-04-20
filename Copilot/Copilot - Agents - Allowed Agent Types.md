# Copilot - Agents - Allowed Agent Types

![KQL](https://img.shields.io/badge/language-KQL-blue.svg)
![Status: Testing](https://img.shields.io/badge/status-testing-blue.svg)

## Query Information

### Description

Retrieve Copilot - Agent - Allowed Agent Types Settings changes

Allowed agent types allows control of which types of agents users can view and install from the agent catalog. You can select from the following options:

- Allow apps and agents built by Microsoft - Enables users to install agents created by Microsoft.
- Allow apps and agents built by your organization - Enables users to install custom agents developed within your tenant.
- Allow apps and agents built by external publishers - Enables users to install non-Microsoft agents built by external developers.

If you disable an option, agents of that type don't appear for users in the Agent store. Agents built by Microsoft are visible to users even if the setting is disabled. Users aren't able to install those agents.

#### References

- [Agent settings in Microsoft 365 admin center](https://learn.microsoft.com/en-us/microsoft-365/admin/manage/agent-settings?view=o365-worldwide)

### Author

- **Alex Verboon**

## Defender XDR

Agent Settings - Allowed Agent Types

```kql
CloudAppEvents
| where Application == "Microsoft 365"
| where ActionType == "UpdateTenantSettings"
| extend AgentTypeSetting = tostring(parse_json(tostring(RawEventData.Resource)).Property)
| where AgentTypeSetting in ("AllowFirstParty","AllowThirdParty","AllowLOB")
| extend NewValue = tostring(parse_json(tostring(parse_json(tostring(RawEventData.Resource)).NewValue)))
| extend OriginalValue = tostring(parse_json(tostring(parse_json(tostring(RawEventData.Resource)).OriginalValue)))
| extend Configuration = case(
    AgentTypeSetting == "AllowFirstParty", "Allow Apps and Agents built by Microsoft",
    AgentTypeSetting == "AllowThirdParty", "Allow Apps and Agents built by external publishers",
    AgentTypeSetting == "AllowLOB",        "Allow Apps and Agent Built by your organization",
    "Unknown"
)
| extend ConfigurationState = case(
    NewValue == "True",  "Enabled",
    NewValue == "False", "Disabled",
    "Unknown"
)
| project TimeGenerated, AgentTypeSetting, Configuration, ConfigurationState,AccountDisplayName
| sort by TimeGenerated
```

