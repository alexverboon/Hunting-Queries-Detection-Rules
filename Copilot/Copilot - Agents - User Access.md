# Copilot - Agents - User Access

![KQL](https://img.shields.io/badge/language-KQL-blue.svg)
![Status: Testing](https://img.shields.io/badge/status-testing-blue.svg)

## Query Information

### Description

Retrieve Copilot - Agent - User Access setting changes

User access allows control of how members of your organization access and install agents. The setting has three options:

- All users - This option is the default. It means that all users in the organization can access agents, subject to the existing app policies and user assignments.
- No users - This option means that no users in the organization can access agents.
- Specific users/groups - This option lets you select specific users or groups in your organization to have access to agents. While some users in your organization might have permission to install and use agents from the Agent Registry list, only the users or groups you select in this setting can use agents.

#### References

- [Agent settings in Microsoft 365 admin center](https://learn.microsoft.com/en-us/microsoft-365/admin/manage/agent-settings?view=o365-worldwide)

### Author

- **Alex Verboon**

## Defender XDR

```kql
// User Access
CloudAppEvents
| where Application == "Microsoft 365"
| where ActionType == "UpdateTenantSettings"
| extend UserAccessSetting = tostring(parse_json(tostring(RawEventData.Resource)).Property)
| where UserAccessSetting == "EnableCopilotExtensibility"
| extend ForAllUsers = tostring(RawEventData.ForAllUsers)
| extend NewValue = tostring(parse_json(tostring(parse_json(tostring(RawEventData.Resource)).NewValue)))
| extend OriginalValue = tostring(parse_json(tostring(parse_json(tostring(RawEventData.Resource)).OriginalValue)))
| extend RemovedIdentities = parse_json(RawEventData.RemovedIdentities)
| extend AddedIdentities = parse_json(RawEventData.AddedIdentities)
| extend Configuration = "Users who can access Agents"
| extend ConfigurationState = case(
    // No Users: was All Users, now explicitly disabled
    ForAllUsers == "true"  and NewValue == "false", "No Users",
    // All Users: enabled for everyone
    ForAllUsers == "true"  and array_length(AddedIdentities) == 0 and NewValue == "true",  "All Users",
    // Specific Users or Groups: scoped to identities
    ForAllUsers == "false" and array_length(AddedIdentities) > 0,   "Specific Users or Groups",
    ForAllUsers == "false" and array_length(RemovedIdentities) > 0, "Specific Users or Groups",
    "Unknown"
)
| project TimeGenerated, UserAccessSetting, Configuration,ConfigurationState, ForAllUsers, AddedIdentities, RemovedIdentities, OriginalValue, NewValue,AccountDisplayName
| sort by TimeGenerated
```

Query with enriched added and removed user entities

```kql
// User Access
CloudAppEvents
| where Application == "Microsoft 365"
| where ActionType == "UpdateTenantSettings"
| extend UserAccessSetting = tostring(parse_json(tostring(RawEventData.Resource)).Property)
| where UserAccessSetting == "EnableCopilotExtensibility"
| extend ForAllUsers = tostring(RawEventData.ForAllUsers)
| extend NewValue = tostring(parse_json(tostring(parse_json(tostring(RawEventData.Resource)).NewValue)))
| extend OriginalValue = tostring(parse_json(tostring(parse_json(tostring(RawEventData.Resource)).OriginalValue)))
| extend RemovedIdentities = parse_json(RawEventData.RemovedIdentities)
| extend AddedIdentities = parse_json(RawEventData.AddedIdentities)
| extend Configuration = "Users who can access Agents"
| extend ConfigurationState = case(
    ForAllUsers == "true"  and NewValue == "false", "No Users",
    ForAllUsers == "true"  and array_length(AddedIdentities) == 0 and NewValue == "true", "All Users",
    ForAllUsers == "false" and array_length(AddedIdentities) > 0,   "Specific Users or Groups",
    ForAllUsers == "false" and array_length(RemovedIdentities) > 0, "Specific Users or Groups",
    "Unknown"
)
// Pad empty arrays with a placeholder so mv-expand never drops the row
| extend AddedIdentities   = iff(array_length(AddedIdentities)   == 0, dynamic([null]), AddedIdentities)
| extend RemovedIdentities = iff(array_length(RemovedIdentities) == 0, dynamic([null]), RemovedIdentities)
// Enrich AddedIdentities
| mv-expand AddedIdentity = AddedIdentities
| extend AddedObjectId = tostring(AddedIdentity)
| join kind=leftouter (
    IdentityInfo
    | where TimeGenerated > ago(21d)
    | summarize arg_max(TimeGenerated, *) by AccountObjectId
    | project AccountObjectId, AddedDisplayName = AccountDisplayName
) on $left.AddedObjectId == $right.AccountObjectId
// Only pack non-placeholder rows
| extend AddedIdentitiesDetails = iff(isnotempty(AddedObjectId), pack("ObjectId", AddedObjectId, "DisplayName", AddedDisplayName), dynamic(null))
| summarize
    AddedIdentitiesDetails = make_list(AddedIdentitiesDetails),
    arg_max(TimeGenerated, *)
    by TimeGenerated, UserAccessSetting, Configuration, ConfigurationState, ForAllUsers,
       RemovedIdentities = tostring(RemovedIdentities),
       OriginalValue, NewValue, AccountDisplayName
// Enrich RemovedIdentities
| mv-expand RemovedIdentity = parse_json(RemovedIdentities)
| extend RemovedObjectId = tostring(RemovedIdentity)
| join kind=leftouter (
    IdentityInfo
    | where TimeGenerated > ago(21d)
    | summarize arg_max(TimeGenerated, *) by AccountObjectId
    | project AccountObjectId, RemovedDisplayName = AccountDisplayName
) on $left.RemovedObjectId == $right.AccountObjectId
// Only pack non-placeholder rows
| extend RemovedIdentitiesDetails = iff(isnotempty(RemovedObjectId), pack("ObjectId", RemovedObjectId, "DisplayName", RemovedDisplayName), dynamic(null))
| summarize
    RemovedIdentitiesDetails = make_list(RemovedIdentitiesDetails),
    AddedIdentitiesDetails   = any(AddedIdentitiesDetails)
    by TimeGenerated, UserAccessSetting, Configuration, ConfigurationState, ForAllUsers, OriginalValue, NewValue, AccountDisplayName
| project TimeGenerated, AccountDisplayName, UserAccessSetting, Configuration, ConfigurationState,
    AddedIdentitiesDetails, RemovedIdentitiesDetails
| sort by TimeGenerated
```


