# EntraID - Group Membership changes - Dynamic Group memberships

## Query Information

### Description

Use the below queires to find Entra ID group membership changes initiated for Dynamic Groups.

#### References

- [Dynamic membership rules for groups in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/users/groups-dynamic-membership)

### Microsoft Sentinel

Group Membership changes from the Entra ID Auditlog log

```kql
AuditLogs 
| where OperationName == "Add member to group"
| where Category == "GroupManagement"
| where parse_json(tostring(InitiatedBy.app)).displayName == "Microsoft Approval Management"
| extend DeviceName = tostring(TargetResources[0].displayName)
| extend GroupObjectId = tostring(TargetResources[1].id)
| project TimeGenerated, OperationName, DeviceName, GroupObjectId
```

```kql
AuditLogs 
| where OperationName == "Remove member from group"
| where Category == "GroupManagement"
| where parse_json(tostring(InitiatedBy.app)).displayName == "Microsoft Approval Management"
| extend DeviceName = tostring(TargetResources[0].displayName)
| extend GroupObjectId = tostring(TargetResources[1].id)
| project TimeGenerated, OperationName, DeviceName, GroupObjectId
```

Group Membership changes from Defender for Cloud Apps log

```kql
CloudAppEvents
| where AccountDisplayName == "Microsoft Approval Management"
| where ActionType == "Remove member from group."
| extend GroupName = tostring(ActivityObjects[0].Name)
| extend DeviceName = tostring(ActivityObjects[1].Name)
| project TimeGenerated, ActionType, GroupName, DeviceName
```

```kql
CloudAppEvents
| where AccountDisplayName == "Microsoft Approval Management"
| where ActionType == "Add member to group."
| extend GroupName = tostring(ActivityObjects[0].Name)
| extend DeviceName = tostring(ActivityObjects[1].Name)
| project TimeGenerated, ActionType, GroupName, DeviceName
```

