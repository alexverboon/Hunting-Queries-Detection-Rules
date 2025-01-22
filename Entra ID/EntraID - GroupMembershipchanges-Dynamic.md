# EntraID - Group Membership changes - Dynamic Group memberships

## Query Information

### Description

Use the below queires to find Entra ID group membership changes initiated for Dynamic Groups.

#### References

- [Dynamic membership rules for groups in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/users/groups-dynamic-membership)

### Microsoft Sentinel

Device Dynamic Group Membership changes from the Entra ID Auditlog log

```kql
AuditLogs 
| where OperationName == "Add member to group" or OperationName == "Remove member from group"
| where Identity == "Microsoft Approval Management"
| mv-expand TargetResources
| where TargetResources.type == "Device"
| extend DeviceName = tostring(TargetResources.displayName)
| mv-apply Group =  TargetResources.modifiedProperties on ( project Attribute = Group.displayName, AddedGroupName = replace_string(tostring(Group.newValue), '"', '')
| where Attribute == 'Group.DisplayName')
| mv-apply Group =  TargetResources.modifiedProperties on ( project Attribute = Group.displayName, RemovedGroupName = replace_string(tostring(Group.oldValue), '"', '')
| where Attribute == 'Group.DisplayName')
| extend GroupName = iff(OperationName == 'Remove member from group',RemovedGroupName, iff(OperationName == 'Add member to group',AddedGroupName,""))
| project TimeGenerated, OperationName, DeviceName,GroupName
```

Group Membership changes from Defender for Cloud Apps log

```kql
CloudAppEvents
| where ActionType == "Remove member from group." or ActionType == 'Add member to group.'
| where AccountDisplayName == "Microsoft Approval Management"
| mv-apply RemoveDevice = ActivityObjects on (project RemoveDeviceName = RemoveDevice.Name, Role = RemoveDevice.Role
| where Role == 'Target object'
)
| mv-apply AddDevice = RawEventData.Target on (project  AddDeviceName = AddDevice.ID, Type = AddDevice.Type
| where Type == 1
)
| mv-apply Group = ActivityObjects on (project GroupName = Group.Name, Type = Group.Type
| where Type == 'Group'
)
| extend DeviceName = iff(ActionType == 'Remove member from group.',RemoveDeviceName, iff(ActionType == 'Add member to group.',AddDeviceName,""))
| project TimeGenerated, ActionType, DeviceName,GroupName
| summarize arg_max(TimeGenerated,*) by  ActionType, DeviceName, tostring(GroupName)
| project TimeGenerated, ActionType, DeviceName, GroupName
```

Regular group changes

```kql
AuditLogs
| where OperationName == "Remove member from group" or  OperationName == "Add member to group"
| mv-expand TargetResources
| mv-apply Group =  TargetResources.modifiedProperties on ( project Attribute = Group.displayName, AddedGroupName = replace_string(tostring(Group.newValue), '"', '')
| where Attribute == 'Group.DisplayName')
| mv-apply Group =  TargetResources.modifiedProperties on ( project Attribute = Group.displayName, RemovedGroupName = replace_string(tostring(Group.oldValue), '"', '')
| where Attribute == 'Group.DisplayName')
| extend GroupName = iff(OperationName == 'Remove member from group',RemovedGroupName, iff(OperationName == 'Add member to group',AddedGroupName,""))
| extend InitiateduserPrincipalName = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend TargetuserPrincipalName = tostring(TargetResources.userPrincipalName)
| extend Action = iff(OperationName == "Remove member from group","Remove",iff(OperationName == "Add member to group","Add","unknown"))
| project TimeGenerated, Action, GroupName,InitiateduserPrincipalName, TargetuserPrincipalName 

```