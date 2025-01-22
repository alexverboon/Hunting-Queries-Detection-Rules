# Azure Active Dirctory - Groups

## Query Information

### Description

Use the below queries to retrieve information about Azure AD Group changes

#### References

### Microsoft Sentinel

```kql
let xGroupName = 'CA-ExcludeTestUser';
AuditLogs
| where TimeGenerated > ago(360d)
| where OperationName == "Add member to group"
| extend GroupName = tostring(parse_json(tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[1].newValue)))
| where GroupName == (xGroupName)
| extend InitiatedByUser = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend AddedUser = tostring(TargetResources[0].userPrincipalName)
| project TimeGenerated, GroupName, InitiatedByUser, AddedUser
```
