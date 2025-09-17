# Entra ID - PIM Group Members

## Query Information

### Description

Use the below query to list all the Entra ID Group Members.

#### References

### Microsoft Sentinel

List all the members of a Group, in this case the Group Name pattern relates to the groups that are used in combination with Entra ID PIM

>> consider adjusting the GroupName pattern.

```kql
IdentityInfo
| where TimeGenerated > ago(14d)
| summarize arg_max(TimeGenerated, *) by AccountObjectId
| mv-expand GroupMembership
| extend GroupName = tostring(GroupMembership)
| where GroupName startswith "AAD-SG-Role-"
| summarize GroupMembers = make_set(AccountUPN), TotalUsers = dcount(AccountUPN) by GroupName
| project GroupName, TotalUsers, GroupMembers
```
