# Active Directory - Sensitive Group Membership Changes

## Query Information

### Description

Use the below query to monitor Active Directory sensitive group changes

#### References

### Microsoft 365 Defender

```kql
// Monitor Active Directory sensitive Group Membership changes
// Active Directory, sensitive groups
let SensitiveGroups = dynamic(["Administrators","Power Users","Account Operators" ,"Server Operators","Print Operators","Backup Operators","Replicators","Network Configuration Operators","Incoming Forest Trust Builders",
"Domain Admins","Domain Controllers","Group Policy Creator Owners","read-only Domain Controllers","Enterprise Read-only Domain Controllers","Enterprise Admins","Schema Admins","Microsoft Exchange Servers"
"Remote Desktop Users","Remote Management Users","DnsAdmins","Protected Users"]);
// Active Directory, custom sensitive groups
let customSensitiveGroups = dynamic(["NLAdmins"]);
IdentityDirectoryEvents 
| where Timestamp > ago (2h)
| where ActionType == "Group Membership changed"
| extend Actor = tostring(AdditionalFields ['ACTOR.ACCOUNT'])
| extend ActorUpn = AccountUpn 
| extend TargetObjectIdentity = iff(AdditionalFields contains "TARGET_OBJECT.USER",AdditionalFields['TARGET_OBJECT.USER'],iff(AdditionalFields contains "TARGET_OBJECT.GROUP",AdditionalFields['TARGET_OBJECT.GROUP'],"undefined"))
| extend TargetObjectType = iff(AdditionalFields contains "TARGET_OBJECT.USER","User",iff(AdditionalFields contains "TARGET_OBJECT.GROUP","Group","undefined"))
| extend Operation = iff(AdditionalFields contains "TO.GROUP","Add",iff(AdditionalFields contains "FROM.GROUP","Remove","Undefined"))
| extend ChangedGroup = iff(Operation == "Add", AdditionalFields['TO.GROUP'],iff(Operation == "Remove", AdditionalFields['FROM.GROUP'],"Undefined"))
| extend IsSensitive = iff( ChangedGroup in (SensitiveGroups) or ChangedGroup in (customSensitiveGroups),"1","0")
| join kind= leftouter(IdentityInfo 
| distinct AccountObjectId , AccountUpn, IsAccountEnabled, CloudSid )
on $left. TargetAccountUpn == $right. AccountUpn 
| extend AccountUpn = AccountUpn1 
| extend AccountSid  = CloudSid 
| extend AccountObjectId = AccountObjectId1 
| sort by Timestamp 
| where IsSensitive == "1" 
| project Timestamp , ActionType,Operation, ChangedGroup,Actor, ActorUpn,LegitActor, TargetObjectIdentity,TargetAccountUpn, AccountUpn, AccountObjectId, AccountSid,TargetAccountDisplayName, IsAccountEnabled , TargetObjectType  , IsSensitive, DestinationDeviceName, ReportId 
```
