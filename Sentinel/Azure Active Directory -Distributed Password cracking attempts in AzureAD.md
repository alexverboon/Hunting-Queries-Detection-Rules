# Azure Active Directory - Distributed Password cracking attempts in AzureAD

## Query Information

### Description

Identify users involved in "Distributed Password cracking attempts in AzureAD" and check whether they have MFA enabled or not. 

#### References


### Microsoft Sentinel

Use the below query to get the list of users and whether they have MFA enabled or not. Note! this requires that you have an Azure AD group with users that do not have MFA enabled. 

```kql
let NoMFA = (
IdentityInfo
| where TimeGenerated > ago(30d)
| where isnotempty( GroupMembership)
| summarize arg_max(TimeGenerated,*) by AccountUPN
| project AccountUPN, GroupMembership 
| mv-expand GroupMembership
| extend GroupName = tostring(parse_json(tostring(GroupMembership)))
| where GroupName == 'AAD-SG-UserMFA-NotCapable'
| extend iAccountUPN = AccountUPN
| distinct iAccountUPN);
let ioc_lookBack = 90d;
let lookback = 90d;
let IncTitle = dynamic(["Distributed Password cracking attempts in AzureAD"]);
SecurityIncident
| where TimeGenerated > ago(lookback)
| where Title has_any (IncTitle)
| summarize arg_max(TimeGenerated,*) by IncidentNumber
| mv-expand AlertIds
| extend AlertId = tostring(AlertIds)
| join  (SecurityAlert)
on $left. AlertId == $right. SystemAlertId
| mv-expand parse_json(Entities)
| extend EType = tostring((Entities.Type))
| where EType == 'account'
| extend AccountName = tostring(Entities.Name)
| summarize count() by AccountName
| join kind=leftouter (IdentityInfo
| summarize arg_max(TimeGenerated,*) by AccountName)
on $left. AccountName == $right. AccountName
| project AccountName, count_, AccountUPN, AccountDisplayName
| join kind=leftouter NoMFA
on $left. AccountUPN == $right. iAccountUPN
| extend HasMFA = iff(isempty(iAccountUPN), "Yes","No")
| project AccountUPN, AccountName, HasMFA, count_
```

