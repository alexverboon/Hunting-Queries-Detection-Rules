# Active Directory - Extract Account OU 

## Query Information


### Description

Use the below query example to extract the Accounts AD organizational unit from the OnPremisesDistinguishedName

First we define the regex pattern

```
let OUPattern = @"^(CN=[^,]+,)?(.+)$";
```
and then use this regex to extract the OU

```
| extend OU = extract(OUPattern, 2, OnPremisesDistinguishedName)
```

#### References


### Microsoft Sentinel

```kql
let ADGroups = dynamic(['LAPS_Global_Workplace_Reset', 'LAPS_Servers_Reset']);
let OUPattern = @"^(CN=[^,]+,)?(.+)$";
IdentityInfo
| where TimeGenerated > ago(90d)
| summarize arg_max(TimeGenerated, *) by AccountName
| where GroupMembership has_any (ADGroups)
| extend OU = extract(OUPattern, 2, OnPremisesDistinguishedName)
| project AccountUPN, AccountName, OnPremisesDistinguishedName, OU, GroupMembership 
//| summarize count() by OU

```





