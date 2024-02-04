# Defender for Endpoint - Local Built-in Group Membership additions

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1098     | Account Manipulation | https://attack.mitre.org/techniques/T1098/ |
| T1136     |  Create Account | https://attack.mitre.org/techniques/T1136/ |

### Description

Use the below query to identify membership additons to the built-in local groups on Windows devices.

Note that the below queries alsmost look identical, however due to some slight differences in the IdentityInfo table in Microsoft Defender XDR and Sentinel two different queries are required.

#### References

- [Security Identifiers](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers)
- [Local Accounts](https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts)

### Microsoft Defender XDR

```kql
let DirectoryIdentities = (IdentityInfo
| where Timestamp > ago(21d)
| summarize arg_max(TimeGenerated,*) by AccountUpn
| project AccountDisplayName, AccountObjectId,OnPremSid, AccountDomain, AccountName);
let DomainIdentifiers = (DirectoryIdentities
| where isnotempty(OnPremSid)
| extend DomainIdentifier = extract("S-1-5-21-(\\d+-\\d+-\\d+)-\\d+", 1, OnPremSid)
| distinct DomainIdentifier);
let LocalAccounts = (DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == @"UserAccountCreated"
| extend LocalAccountSid = AccountSid
| extend LocalAccountName = AccountName
| extend LocalAccountDomain = AccountDomain
| extend LocalDeviceName = split(DeviceName,".")[0]
| where LocalAccountDomain == LocalDeviceName
| project LocalAccountSid, LocalAccountName, LocalAccountDomain, LocalDeviceName);
let SensitiveBuiltInGroups = datatable(GroupsSID: string,BuildInGroupName: string)
[
"S-1-5-32-544","Administrtors",
"S-1-5-32-546","Guests",
"S-1-5-32-547","Power Users",
"S-1-5-32-555","Remote Desktop Users",
"S-1-5-32-580","Remote Management Users",
];
SensitiveBuiltInGroups
| join kind=inner (
DeviceEvents
| where ActionType == 'UserAccountAddedToLocalGroup'
| extend AccoundSIDAdded = AccountSid
| extend ChangedGroupSid = tostring(parse_json(AdditionalFields).GroupSid)
| extend ChangedGroupName = tostring(parse_json(AdditionalFields).GroupName)
| extend ChangedGroupDomainName = tostring(parse_json(AdditionalFields).GroupDomainName)
| extend ActorSID = InitiatingProcessAccountSid
| extend ActorAccountName = InitiatingProcessAccountName
| extend ActorDomain = InitiatingProcessAccountDomain
| where InitiatingProcessAccountSid <> "S-1-5-18" // exclude actions from local system account
)
on $left.GroupsSID == $right.ChangedGroupSid
| join kind=leftouter (DirectoryIdentities) on $left.AccoundSIDAdded == $right.OnPremSid
| extend AccountNameAdded = AccountName1
| extend AccountDomainAdded = AccountDomain1
| extend AccountDisplayNameAdded = AccountDisplayName
| extend AccountSource = iff(AccoundSIDAdded has_any (DomainIdentifiers), "AD",iff(AccoundSIDAdded startswith "S-1-12-1","EntraID","local"))
| extend ActorAccountType = iff(ActorDomain == split(DeviceName,".")[0],"local",iff(ActorDomain == 'azuread',"EntraID","AD"))
| join kind=leftouter LocalAccounts
on $left. AccoundSIDAdded == $right.LocalAccountSid
| extend  AccountNameAdded = iff(isnotempty(LocalAccountSid),LocalAccountName, AccountNameAdded)
| extend  AccountDomainAdded = iff(isnotempty(LocalAccountSid),LocalAccountDomain, AccountDomainAdded)
| project Timestamp, DeviceName, AccoundSIDAdded,AccountSource, AccountNameAdded, AccountDomainAdded, ChangedGroupName, ChangedGroupSid, ChangedGroupDomainName, ActorAccountName, ActorDomain,ActorAccountType,ActorSID
```

### Microsoft Sentinel

```kql
let DirectoryIdentities = (IdentityInfo
| where TimeGenerated > ago(21d)
| summarize arg_max(TimeGenerated,*) by AccountUPN
| project AccountDisplayName, AccountObjectId,AccountSID, AccountDomain, AccountName);
let DomainIdentifiers = (DirectoryIdentities
| where isnotempty(AccountSID)
| extend DomainIdentifier = extract("S-1-5-21-(\\d+-\\d+-\\d+)-\\d+", 1, AccountSID)
| distinct DomainIdentifier);
let LocalAccounts = (DeviceEvents
| where TimeGenerated > ago(30d)
| where ActionType == @"UserAccountCreated"
| extend LocalAccountSid = AccountSid
| extend LocalAccountName = AccountName
| extend LocalAccountDomain = AccountDomain
| extend LocalDeviceName = split(DeviceName,".")[0]
| where LocalAccountDomain == LocalDeviceName
| project LocalAccountSid, LocalAccountName, LocalAccountDomain, LocalDeviceName);
let SensitiveBuiltInGroups = datatable(GroupsSID: string,BuildInGroupName: string)
[
"S-1-5-32-544","Administrtors",
"S-1-5-32-546","Guests",
"S-1-5-32-547","Power Users",
"S-1-5-32-555","Remote Desktop Users",
"S-1-5-32-580","Remote Management Users",
];
SensitiveBuiltInGroups
| join kind=inner (
DeviceEvents
| where ActionType == 'UserAccountAddedToLocalGroup'
| extend AccoundSIDAdded = AccountSid
| extend ChangedGroupSid = tostring(parse_json(AdditionalFields).GroupSid)
| extend ChangedGroupName = tostring(parse_json(AdditionalFields).GroupName)
| extend ChangedGroupDomainName = tostring(parse_json(AdditionalFields).GroupDomainName)
| extend ActorSID = InitiatingProcessAccountSid
| extend ActorAccountName = InitiatingProcessAccountName
| extend ActorDomain = InitiatingProcessAccountDomain
| where InitiatingProcessAccountSid <> "S-1-5-18" // exclude actions from local system account , like membership changes made by Group Policy
)
on $left.GroupsSID == $right.ChangedGroupSid
| join kind=leftouter (DirectoryIdentities) on $left.AccoundSIDAdded == $right.AccountSID
| extend AccountNameAdded = AccountName1
| extend AccountDomainAdded = AccountDomain1
| extend AccountDisplayNameAdded = AccountDisplayName
| extend AccountSource = iff(AccoundSIDAdded has_any (DomainIdentifiers), "AD",iff(AccoundSIDAdded startswith "S-1-12-1","EntraID","local"))
| extend ActorAccountType = iff(ActorDomain == split(DeviceName,".")[0],"local",iff(ActorDomain == 'azuread',"EntraID","AD"))
| join kind=leftouter LocalAccounts
on $left. AccoundSIDAdded == $right.LocalAccountSid
| extend  AccountNameAdded = iff(isnotempty(LocalAccountSid),LocalAccountName, AccountNameAdded)
| extend  AccountDomainAdded = iff(isnotempty(LocalAccountSid),LocalAccountDomain, AccountDomainAdded)
| project TimeGenerated, DeviceName, AccoundSIDAdded, AccountSource, AccountNameAdded, AccountDomainAdded, ChangedGroupName, ChangedGroupSid, 
ChangedGroupDomainName, ActorAccountName, ActorDomain, ActorAccountType, ActorSID
```
