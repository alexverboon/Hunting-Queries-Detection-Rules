# Defender for Identity - Dormant Account Details

## Query Information

### Description

Use the below query to retrieve detailed information about ***Dormant Accounts***

#### References

### Author

- **Alex Verboon**

## Defender XDR

```kql
let sid_list = dynamic(['S-1-5-21-2026063863-2462317154-4127401698-00001', 'S-1-5-21-3621612571-1889916199-1199630630-00002', 'S-1-5-21-4055507806-322200393-1713978839-0002']);
IdentityInfo
| where TimeGenerated > ago(21d)
| where OnPremSid in~ (sid_list)
| summarize arg_max(TimeGenerated,*) by OnPremSid
| project AccountDisplayName, AccountName,AccountDomain, OnPremSid, OnPremObjectId, CompanyName, Department, Country, AccountUpn, DistinguishedName, IsAccountEnabled, Manager

```

Track account disablement activities

```kql
let sid_list = dynamic(['S-1-5-21-2026063863-2462317154-4127401698-00001', 'S-1-5-21-3621612571-1889916199-1199630630-00002', 'S-1-5-21-4055507806-322200393-1713978839-0002']);
IdentityDirectoryEvents
| where ActionType == "Account disabled"
| extend TargetAccountSid = tostring(AdditionalFields.TargetAccountSid)
| extend Initiator = AccountName
| project TimeGenerated, TargetAccountUpn, TargetAccountSid, Initiator
| where TargetAccountSid in(sid_list)
```

See changes

```kql
IdentityDirectoryEvents
| where ActionType == "Group Membership changed"
| extend MembershipChangeAction = tostring(AdditionalFields.MembershipChange)
| where MembershipChangeAction == "removed"
| extend TargetAccountSid = tostring(AdditionalFields.TargetAccountSid)
| extend Initiator = AccountName
| extend GroupName = tostring(AdditionalFields.["FROM.GROUP"])
| project TimeGenerated, TargetAccountUpn, TargetAccountSid, Initiator, GroupName
| where TargetAccountSid in(sid_list)
```



