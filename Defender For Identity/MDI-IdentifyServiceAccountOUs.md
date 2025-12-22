# MDI - Identify Service Account OU

## Query Information

### Description

This KQL query is designed to identify accounts in Microsoft Defender for Identity whose Organizational Unit (OU) in Active Directory contains the word "service." It extracts the OU from the DistinguishedName field and filters for accounts where the OU name includes "service," helping to pinpoint service accounts within the directory.

#### References

- [Discover and protect Service Accounts with Microsoft Defender for Identity](https://techcommunity.microsoft.com/blog/microsoftthreatprotectionblog/discover-and-protect-service-accounts-with-microsoft-defender-for-identity/4395347)
- [Investigate and protect Service Accounts](https://learn.microsoft.com/en-us/defender-for-identity/service-account-discovery)

### Author

- **Alex Verboon**

## Defender XDR

```kql
let OUPattern = @"^(CN=[^,]+,)?(.+)$";
IdentityInfo
| project AccountName, AccountDisplayName, DistinguishedName
| extend OU = extract(OUPattern, 2, DistinguishedName)
| project-rename DistinguishedName
| where OU contains "service"
| distinct OU
```

```kql
IdentityInfo
| summarize arg_max(Timestamp,*) by AccountName
| project AccountName, DistinguishedName
| extend OUPath = extract(@"CN=[^,]+,(.*)", 1, DistinguishedName)
| where OUPath contains "OU=ServiceAccounts"
| distinct OUPath
```
