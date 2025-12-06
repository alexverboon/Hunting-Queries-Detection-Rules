# Active Directory - Password Security Posture Assessment

![KQL](https://img.shields.io/badge/language-KQL-blue.svg)
![Status: Testing](https://img.shields.io/badge/status-testing-blue.svg)

## Query Information

### Description

iThis query leverages the `IdentityAccountInfo` and `IdentityInfo` tables in Microsoft Defender XDR to identify Active Directory accounts with outdated passwords and assess their security risk. By combining key attributes such as `Tags`, `LastPasswordChangeTime`, `AccountStatus`, and `UserAccountControl`, the query helps security teams:

- **Identify stale passwords**: Detect accounts that haven't changed their password in an extended period, calculated in both days and years
- **Assess sensitivity**: Determine whether accounts are tagged as sensitive or have elevated privileges
- **Review password policies**: Identify accounts with `PasswordNeverExpires` or `PasswordNotRequired` flags set
- **Analyze account status**: Focus on enabled accounts that may pose active security risks

This query is particularly useful for addressing **Microsoft Defender for Identity security posture assessments**, including:

- Built-in Active Directory Guest account is enabled
- Change password for krbtgt account
- Change password of built-in domain Administrator account
- Rotate password for Microsoft Entra Connect AD DS Connector account
- Remove unsafe permissions on sensitive Microsoft Entra Connect accounts

The second query variant provides focused results by filtering specifically for high-risk built-in accounts (Administrator, Guest, krbtgt) and Microsoft Entra Connect synchronization accounts (MSOL_, AAD_, ADSync).

#### References

- [IdentityAccountInfo](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identityaccountinfo-table)
- [IdentityInfo](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identityinfo-table)
- [Hybrid security posture assessments](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/hybrid-security)
- [Identity infrastructure security assessments](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/identity-infrastructure)
- [Accounts security posture assessments](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/accounts)

### Author

- **Alex Verboon**

## Defender XDR

```kql
let accountinfo = IdentityAccountInfo
| summarize arg_max(TimeGenerated,*) by IdentityId
| extend DaysSinceLastPasswordChange =
    iff(isnull(LastPasswordChangeTime), int(null),
        datetime_diff('day', now(), LastPasswordChangeTime))
| extend YearsSinceLastPasswordChange =
    iff(isnull(LastPasswordChangeTime), int(null),
        datetime_diff('year', now(), LastPasswordChangeTime))   
| extend Sensitive = array_index_of(Tags, "Sensitive")   != -1
| extend SensitiveLabel = iff(Sensitive == 1, "🟥 Sensitive", "⬜ Not Sensitive")
| project IdentityId,AccountUpn, AccountStatus, LastPasswordChangeTime,DaysSinceLastPasswordChange,YearsSinceLastPasswordChange, Sid, Sensitive, SensitiveLabel;
let IdInfo = IdentityInfo
| summarize arg_max(TimeGenerated,*) by IdentityId
| extend PasswordNeverExpires = array_index_of(UserAccountControl, "PasswordNeverExpires")   != -1,
         PasswordNotRequired = array_index_of(UserAccountControl, "PasswordNotRequired")   != -1
| extend OUPath = extract(@"CN=[^,]+,(.*)", 1, DistinguishedName)
| project IdentityId,AccountName, AccountDomain, AccountDisplayName, OnPremSid, OnPremObjectId, AccountUpn, PasswordNeverExpires, PasswordNotRequired, OUPath;
IdInfo
| join kind=leftouter (accountinfo)
on $left. IdentityId == $right. IdentityId
| project IdentityId, AccountName, AccountStatus,AccountDomain, AccountDisplayName,AccountUpn,Sensitive,SensitiveLabel,LastPasswordChangeTime, DaysSinceLastPasswordChange, YearsSinceLastPasswordChange, PasswordNeverExpires, PasswordNotRequired, OUPath
| sort by DaysSinceLastPasswordChange desc 
| where AccountStatus != @"Disabled"
```

Filter the results by Built-in Administrator, Guest accounts, krbgt and Entra ID Synch accounts.

```kql
let accountinfo = IdentityAccountInfo
| summarize arg_max(TimeGenerated,*) by IdentityId
| extend DaysSinceLastPasswordChange =
    iff(isnull(LastPasswordChangeTime), int(null),
        datetime_diff('day', now(), LastPasswordChangeTime))
| extend YearsSinceLastPasswordChange =
    iff(isnull(LastPasswordChangeTime), int(null),
        datetime_diff('year', now(), LastPasswordChangeTime))   
| extend Sensitive = array_index_of(Tags, "Sensitive")   != -1
| extend SensitiveLabel = iff(Sensitive == 1, "🟥 Sensitive", "⬜ Not Sensitive")
| project IdentityId,AccountUpn, AccountStatus, LastPasswordChangeTime,DaysSinceLastPasswordChange,YearsSinceLastPasswordChange, Sid, Sensitive, SensitiveLabel;
let IdInfo = IdentityInfo
| summarize arg_max(TimeGenerated,*) by IdentityId
| where isnotempty( AccountName)
| extend PasswordNeverExpires = array_index_of(UserAccountControl, "PasswordNeverExpires")   != -1,
         PasswordNotRequired = array_index_of(UserAccountControl, "PasswordNotRequired")   != -1
| extend OUPath = extract(@"CN=[^,]+,(.*)", 1, DistinguishedName)
| project IdentityId,AccountName, AccountDomain, AccountDisplayName, OnPremSid, OnPremObjectId, AccountUpn, PasswordNeverExpires, PasswordNotRequired, OUPath;
IdInfo
| join kind=leftouter (accountinfo)
on $left. IdentityId == $right. IdentityId
| project IdentityId, AccountName, AccountStatus,AccountDomain, AccountDisplayName,AccountUpn,Sensitive,SensitiveLabel,LastPasswordChangeTime, DaysSinceLastPasswordChange, YearsSinceLastPasswordChange, PasswordNeverExpires, PasswordNotRequired, OUPath
| sort by DaysSinceLastPasswordChange desc 
| where tolower(AccountName) in ("krbtgt", "administrator","guest","admin") or tolower(AccountName) startswith "msol_"
                                                                    or tolower(AccountName) startswith "AAD_"
                                                                    or tolower(AccountName) startswith "ADSync"
```
