# Active Directory - User last logon

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1110.003 | Credential Access: Brute Force: Password Spraying | https://attack.mitre.org/techniques/T1110/003/ |

### Description

Use the below query to identify User account last logon activity. Those that did not have activity for the defined lookback period can be considered to be disabled depending
on your company policies.

#### References

### Microsoft Defender XDR

```kql
IdentityInfo
| summarize arg_max(Timestamp, *) by AccountObjectId
| join kind=leftouter (
    IdentityLogonEvents
    | where Application == @"Active Directory"
    | extend LastLogonTime = Timestamp
    | summarize arg_max(Timestamp, *) by AccountObjectId, AccountSid, AccountDomain
    | where ActionType == @"LogonSuccess")
    on $left.AccountObjectId == $right.AccountObjectId
| extend NoLogon = iff(isempty(LastLogonTime), "True", "False")
| project
    AccountName,
    AccountDomain,
    AccountObjectId,
    LastLogonTime,
    Type,
    DistinguishedName,
    IsAccountEnabled,
    CreatedDateTime,
    NoLogon
    | where NoLogon == "True"
```
