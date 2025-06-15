# Defender for Identity - Disabled Accounts with Privileged Roles

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1110.003 | Credential Access: Brute Force: Password Spraying | https://attack.mitre.org/techniques/T1110/003/ |

### Description

Use the below query to identify ***disabled*** identities with privileged roles assigned.

#### References

### Microsoft Defender XDR

```kql
IdentityInfo
| summarize arg_max(Timestamp,*) by AccountObjectId
| where isnotempty( AssignedRoles) or isnotempty( PrivilegedEntraPimRoles)
| where AssignedRoles != '[]'
| where IsAccountEnabled == false
| project AccountName, AccountDomain, AccountDisplayName, AccountObjectId, OnPremSid, CriticalityLevel, IsAccountEnabled, PrivilegedEntraPimRoles, AssignedRoles, SourceProvider, Type
```
