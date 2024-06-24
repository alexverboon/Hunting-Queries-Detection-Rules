# Active Directory - Failed logons

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1078.002 | Valid Accounts: Domain Accounts | https://attack.mitre.org/techniques/T1078/002/ |

### Description

Run the below query to review failed logon activities within Active Directory

#### References

### Microsoft 365 Defender

```kql
// Active Directory
IdentityLogonEvents
| where isnotempty(FailureReason )
| where ActionType <> "LogonSuccess"
| where Application == "Active Directory"
// | summarize count() by AccountName
// | sort by count_
```
