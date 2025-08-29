# Use of Administrator Account

## Query Information

### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1078.002 | Valid Accounts: Domain Accounts | https://attack.mitre.org/techniques/T1078/002  |
| T1078.001 | Valid Accounts: Default Accounts | https://attack.mitre.org/techniques/T1078/001 | 

### Description

Use the below query to identify logon events with the Administrator account.

#### References

- [Securing Built-in Administrator Accounts in Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-d--securing-built-in-administrator-accounts-in-active-directory)
- [Local Accounts](https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts)

### Microsoft 365 Defender

```kql
DeviceLogonEvents
| where AccountSid endswith "-500"
| extend AccountType = iff(AccountDomain =~ DeviceName, "LocalAdmin", "DomainAdmin")
| project Timestamp, DeviceName, AccountName, AccountDomain, AccountSid, AccountType, LogonType
| sort by Timestamp desc
| summarize TotalLogons = count() by DeviceName, AccountName, AccountDomain, AccountSid, AccountType, LogonType
```
