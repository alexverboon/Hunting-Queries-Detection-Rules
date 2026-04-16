# Defender for Identity - Sensitive Identity Logins

## Query Information

### Description

The query below detects Defender for Identity logins which involves a sensitive user account. 

#### References

- [Leveraging the convergence of Microsoft Defender for Identity in Microsoft 365 Defender Portal
](https://techcommunity.microsoft.com/t5/microsoft-365-defender-blog/leveraging-the-convergence-of-microsoft-defender-for-identity-in/ba-p/3856321)

### Microsoft 365 Defender


```kql
//Detect all sensitive logins
IdentityLogonEvents
| where Application == "Active Directory" //Logins detected by Defender for Identity
| where LogonType == "Interactive" //Interactive login type
| join kind=inner (
IdentityInfo
| where Tags contains "Sensitive" //Only Sensitive identities
) on $left.AccountSid == $right.OnPremSid
| summarize SensitiveLogins = count(LogonType) by AccountDisplayName1, DeviceName
```

