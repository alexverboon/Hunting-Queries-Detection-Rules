# Defender for Identity - Service Accounts

## Query Information

### Description

Use the below query to retrieve Active Directory Service Accounts from the Defender for Identity Service Accounts inventory.

Service Account Types

- ***gMSA (Group Managed Service Accounts)*** gMSAs provide a single identity solution for multiple services that require mutual authentication
 across multiple servers, as they allow Windows to handle password management, reducing administrative overhead.
- ***sMSA (Managed Service Accounts)*** Like gMSA but are designed for individual services on a single server rather than groups.
- ***User Account*** These standard user accounts are typically used for interactive logins but can also be configured to run services.

Regular User Accounts are classified as 'Service Accounts' when the account is configured to "Password never expires" AND has a SPN (Service Principal Name)

#### References

- [Microsoft Defender for Identity has announced the public preview of a new service account discovery module that automatically identifies and classifies service accounts in Active Directory](https://techcommunity.microsoft.com/blog/microsoftthreatprotectionblog/discover-and-protect-service-accounts-with-microsoft-defender-for-identity/4395347)
- [Investigate and protect Service Accounts - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/service-account-discovery)
- [Start having visibility in service accounts with defender for identity](https://m365internals.com/2021/03/27/start-having-visibility-in-service-accounts-with-defender-for-identity/)

### Microsoft Defender XDR

List Active Directory Service Accounts

```kql
IdentityInfo
| where Timestamp > ago(30d)
| where Type == @"ServiceAccount"
| where SourceProvider == @"ActiveDirectory"
| summarize arg_max(Timestamp,*) by OnPremSid
```

```kql
IdentityInfo
| summarize arg_max(Timestamp,*) by AccountName
| project AccountName, DistinguishedName
| extend OUPath = extract(@"CN=[^,]+,(.*)", 1, DistinguishedName)
| where OUPath contains "OU=ServiceAccounts"
| distinct OUPath
```
