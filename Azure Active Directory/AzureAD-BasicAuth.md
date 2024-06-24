# AzureAD - Basic Authentication

## Query Information

### Description

Use the below queries to identify basic authentication activities in Azure AD

#### References

- [Deprecation of Basic authentication in Exchange Online](https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/deprecation-of-basic-authentication-exchange-online)

### Microsoft Sentinel

Siginin logs

```kql
SigninLogs
| extend IsLegacyAuth = 
case(ClientAppUsed contains "Browser", "No", 
ClientAppUsed contains "Mobile Apps and Desktop clients", "No",
ClientAppUsed contains "Exchange ActiveSync", "No",
ClientAppUsed contains "Authenticated SMTP", "Yes",
ClientAppUsed contains "Other clients", "Yes", "Unknown") 
| where IsLegacyAuth == 'Yes'
| where ResultType == 0
```

NonInteractive Signin logs

```kql
AADNonInteractiveUserSignInLogs
| extend IsLegacyAuth = 
case(ClientAppUsed contains "Browser", "No", 
ClientAppUsed contains "Mobile Apps and Desktop clients", "No",
ClientAppUsed contains "Exchange ActiveSync", "No",
ClientAppUsed contains "Authenticated SMTP", "Yes",
ClientAppUsed contains "Other clients", "Yes", "Unknown") 
| where IsLegacyAuth == 'Yes'
| where ResultType == 0
```

Both Sigin and NonInteractive Sign in logs

```kql
union  isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| extend IsLegacyAuth = 
case(ClientAppUsed contains "Browser", "No", 
ClientAppUsed contains "Mobile Apps and Desktop clients", "No",
ClientAppUsed contains "Exchange ActiveSync", "No",
ClientAppUsed contains "Authenticated SMTP", "Yes",
ClientAppUsed contains "Other clients", "Yes", "Unknown") 
| where IsLegacyAuth == 'Yes'
| where ResultType == 0
```
