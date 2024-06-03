# EntraID - Tenant Restriction - Failed sign-in

## Query Information

### Description

Use the below query to identify failed sign-insto Entra ID due to Tenant restriction policy

#### References

- [Set up tenant restrictions v2](https://learn.microsoft.com/en-us/entra/external-id/tenant-restrictions-v2#option-3-enable-tenant-restrictions-on-windows-managed-devices-preview)


### Microsoft Sentinel

```kql
// Tenant restriction
SigninLogs
| where ResultType == "5000211"
| project TimeGenerated, ResultType, ResultDescription, UserPrincipalName,ClientAppUsed, AppDisplayName, HomeTenantId, CrossTenantAccessType, IPAddress
```

