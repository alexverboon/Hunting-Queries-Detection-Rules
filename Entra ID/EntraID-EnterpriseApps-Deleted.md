# Entra ID - Enterprise Applications - Deletions

## Query Information

### Description

Use the below query to identify deleted Enterprise Applications in Entra ID

When you delete and enterprise application, it remains in a suspended state in the recycle bin for 30 days. During the 30 days, you can Restore the application.

#### References

- [Delete an enterprise application](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/delete-application-portal?pivots=portal)

### Microsoft Sentinel

```kql
AuditLogs
| where OperationName == "Remove service principal"
| extend Application = tostring(TargetResources[0].displayName)
| extend InitiatedByData = parse_json(tostring(InitiatedBy))
| extend 
    InitiatorType = iff(isnotempty(InitiatedByData.user), "User", "App"),
    DisplayName = iff(isnotempty(InitiatedByData.user), InitiatedByData.user.displayName, InitiatedByData.app.displayName),
    Id = iff(isnotempty(InitiatedByData.user), InitiatedByData.user.id, InitiatedByData.app.servicePrincipalId),
    UserPrincipalName = InitiatedByData.user.userPrincipalName,
    IPAddress = InitiatedByData.user.ipAddress
| project TimeGenerated, Application, InitiatorType, DisplayName, Id, UserPrincipalName, IPAddress
```
