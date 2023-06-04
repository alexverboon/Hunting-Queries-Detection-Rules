# Azure Active Directory - Conditional Access Changes

## Query Information

### Description

This query provides a simple overview of Conditional Access policy changes

```kql
AuditLogs
| where OperationName has_any("conditional access policy")
| project
    TimeGenerated,
    OperationName,
    policy=TargetResources[0].displayName,
    modifiedBy=InitiatedBy.user.userPrincipalName
```
